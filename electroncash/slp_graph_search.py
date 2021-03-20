"""
SLP Graph Search Client

Performs a background search and batch download of graph
transactions from a Graph Search server. For more information about
a Graph Search server see:

* gs++: https://github.com/blockparty-sh/cpp_slp_graph_search
* bchd: https://github.com/simpleledgerinc/bchd/tree/graphsearch

This class is currently only used by slp_validator_0x01.py.
The NFT1 validator has not yet been attached to the NFT1 validator.

Servers can be added or removed using "lib/servers_slpdb.json" and 
"lib/servers_slpdb_testnet.json".  Currently only the bchd has been tested
with the validation cache excludes.

"""

import sys
import time
import threading
import queue
import traceback
import weakref
import collections
import json
import base64
import requests
import codecs
import random
from operator import itemgetter
from .transaction import Transaction
from .caches import ExpiringCache
from electroncash import networks

from . import slp_validator_0x01

class _GraphSearchJob:
    def __init__(self, valjob):
        self.root_txid = valjob.root_txid
        self.valjob = valjob

        # metadata fetched from back end
        self.depth_map = None
        self.total_depth = None
        self.txn_count_total = None
        self.validity_cache_size = 0

        # job status info
        self.search_started = False
        self.search_success = None
        self.job_complete = False
        self.exit_msg = ''
        self.depth_current_query = None
        self.txn_count_progress = 0
        self.gs_response_size = 0
        self.last_search_url = '(url empty)'

        # ctl
        self.waiting_to_cancel = False
        self.cancel_callback = None

        # gs job results cache - clears data after 30 minutes
        self._txdata = ExpiringCache(maxlen=10000000, name="GraphSearchTxnFetchCache", timeout=1800)

    def sched_cancel(self, callback=None, reason='job canceled'):
        self.exit_msg = reason
        if self.job_complete:
            return
        if not self.waiting_to_cancel:
            self.waiting_to_cancel = True
            self.cancel_callback = callback

    def set_success(self):
        self.search_success = True
        self.job_complete = True

    def set_failed(self, reason=None):
        self.search_started = True
        self.search_success = False
        self.job_complete = True
        self.exit_msg = reason

    def get_tx(self, txid: str) -> object:
        ''' Attempts to retrieve txid from the tx cache that this class
        keeps in-memory.  Returns None on failure. The returned tx is
        not deserialized, and is a copy of the one in the cache. '''
        tx = self._txdata.get(txid)
        if tx is not None and tx.raw:
            # make sure to return a copy of the transaction from the cache
            # so that if caller does .deserialize(), *his* instance will
            # use up 10x memory consumption, and not the cached instance which
            # should just be an undeserialized raw tx.
            return Transaction(tx.raw)
        return None

    def put_tx(self, tx: bytes, txid: str = None):
        ''' Puts a non-deserialized copy of tx into the tx_cache. '''
        txid = txid or Transaction._txid(tx.raw)  # optionally, caller can pass-in txid to save CPU time for hashing
        self._txdata.put(txid, tx)

    def get_job_cache(self, *, reverse=True, max_size=-1, is_mint=False):
        ''' Get validity cache for a token graph 
            
            reverse reverses the endianess of the txid
            
            max_size=-1 returns a cache with no size limit

            is_mint is used to further limit which txids are included in the cache
            for mint transactions, since other mint transactions are the only 
            validation contributors
        '''
        if max_size == 0:
            return []

        wallet = self.valjob.ref()
        if not wallet:
            return []

        wallet_val = self.valjob.validitycache
        token_id = self.valjob.graph.validator.token_id_hex
        gs_cache = []

        # pull valid txids from wallet storage
        for [txid, val] in wallet.slpv1_validity.items():
            _token_id = wallet.tx_tokinfo.get(txid, {}).get("token_id", None)
            if _token_id == token_id and val == 1:
                gs_cache.append(txid)

        # pull valid txids from the shared in-memory token graph
        # and prioritize items from the wallet validity cache
        if not is_mint:
            sample_size = -1
            if max_size > 0 and len(gs_cache) < max_size:
                sample_size = max_size - len(gs_cache)
            if sample_size > 0:
                for txid in self.valjob.graph.get_valid_txids(max_size=sample_size, exclude=gs_cache):
                    gs_cache.append(txid)

        # TODO: pull valid txids from a "checkpoints" file shipped with the wallet
        #   these txids can be selected intelligently through graph analysis.  Tokens
        #   supported in the type of arrangement would likely be done through the
        #   support of the token issuer for the purpose of improving user experience.

        # if required limit the size of the cache
        gs_cache = list(set(gs_cache))
        if gs_cache and max_size > 0 and len(gs_cache) > max_size:
            gs_cache = list(set(random.choices(gs_cache, k=max_size)))

        # update the cache size variable used in the UI
        self.validity_cache_size = len(gs_cache)

        # return as base64, not hex
        b64_hashes = []
        for txid in gs_cache:
            b = codecs.decode(txid, 'hex')
            if reverse:
                b = b[::-1]
            b64 = base64.standard_b64encode(b).decode("ascii")
            b64_hashes.append(b64)

        return b64_hashes

    def _cancel(self):
        self.job_complete = True
        self.search_success = False
        if self.cancel_callback:
            self.cancel_callback(self)

class _SlpGraphSearchManager:
    """
    A single thread that processes graph search requests sequentially.
    """
    def __init__(self, threadname="GraphSearch"):

        # holds the job history and status
        self._search_jobs = dict()
        self._gui_object = None
        self.lock = threading.Lock()

        # Create a single use queue on a new thread
        self.search_queue = queue.Queue()  # TODO: make this a PriorityQueue based on dag size

        self.threadname = threadname
        self.search_thread = threading.Thread(target=self.mainloop, name=self.threadname+'/search', daemon=True)
        self.search_thread.start()
        
        self.bytes_downloaded = 0 # this is the total number of bytes downloaded by graph search

    def bind_gui(self, gui):
        self._gui_object = gui

    @property
    def slp_validity_signal(self):
        return self._gui_object().slp_validity_signal

    @property
    def slp_validation_fetch_signal(self):
        return self._gui_object().slp_validation_fetch_signal

    @property
    def gs_enabled(self):
        return self._gui_object().config.get('slp_validator_graphsearch_enabled', False)

    def _set_gs_enabled(self, enable):
        self._gui_object().config.set_key('slp_validator_graphsearch_enabled', enable)

    @property
    def gs_host(self):
        host = self._gui_object().config.get('slp_validator_graphsearch_host', '')
        # handle case for upgraded config key name
        if not host:
            host = self._gui_object().config.get('slp_gs_host', '')
            if not host: self.set_gs_host(host)
        return host

    def set_gs_host(self, host):
        self._gui_object().config.set_key('slp_validator_graphsearch_host', host)

    # def _emit_ui_update(self, data):
    #     if not self.slp_validation_fetch_signal:
    #         return
    #     self.slp_validation_fetch_signal.emit(data)

    def get_gs_job(self, valjob):
        """
        Returns the GS job object, if new job is created it is added to the gs queue.
        """
        txid = valjob.root_txid
        with self.lock:
            if txid not in self._search_jobs.keys():
                job = _GraphSearchJob(valjob)
                self._search_jobs[txid] = job
                self.search_queue.put(job)
            return self._search_jobs[txid]

    def toggle_graph_search(self, enable):
        """
        Used by the UI to enable/disable graph search

        Since its called only by the UI no locks are being held.
        """
        if self.gs_enabled == enable:
            return

        # get a weakref to each open wallet
        wallets = weakref.WeakSet()
        jobs_copy = self._search_jobs.copy()
        for job_id in jobs_copy:
            job = jobs_copy[job_id]
            job.valjob.stop()
            if job.valjob.ref and job.valjob.ref():
                wallets.add(job.valjob.ref())

        # kill the current validator activity
        slp_validator_0x01.shared_context.kill()

        # delete all the gs jobs
        self._search_jobs.clear()

        self._set_gs_enabled(enable)

        # activate slp in each wallet
        for wallet in wallets:
            if wallet: wallet.activate_slp()

    def find(self, root_txid):
        return self._search_jobs.get(root_txid, None)

    def jobs_copy(self):
        with self.lock:
            return self._search_jobs.copy()

    def restart_search(self, job):
        def callback(job):
            self.get_gs_job(job.valjob)
            job = None
        if not job.job_complete:
            job.sched_cancel(callback, reason='job restarted')
        else:
            callback(job)

    def mainloop(self,):
        while True:
            job = self.search_queue.get(block=True)
            if not self.gs_enabled:
                job.set_failed('gs is disabled')
                continue
            job.search_started = True
            if not job.valjob.running and not job.valjob.has_never_run:
                job.set_failed('validation finished')
                continue
            try:
                # search_query is a network call, most time will be spent here
                self.search_query(job)
            except Exception as e:
                print("error in graph search query", e, file=sys.stderr)
                job.set_failed(str(e))
            finally:
                job.valjob.wakeup.set()
                #self._emit_ui_update(self.bytes_downloaded)

    def search_query(self, job):
        if job.waiting_to_cancel:
            job._cancel()
            return
        if not job.valjob.running and not job.valjob.has_never_run:
            job.set_failed('validation finished')
            return
        print('GS Request: {} ({})'.format(job.root_txid, self.gs_host))
        txid = codecs.encode(codecs.decode(job.root_txid,'hex')[::-1], 'hex').decode()
        print('GS Request: {} (reversed) ({})'.format(txid, self.gs_host))

        # setup post url/query based on gs server kind
        kind = 'bchd'
        host = slp_gs_mgr.gs_host
        if networks.net.SLPDB_SERVERS.get(host):
            kind = networks.net.SLPDB_SERVERS.get(host)["kind"]
        if kind == 'gs++':
            url = host + "/v1/graphsearch/graphsearch"
            query_json = { "txid": txid } # TODO: handle 'validity_cache' exclusion from graph search (NOTE: this will impact total dl count)
            res_txns_key = 'txdata'
        elif kind == 'bchd':
            root_hash_b64 = base64.standard_b64encode(codecs.decode(job.root_txid,'hex')[::-1]).decode("ascii") 
            url = host + "/v1/GetSlpGraphSearch"
            cache = job.get_job_cache(max_size=100)
            query_json = { "hash": root_hash_b64, "valid_hashes": cache }  # TODO: can use is_mint to improve cache for mint transactions
            res_txns_key = 'txdata'
        else:
            raise Exception("unknown server kind")

        dat = b''
        time_last_updated = time.perf_counter()
        headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
        with requests.post(url, data=json.dumps(query_json), headers=headers, stream=True, timeout=60) as r:
            for chunk in r.iter_content(chunk_size=None):
                job.gs_response_size += len(chunk)
                self.bytes_downloaded += len(chunk)
                dat += chunk
                # t = time.perf_counter()
                # if (t - time_last_updated) > 5:
                #     self._emit_ui_update(self.bytes_downloaded)
                #     time_last_updated = t
                if not job.valjob.running:
                    job.set_failed('validation job stopped')
                    return
                # FIXME: for some reason weakref to wallet still exists after closing (o_O)
                # if not job.valjob.ref():  
                #     job.set_failed('wallet file closed')
                #     return
                elif job.waiting_to_cancel:
                    job._cancel()
                    return
                elif not self.gs_enabled:
                    return

        try:
            dat = json.loads(dat.decode('utf-8'))
            txns = dat[res_txns_key]
        except:
            raise Exception(dat)

        for txn in txns:
            job.txn_count_progress += 1
            tx = Transaction(base64.b64decode(txn).hex())
            job.put_tx(tx)
        job.set_success()
        print("[SLP Graph Search] job success.")

slp_gs_mgr = _SlpGraphSearchManager()
