"""
SLP Graph Search Client

Performs a background search and batch download of graph
transactions from gs++ server. For more information about
the gs++ server see:

https://github.com/blockparty-sh/cpp_slp_graph_search

This class is currently only used by slp_validator_0x01.py.
The NFT1 validator has not yet been attached to the NFT1 validator.

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
from .transaction import Transaction
from .caches import ExpiringCache
from electroncash import networks

class _GraphSearchJob:
    def __init__(self, txid, valjob_ref):
        self.root_txid = txid
        self.valjob = valjob_ref

        # metadata fetched from back end
        self.depth_map = None
        self.total_depth = None
        self.txn_count_total = None

        # job status info
        self.search_started = False
        self.search_success = None
        self.job_complete = False
        self.exit_msg = None
        self.depth_current_query = None
        self.txn_count_progress = 0
        self.gs_response_size = 0
        self.last_search_url = '(url empty)'

        # ctl
        self.waiting_to_cancel = False
        self.cancel_callback = None

        # host for graph search
        self.host = slp_gs_mgr.slp_gs_host

        # gs job results cache - clears data after 30 minutes
        self._txdata = ExpiringCache(maxlen=10000000, name="GraphSearchTxnFetchCache", timeout=1800)

    def sched_cancel(self, callback=None, reason='job canceled'):
        self.exit_msg = reason
        if self.job_complete:
            return
        if not self.waiting_to_cancel:
            self.waiting_to_cancel = True
            self.cancel_callback = callback
            return

    def _cancel(self):
        self.job_complete = True
        self.search_success = False
        if self.cancel_callback:
            self.cancel_callback(self)

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

class _SlpGraphSearchManager:
    """
    A single thread that processes graph search requests sequentially.
    """
    def __init__(self, threadname="GraphSearch"):

        # holds the job history and status
        self._search_jobs = dict()
        self._gui_object = None
        self.lock = threading.Lock()

        # graph search host url
        self.slp_gs_host = ""

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
        return self._gui_object().slp_validity_signal if self._gui_object else None

    @property
    def slp_validation_fetch_signal(self):
        return self._gui_object().slp_validation_fetch_signal if self._gui_object else None

    def _emit_ui_update(self, data):
        if not self.slp_validation_fetch_signal:
            return
        self.slp_validation_fetch_signal.emit(data)

    def new_search(self, valjob_ref):
        """
        Starts a new thread to fetch GS metadata for a job.
        Depending on the metadata results the job may end up being added to the GS queue.

        Returns weakref of the new GS job object if new job is created.
        """
        txid = valjob_ref.root_txid

        with self.lock:
            if txid not in self._search_jobs.keys():
                job = _GraphSearchJob(txid, valjob_ref)
                self._search_jobs[txid] = job
                self.search_queue.put(job)
            else:
                job = self._search_jobs[txid]
            return job
        return None

    def remove_search_job(self, root_txid):
        with self.lock:
            self._search_jobs.pop(root_txid, None)

    def is_job_failed(self, root_txid):
        with self.lock:
            if root_txid in self._search_jobs.keys() \
                and self._search_jobs[root_txid].job_complete \
                and not self._search_jobs[root_txid].search_success:
                return True
            return False

    def cancel_all_jobs(self):
        with self.lock:
            for job in self._search_jobs.values():
                job.sched_cancel()

    def find(self, root_txid):
        with self.lock:
            if root_txid in self._search_jobs.keys():
                return self._search_jobs[root_txid]
        return None

    def jobs_copy(self):
        with self.lock:
            return self._search_jobs.copy()

    def restart_search(self, job):
        def callback(job):
            self.remove_job(job.root_txid)
            self.new_search(job.valjob)
            job = None
        if not job.job_complete:
            job.sched_cancel(callback, reason='job restarted')
        else:
            callback(job)

    def mainloop(self,):
        try:
            while True:
                job = self.search_queue.get(block=True)
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
                    if job.valjob.wakeup:
                        job.valjob.wakeup.set()
                    self._emit_ui_update(self.bytes_downloaded)
        finally:
            print("[SLP Graph Search] Error: mainloop exited.", file=sys.stderr)

    def search_query(self, job):
        if job.waiting_to_cancel:
            job._cancel()
            return
        if not job.valjob.running and not job.valjob.has_never_run:
            job.set_failed('validation finished')
            return
        print('Requesting txid from gs++: ' + job.root_txid)
        txid = codecs.encode(codecs.decode(job.root_txid,'hex')[::-1], 'hex').decode()
        print('Requesting txid from gs++ (reversed): ' + txid)

        dat = b''
        time_last_updated = time.perf_counter()

        # setup post url/query based on gs server kind
        kind = 'bchd'
        host = slp_gs_mgr.slp_gs_host
        if networks.net.SLPDB_SERVERS.get(host):
            kind = networks.net.SLPDB_SERVERS.get(host)["kind"]
        if kind == 'gs++':
            url = host + "/v1/graphsearch/graphsearch"
            query_json = { "txid": txid } # TODO: handle 'validity_cache' exclusion from graph search (NOTE: this will impact total dl count)
            res_txns_key = 'txdata'
        elif kind == 'bchd':
            txid_b64 = base64.standard_b64encode(codecs.decode(job.root_txid,'hex')[::-1]).decode("ascii") 
            url = host + "/v1/GetSlpGraphSearch"
            query_json = { "hash": txid_b64 } # , "valid_txids": [] }
            res_txns_key = 'txdata'
        else:
            raise Exception("unknown server kind")

        with requests.post(url, json=query_json, stream=True, timeout=60) as r:
            for chunk in r.iter_content(chunk_size=None):
                job.gs_response_size += len(chunk)
                self.bytes_downloaded += len(chunk)
                dat += chunk
                t = time.perf_counter()
                if (t - time_last_updated) > 2:
                    self._emit_ui_update(self.bytes_downloaded)
                    time_last_updated = t
                if not job.valjob.running:
                    job.set_failed('validation job stopped')
                    return
                elif job.waiting_to_cancel:
                    job._cancel()
                    return
        try:
            dat = json.loads(dat.decode('utf-8'))
            txns = dat[res_txns_key]
        except:
            m = json.loads(dat)
            if m["error"]:
                raise Exception(m["error"])
            raise Exception(m)

        for txn in txns:
            job.txn_count_progress += 1
            tx = Transaction(base64.b64decode(txn).hex())
            job.put_tx(tx)
        job.set_success()
        print("[SLP Graph Search] job success.")

slp_gs_mgr = _SlpGraphSearchManager()
