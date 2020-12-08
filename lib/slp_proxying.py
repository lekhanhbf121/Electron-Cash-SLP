"""
Background jobber to query an SLP proxy server.

Proxy queries take the form of

request: "give me SLP validity results for [txid0, txid1, txid2, txid3, ...]"
response: "true, false, false, true, ..."

This is used by slp_validator_0x01.py.
"""

import sys, json
import threading
import queue
import traceback
import weakref
import collections
import requests
import codecs

from .slp_dagging import INF_DEPTH

# Endpoint hardcoded for now:
# https://tokengraph.network/verify/3979a8338e63883c865088e8f544a7b026ed4860c061e83c5ec158bf41492a74,...
# missing txes

class ProxyQuerier:
    """
    A single thread that processes proxy requests sequentially.

    (if more proxies are added, this should be split to abstract class)
    """

    def __init__(self, threadname="ProxyQuerier"):
        # ---
        self.queue = queue.Queue()

        self.pastresults = dict()

        # Kick off the thread
        self.thread = threading.Thread(target=self.mainloop, name=threadname, daemon=True)
        self.thread.start()

    def mainloop(self,):
        try:
            while True:
                job = self.queue.get(block=True) #timeout=60)
                txids, callback = job

                # query just the keys we don't yet know
                #known = txids.intersection(self.pastresults.keys())
                #unk = txids.difference(known)
                unk = txids.difference(self.pastresults.keys())

                try:
                    qresults = self.query(unk)
                except Exception as e:
                    # If query dies, keep going.

                    print("error in proxy query", e, file=sys.stderr)
                    pass
#                    traceback.print_exc()
                else:
                    # Got answer - update list.
                    self.pastresults.update(qresults)

                # Now construct results -- combines new and past results.
                results = {}
                for t in txids:
                    try:
                        results[t] = self.pastresults[t]
                    except KeyError:
                        pass
                callback(txids, results)
        finally:
            print("Proxy thread died!", file=sys.stderr)

    def add_job(self, txids, callback):
        """ Callback called as `callback(txids, results)`
        where txids is set and results is txid-keyed dict. """
        txids = frozenset(txids)
        self.queue.put((txids, callback))
        return txids

    def query(self, txids):
        ret = {}
        for txid in txids:
            print('Requesting txid validity from gs.fountainhead.cash: ' + txid)
            _hash = codecs.encode(codecs.decode(txid,'hex')[::-1], 'hex').decode()
            print('Requesting txid validity from gs.fountainhead.cash (reversed): ' + _hash)

            query_json = { "txid": _hash }
            requrl = 'https://gs.fountainhead.cash/v1/graphsearch/trustedvalidation'
    #        print(requrl, file=sys.stderr)
            reqresult = requests.post(requrl, json=query_json, timeout=3)

            try:
                dat = json.loads(reqresult.content.decode('utf-8'))
                resp = dat['valid']
            except:
                m = json.loads(dat)
                if m["error"]:
                    raise Exception(m["error"])
                raise Exception(m)
            if resp:
                ret[txid] = resp
        return ret

tokengraph_proxy = ProxyQuerier()
