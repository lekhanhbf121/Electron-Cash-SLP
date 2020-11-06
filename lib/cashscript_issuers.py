import threading
import queue
from collections import namedtuple
from typing import List, Dict, Generator
from . import util
from . import cashscript
from .storage import WalletStorage
from .cashscript_issuers_pb2 import IssuerTemplateParams

_valid_issuer_templates = [ cashscript.SLP_DOLLAR_ID ]
_valid_template_statuses = [ 'unprocessed', 'downloaded', 'failed' ]
_valid_contract_statuses = [ 'unprocessed', 'matched', 'unmatched' ]

class Address(namedtuple("Address", "p2sh_address" "p2pkh_address" "bfp_txid" "params")):
    ''' Address item for storage '''

class IssuerTemplate(namedtuple("IssuerTemplate", "name" "bfp_txid" "artifact_sha256" "params")):
    ''' Issuer's Template params for storage '''

class DownloadQueueItem:
    ''' Downloads a new bitcoin file associated with the issuer's p2sh template parameters '''
    def __init__(self, txid):
        self.txid = txid
        self.data = None  # IssuerTemplateParams unmarshalled protobuf object 

    def download(self):
        # TODO: download and attempt to unmarshal the Bitcoin File
        pass

class ContractMatcherQueueItem:
    ''' Attempts to matches a specific p2sh outpoint, and associated p2pkh notifiers, to a list of known issuer templates '''
    def __init__(self, txid, vout, p2pkh_addrs):
        self.txid = txid
        self.vout = vout
        self.status = 'unprocessed'
        self.artifact_sha256 = None
        self.params = None
        self.date_added = -1

    def match(self):
        # TODO: loops through known templates to find match for 
        pass

class IssuerContractManager(util.PrintError):
    '''
    Used to maintain a processing queue of items related accounting for our coins located
    in p2sh smart contracts associated with specific token issuer.

    Types of items in this manager's processing queue include:

        1) DownloadQueueItem:
                    An item with potential Bitcoin File Protocol file containing an
                    issuer's smart contract parameters. This will be normally be 
                    added when the wallet is holding a token with Genesis document
                    URL pointing to a Bitcoin File Protocol hash.

        2) ContractMatcherQueueItem:
                    An item containing a p2sh outpoint which may is able to be
                    matched against a set of known p2sh issuer specific templates.
                    Each candidate p2sh outpoint item is accompanied with one or
                    more p2pkh addresses which were included in the transaction as 
                    notifiers to the p2pkh wallet.  The notifier also indicates
                    which of the wallet's keys can be used to derive the
                    redeemScript.

    This manager performs a number of actions, including:
        - Persists a global store of known issuer template parameters
          (i.e., ~/.electron-cash/issuer_params )

        - Persists, to the wallet file, a list of successful and unsuccessful p2sh contract
          matches, and will retry matching unmatched addresses whenever new issuer params are added.
          Previous unsuccessful transaction match attempts on certain events. 
        
        - Will update wallet._slp_txo dict, and wallet.txo/txi dicts as needed
        
        - Keeps a list of addresses for use in 'is_mine'.
    '''
    def __init__(self, storage: WalletStorage, threadname="CashScript"):

        self.storage = storage
        self.threadname = threadname

        self.lock = threading.Lock()
        self._queue = queue.Queue()  # TODO: make this a PriorityQueue based on class, status, or age?
        self.queue_thread = threading.Thread(target=self.mainloop, name=self.threadname+'/issuer_queue', daemon=True)
        self.queue_thread.start()

        self.load()

    ##########################################
    # Load / Save plus their private methods #
    ##########################################

    def load(self):
        self.addresses = IssuerContractManager._load_addresses(self.storage)
        self.issuer_templates = IssuerContractManager._load_issuer_templates(self.storage)

    @staticmethod
    def _load_addresses(storage : WalletStorage) -> List[Address]:
        assert callable(getattr(storage, 'get', None))
        _list = storage.get('cashscript_addresses', [])
        out = []
        for d in _list:
            out.append( Address(d.get('p2sh_address'), d.get('p2pkh_address'), d.get('bfp_txid'), d.get('params')) )
        return out

    @staticmethod
    def _save_addresses(data : List[Address]) -> dict:
        d = []
        for addr in data:
            d.append({
                'p2sh_address': addr.p2sh_address,
                'p2pkh_address': addr.p2pkh_address,
                'bfp_txid': addr.bfp_txid,
                'params': addr.params
            })
        return d

    @staticmethod
    def _load_issuer_templates(storage : WalletStorage) -> List[IssuerTemplate]:
        assert callable(getattr(storage, 'get', None))
        _list = storage.get('cashscript_issuers', [])
        out = []
        for d in _list:
            out.append( Address(d.get('name'), d.get('bfp_txid'), d.get('artifact_sha256'), d.get('params')) )
        return out

    @staticmethod
    def _save_issuer_templates(data : List[IssuerTemplate]) -> dict:
        d = []
        for temp in data:
            d.append({
                'name': temp.name,
                'bfp_txid': temp.bfp_txid,
                'artifact_sha256': temp.artifact_sha256,
                'params': temp.params
            })
        return d

    def save(self):
        addr_dict = _save_addresses(self.addresses)
        self.storage.put('cashscript_addresses', addr_dict)
        issuer_dict = _save_issuer_dict(self.issuer_templates)
        self.storage.put('cashscript_issuers', issuer_dict)

    ################
    # Queue Thread #
    ################

    def mainloop(self):
        try:
            while True:
                candidate = self._queue.get(block=True)
                #res = candidate.match()
        finally:
            print("[CashScript Issuer Manager] Error: mainloop exited.", file=sys.stderr)

    ###############
    # Plublic API #
    ###############

    def add_transaction_candidate(self, transaction):
        # TODO: loop through transaction outputs and add ContractMatcherQueueItem items as needed 
        pass
