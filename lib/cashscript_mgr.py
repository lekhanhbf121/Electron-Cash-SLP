import threading
import queue
from collections import namedtuple
from typing import List, Dict, Generator
from . import util
from . import cashscript
from .address import Address
from .storage import WalletStorage
from .bitcoin import TYPE_ADDRESS
from .cashscript_pb2 import IssuerTemplateParams, ScriptPinPayload, NamedParam
from .networks import net

_valid_contract_statuses = [ 'unprocessed', 'matched', 'unmatched' ]
class ScriptMatch(namedtuple("ScriptMatch", "bfp_txid p2sh_address p2pkh_address params status")):
    ''' 
    ScriptMatch item for storage 

        bfp_txid      : this is the bitcoin files txid associated with the issuer's script
                        constructor input parameters, hex string format
        p2sh_address  : p2sh string with cash address formatted
        p2pkh_address : p2pkh string with cash address formatted
        params        : dict of hexadecimal strings
        status        : match status

    '''

    def match_to_issuer(self, mgr):
        for issuer_params in mgr.issuer_templates:
            artifact_entry = net.SCRIPT_ARTIFACTS[issuer_params.artifact_sha256]
            params = issuer_params.params
            addr = Address.from_string(p2pkh_address)
            params["pkh"] = addr.hash160.hex()
            _p2sh = cashscript.get_redeem_script_address_string(issuer_params.artifact_sha256, params)
            if _p2sh == self.p2sh_address:
                self.params = params
                self.bfp_txid = issuer_params.bfp_txid
                self.status = 'matched'
                return self
        return None

_valid_template_statuses = [ 'unprocessed', 'downloaded', 'failed' ]
class IssuerParams(namedtuple("IssuerParams", "name bfp_txid artifact_sha256 params status")):
    ''' Issuer's Template params for storage '''

    def try_download(self, mgr):
        # TODO: download and attempt to unmarshal the Bitcoin File
        # ignore any downloads
        if template.artifact_sha256 not in _valid_cashscript_templates:
            return None
        template = None
        return template

''' 
list of valid scripts which issuers are partially dependent on issuer defined parameters
'''
_valid_cashscript_templates = [ cashscript.SLP_DOLLAR_ID ]
_built_in_issuer_params = [
    IssuerParams(name='usd_test_dollar', bfp_txid='0', artifact_sha256=cashscript.SLP_DOLLAR_ID, params={'issuerPk': '...', 'slpSendFront': '...' }, status='downloaded')
]

class CashScriptManager(util.PrintError):
    '''
    Used to maintain a processing queue of items related accounting for our coins located
    in p2sh smart contracts associated with specific token issuer.

    Types of items in this manager's processing queue include:

        1) ScriptPin BFP upload/download

        1) IssuerParams:
                    An item with potential Bitcoin File Protocol file containing an
                    issuer's smart contract parameters. This will be normally be 
                    added when the wallet is holding a token with Genesis document
                    URL pointing to a Bitcoin File Protocol hash.

        2) ScriptMatch:
                    An item containing a p2sh outpoint which may is able to be
                    matched against a set of known p2sh issuer specific templates.
                    Each candidate p2sh outpoint item is accompanied with one or
                    more p2pkh script_matches which were included in the transaction as 
                    notifiers to the p2pkh wallet.  The notifier also indicates
                    which of the wallet's keys can be used to derive the
                    redeemScript.

    This manager performs a number of actions, including:
        - Persists a global store of known issuer template parameters
          (i.e., ~/.electron-cash/issuer_params )

        - Persists, to the wallet file, a list of successful and unsuccessful p2sh contract
          matches, and will retry matching unmatched script_matches whenever new issuer params are added.
          Previous unsuccessful transaction match attempts on certain events. 
        
        - Will update wallet._slp_txo dict, and wallet.txo/txi dicts as needed
        
        - Keeps a list of script_matches for use in 'is_mine'.
    '''
    def __init__(self, wallet, storage : WalletStorage, threadname="CashScript"):
        self.wallet = wallet
        self.storage = storage
        self.threadname = threadname
        self._queue = queue.Queue()  # TODO: make this a PriorityQueue based on class, status, or age?
        self.lock = threading.Lock()
        self.queue_thread = threading.Thread(target=self.mainloop, name=self.threadname+'/issuer_queue', daemon=True)
        self.queue_thread.start()
        self.load()

    ################
    # Queue Thread #
    ################

    def mainloop(self):
        try:
            while True:
                item = self._queue.get(block=True)

                if isinstance(item, ScriptMatch):
                    p2sh = item.p2sh_addr.to_full_string(Address.FMT_CASHADDR)
                    if p2sh in self.script_matches:
                        continue

                    # most time spent here trying to match the p2sh address with a known issuer's template parameters
                    match = item.match_to_issuer(self)
                    if match:
                        addr = match.p2sh_addr.to_full_string(Address.FMT_CASHADDR)
                        self.script_matches[addr] = match
                        # TODO: save
                    else:
                        continue

                elif isinstance(item, IssuerParams):

                    if item.bfp_txid in self.issuer_templates:
                        continue

                    # most time spent here downloading BFP from blockchain
                    template = item.try_download()
                    if template:
                        # save
                        pass
                    else:
                        continue

                else:
                    raise Exception('unsupported queue item type')
        finally:
            print("[CashScript Issuer Manager] Error: mainloop exited.", file=sys.stderr)

    ################
    #  Public API  #
    ################

    def process_transaction(self, tx_hash, tx):
        p2sh_indices = []
        for n, txo in enumerate(tx.outputs()):
            _type, addr, v = txo
            if _type != TYPE_ADDRESS:
                return
            if addr.kind == Address.ADDR_P2SH:
                is_my_p2sh = cashscript.is_mine(self.wallet, addr)
                if not is_my_p2sh:
                    p2sh_indices.append(n)
            elif addr.kind == Address.ADDR_P2PKH and n-1 in p2sh_indices and self.wallet.is_mine(addr, check_cashscript=False):
                _, p2sh_addr, _ = tx.outputs()[n-1]
                p2sh_address = p2sh_addr.to_full_string(Address.FMT_CASHADDR)
                p2pkh_address = addr.to_full_string(Address.FMT_CASHADDR)
                self._queue.put(ScriptMatch(p2sh_address, p2pkh_address, bfp_txid=None, params=None, status='unmatched'))

    def is_mine(self):
        return False

    ##########################################
    # Load / Save plus their private methods #
    ##########################################

    def load(self):
        self.script_matches = CashScriptManager._load_script_matches(self.storage)
        self.issuer_templates = CashScriptManager._load_issuer_templates(self.storage)

    @staticmethod
    def _load_script_matches(storage : WalletStorage) -> Dict[str, ScriptMatch]:
        assert callable(getattr(storage, 'get', None))
        _list = storage.get('cashscript_script_matches', [])
        out = {}
        for d in _list:
            out[d.get('p2sh_address')] = ScriptMatch(d.get('p2sh_address'), d.get('p2pkh_address'), d.get('bfp_txid'), d.get('params'))
        return out

    @staticmethod
    def _save_script_matches(data : Dict[str, ScriptMatch]) -> dict:
        d = []
        for addr in data:
            d.append({
                'p2sh_address': addr.p2sh_address,
                'p2pkh_address': addr.p2pkh_address,
                'bfp_txid': addr.bfp_txid,
                'params': addr.params,
                'status': addr.status
            })
        return d

    @staticmethod
    def _load_issuer_templates(storage : WalletStorage) -> Dict[str, IssuerParams]:

        assert callable(getattr(storage, 'get', None))
        out = {}

        # locally stored issuer params 
        _list = storage.get('cashscript_issuers', [])
        for d in _list:
            out[d.get('bfp_txid')] = IssuerParams(d.get('name'), d.get('bfp_txid'), d.get('artifact_sha256'), d.get('params'), d.get('status'))
        
        # pre-loaded issuer params
        for issuer_params in _built_in_issuer_params:
            out[issuer_params.bfp_txid] = issuer_params

        return out

    @staticmethod
    def _save_issuer_templates(data : Dict[str, IssuerParams]) -> dict:
        d = []
        for temp in data:
            d.append({
                'name': temp.name,
                'bfp_txid': temp.bfp_txid,
                'artifact_sha256': temp.artifact_sha256,
                'params': temp.params,
                'status': temp.status
            })
        return d

    def save(self):
        addr_dict = _save_script_matches(self.script_matches)
        self.storage.put('cashscript_script_matches', addr_dict)
        issuer_dict = _save_issuer_dict(self.issuer_templates)
        self.storage.put('cashscript_issuers', issuer_dict)

class IssuerDownloadQueueItem:
    ''' Downloads a new bitcoin file associated with the issuer's p2sh template parameters '''
    def __init__(self, txid):
        self.txid = txid
        self.data = None  # IssuerParamsParams unmarshalled protobuf object 

class ScriptMatcherQueueItem:
    ''' Attempts to matches a specific p2sh outpoint, and associated p2pkh notifiers, to a list of known issuer templates '''
    def __init__(self, tx, txid, vout, p2sh_addr, p2pkh_addrs):
        self.tx = tx
        self.txid = txid
        self.vout = vout
        self.p2sh_addr = p2sh_addr
        self.p2pkh_addrs = p2pkh_addrs
        self.status = 'unprocessed'
        self.artifact_sha256 = None
        self.params = None

