#!/usr/bin/env python3
#
# Electron Cash SLP Edition
# Copyright (C) 2020 Simple Ledger, Inc.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .networks import net
from .address import OpCodes, Address, hash160, sha256
from .bitcoin import TYPE_SCRIPT, var_int, int_to_hex, push_script

# Slp Vault contract constants
SLP_VAULT_ID = "32b14aa93b0d0cd360a3e0204ac6ac2087564d2aa7cd7462db073358b6a55c62"
SLP_VAULT_NAME = net.SCRIPT_ARTIFACTS[SLP_VAULT_ID]['artifact']['contractName']
SLP_VAULT_SWEEP = SLP_VAULT_NAME + '_sweep'
SLP_VAULT_REVOKE = SLP_VAULT_NAME + '_revoke'

# Slp Mint Guard contract constants
SLP_MINT_GUARD_ID = "cf7ced1c3e2ff3d6620a9cc5d3cb000a5109fd09ce6b0ba86051424a3ede980d"
SLP_MINT_GUARD_NAME = net.SCRIPT_ARTIFACTS[SLP_MINT_GUARD_ID]['artifact']['contractName']
SLP_MINT_GUARD_MINT = SLP_MINT_GUARD_NAME + '_Mint'
SLP_MINT_GUARD_TRANSFER = SLP_MINT_GUARD_NAME + '_Transfer'

# The front part of an SLP Mint Message (i.e., mint = SLP_MINT_FRONT + tokenID + 0x08 + mint_amount)
SLP_MINT_FRONT = "0000000000000000396a04534c50000101044d494e5420"

_valid_scripts = [
    SLP_VAULT_ID,
    SLP_MINT_GUARD_ID
]

valid_script_sig_types = [
    SLP_VAULT_SWEEP,
    SLP_VAULT_REVOKE,
    SLP_MINT_GUARD_MINT
]

_allow_pay_to = [
    SLP_VAULT_ID,
    SLP_VAULT_NAME
]

def get_transaction_label_for_actions_by_others(input_type: str) -> str:
    if input_type == SLP_VAULT_REVOKE:
        return 'SLP vault revoked!'
    return None

def is_mine(wallet, address) -> (bool, object):
    _is_known, _contact = is_known(wallet, address)
    if _contact:
        p2pkh_addr = get_p2pkh_owner_address(_contact.sha256, _contact.params)
        if p2pkh_addr:
            return (wallet.is_mine(p2pkh_addr, check_cashscript=False), _contact)
    return (False, None)

def is_known(wallet, address) -> (bool, object):
    if isinstance(address, Address):
        if address.kind != Address.ADDR_P2SH:
            return (False, None)
        else:
            address = address.to_full_string(Address.FMT_SCRIPTADDR)
    contacts = [c for c in wallet.contacts.data if c.type == 'script' and c.address == address]
    if len(contacts) > 0:
        return (True, contacts[0])
    return (False, None)

def allow_pay_to(wallet, address) -> (bool, object):
    _is_known, contact = is_known(wallet, address)
    if _is_known and contact.sha256 in _allow_pay_to:
        return (True, contact)
    return (False, contact)

def get_p2pkh_owner_address(artifact_sha256: str, params: [str]) -> Address:
    if artifact_sha256 == SLP_VAULT_ID:
        return Address.from_P2PKH_hash(bytes.fromhex(params[0]))
    elif artifact_sha256 == SLP_MINT_GUARD_ID:
        return Address.from_P2PKH_hash(bytes.fromhex(params[3]))
    else:
        return None

def get_base_script(artifact_sha256: str, *, for_preimage=False, code_separator_pos=0) -> str:
    artifact = net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']
    script = from_asm(artifact['bytecode'], for_preimage=for_preimage, code_separator_pos=code_separator_pos)
    if for_preimage:
        return script
    _sha256 = sha256(bytes.fromhex(script))
    if _sha256.hex() != artifact_sha256:
        raise Exception('sha256 mismatch')
    return script

def get_redeem_script(artifact_sha256: str, params: [str], *, for_preimage=False, code_separator_pos=0) -> str:
    artifact = net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']
    script = get_base_script(artifact_sha256, for_preimage=for_preimage, code_separator_pos=code_separator_pos)
    if for_preimage and script != get_base_script(artifact_sha256):
        return script
    for param in params:
        if not isinstance(param, str):
            raise Exception('params must be provide as string')
        # TODO: improve this for minimal push requirements.
        if param == '51':
            script = int_to_hex(OpCodes.OP_1) + script
        elif param == '00':
            script = int_to_hex(OpCodes.OP_0) + script
        else:
            script = push_script(param) + script
    return script

def get_redeem_script_dummy(artifact_sha256: str, *, for_preimage=False, code_separator_pos=0) -> str:
    script = get_base_script(artifact_sha256, for_preimage=for_preimage, code_separator_pos=code_separator_pos)
    if for_preimage and script != get_base_script(artifact_sha256):
        return script
    artifact = net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']
    for param in artifact['constructorInputs']:
        if param['type'].startswith('bytes'):
            size = int(param['type'].split('bytes')[1])
            script = push_script('00'*size) + script
        elif param['type'] == 'bool':
            script = int_to_hex(Opcodes.OP_1) + script
        elif param['type'] == "pubkey":
            script = push_script('00'*32) + script
    return script

def get_script_sig_dummies(artifact_sha256: str):
    script_sigs = []
    artifact = net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']
    for abi in artifact['abi']:
        script_sig = push_script(get_redeem_script_dummy(artifact_sha256))
        if len(abi.get('inputs', [])) > 1:
            script_sig = int_to_hex(OpCodes.OP_0) + script_sig
        if abi.get('covenant', False):
            preimage = '00'*4 + '00'*100 + get_redeem_script_dummy(artifact_sha256) + '00'*8 + '00'*4 + '00'*4 + '00'*8
            script_sig = push_script(preimage) + script_sig
        for param in abi['inputs']:
            if param['type'] == 'bytes':
                script_sig = push_script('ff'*32) + script_sig  # NOTE: this is just a filler value, we should try to avoid arbitrary size
            elif param['type'].startswith('bytes'):
                size = int(param['type'].split('bytes')[1])
                script_sig = push_script('00'*size) + script_sig
            elif param['type'] == "pubkey":
                script_sig = push_script('00'*33) + script_sig
            elif param['type'] == "sig":
                script_sig = push_script('00'*72) + script_sig
        script_sigs.append( (artifact_sha256, abi['name'], script_sig) )
    return script_sigs

def get_redeem_script_address(artifact_sha256: str, params: [str]) -> Address:
    return Address.from_P2SH_hash(hash160(bytes.fromhex(get_redeem_script(artifact_sha256, params))))

def get_redeem_script_address_string(artifact_sha256: str, params: [str]) -> str:
    return get_redeem_script_address(artifact_sha256, params).to_full_string(Address.FMT_SCRIPTADDR)

def from_asm(asm: str, *, for_preimage=False, code_separator_pos=0) -> str:
    asm_chunks = asm.split(' ')
    bin_chunks = []
    code_separator_idx = []
    for i, val in enumerate(asm_chunks):
        if val == "OP_CODESEPARATOR":
            code_separator_idx.append(i)
        if val.startswith('OP_'):
            bin_chunks.append(OpCodes[val].value)
        else:
            bin_chunks.append(val)
    _hex = ''
    if code_separator_pos > 0:
        if code_separator_pos > len(code_separator_idx):
            raise Exception('selected op_code_separator count is larger than the number of available code separators.')
        bin_chunks = bin_chunks[code_separator_idx[code_separator_pos-1]+1:]
    for chunk in bin_chunks:
        if isinstance(chunk, int):
            _hex += int_to_hex(chunk)
        elif isinstance(chunk, str):
            _hex += push_script(chunk)
    return _hex

def get_contact_label(wallet, artifact_sha256, params):
    name = get_contract_name_string(artifact_sha256)
    if artifact_sha256 in _valid_scripts:
        script_addr = get_redeem_script_address(artifact_sha256, params)
        p2pkh_addr = get_p2pkh_owner_address(artifact_sha256, params)
        if wallet.is_mine(p2pkh_addr, check_cashscript=False):
            return name + " for me (" + p2pkh_addr.to_full_string(Address.FMT_CASHADDR) + ")"
        else:
            return name + " for " + p2pkh_addr.to_full_string(Address.FMT_CASHADDR)
    else:
        return "get_contact_label unimplemented for this contract"

def get_contract_name_string(artifact_sha256):
    if artifact_sha256 in net.SCRIPT_ARTIFACTS:
        return net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']['contractName']
    else:
        return "unknown cashscript artifact"

def get_script_sig_type(decoded: list) -> (str, str):
    from .transaction import script_GetOp
    for script_id in _valid_scripts:
        sigs = get_script_sig_dummies(script_id)
        for _id, abi_name, sig in sigs:
            _decoded = list(script_GetOp(bytearray.fromhex(sig)))
            if len(decoded) != len(_decoded):
                continue
            base = get_base_script(script_id)
            if base not in decoded[len(decoded)-1][1].hex():
                continue
            return (script_id, net.SCRIPT_ARTIFACTS[script_id]['artifact']['contractName'] + '_' + abi_name)
    return (None, None)

def build_pin_msg(artifact_sha256_hex: str, constructorInputs: [str]) -> tuple:
    chunks = []
    # lokad id
    chunks.append(pin_protocol_id)
    # token version/type
    chunks.append(b'\x01')
    # artifact sha256
    sha = bytes.fromhex(artifact_sha256_hex)
    if len(sha) != 32:
        raise Exception('sha256 must be 32 bytes')

    if artifact_sha256_hex not in net.SCRIPT_ARTIFACTS:
        raise Exception("cashscript sha256 doesn't exist")

    chunks.append(sha)
    # output quantities
    ci = b''
    for constInp in constructorInputs:
        ci += bytes.fromhex(var_int(len(bytes.fromhex(constInp)))) + bytes.fromhex(constInp)

    chunks.append(ci)

    return chunksToOpreturnOutput(chunks)

def check_constructor_params(artifact_sha256: str, params: [str]) -> bool:

    artifact = net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']
    script = from_asm(artifact['bytecode'])
    _sha256 = sha256(bytes.fromhex(script))
    if _sha256.hex() != artifact_sha256:
        raise Exception('sha256 mismatch')

    if len(artifact['constructorInputs']) != len(params):
        raise Exception('params length does not match required length of constructorInputs')
    for i, val in enumerate(artifact['constructorInputs']):
        if val['type'] == 'bytes':
            if len(bytes.fromhex(params[i])) < 1:
                raise Exception('expected at least 1 byte for ' + val['name'] + ' but got ' + str(len(params[i])))
                continue
            if len(bytes.fromhex(params[i])) > 520:
                raise Exception('cannot push more than 520 bytes for ' + val['name'] + ' but got ' + str(len(params[i])))
                continue
        elif val['type'].startswith('bytes'):
            size = int(val['type'].split('bytes')[1])
            if len(bytes.fromhex(params[i])) != size:
                raise Exception('expected ' + str(size) + ' bytes for ' + val['name'] + ' but got ' + str(len(params[i])))
            continue
        elif val['type'] == "pubkey" and len(bytes.fromhex(params[i])) != 33:
            if len(bytes.fromhex(params[i])) != 33:
                raise Exception('expected ' + str(33) + ' bytes for ' + val['name'] + ' but got ' + str(len(params[i])))         
            continue
        else:
            raise Exception('unimplemented type "' + val['type'] + '" for ' + val['name'])
    return True

pin_protocol_id = b"PIN\x00"

class ScriptPin:

    tag_id = pin_protocol_id

    def __init__(self):
        self.pin_version = None
        self.artifact_sha256 = None
        self.artifact = None
        self.constructor_inputs = []
        self.address = None

    @staticmethod
    def parsePinScriptOutput(outputScript):
        pinMsg = ScriptPin()
        try:
            chunks = parseOpreturnToChunks(outputScript.to_script(), allow_op_0 = False, allow_op_number = False)
        except OPReturnError as e:
            raise Exception('bad OP_RETURN', *e.args) from e

        if len(chunks) == 0:
            raise Exception('empty OP_RETURN')

        if chunks[0] != pin_protocol_id:
            raise Exception('not script pin')

        if len(chunks) == 1:
            raise Exception('missing pin version')
        pinMsg.pin_version = parseChunkToInt(chunks[1], 1, 1, True)
        if pinMsg.pin_version != 1:
            raise UnsupportedPinMsgType(pinMsg.pin_version)

        if len(chunks) == 2:
            raise Exception('missing pin artifact sha256')
        pinMsg.artifact_sha256 = chunks[2]
        if len(chunks[2]) != 32:
            raise Exception('invalid sha256')
        if pinMsg.artifact_sha256.hex() not in net.SCRIPT_ARTIFACTS:
            raise Exception('not an available script')

        pinMsg.artifact = net.SCRIPT_ARTIFACTS[pinMsg.artifact_sha256.hex()]['artifact']

        if len(chunks) == 3:
            raise Exception('missing script constructor inputs')
        try:
            if chunks[3] is not None:
                pinMsg.constructor_inputs = deserialize(chunks[3])
            if len(pinMsg.constructor_inputs) != len(pinMsg.artifact['constructorInputs']):
                raise Exception('cannot have empty script constructor inputs')
        except:
            raise Exception('could not parse constructor inputs')

        pinMsg.address = get_redeem_script_address(pinMsg.artifact_sha256.hex(), [p.hex() for p in pinMsg.constructor_inputs])

        return pinMsg

def deserialize(raw):
    from .transaction import BCDataStream
    vds = BCDataStream()
    vds.write(raw)
    d = []
    start = vds.read_cursor
    while True:
        try:
            n_len = vds.read_compact_size()
            _d = vds.read_bytes(n_len)
            d.append(_d)
        except:
            break
    return d

def chunksToOpreturnOutput(chunks: [bytes]) -> tuple:
    script = bytearray([0x6a,]) # start with OP_RETURN
    for c in chunks:
        script.extend(pushChunk(c))
    if len(script) > 223:
        raise Exception('OP_RETURN message too large, cannot be larger than 223 bytes')
    from .address import ScriptOutput
    return (TYPE_SCRIPT, ScriptOutput(bytes(script)), 0)

# utility for creation: use smallest push except not any of: op_0, op_1negate, op_1 to op_16
def pushChunk(chunk: bytes) -> bytes: # allow_op_0 = False, allow_op_number = False
    length = len(chunk)
    if length == 0:
        return b'\x4c\x00' + chunk
    elif length < 76:
        return bytes((length,)) + chunk
    elif length < 256:
        return bytes((0x4c,length,)) + chunk
    elif length < 65536: # shouldn't happen but eh
        return b'\x4d' + length.to_bytes(2, 'little') + chunk
    elif length < 4294967296: # shouldn't happen but eh
        return b'\x4e' + length.to_bytes(4, 'little') + chunk
    else:
        raise ValueError()

class OPReturnError(Exception):
    """ thrown when the OP_RETURN for a tx not of the right format """

class UnsupportedPinMsgType(Exception):
    """ thrown when an unknown pin message version is found """

def parseOpreturnToChunks(script: bytes, *,  allow_op_0: bool, allow_op_number: bool):
    """Extract pushed bytes after opreturn. Returns list of bytes() objects,
    one per push.

    Strict refusal of non-push opcodes; bad scripts throw OPReturnError."""
    from .address import ScriptError, OpCodes, Script
    try:
        ops = Script.get_ops(script)
    except ScriptError as e:
        raise OPReturnError('Script error') from e

    if not ops or ops[0] != OpCodes.OP_RETURN:
        raise OPReturnError('No OP_RETURN')

    chunks = []
    for opitem in ops[1:]:
        op, data = opitem if isinstance(opitem, tuple) else (opitem, None)
        if op > OpCodes.OP_16:
            raise OPReturnError('Non-push opcode')
        if op > OpCodes.OP_PUSHDATA4:
            if op == 80:
                raise OPReturnError('Non-push opcode')
            if not allow_op_number:
                raise OPReturnError('OP_1NEGATE to OP_16 not allowed')
            if op == OpCodes.OP_1NEGATE:
                data = [0x81]
            else: # OP_1 - OP_16
                data = [op-80]
        if op == OpCodes.OP_0 and not allow_op_0:
            raise OPReturnError('OP_0 not allowed')
        chunks.append(b'' if data is None else bytes(data))
    return chunks

def parseChunkToInt(intBytes: bytes, minByteLen: int, maxByteLen: int, raise_on_Null: bool = False):
    # Parse data as unsigned-big-endian encoded integer.
    # For empty data different possibilities may occur:
    #      minByteLen <= 0 : return 0
    #      raise_on_Null == False and minByteLen > 0: return None
    #      raise_on_Null == True and minByteLen > 0:  raise BfpInvalidOutput
    if len(intBytes) >= minByteLen and len(intBytes) <= maxByteLen:
        return int.from_bytes(intBytes, 'big', signed=False)
    if len(intBytes) == 0 and not raise_on_Null:
        return None
    raise Exception('File is not stored on the blockchain, or field has wrong length in BFP message.')
