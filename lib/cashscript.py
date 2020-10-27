from .bitcoin import TYPE_SCRIPT, var_int, int_to_hex, push_script
from .networks import net
from .address import OpCodes, Address, hash160

slp_vault_id = "32b14aa93b0d0cd360a3e0204ac6ac2087564d2aa7cd7462db073358b6a55c62"
slp_dollar_id = "TODO_2"
slp_mint_id = "TODO_1"

valid_scripts = [ slp_vault_id, slp_dollar_id, slp_mint_id]

def is_mine(wallet, artifact_sha256: str, params: [str]) -> bool:
    if artifact_sha256 == slp_vault_id:
        cashaddr = Address.from_P2PKH_hash(bytes.fromhex(params[0]))
        return wallet.is_mine(cashaddr)
    return False

def get_script(artifact_sha256: str, params: [str]) -> bytes:
    artifact = net.SCRIPT_ARTIFACTS[artifact_sha256]['artifact']
    script = from_asm(artifact['bytecode'])
    for param in params:
        script = push_script(param) + script
    return bytes.fromhex(script)

def get_script_address(artifact_sha256: str, params: [str]) -> Address:
    return Address.from_P2SH_hash(hash160(get_script(artifact_sha256, params)))

def get_script_address_string(artifact_sha256: str, params: [str]) -> str:
    return get_script_address(artifact_sha256, params).to_full_string(Address.FMT_SCRIPTADDR)

def from_asm(asm: str) -> str:
    asm_chunks = asm.split(' ')
    bin_chunks = []
    for val in asm_chunks:
        if val.startswith('OP_'):
            bin_chunks.append(OpCodes[val].value)
        else:
            bin_chunks.append(val)
    _hex = ''
    for chunk in bin_chunks:
        if isinstance(chunk, int):
            _hex += int_to_hex(chunk)
        elif isinstance(chunk, str):
            _hex += push_script(chunk)
    return _hex

def get_label_string(wallet, artifact_sha256, params):
    if artifact_sha256 == slp_vault_id:
        if is_mine(wallet, artifact_sha256, params):
            return "for me"
        else:
            return "for " + get_script_address_string(artifact_sha256, params)
    else:
        return "get_label_string unimplemented for this contract"

def buildCashscriptPinMsg(artifact_sha256_hex: str, constructorInputs: [bytearray]) -> tuple:
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
        ci += bytes.fromhex(var_int(len(constInp))) + constInp
    chunks.append(ci)

    return chunksToOpreturnOutput(chunks)

def check_cashscript_parms(artifact: dict, params: [str]) -> bool:
    if len(artifact['constructorInputs']) != len(params):
        raise Exception('params length does not match required length of constructorInputs')
    for i, val in enumerate(artifact['constructorInputs']):
        if val['type'] == "bytes20":
            if len(bytes.fromhex(params[i])) != 20:
                raise Exception('expected 20 bytes for ' + val['name'] + ' but got ' + str(len(params[i])))
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

        pinMsg.address = get_script_address(pinMsg.artifact_sha256.hex(), [p.hex() for p in pinMsg.constructor_inputs])

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
