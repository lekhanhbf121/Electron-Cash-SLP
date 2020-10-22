from .bitcoin import TYPE_SCRIPT, TYPE_ADDRESS, var_int
from .transaction import BCDataStream
from .address import Address, ScriptOutput, Script, ScriptError, OpCodes
from .util import bfh

lokad_id = b"PIN\x00"

def buildCashscriptPinMsg(artifact_sha256_hex: str, constructorInputs: [bytearray], abiRequirements: [[bytearray]]) -> tuple:
    chunks = []
    # lokad id
    chunks.append(lokad_id)
    # token version/type
    chunks.append(b'\x01')
    # artifact sha256
    sha = bytes.fromhex(artifact_sha256_hex)
    if len(sha) != 32:
        raise Exception('sha256 must be 32 bytes')
    chunks.append(sha)
    # output quantities
    ci = b''
    for constInp in constructorInputs:
        ci += bytes.fromhex(var_int(len(constInp))) + constInp
    chunks.append(ci)
    # abi
    for abiReq in abiRequirements:
        abi = b''
        for r in abiReq:
            abi += bytes.fromhex(var_int(len(r))) + r
        chunks.append(abiReq)
    return chunksToOpreturnOutput(chunks)

def chunksToOpreturnOutput(chunks: [bytes]) -> tuple:
    script = bytearray([0x6a,]) # start with OP_RETURN
    for c in chunks:
        script.extend(pushChunk(c))
    if len(script) > 223:
        raise Exception('OP_RETURN message too large, cannot be larger than 223 bytes')
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

class ScriptPin:
    lokad_id = lokad_id

    def __init__(self):
        self.pin_version = None
        self.artifact_sha256 = None
        self.constructor_inputs = []
        self.abi_inputs = []

    # def __repr__(self,):
    #     return "<%s pin_version=%d %r %r>"%(type(self).__qualname__, self.pin_version, self.op_return_fields)

    # This method attempts to parse a ScriptOutput object as an BFP message.
    # Bad scripts will throw a subclass of BfpParsingError; any other exception indicates a bug in this code.
    # - Unrecognized SLP versions will throw BfpUnsupportedSlpTokenType.
    # - It is a STRICT parser -- consensus-invalid messages will throw Exception.
    # - Non-SLP scripts will also throw Exception.
    @staticmethod
    def parsePinScriptOutput(outputScript: ScriptOutput):
        pinMsg = ScriptPin()
        try:
            chunks = parseOpreturnToChunks(outputScript.to_script(), allow_op_0 = False, allow_op_number = False)
        except OPReturnError as e:
            raise Exception('bad OP_RETURN', *e.args) from e

        if len(chunks) == 0:
            raise Exception('empty OP_RETURN')

        if chunks[0] != lokad_id:
            raise Exception('not script pin')

        if len(chunks) == 1:
            raise Exception('missing pin version')
        pinMsg.pin_version = parseChunkToInt(chunks[1], 1, 1, True)
        if pinMsg.pin_version != 1:
            raise UnsupportedPinMsgType(pinMsg.pin_version)
        # NOTE: 
        #  Version 1 will simply have the pinned data within the OP_RETURN message.
        #  Version 2 can have the pinned data stored at a Bitcoin Files location
        #  to allow for contracts with more data.

        if len(chunks) == 2:
            raise Exception('missing pin artifact sha256')
        pinMsg.artifact_sha256 = chunks[2]
        if len(chunks[2]) != 32:
            raise Exception('invalid sha256')

        # TODO: check for acceptable artifacts here?

        if len(chunks) == 3:
            raise Exception('missing script constructor inputs')
        try:
            if chunks[3] is not None:
                pinMsg.constructor_inputs = deserialize(chunks[3])
            # TODO: need to check for the proper length of constructor inputs
            # if len(pinMsg.constructor_inputs) == X:
            #     raise Exception('cannot have empty script constructor inputs')
        except:
            raise Exception('could not parse constructor inputs')

        # TODO: check proper abi method chunk length for specific artifact requirements
        #       - Each chunk[4:] is a different ABI method
        #       - Each chunk[4:] is serialized using bitcoin var int
        #       - Need to check the proper number of parameters in each method
        if len(chunks) > 4:
            abi_inputs = chunks[4:]
            pinMsg.abi_inputs = []
            for dat in abi_inputs:
                if len(dat) == 0:
                    pinMsg.abi_inputs.append(None)
                else:
                    pinMsg.abi_inputs.append(deserialize(dat))

        return pinMsg

def deserialize(raw):
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