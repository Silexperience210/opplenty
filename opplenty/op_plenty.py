"""
OP_PLENTY codec — encode arbitrary bytes as the *choice* of Tapscript opcodes.

Each payload byte -> two nibbles -> two opcodes with (opcode % 22) == nibble.
Decoding is stateless; encoding walks a scratch-stack depth in {5,6,7} so the
script always executes cleanly under BIP342 (no data pushes, no OP_SUCCESSx).

V2 framing (used here):
    seed   : 7x OP_5 (0x55) — initial scratch stack AND searchable magic
    length : 8 encoded nibbles = 4-byte BE count of payload *hex chars*
    body   : encoded payload
    footer : collapses scratch back to the truthy anchor (depth-dependent)

Full signed tapleaf appends: OP_DROP <32B x-only pubkey> OP_CHECKSIG
"""

from enum import IntEnum


class Op(IntEnum):
    OP_1 = 0x51
    OP_5 = 0x55
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5A
    OP_11 = 0x5B
    OP_12 = 0x5C
    OP_13 = 0x5D
    OP_14 = 0x5E
    OP_15 = 0x5F
    OP_16 = 0x60
    OP_NOP = 0x61
    OP_2DROP = 0x6D
    OP_DROP = 0x75
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_EQUAL = 0x87
    OP_NEGATE = 0x8F
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92
    OP_ADD = 0x93
    OP_BOOLAND = 0x9A
    OP_BOOLOR = 0x9B
    OP_NUMEQUAL = 0x9C
    OP_NUMNOTEQUAL = 0x9E
    OP_LESSTHAN = 0x9F
    OP_GREATERTHAN = 0xA0
    OP_LESSTHANOREQUAL = 0xA1
    OP_GREATERTHANOREQUAL = 0xA2
    OP_MAX = 0xA4


# nibble -> (growing/neutral representative, shrinking representative)
PAIR = {
    0x0: (Op.OP_8, Op.OP_BOOLAND),
    0x1: (Op.OP_9, Op.OP_BOOLOR),
    0x2: (Op.OP_10, Op.OP_NUMEQUAL),
    0x3: (Op.OP_11, Op.OP_EQUAL),
    0x4: (Op.OP_12, Op.OP_NUMNOTEQUAL),
    0x5: (Op.OP_13, Op.OP_LESSTHAN),
    0x6: (Op.OP_14, Op.OP_GREATERTHAN),
    0x7: (Op.OP_15, Op.OP_LESSTHANOREQUAL),
    0x8: (Op.OP_16, Op.OP_GREATERTHANOREQUAL),
    0x9: (Op.OP_NOP, Op.OP_NIP),
    0xA: (Op.OP_OVER, Op.OP_MAX),
    0xF: (Op.OP_1, Op.OP_ADD),
}

UNARY = {
    0xB: Op.OP_NEGATE,
    0xC: Op.OP_ABS,
    0xD: Op.OP_NOT,
    0xE: Op.OP_0NOTEQUAL,
}

FOOTER = {
    5: (Op.OP_2DROP, Op.OP_2DROP, Op.OP_NOP),
    6: (Op.OP_2DROP, Op.OP_2DROP, Op.OP_DROP),
    7: (Op.OP_2DROP, Op.OP_2DROP, Op.OP_2DROP),
}

MAGIC = bytes([Op.OP_5]) * 7
LENGTH_NIBBLES = 8

# Alphabet lookup for pretty-printing / sanity checks
_ALPHABET = {int(op) for op in Op}


def encode(data: bytes) -> bytes:
    """Encode ``data`` into a self-framed (v2) OP_PLENTY opcode stream."""
    framed = (2 * len(data)).to_bytes(4, "big") + data

    out = bytearray(MAGIC)
    depth = 7

    for byte in framed:
        for nib in (byte >> 4, byte & 0xF):
            if nib in UNARY:
                op = UNARY[nib]
            elif depth == 7 or (depth == 6 and nib == 0xA):
                op = PAIR[nib][1]
                depth -= 1
            else:
                op = PAIR[nib][0]
                if nib != 0x9:  # OP_NOP is depth-neutral
                    depth += 1
            out.append(op)

    out.extend(FOOTER[depth])
    return bytes(out)


def decode(blob: bytes) -> bytes:
    """Decode from a bare script OR a complete raw transaction (v2 framing)."""
    start = blob.index(MAGIC) + len(MAGIC)
    encoded = blob[start:]

    header = "".join(f"{op % 22:x}" for op in encoded[:LENGTH_NIBBLES])
    hex_length = int(header, 16)

    payload = encoded[LENGTH_NIBBLES : LENGTH_NIBBLES + hex_length]
    if len(payload) < hex_length:
        raise ValueError(
            f"truncated OP_PLENTY body: need {hex_length} opcodes, got {len(payload)}"
        )
    payload_hex = "".join(f"{op % 22:x}" for op in payload)
    return bytes.fromhex(payload_hex)


def asm(script: bytes) -> str:
    """Human-readable disassembly of an OP_PLENTY opcode stream."""
    parts = []
    for op in script:
        parts.append(Op(op).name if op in _ALPHABET else f"0x{op:02x}")
    return " ".join(parts)


def simulate(script: bytes) -> int:
    """
    Dry-run the encoded body against a stack model and return the final
    logical stack depth (must be 1: the truthy anchor). Raises on underflow.
    Used as a pre-broadcast safety check.
    """
    depth = 0
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        if 0x51 <= op <= 0x60:  # OP_1..OP_16 push
            depth += 1
        elif op == Op.OP_NOP:
            pass
        elif op in UNARY.values():
            if depth < 1:
                raise ValueError(f"stack underflow at index {i} ({Op(op).name})")
        elif op == Op.OP_OVER:
            if depth < 2:
                raise ValueError(f"stack underflow at index {i} (OP_OVER)")
            depth += 1
        elif op == Op.OP_DROP:
            if depth < 1:
                raise ValueError(f"stack underflow at index {i} (OP_DROP)")
            depth -= 1
        elif op == Op.OP_2DROP:
            if depth < 2:
                raise ValueError(f"stack underflow at index {i} (OP_2DROP)")
            depth -= 2
        elif op in _ALPHABET:  # binary ops: consume 2, produce 1
            if depth < 2:
                raise ValueError(f"stack underflow at index {i} ({Op(op).name})")
            depth -= 1
        else:
            raise ValueError(f"opcode 0x{op:02x} at index {i} not in alphabet")
        i += 1
    return depth
