"""
Taproot (BIP341/342) helpers for OP_PLENTY tapleaf commit/reveal.

Single-leaf tree only: merkle_root == tagged_hash("TapLeaf", 0xc0 || ser(script)).
"""

from embit import ec, script as escript
from embit.hashes import tagged_hash
from embit.script import Script
from . import op_plenty

LEAF_VERSION = 0xC0

# BIP341 recommended NUMS point (H = lift_x(sha256(G))) — provably unspendable
# key path. Used so ONLY the script path (our tapleaf) can spend the commit.
NUMS_XONLY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def build_leaf_script(data: bytes, xonly_pubkey: bytes) -> bytes:
    """OP_PLENTY(v2 framed) || OP_DROP || PUSH33? no: PUSH32 xonly || OP_CHECKSIG"""
    assert len(xonly_pubkey) == 32
    body = op_plenty.encode(data)
    # sanity: dry-run must leave exactly the truthy anchor
    depth = op_plenty.simulate(body)
    if depth != 1:
        raise ValueError(f"encoded body leaves depth {depth}, expected 1")
    return body + bytes([0x75]) + bytes([0x20]) + xonly_pubkey + bytes([0xAC])


def leaf_hash(leaf_script: bytes) -> bytes:
    return tagged_hash(
        "TapLeaf",
        bytes([LEAF_VERSION]) + compact_size(len(leaf_script)) + leaf_script,
    )


def commit_output(internal_xonly: bytes, leaf_script: bytes):
    """
    Returns (scriptpubkey: Script, output_parity: int, merkle_root: bytes).
    """
    root = leaf_hash(leaf_script)
    internal = ec.PublicKey.from_xonly(internal_xonly)
    output_key = internal.taproot_tweak(root)
    parity = output_key.serialize()[0] & 1  # 0x02 even / 0x03 odd
    spk = Script(b"\x51\x20" + output_key.xonly())
    return spk, parity, root


def control_block(internal_xonly: bytes, output_parity: int) -> bytes:
    """Single-leaf tree: control block = (leaf_version | parity) || internal key."""
    return bytes([LEAF_VERSION | output_parity]) + internal_xonly


def wallet_p2tr(xonly: bytes) -> Script:
    """Plain key-path P2TR (BIP86-style, tweak with empty message)."""
    pub = ec.PublicKey.from_xonly(xonly)
    return escript.p2tr(pub)
