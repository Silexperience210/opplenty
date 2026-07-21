"""
Commit / reveal builder for OP_PLENTY data.

commit : wallet UTXOs (P2TR key-path) -> commit output
         commit output = P2TR(NUMS internal key, merkle_root = leaf_hash)
         => key path provably unspendable, only our tapleaf can spend.
reveal : commit output --script-path--> wallet address
         witness = [schnorr_sig, leaf_script, control_block]
"""

from io import BytesIO

from embit import ec
from embit.networks import NETWORKS
from embit.script import Script, Witness
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from . import taproot

DUST_P2TR = 330
SIGHASH_DEFAULT = 0


def _vsize(tx: Transaction) -> int:
    total = len(tx.serialize())
    stripped = Transaction(
        version=tx.version, locktime=tx.locktime,
        vin=[TransactionInput(i.txid, i.vout, sequence=i.sequence) for i in tx.vin],
        vout=tx.vout,
    )
    base = len(stripped.serialize())
    weight = base * 3 + total
    return (weight + 3) // 4


def _keypath_sign(tx: Transaction, spks, values, prv_tweaked: ec.PrivateKey):
    for i, vin in enumerate(tx.vin):
        h = tx.sighash_taproot(i, spks, values, sighash=SIGHASH_DEFAULT)
        sig = prv_tweaked.schnorr_sign(h)
        vin.witness = Witness([sig.serialize()])


def build_commit(utxos, wallet_prv_tweaked, wallet_spk: Script,
                 commit_spk: Script, commit_value: int, fee_rate: float,
                 change_spk: Script):
    """
    utxos: list of dicts {txid, vout, value} all locked to wallet_spk (key path).
    Returns signed Transaction. Raises if funds are insufficient.
    """
    total_in = sum(u["value"] for u in utxos)
    vin = [TransactionInput(bytes.fromhex(u["txid"]), u["vout"]) for u in utxos]
    spks = [wallet_spk] * len(vin)
    values = [u["value"] for u in utxos]

    def make(change: int) -> Transaction:
        vout = [TransactionOutput(commit_value, commit_spk)]
        if change >= DUST_P2TR:
            vout.append(TransactionOutput(change, change_spk))
        tx = Transaction(version=2, vin=[TransactionInput(i.txid, i.vout) for i in vin],
                         vout=vout)
        _keypath_sign(tx, spks, values, wallet_prv_tweaked)
        return tx

    # two-pass fee sizing
    tx = make(max(total_in - commit_value - 200, 0))
    fee = int(_vsize(tx) * fee_rate) + 1
    change = total_in - commit_value - fee
    if change < 0:
        raise ValueError(f"fonds insuffisants: besoin {commit_value + fee} sats, "
                         f"dispo {total_in} sats")
    tx = make(change)
    # re-check: dropping the change output shrinks the tx, fee only overshoots
    return tx


def build_reveal(commit_txid: bytes, commit_vout: int, commit_value: int,
                 commit_spk: Script, leaf_script: bytes, control_block: bytes,
                 leaf_prv: ec.PrivateKey, dest_spk: Script, fee_rate: float):
    """Spend the commit output through the OP_PLENTY tapleaf."""
    script_obj = Script(leaf_script)

    def make(out_value: int) -> Transaction:
        tx = Transaction(
            version=2,
            vin=[TransactionInput(commit_txid, commit_vout)],
            vout=[TransactionOutput(out_value, dest_spk)],
        )
        h = tx.sighash_taproot(0, [commit_spk], [commit_value],
                               sighash=SIGHASH_DEFAULT, ext_flag=1,
                               script=script_obj, leaf_version=taproot.LEAF_VERSION)
        sig = leaf_prv.schnorr_sign(h)
        tx.vin[0].witness = Witness([sig.serialize(), leaf_script, control_block])
        return tx

    tx = make(DUST_P2TR)
    fee = int(_vsize(tx) * fee_rate) + 1
    out_value = commit_value - fee
    if out_value < DUST_P2TR:
        raise ValueError(
            f"sortie commit trop petite: {commit_value} sats - {fee} sats de frais "
            f"< dust ({DUST_P2TR})")
    return make(out_value)


def estimate_reveal_fee(leaf_script: bytes, fee_rate: float) -> int:
    """Analytic vsize of the reveal tx for commit funding."""
    wit_bytes = 1 + 1 + 64 + _cs(len(leaf_script)) + len(leaf_script) + 1 + 34
    base = 10 + 41 + 1 + 43  # header + input + marker-ish + p2tr output (approx)
    weight = (base + 2) * 4 + wit_bytes  # +2: segwit marker/flag counted once
    return int(((weight + 3) // 4) * fee_rate) + 64  # safety margin


def _cs(n: int) -> int:
    return 1 if n < 0xFD else (3 if n <= 0xFFFF else 5)
