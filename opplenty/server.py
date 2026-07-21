"""
opplenty web backend — wraps the CLI modules behind a local API.

Runs 100% locally. Nothing is sent anywhere except mempool.space (broadcast /
utxo lookups), exactly like the CLI. The vault password lives only in RAM for
the process lifetime and is never written to disk.

    pip install fastapi uvicorn embit cryptography
    python3 -m opplenty.server            # -> http://127.0.0.1:8787
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from embit.networks import NETWORKS

from . import chain as chain_mod
from . import inscribe, op_plenty, taproot, wallet as wallet_mod

WEB = Path(__file__).parent / "web"

app = FastAPI(title="opplenty", docs_url=None, redoc_url=None)

# In-memory session. Single local user, single process — no persistence.
_SESSION: dict = {"wallet": None, "network": "signet"}


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class UnlockReq(BaseModel):
    vault: str = "opplenty.vault"
    password: str
    network: str = "signet"
    passphrase: str = ""


class CreateReq(BaseModel):
    vault: str = "opplenty.vault"
    password: str
    network: str = "signet"
    mnemonic: str | None = None


class CodecReq(BaseModel):
    message: str


class InscribeReq(BaseModel):
    message: str
    index: int = 0
    fee_rate: float | None = None
    dry_run: bool = True


def _wallet() -> wallet_mod.Wallet:
    w = _SESSION["wallet"]
    if w is None:
        raise HTTPException(401, "wallet verrouillé — déverrouille d'abord")
    return w


# --------------------------------------------------------------------------- #
# codec (offline, no wallet needed)
# --------------------------------------------------------------------------- #
@app.post("/api/encode")
def api_encode(req: CodecReq):
    data = req.message.encode()
    body = op_plenty.encode(data)
    return {
        "bytes": len(data),
        "opcodes": len(body),
        "hex": body.hex(),
        "asm": op_plenty.asm(body).split(),
        "depth_ok": op_plenty.simulate(body) == 1,
    }


@app.post("/api/decode")
def api_decode(req: CodecReq):
    try:
        blob = bytes.fromhex(req.message.strip())
    except ValueError:
        raise HTTPException(400, "hex invalide")
    try:
        data = op_plenty.decode(blob)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"décodage impossible: {e}")
    try:
        text = data.decode()
    except UnicodeDecodeError:
        text = None
    return {"hex": data.hex(), "text": text, "bytes": len(data)}


# --------------------------------------------------------------------------- #
# wallet lifecycle
# --------------------------------------------------------------------------- #
@app.post("/api/create")
def api_create(req: CreateReq):
    if os.path.exists(req.vault):
        raise HTTPException(409, f"{req.vault} existe déjà")
    mnemonic = wallet_mod.create_vault(req.vault, req.password, mnemonic=req.mnemonic)
    return {"mnemonic": mnemonic.split(), "vault": req.vault}


@app.post("/api/unlock")
def api_unlock(req: UnlockReq):
    try:
        w = wallet_mod.Wallet.from_vault(
            req.vault, req.password, req.network, bip39_passphrase=req.passphrase
        )
    except FileNotFoundError:
        raise HTTPException(404, f"vault introuvable: {req.vault}")
    except Exception:
        raise HTTPException(401, "mot de passe ou passphrase incorrect")
    _SESSION["wallet"] = w
    _SESSION["network"] = w.network
    return {"network": w.network, "address": w.address(0, 0)}


@app.post("/api/lock")
def api_lock():
    _SESSION["wallet"] = None
    return {"locked": True}


@app.get("/api/status")
def api_status():
    w = _SESSION["wallet"]
    return {"unlocked": w is not None,
            "network": _SESSION["network"] if w else None}


@app.get("/api/address")
def api_address(index: int = 0):
    w = _wallet()
    return {"address": w.address(0, index), "index": index}


@app.get("/api/balance")
def api_balance(index: int = 0):
    w = _wallet()
    addr = w.address(0, index)
    try:
        utxos = chain_mod.Chain(w.network).utxos(addr)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"backend indisponible: {e}")
    return {"address": addr, "sats": sum(u["value"] for u in utxos),
            "utxos": len(utxos),
            "url": chain_mod.Chain(w.network).address_url(addr)}


@app.get("/api/tx/{txid}")
def api_tx(txid: str):
    w = _wallet()
    c = chain_mod.Chain(w.network)
    try:
        st = c.tx_status(txid)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"backend indisponible: {e}")
    return {"txid": txid, "url": c.tx_url(txid), **st}


@app.get("/api/fees")
def api_fees():
    w = _wallet()
    try:
        return chain_mod.Chain(w.network).fee_rates()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"backend indisponible: {e}")


# --------------------------------------------------------------------------- #
# inscription
# --------------------------------------------------------------------------- #
@app.post("/api/inscribe")
def api_inscribe(req: InscribeReq):
    w = _wallet()
    net = NETWORKS[w.network]
    c = chain_mod.Chain(w.network)

    data = req.message.encode()
    leaf_key = w.key(0, req.index)
    leaf_xonly = leaf_key.get_public_key().xonly()
    leaf_script = taproot.build_leaf_script(data, leaf_xonly)
    commit_spk, parity, _ = taproot.commit_output(taproot.NUMS_XONLY, leaf_script)
    ctrl = taproot.control_block(taproot.NUMS_XONLY, parity)
    wallet_prv_tw, _ = w.output_key_pair(0, req.index)
    wallet_spk = taproot.wallet_p2tr(leaf_xonly)

    try:
        fee_rate = req.fee_rate or float(c.fee_rates()["halfHourFee"])
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"impossible d'estimer les frais: {e}")

    reveal_fee = inscribe.estimate_reveal_fee(leaf_script, fee_rate)
    commit_value = inscribe.DUST_P2TR + reveal_fee

    try:
        utxos = c.utxos(w.address(0, req.index))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"backend indisponible: {e}")
    if not utxos:
        raise HTTPException(400, "aucun UTXO — alimente l'adresse du wallet d'abord")

    try:
        commit_tx = inscribe.build_commit(
            utxos, wallet_prv_tw, wallet_spk, commit_spk,
            commit_value, fee_rate, change_spk=wallet_spk)
        reveal_tx = inscribe.build_reveal(
            commit_tx.txid(), 0, commit_value, commit_spk,
            leaf_script, ctrl, leaf_key, wallet_spk, fee_rate)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if op_plenty.decode(reveal_tx.serialize()) != data:
        raise HTTPException(500, "roundtrip pré-diffusion échoué — abort")

    result = {
        "bytes": len(data),
        "leaf_bytes": len(leaf_script),
        "fee_rate": fee_rate,
        "commit_value": commit_value,
        "commit_address": commit_spk.address(net),
        "commit_txid": commit_tx.txid().hex(),
        "commit_hex": commit_tx.serialize().hex(),
        "reveal_txid": reveal_tx.txid().hex(),
        "reveal_hex": reveal_tx.serialize().hex(),
        "commit_url": c.tx_url(commit_tx.txid().hex()),
        "reveal_url": c.tx_url(reveal_tx.txid().hex()),
        "broadcast": False,
    }
    if req.dry_run:
        return result

    try:
        result["commit_txid"] = c.broadcast(commit_tx.serialize().hex())
        result["reveal_txid"] = c.broadcast(reveal_tx.serialize().hex())
        result["commit_url"] = c.tx_url(result["commit_txid"])
        result["reveal_url"] = c.tx_url(result["reveal_txid"])
        result["broadcast"] = True
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"diffusion refusée: {e}")
    return result


# --------------------------------------------------------------------------- #
# static UI
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


app.mount("/", StaticFiles(directory=WEB), name="web")


def main():
    import uvicorn
    print("opplenty → http://127.0.0.1:8787")
    uvicorn.run(app, host="127.0.0.1", port=8787, log_level="warning")


if __name__ == "__main__":
    main()
