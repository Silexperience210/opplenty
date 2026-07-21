"""
opplenty web backend — standard-library http.server, no third-party web stack.

Dropping FastAPI/uvicorn/pydantic removes all Rust-compiled dependencies, so on
Android/Termux the only native piece left is cryptography (installed via
`pkg install python-cryptography`). Serves the same UI and the same JSON routes.

Runs 100% locally. Nothing leaves the machine except mempool.space calls
(utxos / fees / broadcast), exactly like the CLI. The decrypted key material
lives only in this process's RAM.

    python3 -m opplenty.server        # -> http://127.0.0.1:8787
"""

from __future__ import annotations

import io
import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from embit.networks import NETWORKS

from . import chain as chain_mod
from . import inscribe, op_plenty, taproot, wallet as wallet_mod

WEB = Path(__file__).parent / "web"
HOST, PORT = "127.0.0.1", 8787

# In-memory session. Single local user, single process — no persistence.
_SESSION: dict = {"wallet": None, "network": "signet"}


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail


def _wallet() -> wallet_mod.Wallet:
    w = _SESSION["wallet"]
    if w is None:
        raise ApiError(401, "wallet verrouillé — déverrouille d'abord")
    return w


# --------------------------------------------------------------------------- #
# handlers: each takes (body_dict, query_dict) and returns a dict, OR a
# (bytes, content_type) tuple for raw responses (QR). Raise ApiError for 4xx/5xx.
# --------------------------------------------------------------------------- #
def h_encode(body, q):
    data = body["message"].encode()
    prog = op_plenty.encode(data)
    return {"bytes": len(data), "opcodes": len(prog), "hex": prog.hex(),
            "asm": op_plenty.asm(prog).split(),
            "depth_ok": op_plenty.simulate(prog) == 1}


def h_decode(body, q):
    try:
        blob = bytes.fromhex(body["message"].strip())
    except ValueError:
        raise ApiError(400, "hex invalide")
    try:
        data = op_plenty.decode(blob)
    except Exception as e:  # noqa: BLE001
        raise ApiError(400, f"décodage impossible: {e}")
    try:
        text = data.decode()
    except UnicodeDecodeError:
        text = None
    return {"hex": data.hex(), "text": text, "bytes": len(data)}


def h_create(body, q):
    vault = body.get("vault", "opplenty.vault")
    if os.path.exists(vault):
        raise ApiError(409, f"{vault} existe déjà")
    mnemonic = wallet_mod.create_vault(vault, body["password"],
                                       mnemonic=body.get("mnemonic"))
    return {"mnemonic": mnemonic.split(), "vault": vault}


def h_unlock(body, q):
    try:
        w = wallet_mod.Wallet.from_vault(
            body.get("vault", "opplenty.vault"), body["password"],
            body.get("network", "signet"),
            bip39_passphrase=body.get("passphrase", ""))
    except FileNotFoundError:
        raise ApiError(404, f"vault introuvable: {body.get('vault')}")
    except Exception:
        raise ApiError(401, "mot de passe ou passphrase incorrect")
    _SESSION["wallet"] = w
    _SESSION["network"] = w.network
    return {"network": w.network, "address": w.address(0, 0)}


def h_lock(body, q):
    _SESSION["wallet"] = None
    return {"locked": True}


def h_status(body, q):
    w = _SESSION["wallet"]
    return {"unlocked": w is not None,
            "network": _SESSION["network"] if w else None}


def h_address(body, q):
    w = _wallet()
    idx = int(q.get("index", ["0"])[0])
    return {"address": w.address(0, idx), "index": idx}


def h_balance(body, q):
    w = _wallet()
    idx = int(q.get("index", ["0"])[0])
    addr = w.address(0, idx)
    c = chain_mod.Chain(w.network)
    try:
        utxos = c.utxos(addr)
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"backend indisponible: {e}")
    return {"address": addr, "sats": sum(u["value"] for u in utxos),
            "utxos": len(utxos), "url": c.address_url(addr)}


def h_tx(body, q, txid):
    w = _wallet()
    c = chain_mod.Chain(w.network)
    try:
        st = c.tx_status(txid)
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"backend indisponible: {e}")
    return {"txid": txid, "url": c.tx_url(txid), **st}


def h_qr(body, q):
    import segno
    data = q.get("data", [""])[0]
    buf = io.BytesIO()
    segno.make(data, error="m").save(
        buf, kind="svg", scale=5, border=2, dark="#ff7a1a", light="#0f0b07")
    return buf.getvalue(), "image/svg+xml"


def h_fees(body, q):
    w = _wallet()
    try:
        return chain_mod.Chain(w.network).fee_rates()
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"backend indisponible: {e}")


def h_quote(body, q):
    w = _wallet()
    c = chain_mod.Chain(w.network)
    message = q.get("message", [""])[0]
    idx = int(q.get("index", ["0"])[0])
    fee_rate = q.get("fee_rate", [None])[0]
    data = message.encode()
    leaf_xonly = w.key(0, idx).get_public_key().xonly()
    leaf_script = taproot.build_leaf_script(data, leaf_xonly)
    try:
        rate = float(fee_rate) if fee_rate else float(c.fee_rates()["halfHourFee"])
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"impossible d'estimer les frais: {e}")
    reveal_fee = inscribe.estimate_reveal_fee(leaf_script, rate)
    commit_value = inscribe.DUST_P2TR + reveal_fee
    return {"bytes": len(data), "leaf_bytes": len(leaf_script), "fee_rate": rate,
            "reveal_fee": reveal_fee, "commit_value": commit_value,
            "total_est": commit_value + int(reveal_fee * 0.6)}


def h_inscribe(body, q):
    w = _wallet()
    net = NETWORKS[w.network]
    c = chain_mod.Chain(w.network)

    index = int(body.get("index", 0))
    dry_run = bool(body.get("dry_run", True))
    fee_rate_in = body.get("fee_rate")
    data = body["message"].encode()

    leaf_key = w.key(0, index)
    leaf_xonly = leaf_key.get_public_key().xonly()
    leaf_script = taproot.build_leaf_script(data, leaf_xonly)
    commit_spk, parity, _ = taproot.commit_output(taproot.NUMS_XONLY, leaf_script)
    ctrl = taproot.control_block(taproot.NUMS_XONLY, parity)
    wallet_prv_tw, _ = w.output_key_pair(0, index)
    wallet_spk = taproot.wallet_p2tr(leaf_xonly)

    try:
        fee_rate = float(fee_rate_in) if fee_rate_in else float(
            c.fee_rates()["halfHourFee"])
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"impossible d'estimer les frais: {e}")

    reveal_fee = inscribe.estimate_reveal_fee(leaf_script, fee_rate)
    commit_value = inscribe.DUST_P2TR + reveal_fee

    try:
        utxos = c.utxos(w.address(0, index))
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"backend indisponible: {e}")
    if not utxos:
        raise ApiError(400, "aucun UTXO — alimente l'adresse du wallet d'abord")

    try:
        commit_tx = inscribe.build_commit(
            utxos, wallet_prv_tw, wallet_spk, commit_spk,
            commit_value, fee_rate, change_spk=wallet_spk)
        reveal_tx = inscribe.build_reveal(
            commit_tx.txid(), 0, commit_value, commit_spk,
            leaf_script, ctrl, leaf_key, wallet_spk, fee_rate)
    except ValueError as e:
        raise ApiError(400, str(e))

    if op_plenty.decode(reveal_tx.serialize()) != data:
        raise ApiError(500, "roundtrip pré-diffusion échoué — abort")

    result = {
        "bytes": len(data), "leaf_bytes": len(leaf_script), "fee_rate": fee_rate,
        "commit_value": commit_value, "commit_address": commit_spk.address(net),
        "commit_txid": commit_tx.txid().hex(),
        "commit_hex": commit_tx.serialize().hex(),
        "reveal_txid": reveal_tx.txid().hex(),
        "reveal_hex": reveal_tx.serialize().hex(),
        "commit_url": c.tx_url(commit_tx.txid().hex()),
        "reveal_url": c.tx_url(reveal_tx.txid().hex()),
        "broadcast": False,
    }
    if dry_run:
        return result
    try:
        result["commit_txid"] = c.broadcast(commit_tx.serialize().hex())
        result["reveal_txid"] = c.broadcast(reveal_tx.serialize().hex())
        result["commit_url"] = c.tx_url(result["commit_txid"])
        result["reveal_url"] = c.tx_url(result["reveal_txid"])
        result["broadcast"] = True
    except Exception as e:  # noqa: BLE001
        raise ApiError(502, f"diffusion refusée: {e}")
    return result


POST_ROUTES = {
    "/api/encode": h_encode, "/api/decode": h_decode, "/api/create": h_create,
    "/api/unlock": h_unlock, "/api/lock": h_lock, "/api/inscribe": h_inscribe,
}
GET_ROUTES = {
    "/api/status": h_status, "/api/address": h_address, "/api/balance": h_balance,
    "/api/qr": h_qr, "/api/fees": h_fees, "/api/quote": h_quote,
}

_STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css",
                 ".js": "text/javascript", ".svg": "image/svg+xml"}


class Handler(BaseHTTPRequestHandler):
    server_version = "opplenty"

    def log_message(self, *a):  # keep the console quiet
        pass

    # -- response helpers --------------------------------------------------- #
    def _send(self, status, payload, ctype="application/json"):
        if ctype == "application/json":
            payload = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        # local single-origin app; no caching of API responses
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _run(self, fn, body, q, *extra):
        try:
            out = fn(body, q, *extra)
            if isinstance(out, tuple):  # raw (bytes, content_type)
                self._send(200, out[0], out[1])
            else:
                self._send(200, out)
        except ApiError as e:
            self._send(e.status, {"detail": e.detail})
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._send(500, {"detail": f"erreur interne: {e}"})

    # -- static ------------------------------------------------------------- #
    def _serve_static(self, path):
        rel = "index.html" if path == "/" else path.lstrip("/")
        target = (WEB / rel).resolve()
        if WEB.resolve() not in target.parents and target != (WEB / "index.html").resolve():
            self._send(404, {"detail": "not found"}); return
        if not target.is_file():
            self._send(404, {"detail": "not found"}); return
        ctype = _STATIC_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # -- verbs -------------------------------------------------------------- #
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in GET_ROUTES:
            self._run(GET_ROUTES[u.path], None, q)
        elif u.path.startswith("/api/tx/"):
            self._run(h_tx, None, q, u.path[len("/api/tx/"):])
        elif u.path.startswith("/api/"):
            self._send(404, {"detail": "route inconnue"})
        else:
            self._serve_static(u.path)

    def do_POST(self):
        u = urlparse(self.path)
        fn = POST_ROUTES.get(u.path)
        if fn is None:
            self._send(404, {"detail": "route inconnue"}); return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._send(400, {"detail": "JSON invalide"}); return
        self._run(fn, body, parse_qs(u.query))


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"opplenty → http://{HOST}:{PORT}  (Ctrl-C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\narrêt.")
        srv.shutdown()


if __name__ == "__main__":
    main()
