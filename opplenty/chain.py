"""mempool.space REST backend (mainnet / testnet / signet)."""

import json
import urllib.request

API = {
    "main": "https://mempool.space/api",
    "test": "https://mempool.space/testnet/api",
    "signet": "https://mempool.space/signet/api",
}

EXPLORER = {
    "main": "https://mempool.space",
    "test": "https://mempool.space/testnet",
    "signet": "https://mempool.space/signet",
}


class Chain:
    def __init__(self, network: str):
        if network not in API:
            raise ValueError(f"réseau sans backend public: {network}")
        self.base = API[network]
        self.explorer = EXPLORER[network]

    def tx_url(self, txid: str) -> str:
        return f"{self.explorer}/tx/{txid}"

    def address_url(self, address: str) -> str:
        return f"{self.explorer}/address/{address}"

    def tx_status(self, txid: str) -> dict:
        """{"confirmed": bool, "block_height": int?, "block_time": int?}"""
        return self._get(f"/tx/{txid}/status")

    def _get(self, path: str):
        req = urllib.request.Request(self.base + path,
                                     headers={"User-Agent": "opplenty/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body.decode()

    def utxos(self, address: str) -> list[dict]:
        return self._get(f"/address/{address}/utxo")

    def balance(self, address: str) -> int:
        return sum(u["value"] for u in self.utxos(address))

    def tx_hex(self, txid: str) -> str:
        return self._get(f"/tx/{txid}/hex")

    def fee_rates(self) -> dict:
        return self._get("/v1/fees/recommended")

    def broadcast(self, tx_hex: str) -> str:
        req = urllib.request.Request(
            self.base + "/tx", data=tx_hex.encode(),
            headers={"User-Agent": "opplenty/1.0",
                     "Content-Type": "text/plain"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode().strip()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"broadcast refusé: {e.read().decode()}") from e
