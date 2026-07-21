# opplenty

On-chain Bitcoin Taproot wallet with a built-in **OP_PLENTY** encoder/decoder.

Data is encoded in the **choice of Tapscript opcodes** (modulo 22), not in data pushes: two opcodes per byte, a script that always executes cleanly under BIP342, and stateless decoding straight from a txid. The wallet is BIP39/BIP86 (P2TR), ships a CLI and a local web UI, and talks to mempool.space for UTXOs, fees, broadcast and confirmation status.

> **Before any mainnet use — read the [warning](#-before-mainnet).** OP_PLENTY is a novel encoding scheme and no transaction from this repo has been broadcast to a live node yet.

---

## Install

Requires **Python 3.10+**. Pick one of the three methods below.

### Method 1 — from the published wheel (simplest)

```bash
pip install https://github.com/Silexperience210/opplenty/releases/download/v1.1.0/opplenty-1.1.0-py3-none-any.whl
```

This pulls every dependency (embit, cryptography, fastapi, uvicorn, segno) and installs two commands: `opplenty` (CLI) and `opplenty-web` (UI).

### Method 2 — from source

```bash
git clone https://github.com/Silexperience210/opplenty.git
cd opplenty
pip install -r requirements.txt
python3 -m opplenty.server        # UI -> http://127.0.0.1:8787
python3 -m opplenty.cli --help    # or the CLI
```

### Method 3 — Android / Termux

On a phone, do **not** let pip compile `cryptography` from source — it rebuilds the whole Rust toolchain and can take 10–25 minutes (or run out of memory). Install Termux's prebuilt package instead, then pip installs the rest with zero compilation.

```bash
pkg update && pkg upgrade -y
pkg install python git python-cryptography -y

git clone https://github.com/Silexperience210/opplenty.git
cd opplenty
pip install embit fastapi uvicorn segno   # cryptography already provided by pkg

python3 -c "import cryptography, embit, fastapi, uvicorn, segno; print('ok')"
python3 -m opplenty.server
```

Then open `http://127.0.0.1:8787` in your Android browser. Everything runs locally; nothing is exposed off-device.

Tips:
- Run `termux-wake-lock` in a second Termux session so Android doesn't kill the process.
- If a pip step still tries to rebuild cryptography, check the installed version with `python3 -c "import cryptography;print(cryptography.__version__)"` — Termux ships a recent one (well above the `>=42` requirement), so pip should skip it.

---

## Web UI

Single-page, no build step, runs locally:

```bash
python3 -m opplenty.server        # -> http://127.0.0.1:8787
```

Three tabs:

- **Codec** — live encoding with the animated opcode stream, plus decoding from raw hex.
- **Wallet** — create/unlock the encrypted vault, receive address with a locally generated QR, live balance.
- **Inscribe** — fee selector (economy / normal / fast from live mempool rates), cost preview, dry-run, then broadcast, with clickable mempool links and a confirmation check.

The vault password only lives in the process's RAM, never on disk. The receive-address QR is generated on-device, so the address is never sent to any third party. On mainnet the whole UI switches to a persistent red state and requires you to type `MAINNET` before broadcasting.

---

## CLI

```bash
# 1. Create the wallet (signet by default — recommended for testing)
opplenty create

# 2. Receive address (BIP86, tb1p…) — fund it from a signet faucet
opplenty address
opplenty balance

# 3. Encode / decode offline
opplenty encode --message "gm" --asm
opplenty decode --hex 5555555555555...

# 4. Inscribe on-chain (commit + reveal)
opplenty inscribe --message "gm" --dry-run   # inspect first
opplenty inscribe --message "gm"
opplenty inscribe --file logo.bin --fee-rate 2

# 5. Recover data from the txid alone (v2 framing)
opplenty decode --txid <reveal_txid> --network signet
```

Mainnet: add `--network mainnet` (an explicit confirmation is required). If installed from source, replace `opplenty` with `python3 -m opplenty.cli`.

---

## First run

1. **Wallet** tab → network **signet** → set a password → **Create a wallet**. Write the 24 words down on paper.
2. **Unlock**, copy the `tb1p…` address (or scan the QR), and fund it from a signet faucet.
3. **Inscribe** tab → type a message → **Dry-run** first, then **Build & broadcast**.
4. Confirm the reveal transaction lands on mempool before you even think about mainnet.

---

## Architecture

```
opplenty/
├── op_plenty.py   # the mod-22 codec + simulate() (stack dry-run, anti-underflow)
├── taproot.py     # BIP341 leaf hash, control block, commit output (NUMS key)
├── wallet.py      # scrypt + AES-256-GCM vault, BIP86 derivation
├── chain.py       # mempool.space backend (utxos, fees, broadcast, tx hex, status)
├── inscribe.py    # commit & reveal build/sign, fee sizing
├── cli.py         # command-line interface
├── server.py      # FastAPI backend (wraps the modules above)
└── web/index.html # cyberpunk UI, vanilla JS, animated opcode stream
```

### Commit / reveal flow

1. **Leaf** = `OP_PLENTY(data)` + `OP_DROP <xonly_pk> OP_CHECKSIG`.
2. **Commit** — a P2TR output whose **internal key is the BIP341 NUMS point** (`50929b74…`), making the key path provably unspendable so only your tapleaf can spend it.
3. **Reveal** — a script-path spend, witness `[schnorr_sig, leaf_script, control_block]`, sending the sats back to your wallet address.
4. The decoder finds the `55×7` magic in the raw transaction, folds the 8 length opcodes mod 22, then decodes exactly N nibbles.

---

## Security

- **Mnemonic is never on disk in cleartext** — scrypt (N=2¹⁷ ≈ 134 MB, phone-safe; params are stored per vault, so old vaults keep opening if the default changes) + AES-256-GCM with AAD, file `chmod 600`. BIP39 passphrase (25th word) supported and never stored.
- **Signet by default**, with an interactive guard on mainnet.
- **Commit key path neutralized** (NUMS point) — no hidden spend path.
- **`simulate()` before broadcast** — dry-runs the encoded script against a stack model and rejects any underflow or out-of-alphabet opcode before signing.
- **Roundtrip verified before broadcast** — `decode(reveal_raw_tx) == data`, else abort.
- **SIGHASH_DEFAULT** throughout, 64-byte signatures.
- 45 tests (`python3 tests.py`): the gist vector, roundtrips from 0 to 5000 bytes, every byte 0x00–0xFF, independent BIP340 Schnorr verification of both signatures, the BIP341 tweak recomputed by hand, and the vault (wrong password rejected, plaintext absent from the file).

---

## ⚠ Before mainnet

OP_PLENTY is a **novel** encoding scheme. Structure, signatures (BIP340) and the tweak (BIP341) are covered by 45 tests, but **no transaction from this repo has been broadcast to a live node yet**. A reveal script that failed to validate under consensus would leave the committed sats **permanently locked**. So: run a full commit→reveal cycle on **signet** (with real signet UTXOs from a faucet) and confirm the reveal lands, **before** risking a single satoshi on mainnet. That is exactly why the UI puts so much friction on the mainnet path.

---

## Notes & limits

- Cost: ~2 opcodes/byte → roughly **4× heavier** in witness than a push-based inscription (ord envelope). That's the price of stealth: no data push, no `OP_IF OP_FALSE`, a fully executed script.
- One leaf per commit; practical payload cap is bound by the standard tx weight (400 kWU ≈ ~190 KB of payload, plenty).
- Backend is the public mempool.space API. For self-sovereignty, swap `chain.py` for your own Core/Esplora (interface: `utxos / tx_hex / fee_rates / broadcast / tx_status`).
- The alphabet avoids `OP_SUCCESSx` slots (Core policy rejection, mandatory under BIP110).

---

## Build & release

Build: `python -m build` → `dist/*.whl` + `dist/*.tar.gz`. Releases are **CI-automated** — no token is ever pasted:

```bash
git tag v1.1.0
git push origin v1.1.0     # .github/workflows/release.yml runs tests, builds, publishes
```

The workflow runs the 45 tests, builds the wheel + sdist, and creates the GitHub Release using the `GITHUB_TOKEN` that GitHub Actions injects automatically.

## License

MIT
