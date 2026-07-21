# opplenty — Wallet Taproot + inscription de données via OP_PLENTY

Wallet Bitcoin on-chain (BIP39/BIP86, P2TR) avec encodeur/décodeur **OP_PLENTY** intégré : les données sont encodées dans le **choix des opcodes Tapscript** (modulo 22), pas dans des pushes. Deux opcodes par octet, script toujours exécutable proprement sous BIP342, décodage stateless directement depuis le txid.

## Installation

```bash
pip install embit cryptography
python3 -m opplenty.cli --help
```

Aucune autre dépendance. Fonctionne sur Android via Termux (`pkg install python`).

## Usage

```bash
# 1. Créer le wallet (signet par défaut — recommandé pour tester)
python3 -m opplenty.cli create

# 2. Adresse de dépôt (BIP86, tb1p…) — alimente-la via un faucet signet
python3 -m opplenty.cli address
python3 -m opplenty.cli balance

# 3. Encoder/décoder offline
python3 -m opplenty.cli encode --message "gm ⚡" --asm
python3 -m opplenty.cli decode --hex 5555555555555...

# 4. Inscrire on-chain (commit + reveal)
python3 -m opplenty.cli inscribe --message "gm ⚡" --dry-run   # inspecte d'abord
python3 -m opplenty.cli inscribe --message "gm ⚡"
python3 -m opplenty.cli inscribe --file logo.bin --fee-rate 2

# 5. Récupérer les données depuis le txid seul (framing v2)
python3 -m opplenty.cli decode --txid <reveal_txid> --network signet
```

Mainnet : `--network mainnet` (confirmation explicite demandée).

## Interface web

UI cyberpunk (orange/noir/rouge), page unique, sans build, tourne en local :

```bash
pip install -r requirements.txt
python3 -m opplenty.server        # -> http://127.0.0.1:8787
```

Trois onglets : **Codec** (encode en direct avec le flux d'opcodes animé + decode), **Wallet** (création/déverrouillage du vault chiffré, adresse, solde), **Inscrire** (dry-run puis diffusion). Le mot de passe du vault ne vit qu'en RAM du process, jamais sur disque. Élément signature : le flux d'opcodes montre les données devenir des choix de Tapscript (seed gris, longueur jaune, corps, footer rouge).

## Build & release

Le build : `python -m build` → `dist/*.whl` + `dist/*.tar.gz`. La release est **automatisée par CI**, sans jamais coller de token :

```bash
# 1. crée le repo et pousse (une fois, avec un token frais gardé secret)
git init && git add -A && git commit -m "opplenty v1.0.0"
git remote add origin https://github.com/<toi>/opplenty.git
git push -u origin main

# 2. tag -> le workflow .github/workflows/release.yml build, teste et publie
git tag v1.0.0 && git push origin v1.0.0
```

Le workflow tourne les 45 tests, build wheel + sdist, et crée la GitHub Release via le `GITHUB_TOKEN` que GitHub Actions injecte tout seul — aucun secret à saisir nulle part.

## Architecture

```
opplenty/
├── op_plenty.py   # codec du gist + simulate() (dry-run stack, anti-underflow)
├── taproot.py     # leaf hash BIP341, control block, sortie commit (clé NUMS)
├── wallet.py      # vault scrypt(N=2^20)+AES-256-GCM, dérivation BIP86
├── chain.py       # backend mempool.space (utxos, fees, broadcast, tx hex)
├── inscribe.py    # construction/signature commit & reveal, sizing des frais
├── cli.py         # interface ligne de commande
├── server.py      # backend FastAPI (wrappe les modules ci-dessus)
└── web/index.html # UI cyberpunk, vanilla JS, flux d'opcodes animé
```

### Flow commit/reveal

1. **Leaf** = `OP_PLENTY(data)` + `OP_DROP <xonly_pk> OP_CHECKSIG`
2. **Commit** : sortie P2TR avec **clé interne NUMS** (`50929b74…`, BIP341) → le key path est prouvablement indépensable, seule ta tapleaf peut dépenser.
3. **Reveal** : dépense script-path, witness `[sig_schnorr, leaf_script, control_block]`, renvoie les sats sur ton adresse wallet.
4. Le décodeur cherche le magic `55×7` dans la raw tx, replie les 8 opcodes de longueur mod 22, puis décode exactement N nibbles.

## Sécurité

- **Mnémonique jamais en clair sur disque** : vault scrypt (N=2²⁰, r=8) + AES-256-GCM avec AAD, fichier `chmod 600`. Passphrase BIP39 (25ᵉ mot) supportée, jamais stockée.
- **Signet par défaut**, garde-fou interactif sur mainnet.
- **Key path du commit neutralisé** (point NUMS) — pas de chemin de dépense caché.
- **`simulate()` pré-broadcast** : dry-run du script encodé contre un modèle de stack ; refuse tout underflow ou opcode hors alphabet avant de signer.
- **Roundtrip vérifié avant diffusion** : `decode(reveal_raw_tx) == data` sinon abort.
- **SIGHASH_DEFAULT** partout, signatures 64 octets.
- 45 tests (`python3 tests.py`) : vecteur du gist, roundtrips 0→5000 octets, tous les octets 0x00–0xFF, vérification Schnorr BIP340 indépendante des deux signatures, tweak BIP341 recalculé à la main, vault (mauvais mdp rejeté, plaintext absent).

## Limites / notes

- Coût : ~2 opcodes/octet → **~4× plus lourd** en witness qu'une inscription par pushes (envelope ord). Le prix de la furtivité : aucun push de données, aucun `OP_IF OP_FALSE`, script 100 % exécuté.
- Un seul leaf par commit ; payload max pratique borné par le poids standard de la tx (400 kWU ≈ ~190 Ko de payload, largement).
- Backend = API publique mempool.space. Pour du souverain, remplace `chain.py` par ton propre Core/Esplora (interface : `utxos/tx_hex/fee_rates/broadcast`).
- L'alphabet évite les slots `OP_SUCCESSx` (rejet policy Core, obligatoire sous BIP110).
