"""
opplenty — wallet Taproot avec inscription de données via OP_PLENTY.

Commandes:
  create            crée un vault chiffré (mnémonique 24 mots)
  import            importe une mnémonique existante dans un vault chiffré
  address           affiche l'adresse de réception (BIP86)
  balance           solde on-chain de l'adresse
  encode            encode un message -> hex du script (offline)
  decode            décode depuis hex brut / fichier / txid
  inscribe          commit + reveal: écrit les données on-chain
"""

import argparse
import sys


from embit.networks import NETWORKS
from embit.script import Script

from . import chain as chain_mod
from . import inscribe, op_plenty, taproot, wallet as wallet_mod


def _load_wallet(args) -> wallet_mod.Wallet:
    pw = wallet_mod.prompt_password()
    return wallet_mod.Wallet.from_vault(args.vault, pw, args.network,
                                        bip39_passphrase=args.passphrase or "")


def cmd_create(args):
    pw = wallet_mod.prompt_password(confirm=True)
    mnemonic = wallet_mod.create_vault(args.vault, pw)
    print("\n=== NOTE CES 24 MOTS SUR PAPIER — ILS NE SERONT PLUS AFFICHÉS ===\n")
    words = mnemonic.split()
    for i in range(0, 24, 4):
        print("  " + "  ".join(f"{j+1:2d}.{words[j]}" for j in range(i, i + 4)))
    print(f"\nVault chiffré écrit dans: {args.vault} (scrypt + AES-256-GCM)")


def cmd_import(args):
    mnemonic = input("Mnémonique (12/24 mots): ").strip()
    pw = wallet_mod.prompt_password(confirm=True)
    wallet_mod.create_vault(args.vault, pw, mnemonic=mnemonic)
    print(f"Vault chiffré écrit dans: {args.vault}")


def cmd_address(args):
    w = _load_wallet(args)
    print(w.address(0, args.index))


def cmd_balance(args):
    w = _load_wallet(args)
    addr = w.address(0, args.index)
    c = chain_mod.Chain(w.network)
    utxos = c.utxos(addr)
    total = sum(u["value"] for u in utxos)
    print(f"{addr}\n{total} sats ({len(utxos)} UTXO)")


def _payload_from_args(args) -> bytes:
    if args.file:
        with open(args.file, "rb") as f:
            return f.read()
    if args.message is None:
        raise SystemExit("fournis --message ou --file")
    return args.message.encode()


def cmd_encode(args):
    data = _payload_from_args(args)
    body = op_plenty.encode(data)
    print(f"payload : {len(data)} octets")
    print(f"script  : {len(body)} opcodes")
    print(f"hex     : {body.hex()}")
    if args.asm:
        print(f"asm     : {op_plenty.asm(body)}")


def cmd_decode(args):
    if args.txid:
        c = chain_mod.Chain(wallet_mod.NETWORK_ALIASES[args.network])
        blob = bytes.fromhex(c.tx_hex(args.txid))
    elif args.hex:
        blob = bytes.fromhex(args.hex)
    elif args.file:
        with open(args.file, "rb") as f:
            blob = f.read()
    else:
        raise SystemExit("fournis --txid, --hex ou --file")
    data = op_plenty.decode(blob)
    try:
        print(data.decode())
    except UnicodeDecodeError:
        sys.stdout.buffer.write(data)


def cmd_inscribe(args):
    data = _payload_from_args(args)
    w = _load_wallet(args)
    net = NETWORKS[w.network]
    c = chain_mod.Chain(w.network)

    # --- keys & scripts -----------------------------------------------------
    leaf_key = w.key(0, args.index)                 # raw BIP86 child, signs the leaf
    leaf_xonly = leaf_key.get_public_key().xonly()
    leaf_script = taproot.build_leaf_script(data, leaf_xonly)
    commit_spk, parity, _root = taproot.commit_output(taproot.NUMS_XONLY, leaf_script)
    ctrl = taproot.control_block(taproot.NUMS_XONLY, parity)

    wallet_prv_tw, _ = w.output_key_pair(0, args.index)
    wallet_spk = taproot.wallet_p2tr(leaf_xonly)
    commit_addr = commit_spk.address(net)

    fee_rate = args.fee_rate or float(c.fee_rates()["halfHourFee"])
    reveal_fee = inscribe.estimate_reveal_fee(leaf_script, fee_rate)
    commit_value = inscribe.DUST_P2TR + reveal_fee

    print(f"payload        : {len(data)} octets -> leaf de {len(leaf_script)} octets")
    print(f"fee rate       : {fee_rate} sat/vB")
    print(f"adresse commit : {commit_addr}")
    print(f"valeur commit  : {commit_value} sats")

    utxos = c.utxos(w.address(0, args.index))
    if not utxos:
        raise SystemExit("aucun UTXO sur l'adresse du wallet — alimente-la d'abord")

    commit_tx = inscribe.build_commit(
        utxos, wallet_prv_tw, wallet_spk, commit_spk,
        commit_value, fee_rate, change_spk=wallet_spk)
    commit_txid_hex = commit_tx.txid().hex()

    reveal_tx = inscribe.build_reveal(
        commit_tx.txid(), 0, commit_value, commit_spk,
        leaf_script, ctrl, leaf_key, wallet_spk, fee_rate)

    # pre-broadcast sanity: full roundtrip on the reveal we just built
    assert op_plenty.decode(reveal_tx.serialize()) == data, "roundtrip decode failed"

    if args.dry_run:
        print("\n--- DRY RUN (rien n'est diffusé) ---")
        print(f"commit txid : {commit_txid_hex}")
        print(f"commit hex  : {commit_tx.serialize().hex()}")
        print(f"reveal hex  : {reveal_tx.serialize().hex()}")
        return

    txid1 = c.broadcast(commit_tx.serialize().hex())
    print(f"commit diffusé : {txid1}")
    txid2 = c.broadcast(reveal_tx.serialize().hex())
    print(f"reveal diffusé : {txid2}")
    print(f"\nDécodage plus tard: opplenty decode --txid {txid2} "
          f"--network {args.network}")


def main():
    p = argparse.ArgumentParser(prog="opplenty", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--network", default="signet",
                   choices=["signet", "testnet", "mainnet"],
                   help="réseau (défaut: signet)")
    p.add_argument("--vault", default="opplenty.vault",
                   help="fichier vault chiffré (défaut: opplenty.vault)")
    p.add_argument("--passphrase", default="",
                   help="passphrase BIP39 optionnelle (25e mot)")
    p.add_argument("--index", type=int, default=0, help="index de dérivation")

    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create").set_defaults(fn=cmd_create)
    sub.add_parser("import").set_defaults(fn=cmd_import)
    sub.add_parser("address").set_defaults(fn=cmd_address)
    sub.add_parser("balance").set_defaults(fn=cmd_balance)

    pe = sub.add_parser("encode")
    pe.add_argument("--message"), pe.add_argument("--file")
    pe.add_argument("--asm", action="store_true")
    pe.set_defaults(fn=cmd_encode)

    pd = sub.add_parser("decode")
    pd.add_argument("--txid"), pd.add_argument("--hex"), pd.add_argument("--file")
    pd.set_defaults(fn=cmd_decode)

    pi = sub.add_parser("inscribe")
    pi.add_argument("--message"), pi.add_argument("--file")
    pi.add_argument("--fee-rate", type=float, help="sat/vB (défaut: API mempool)")
    pi.add_argument("--dry-run", action="store_true",
                    help="construit et signe sans diffuser")
    pi.set_defaults(fn=cmd_inscribe)

    args = p.parse_args()
    if args.network == "mainnet":
        ok = input("⚠️  MAINNET — de vrais sats seront dépensés. Continuer? [oui/N] ")
        if ok.strip().lower() not in ("oui", "yes", "y"):
            raise SystemExit("annulé")
    args.fn(args)


if __name__ == "__main__":
    main()
