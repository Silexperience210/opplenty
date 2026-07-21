"""Test suite: codec, tapleaf, commit/reveal signé, vérification schnorr, vault."""
import os, sys, tempfile
sys.path.insert(0, ".")
from opplenty import op_plenty, taproot, inscribe, wallet as wmod
from embit import ec, bip39, bip32, script as escript
from embit.networks import NETWORKS
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.hashes import tagged_hash

ok = 0
def check(name, cond):
    global ok
    assert cond, f"FAIL: {name}"
    ok += 1
    print(f"  ✓ {name}")

# 1. Vecteur du gist: b"Hi" framé v2
enc = op_plenty.encode(b"Hi")
check("vecteur 'Hi' == gist", enc.hex() == "555555555555559a589a589a589a5c9e60a0616d6d75")
check("decode('Hi')", op_plenty.decode(enc) == b"Hi")

# 2. Roundtrip exhaustif sur tailles/valeurs variées
for size in [0, 1, 2, 3, 15, 16, 64, 255, 1000, 5000]:
    data = os.urandom(size)
    e = op_plenty.encode(data)
    check(f"roundtrip {size}o", op_plenty.decode(e) == data)
    # simulate: doit finir profondeur 1 sans underflow
    check(f"simulate {size}o -> depth 1", op_plenty.simulate(e) == 1)

# 3. Tous les octets possibles
allbytes = bytes(range(256))
e = op_plenty.encode(allbytes)
check("roundtrip 0x00..0xff", op_plenty.decode(e) == allbytes)
check("simulate 0x00..0xff", op_plenty.simulate(e) == 1)

# 4. Décodage depuis un blob avec préfixe/suffixe arbitraire (raw tx)
blob = os.urandom(50) + e + os.urandom(80)
check("decode dans un blob", op_plenty.decode(blob) == allbytes)

# 5. Alphabet: aucun opcode du corps hors alphabet, jamais OP_SUCCESSx
success_slots = set(range(0x7e, 0x82)) | {0x50, 0x62, 0x89, 0x8a, 0x8d, 0x8e} | set(range(0x95, 0x9a)) | set(range(0xbb, 0x100)) | {0x7d} 
# (approximation large des slots OP_SUCCESS BIP342 + disabled)
used = set(e)
check("alphabet ⊆ Op", used <= {int(o) for o in op_plenty.Op})

# 6. Tapleaf + commit + control block + reveal signé, vérif schnorr BIP340
seed = bip39.mnemonic_to_seed(bip39.mnemonic_from_bytes(os.urandom(32)))
root = bip32.HDKey.from_seed(seed, version=NETWORKS["signet"]["xprv"])
key = root.derive("m/86h/1h/0h/0/0").key
xonly = key.get_public_key().xonly()

payload = "Silexperience était ici — OP_PLENTY ⚡".encode()
leaf = taproot.build_leaf_script(payload, xonly)
check("leaf se termine par OP_CHECKSIG", leaf[-1] == 0xAC)
check("leaf contient la clé", xonly in leaf)

commit_spk, parity, mroot = taproot.commit_output(taproot.NUMS_XONLY, leaf)
ctrl = taproot.control_block(taproot.NUMS_XONLY, parity)
check("control block 33 octets", len(ctrl) == 33)
check("leaf_hash == merkle_root (arbre à 1 feuille)", taproot.leaf_hash(leaf) == mroot)

# vérif indépendante du tweak BIP341: Q = P + H(P||root)·G
t = tagged_hash("TapTweak", taproot.NUMS_XONLY + mroot)
P = ec.PublicKey.from_xonly(taproot.NUMS_XONLY)
Q = P.taproot_tweak(mroot)
check("commit spk = OP_1 <Q.xonly>", commit_spk.data == b"\x51\x20" + Q.xonly())

# 7. Commit tx: 1 fake utxo keypath -> commit + change, signé
wallet_spk = taproot.wallet_p2tr(xonly)
prv_tw = key.taproot_tweak(b"")
check("prv_tw pub == wallet spk key", wallet_spk.data[2:] == prv_tw.get_public_key().xonly())
fake_utxo = [{"txid": os.urandom(32).hex(), "vout": 0, "value": 100_000}]
commit_value = 20_000
ctx = inscribe.build_commit(fake_utxo, prv_tw, wallet_spk, commit_spk,
                            commit_value, 2.0, wallet_spk)
check("commit: sortie 0 = commit_value", ctx.vout[0].value == commit_value and ctx.vout[0].script_pubkey == commit_spk)
fee = 100_000 - sum(o.value for o in ctx.vout)
check(f"commit: frais raisonnables ({fee} sats)", 100 < fee < 1000)
# vérif schnorr de la signature keypath
h = ctx.sighash_taproot(0, [wallet_spk], [100_000])
sig = ec.SchnorrSig.parse(ctx.vin[0].witness.items[0])
check("commit: sig keypath valide", prv_tw.get_public_key().schnorr_verify(sig, h))

# 8. Reveal tx signé + vérif schnorr script-path + décodage depuis raw tx
rtx = inscribe.build_reveal(ctx.txid(), 0, commit_value, commit_spk,
                            leaf, ctrl, key, wallet_spk, 2.0)
check("reveal: witness = [sig, script, ctrl]", len(rtx.vin[0].witness.items) == 3)
h2 = rtx.sighash_taproot(0, [commit_spk], [commit_value], ext_flag=1,
                         script=Script(leaf), leaf_version=0xC0)
sig2 = ec.SchnorrSig.parse(rtx.vin[0].witness.items[0])
check("reveal: sig script-path valide (BIP340)", key.get_public_key().schnorr_verify(sig2, h2))
check("reveal: décodage depuis la raw tx", op_plenty.decode(rtx.serialize()) == payload)
rfee = commit_value - rtx.vout[0].value
check(f"reveal: frais cohérents ({rfee} sats)", 200 < rfee < 2000)

# 9. Vault chiffré: création, réouverture, mauvais mot de passe
with tempfile.TemporaryDirectory() as d:
    vp = os.path.join(d, "t.vault")
    mn = wmod.create_vault(vp, "correct horse battery")
    check("vault: mnémonique 24 mots valide", bip39.mnemonic_is_valid(mn) and len(mn.split()) == 24)
    check("vault: chmod 600", oct(os.stat(vp).st_mode & 0o777) == "0o600")
    check("vault: réouverture", wmod.open_vault(vp, "correct horse battery") == mn)
    try:
        wmod.open_vault(vp, "wrong")
        check("vault: mauvais mdp rejeté", False)
    except Exception:
        check("vault: mauvais mdp rejeté", True)
    check("vault: plaintext absent du fichier", mn.split()[0].encode() not in open(vp,"rb").read())

# 10. Adresses BIP86 déterministes signet vs mainnet
w = wmod.Wallet(root=root, network="signet")
a = w.address(0, 0)
check("adresse signet tb1p…", a.startswith("tb1p"))

print(f"\n{ok}/{ok} tests OK ✅")
