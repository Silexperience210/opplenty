"""
Wallet: BIP39 mnemonic (generated with os.urandom), BIP86 taproot derivation,
mnemonic stored ONLY encrypted (scrypt N=2^20 + AES-256-GCM).

Security properties:
- seed material never written to disk in plaintext
- key file chmod 600
- passphrase (25th word) supported, never stored
- mainnet requires explicit --network mainnet (signet is the default)
"""

import json
import os
import getpass
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from embit import bip32, bip39, ec, script as escript
from embit.networks import NETWORKS

VAULT_VERSION = 1

NETWORK_ALIASES = {
    "mainnet": "main",
    "main": "main",
    "testnet": "test",
    "test": "test",
    "signet": "signet",
    "regtest": "regtest",
}

COIN_TYPE = {"main": 0, "test": 1, "signet": 1, "regtest": 1}


def _kdf(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**20, r=8, p=1).derive(password)


def create_vault(path: str, password: str, mnemonic: str | None = None,
                 strength_bits: int = 256) -> str:
    """Generate (or import) a mnemonic and store it encrypted. Returns mnemonic."""
    if mnemonic is None:
        entropy = os.urandom(strength_bits // 8)
        mnemonic = bip39.mnemonic_from_bytes(entropy)
    elif not bip39.mnemonic_is_valid(mnemonic):
        raise ValueError("mnemonic BIP39 invalide (checksum)")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _kdf(password.encode(), salt)
    ct = AESGCM(key).encrypt(nonce, mnemonic.encode(), b"opplenty-vault-v1")

    vault = {
        "version": VAULT_VERSION,
        "kdf": {"name": "scrypt", "n": 2**20, "r": 8, "p": 1, "salt": salt.hex()},
        "cipher": {"name": "aes-256-gcm", "nonce": nonce.hex()},
        "ciphertext": ct.hex(),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(vault, f, indent=2)
    return mnemonic


def open_vault(path: str, password: str) -> str:
    with open(path) as f:
        vault = json.load(f)
    if vault.get("version") != VAULT_VERSION:
        raise ValueError("version de vault non supportée")
    salt = bytes.fromhex(vault["kdf"]["salt"])
    nonce = bytes.fromhex(vault["cipher"]["nonce"])
    key = _kdf(password.encode(), salt)
    pt = AESGCM(key).decrypt(nonce, bytes.fromhex(vault["ciphertext"]),
                             b"opplenty-vault-v1")
    return pt.decode()


@dataclass
class Wallet:
    root: bip32.HDKey
    network: str  # embit network key: main/test/signet/regtest

    @classmethod
    def from_vault(cls, path: str, password: str, network: str,
                   bip39_passphrase: str = "") -> "Wallet":
        net = NETWORK_ALIASES[network]
        mnemonic = open_vault(path, password)
        seed = bip39.mnemonic_to_seed(mnemonic, password=bip39_passphrase)
        root = bip32.HDKey.from_seed(seed, version=NETWORKS[net]["xprv"])
        return cls(root=root, network=net)

    def _account(self) -> bip32.HDKey:
        coin = COIN_TYPE[self.network]
        return self.root.derive(f"m/86h/{coin}h/0h")

    def key(self, change: int = 0, index: int = 0) -> ec.PrivateKey:
        return self._account().derive([change, index]).key

    def xonly(self, change: int = 0, index: int = 0) -> bytes:
        return self.key(change, index).get_public_key().xonly()

    def address(self, change: int = 0, index: int = 0) -> str:
        pub = self.key(change, index).get_public_key()
        spk = escript.p2tr(pub)  # BIP86 tweak(internal, empty)
        return spk.address(NETWORKS[self.network])

    def output_key_pair(self, change: int = 0, index: int = 0):
        """(tweaked privkey for key-path spend, tweaked xonly pubkey)."""
        prv = self.key(change, index).taproot_tweak(b"")
        return prv, prv.get_public_key().xonly()


def prompt_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Mot de passe du vault: ")
    if confirm:
        if pw != getpass.getpass("Confirme le mot de passe: "):
            raise SystemExit("Les mots de passe ne correspondent pas.")
        if len(pw) < 8:
            raise SystemExit("Mot de passe trop court (min 8 caractères).")
    return pw
