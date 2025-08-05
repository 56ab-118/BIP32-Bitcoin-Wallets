from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN
import hashlib
import base58

def generate_mnemonic():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)

def mnemonic_to_seed(mnemonic, passphrase=""):
    mnemo = Mnemonic("english")
    return mnemo.to_seed(mnemonic, passphrase=passphrase)

def derive_legacy_address(seed):
    bip32_key = BIP32Key.fromEntropy(seed)
    key = bip32_key.ChildKey(44 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(0).ChildKey(0)

    private_key = key.WalletImportFormat()
    pubkey = key.PublicKey()

    sha256_bpk = hashlib.sha256(pubkey).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address_bytes = network_byte + checksum
    address = base58.b58encode(address_bytes).decode()

    return private_key, address

def generate_wallets(count=10):
    for i in range(count):
        print(f"\n--- Wallet {i+1} ---")
        mnemonic = generate_mnemonic()
        seed = mnemonic_to_seed(mnemonic)
        private_key, address = derive_legacy_address(seed)

        print(f"Mnemonic Phrase : {mnemonic}")
        print(f"Private Key     : {private_key}")
        print(f"Address         : {address}")


generate_wallets(1)
