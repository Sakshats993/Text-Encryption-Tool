# Example 1: Encrypt with AES-256-GCM
from src.crypto_core import CryptoCore

crypto = CryptoCore()
encrypted = crypto.encrypt_aes_gcm("Secret message")
print(f"Encrypted: {encrypted['ciphertext'][:32]}...")

# Example 2: Hybrid Encryption for Large Data
from src.hybrid_crypto import HybridCrypto

hybrid = HybridCrypto()
private_key, public_key = crypto.generate_rsa_keypair()
encrypted = hybrid.encrypt("Large confidential document...", public_key)
decrypted = hybrid.decrypt(encrypted, private_key)