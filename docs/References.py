# AES Encryption
crypto = CryptoCore()
encrypted = crypto.encrypt_aes_gcm("plaintext", key=None)
decrypted = crypto.decrypt_aes_gcm(encrypted)

# RSA Operations
private_key, public_key = crypto.generate_rsa_keypair(2048)
encrypted = crypto.encrypt_rsa_oaep("small text", public_key)
decrypted = crypto.decrypt_rsa_oaep(encrypted, private_key)

# Hybrid Encryption
hybrid = HybridCrypto()
encrypted = hybrid.encrypt("large text", public_key)
decrypted = hybrid.decrypt(encrypted, private_key)