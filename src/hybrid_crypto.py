"""
Hybrid encryption implementation combining RSA and AES.
Uses RSA to encrypt AES keys and AES-GCM for bulk data encryption.
"""

import json
import base64
from typing import Dict, Any
from .crypto_core import CryptoCore


class HybridCrypto:
    """Implements hybrid encryption using RSA + AES"""
    
    def __init__(self):
        self.crypto = CryptoCore()
    
    def encrypt(self, plaintext: str, public_key_pem: bytes) -> Dict[str, Any]:
        """
        Hybrid encryption: 
        1. Generate ephemeral AES key
        2. Encrypt plaintext with AES-GCM
        3. Encrypt AES key with RSA-OAEP
        """
        # Step 1: Generate ephemeral AES-256 key
        aes_key = self.crypto.generate_key("AES", 256)
        
        # Step 2: Encrypt plaintext with AES-GCM
        aes_result = self.crypto.encrypt_aes_gcm(plaintext, aes_key)
        
        # Step 3: Encrypt AES key with RSA-OAEP
        key_encryption = self.crypto.encrypt_rsa_oaep(
            base64.b64encode(aes_key).decode('utf-8'),
            public_key_pem
        )
        
        # Combine results
        return {
            "scheme": "hybrid",
            "meta": {
                "alg": "RSA-OAEP + AES-256-GCM",
                "timestamp": aes_result["meta"]["timestamp"]
            },
            "enc_key": key_encryption["ciphertext"],  # RSA-encrypted AES key
            "nonce": aes_result["nonce"],
            "tag": aes_result["tag"],
            "ciphertext": aes_result["ciphertext"]
        }
    
    def decrypt(self, encrypted_data: Dict[str, Any], 
                private_key_pem: bytes) -> str:
        """
        Hybrid decryption:
        1. Decrypt AES key with RSA private key
        2. Decrypt ciphertext with recovered AES key
        """
        # Step 1: Decrypt AES key with RSA
        key_decryption = {
            "scheme": "RSA-OAEP",
            "ciphertext": encrypted_data["enc_key"]
        }
        aes_key_b64 = self.crypto.decrypt_rsa_oaep(key_decryption, private_key_pem)
        aes_key = base64.b64decode(aes_key_b64)
        
        # Step 2: Decrypt ciphertext with AES-GCM
        aes_decryption = {
            "key": base64.b64encode(aes_key).decode('utf-8'),
            "nonce": encrypted_data["nonce"],
            "tag": encrypted_data["tag"],
            "ciphertext": encrypted_data["ciphertext"]
        }
        
        return self.crypto.decrypt_aes_gcm(aes_decryption)