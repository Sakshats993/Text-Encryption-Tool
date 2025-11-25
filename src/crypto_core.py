"""
Core cryptographic operations for AES, DES, and RSA encryption.
Implements secure practices as outlined in the project README.
"""

import os
import json
import base64
from datetime import datetime
from typing import Dict, Tuple, Optional, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CryptoCore:
    """Core cryptographic operations handler"""
    
    def __init__(self):
        self.backend = default_backend()
        
    def generate_key(self, algorithm: str, key_size: int = None) -> bytes:
        """Generate a secure random key for the specified algorithm"""
        if algorithm.upper() == "AES":
            key_size = key_size or 256
            return os.urandom(key_size // 8)
        elif algorithm.upper() == "DES":
            return os.urandom(8)  # DES uses 64-bit keys (8 bytes)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def generate_nonce(self, size: int = 12) -> bytes:
        """Generate a secure random nonce for GCM mode"""
        return os.urandom(size)
    
    def generate_iv(self, size: int = 16) -> bytes:
        """Generate a secure random IV for CBC mode"""
        return os.urandom(size)
    
    # AES Encryption/Decryption with GCM (Authenticated Encryption)
    def encrypt_aes_gcm(self, plaintext: str, key: bytes = None) -> Dict[str, str]:
        """
        Encrypt plaintext using AES-256-GCM (authenticated encryption).
        Returns dictionary with base64-encoded components.
        """
        if key is None:
            key = self.generate_key("AES", 256)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Generate nonce for GCM
        nonce = self.generate_nonce(12)  # 96-bit nonce for GCM
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Encrypt and get tag
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        # Return components
        return {
            "scheme": "AES-256-GCM",
            "meta": {
                "alg": "AES-256-GCM",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "key": base64.b64encode(key).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt_aes_gcm(self, encrypted_data: Dict[str, Any]) -> str:
        """
        Decrypt AES-256-GCM encrypted data.
        Verifies authentication tag before returning plaintext.
        """
        # Decode base64 components
        key = base64.b64decode(encrypted_data['key'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Create cipher with tag
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt and verify tag
        try:
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed - authentication tag verification failed: {e}")
    
    # DES Encryption/Decryption (Legacy - Educational Only)
    def encrypt_des_cbc(self, plaintext: str, key: bytes = None) -> Dict[str, str]:
        """
        Encrypt plaintext using DES-CBC (EDUCATIONAL ONLY - NOT SECURE).
        Includes HMAC for integrity since CBC doesn't provide authentication.
        """
        import hmac
        import hashlib
        
        if key is None:
            key = self.generate_key("DES")
        
        # Generate IV
        iv = os.urandom(8)  # DES uses 8-byte blocks
        
        # Pad plaintext to 8-byte boundary
        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext = pad(plaintext_bytes, 8)
        
        # Create cipher
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Calculate HMAC for integrity
        h = hmac.new(key, iv + ciphertext, hashlib.sha256)
        mac = h.digest()
        
        return {
            "scheme": "DES-CBC",
            "meta": {
                "alg": "DES-CBC",
                "warning": "DES is obsolete and insecure - for educational purposes only",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "key": base64.b64encode(key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "mac": base64.b64encode(mac).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt_des_cbc(self, encrypted_data: Dict[str, Any]) -> str:
        """Decrypt DES-CBC encrypted data with HMAC verification"""
        import hmac
        import hashlib
        
        # Decode components
        key = base64.b64decode(encrypted_data['key'])
        iv = base64.b64decode(encrypted_data['iv'])
        mac = base64.b64decode(encrypted_data['mac'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Verify HMAC
        h = hmac.new(key, iv + ciphertext, hashlib.sha256)
        expected_mac = h.digest()
        
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed - data may be tampered")
        
        # Decrypt
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext_bytes = unpad(padded_plaintext, 8)
        return plaintext_bytes.decode('utf-8')
    
    # RSA Key Generation and Operations
    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        Returns (private_key_pem, public_key_pem) as bytes.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt_rsa_oaep(self, plaintext: str, public_key_pem: bytes) -> Dict[str, str]:
        """
        Encrypt small plaintext using RSA-OAEP.
        Note: RSA can only encrypt data smaller than key_size - overhead.
        """
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Check size limit (RSA 2048 with OAEP can encrypt ~214 bytes)
        key_size_bytes = public_key.key_size // 8
        max_size = key_size_bytes - 42  # OAEP overhead with SHA-256
        
        if len(plaintext_bytes) > max_size:
            raise ValueError(f"Plaintext too large for RSA. Max size: {max_size} bytes. "
                           "Use hybrid encryption for larger data.")
        
        # Encrypt with OAEP padding
        ciphertext = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            "scheme": "RSA-OAEP",
            "meta": {
                "alg": "RSA-OAEP",
                "hash": "SHA256",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt_rsa_oaep(self, encrypted_data: Dict[str, Any], 
                        private_key_pem: bytes) -> str:
        """Decrypt RSA-OAEP encrypted data"""
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        
        # Decode ciphertext
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Decrypt with OAEP padding
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext_bytes.decode('utf-8')