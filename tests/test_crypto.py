"""
Unit tests for cryptographic operations
"""

import pytest
import json
import base64
from src.crypto_core import CryptoCore
from src.hybrid_crypto import HybridCrypto
from src.key_manager import KeyManager


class TestCryptoCore:
    """Test suite for CryptoCore functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.crypto = CryptoCore()
        self.test_plaintext = "Hello, World! Testing encryption. 🔐"
    
    def test_aes_gcm_roundtrip(self):
        """Test AES-GCM encryption and decryption"""
        # Encrypt
        encrypted = self.crypto.encrypt_aes_gcm(self.test_plaintext)
        
        # Verify structure
        assert 'scheme' in encrypted
        assert encrypted['scheme'] == 'AES-256-GCM'
        assert 'key' in encrypted
        assert 'nonce' in encrypted
        assert 'tag' in encrypted
        assert 'ciphertext' in encrypted
        
        # Decrypt
        decrypted = self.crypto.decrypt_aes_gcm(encrypted)
        assert decrypted == self.test_plaintext
    
    def test_aes_gcm_tampering_detection(self):
        """Test that AES-GCM detects tampering"""
        encrypted = self.crypto.encrypt_aes_gcm(self.test_plaintext)
        
        # Tamper with ciphertext
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        tampered_ciphertext = bytes([(b + 1) % 256 for b in ciphertext])
        encrypted['ciphertext'] = base64.b64encode(tampered_ciphertext).decode('utf-8')
        
        # Should raise exception
        with pytest.raises(ValueError, match="authentication tag verification failed"):
            self.crypto.decrypt_aes_gcm(encrypted)
    
    def test_des_cbc_roundtrip(self):
        """Test DES-CBC encryption and decryption"""
        # Encrypt
        encrypted = self.crypto.encrypt_des_cbc(self.test_plaintext)
        
        # Verify structure
        assert 'scheme' in encrypted
        assert encrypted['scheme'] == 'DES-CBC'
        assert 'warning' in encrypted['meta']
        assert 'key' in encrypted
        assert 'iv' in encrypted
        assert 'mac' in encrypted
        assert 'ciphertext' in encrypted
        
        # Decrypt
        decrypted = self.crypto.decrypt_des_cbc(encrypted)
        assert decrypted == self.test_plaintext
    
    def test_des_cbc_mac_verification(self):
        """Test that DES-CBC HMAC detects tampering"""
        encrypted = self.crypto.encrypt_des_cbc(self.test_plaintext)
        
        # Tamper with ciphertext
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        tampered_ciphertext = bytes([(b + 1) % 256 for b in ciphertext])
        encrypted['ciphertext'] = base64.b64encode(tampered_ciphertext).decode('utf-8')
        
        # Should raise exception
        with pytest.raises(ValueError, match="HMAC verification failed"):
            self.crypto.decrypt_des_cbc(encrypted)
    
    def test_rsa_oaep_roundtrip(self):
        """Test RSA-OAEP encryption and decryption"""
        # Generate keys
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        
        # Small plaintext for RSA
        small_text = "Small secret message"
        
        # Encrypt
        encrypted = self.crypto.encrypt_rsa_oaep(small_text, public_key)
        
        # Verify structure
        assert 'scheme' in encrypted
        assert encrypted['scheme'] == 'RSA-OAEP'
        assert 'ciphertext' in encrypted
        
        # Decrypt
        decrypted = self.crypto.decrypt_rsa_oaep(encrypted, private_key)
        assert decrypted == small_text
    
    def test_rsa_size_limit(self):
        """Test that RSA encryption fails for large plaintext"""
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        
        # Large plaintext (> 214 bytes for 2048-bit RSA with OAEP)
        large_text = "x" * 500
        
        # Should raise exception
        with pytest.raises(ValueError, match="Plaintext too large for RSA"):
            self.crypto.encrypt_rsa_oaep(large_text, public_key)
    
    def test_key_generation(self):
        """Test key generation for different algorithms"""
        # AES keys
        aes_128 = self.crypto.generate_key("AES", 128)
        assert len(aes_128) == 16  # 128 bits = 16 bytes
        
        aes_256 = self.crypto.generate_key("AES", 256)
        assert len(aes_256) == 32  # 256 bits = 32 bytes
        
        # DES key
        des_key = self.crypto.generate_key("DES")
        assert len(des_key) == 8  # 64 bits = 8 bytes
        
        # Keys should be different
        assert aes_128 != self.crypto.generate_key("AES", 128)
    
    def test_nonce_generation(self):
        """Test nonce/IV generation"""
        nonce1 = self.crypto.generate_nonce(12)
        nonce2 = self.crypto.generate_nonce(12)
        
        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert nonce1 != nonce2  # Should be unique
        
        iv1 = self.crypto.generate_iv(16)
        iv2 = self.crypto.generate_iv(16)
        
        assert len(iv1) == 16
        assert len(iv2) == 16
        assert iv1 != iv2  # Should be unique


class TestHybridCrypto:
    """Test suite for hybrid encryption"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.crypto = CryptoCore()
        self.hybrid = HybridCrypto()
        self.test_plaintext = "This is a longer message that would be too large for direct RSA encryption. " * 10
    
    def test_hybrid_roundtrip(self):
        """Test hybrid encryption and decryption"""
        # Generate RSA keys
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        
        # Encrypt
        encrypted = self.hybrid.encrypt(self.test_plaintext, public_key)
        
        # Verify structure
        assert 'scheme' in encrypted
        assert encrypted['scheme'] == 'hybrid'
        assert 'enc_key' in encrypted
        assert 'nonce' in encrypted
        assert 'tag' in encrypted
        assert 'ciphertext' in encrypted
        
        # Decrypt
        decrypted = self.hybrid.decrypt(encrypted, private_key)
        assert decrypted == self.test_plaintext
    
    def test_hybrid_tampering_detection(self):
        """Test that hybrid encryption detects tampering"""
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        encrypted = self.hybrid.encrypt(self.test_plaintext, public_key)
        
        # Tamper with ciphertext
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        tampered_ciphertext = bytes([(b + 1) % 256 for b in ciphertext])
        encrypted['ciphertext'] = base64.b64encode(tampered_ciphertext).decode('utf-8')
        
        # Should raise exception
        with pytest.raises(ValueError):
            self.hybrid.decrypt(encrypted, private_key)
    
    def test_hybrid_different_keys(self):
        """Test that different RSA keys cannot decrypt"""
        private_key1, public_key1 = self.crypto.generate_rsa_keypair(2048)
        private_key2, public_key2 = self.crypto.generate_rsa_keypair(2048)
        
        # Encrypt with key1
        encrypted = self.hybrid.encrypt(self.test_plaintext, public_key1)
        
        # Try to decrypt with key2 - should fail
        with pytest.raises(Exception):
            self.hybrid.decrypt(encrypted, private_key2)


class TestKeyManager:
    """Test suite for key management"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.key_mgr = KeyManager("test_keys")
        self.crypto = CryptoCore()
    
    def teardown_method(self):
        """Cleanup test keys"""
        import shutil
        from pathlib import Path
        test_dir = Path("test_keys")
        if test_dir.exists():
            shutil.rmtree(test_dir)
    
    def test_save_and_load_rsa_keys(self):
        """Test saving and loading RSA key pairs"""
        # Generate keys
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        
        # Save
        self.key_mgr.save_rsa_keypair("test_rsa", private_key, public_key)
        
        # Load
        loaded_private, loaded_public = self.key_mgr.load_rsa_keypair("test_rsa")
        
        assert loaded_private == private_key
        assert loaded_public == public_key
    
    def test_save_and_load_symmetric_key(self):
        """Test saving and loading symmetric keys"""
        # Generate key
        aes_key = self.crypto.generate_key("AES", 256)
        metadata = {"algorithm": "AES-256", "created": "2024-01-01"}
        
        # Save
        self.key_mgr.save_symmetric_key("test_aes", aes_key, metadata)
        
        # Load
        loaded_key, loaded_metadata = self.key_mgr.load_symmetric_key("test_aes")
        
        assert loaded_key == aes_key
        assert loaded_metadata == metadata
    
    def test_list_keys(self):
        """Test listing available keys"""
        # Initially empty
        keys = self.key_mgr.list_keys()
        assert len(keys['rsa_pairs']) == 0
        assert len(keys['symmetric_keys']) == 0
        
        # Add some keys
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        self.key_mgr.save_rsa_keypair("rsa1", private_key, public_key)
        
        aes_key = self.crypto.generate_key("AES", 256)
        self.key_mgr.save_symmetric_key("aes1", aes_key)
        
        # List again
        keys = self.key_mgr.list_keys()
        assert "rsa1" in keys['rsa_pairs']
        assert "aes1" in keys['symmetric_keys']
    
    def test_delete_key(self):
        """Test secure key deletion"""
        # Create keys
        private_key, public_key = self.crypto.generate_rsa_keypair(2048)
        self.key_mgr.save_rsa_keypair("temp_key", private_key, public_key)
        
        # Verify it exists
        keys = self.key_mgr.list_keys()
        assert "temp_key" in keys['rsa_pairs']
        
        # Delete
        self.key_mgr.delete_key("temp_key", "rsa")
        
        # Verify it's gone
        keys = self.key_mgr.list_keys()
        assert "temp_key" not in keys['rsa_pairs']
        
        # Try to load - should fail
        with pytest.raises(FileNotFoundError):
            self.key_mgr.load_rsa_keypair("temp_key")


if __name__ == '__main__':
    pytest.main([__file__, "-v"])