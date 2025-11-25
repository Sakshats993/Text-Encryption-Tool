"""
Key management utilities for secure key storage and retrieval.
For production, integrate with KMS services.
"""

import os
import json
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


class KeyManager:
    """Manages cryptographic keys with secure storage practices"""
    
    def __init__(self, key_dir: str = "keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        self._ensure_secure_permissions()
    
    def _ensure_secure_permissions(self):
        """Set restrictive permissions on key directory (Unix-like systems)"""
        if os.name != 'nt':  # Not Windows
            os.chmod(self.key_dir, 0o700)
    
    def save_rsa_keypair(self, name: str, private_key: bytes, public_key: bytes,
                         passphrase: Optional[bytes] = None):
        """Save RSA key pair to files with optional encryption"""
        private_path = self.key_dir / f"{name}_private.pem"
        public_path = self.key_dir / f"{name}_public.pem"
        
        # Save private key with restricted permissions
        with open(private_path, 'wb') as f:
            f.write(private_key)
        if os.name != 'nt':
            os.chmod(private_path, 0o600)
        
        # Save public key
        with open(public_path, 'wb') as f:
            f.write(public_key)
        
        return str(private_path), str(public_path)
    
    def load_rsa_keypair(self, name: str) -> Tuple[bytes, bytes]:
        """Load RSA key pair from files"""
        private_path = self.key_dir / f"{name}_private.pem"
        public_path = self.key_dir / f"{name}_public.pem"
        
        if not private_path.exists() or not public_path.exists():
            raise FileNotFoundError(f"Key pair '{name}' not found")
        
        with open(private_path, 'rb') as f:
            private_key = f.read()
        
        with open(public_path, 'rb') as f:
            public_key = f.read()
        
        return private_key, public_key
    
    def save_symmetric_key(self, name: str, key: bytes, metadata: dict = None):
        """Save symmetric key with metadata"""
        key_path = self.key_dir / f"{name}_key.json"
        
        key_data = {
            "key": base64.b64encode(key).decode('utf-8'),
            "metadata": metadata or {}
        }
        
        with open(key_path, 'w') as f:
            json.dump(key_data, f)
        
        if os.name != 'nt':
            os.chmod(key_path, 0o600)
    
    def load_symmetric_key(self, name: str) -> Tuple[bytes, dict]:
        """Load symmetric key and metadata"""
        import base64
        key_path = self.key_dir / f"{name}_key.json"
        
        if not key_path.exists():
            raise FileNotFoundError(f"Key '{name}' not found")
        
        with open(key_path, 'r') as f:
            key_data = json.load(f)
        
        key = base64.b64decode(key_data['key'])
        metadata = key_data.get('metadata', {})
        
        return key, metadata
    
    def list_keys(self) -> dict:
        """List all available keys"""
        keys = {
            "rsa_pairs": [],
            "symmetric_keys": []
        }
        
        for file in self.key_dir.glob("*_private.pem"):
            name = file.stem.replace("_private", "")
            keys["rsa_pairs"].append(name)
        
        for file in self.key_dir.glob("*_key.json"):
            name = file.stem.replace("_key", "")
            keys["symmetric_keys"].append(name)
        
        return keys
    
    def delete_key(self, name: str, key_type: str = "all"):
        """Securely delete keys"""
        files_to_delete = []
        
        if key_type in ["rsa", "all"]:
            files_to_delete.extend([
                self.key_dir / f"{name}_private.pem",
                self.key_dir / f"{name}_public.pem"
            ])
        
        if key_type in ["symmetric", "all"]:
            files_to_delete.append(self.key_dir / f"{name}_key.json")
        
        for file_path in files_to_delete:
            if file_path.exists():
                # Overwrite with random data before deletion
                with open(file_path, 'rb') as f:
                    size = len(f.read())
                
                with open(file_path, 'wb') as f:
                    f.write(os.urandom(size))
                
                file_path.unlink()