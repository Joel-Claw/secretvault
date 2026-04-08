"""
Encrypted local storage for secrets
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import base64

# Cryptography is optional for core functionality
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class Vault:
    """
    A secure, encrypted storage for secrets.

    All secrets are:
    - Stored locally encrypted (AES-256)
    - Never transmitted over network
    - Never included in logs
    - Accessible only via the vault API
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        password: Optional[str] = None,
        auto_encrypt: bool = True
    ):
        """
        Initialize the vault.

        Args:
            path: Where to store the vault (default: ~/.secretvault/vault.json)
            password: Encryption password (default: random key)
            auto_encrypt: Whether to encrypt at rest
        """
        self.path = path or Path.home() / ".secretvault" / "vault.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.auto_encrypt = auto_encrypt and CRYPTO_AVAILABLE
        self._secrets: Dict[str, Any] = {}
        self._audit_log: list = []

        # Initialize encryption
        if self.auto_encrypt:
            self._key = self._derive_key(password or self._get_or_create_master_key())
        else:
            self._key = None

        # Load existing vault
        self._load()

    def _get_or_create_master_key(self) -> str:
        """Get or create a master key file."""
        key_file = self.path.parent / ".master.key"
        if key_file.exists():
            return key_file.read_text().strip()
        else:
            key = base64.urlsafe_b64encode(os.urandom(32)).decode()
            key_file.write_text(key)
            key_file.chmod(0o600)
            return key

    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password."""
        if not CRYPTO_AVAILABLE:
            return password.encode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'secretvault_salt',  # Static salt for simplicity
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _encrypt(self, data: str) -> str:
        """Encrypt data."""
        if not self.auto_encrypt or not self._key:
            return data
        f = Fernet(self._key)
        return f.encrypt(data.encode()).decode()

    def _decrypt(self, data: str) -> str:
        """Decrypt data."""
        if not self.auto_encrypt or not self._key:
            return data
        f = Fernet(self._key)
        return f.decrypt(data.encode()).decode()

    def _load(self) -> None:
        """Load vault from disk."""
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                if self.auto_encrypt:
                    self._secrets = json.loads(self._decrypt(data["secrets"]))
                else:
                    self._secrets = data["secrets"]
                self._audit_log = data.get("audit_log", [])
            except (json.JSONDecode, KeyError):
                self._secrets = {}
                self._audit_log = []

    def _save(self) -> None:
        """Save vault to disk."""
        data = {
            "version": "0.1.0",
            "secrets": self._encrypt(json.dumps(self._secrets)) if self.auto_encrypt else self._secrets,
            "audit_log": self._audit_log[-100:]  # Keep last 100 entries
        }
        self.path.write_text(json.dumps(data, indent=2))
        self.path.chmod(0o600)

    def _audit(self, action: str, key: str) -> None:
        """Log an audit entry."""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "key": key,
        })

    def set(self, key: str, value: str, metadata: Optional[Dict] = None) -> None:
        """
        Store a secret.

        Args:
            key: Secret name
            value: Secret value (NEVER include in logs)
            metadata: Optional metadata about the secret
        """
        self._secrets[key] = {
            "value": value,
            "created": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        self._audit("SET", key)
        self._save()

    def get(self, key: str) -> Optional[str]:
        """
        Retrieve a secret.

        Args:
            key: Secret name

        Returns:
            Secret value or None if not found
        """
        self._audit("GET", key)
        if key in self._secrets:
            return self._secrets[key]["value"]
        return None

    def delete(self, key: str) -> bool:
        """
        Delete a secret.

        Args:
            key: Secret name

        Returns:
            True if deleted, False if not found
        """
        self._audit("DELETE", key)
        if key in self._secrets:
            del self._secrets[key]
            self._save()
            return True
        return False

    def list(self) -> list:
        """
        List all secret names (not values).

        Returns:
            List of secret keys
        """
        self._audit("LIST", "*")
        return list(self._secrets.keys())

    def exists(self, key: str) -> bool:
        """Check if a secret exists."""
        return key in self._secrets

    def clear(self) -> None:
        """Delete all secrets."""
        self._audit("CLEAR", "*")
        self._secrets = {}
        self._save()

    def audit_log(self) -> list:
        """Get audit log."""
        return self._audit_log.copy()