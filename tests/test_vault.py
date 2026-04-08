"""
Tests for SecretVault
"""

import tempfile
from pathlib import Path

import pytest

from secretvault import Vault, redact_secrets, scan_for_secrets


class TestVault:
    """Test Vault class."""

    def test_set_and_get(self):
        """Test storing and retrieving secrets."""
        vault = Vault(path=Path(tempfile.mkdtemp()) / "test_vault.json")
        vault.set("test_key", "test_value_12345")
        assert vault.get("test_key") == "test_value_12345"

    def test_delete(self):
        """Test deleting secrets."""
        vault = Vault(path=Path(tempfile.mkdtemp()) / "test_vault.json")
        vault.set("test_key", "test_value")
        assert vault.delete("test_key") is True
        assert vault.get("test_key") is None

    def test_list(self):
        """Test listing secret names."""
        vault = Vault(path=Path(tempfile.mkdtemp()) / "test_vault.json")
        vault.set("key1", "value1")
        vault.set("key2", "value2")
        names = vault.list()
        assert "key1" in names
        assert "key2" in names
        assert len(names) == 2

    def test_exists(self):
        """Test checking if secret exists."""
        vault = Vault(path=Path(tempfile.mkdtemp()) / "test_vault.json")
        vault.set("exists_key", "value")
        assert vault.exists("exists_key") is True
        assert vault.exists("nonexistent") is False


class TestScanner:
    """Test secret scanning."""

    def test_scan_api_key(self):
        """Test detecting API keys."""
        # FAKE key - will never work
        text = "My API key is sk-fake12345678901234567890"
        results = scan_for_secrets(text)
        assert len(results) > 0
        assert results[0][0] == "openai_api_key"

    def test_scan_github_token(self):
        """Test detecting GitHub tokens."""
        # FAKE token - will never work
        # Using a realistic format: ghp_ followed by alphanumeric
        text = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
        results = scan_for_secrets(text)
        assert len(results) > 0
        # Check that github pattern is among the results
        pattern_names = [r[0] for r in results]
        assert any("github" in name for name in pattern_names)

    def test_redact_secrets(self):
        """Test redacting secrets from text."""
        # FAKE keys - will never work
        text = "api_key: sk-fake12345678901234567890"
        redacted = redact_secrets(text)
        assert "sk-fake" not in redacted
        assert "[REDACTED:" in redacted

    def test_scan_email(self):
        """Test detecting email addresses."""
        text = "Contact: test@example.com"
        results = scan_for_secrets(text, include_pii=True)
        assert len(results) > 0
        assert results[0][0] == "email"

    def test_skip_pii(self):
        """Test skipping PII detection."""
        text = "Contact: test@example.com"
        results = scan_for_secrets(text, include_pii=False)
        # Email should not be detected when PII is skipped
        email_results = [r for r in results if r[0] == "email"]
        assert len(email_results) == 0

    def test_known_secrets_redaction(self):
        """Test redacting known secrets by value."""
        text = "Use the key MY_SECRET_KEY_12345 for authentication"
        redacted = redact_secrets(text, known_secrets={"my_key": "MY_SECRET_KEY_12345"})
        assert "MY_SECRET_KEY_12345" not in redacted
        assert "[REDACTED:my_key]" in redacted
