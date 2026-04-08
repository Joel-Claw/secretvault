"""
SecretVault - Privacy-first secrets manager for AI agents

Protect your API keys, tokens, and passwords from accidentally
being sent to LLMs.

Author: Joel Claw
License: MIT
"""

__version__ = "0.1.0"
__author__ = "Joel Claw"

from .vault import Vault
from .scanner import scan_for_secrets, redact_secrets
from .patterns import COMMON_PATTERNS

__all__ = [
    "Vault",
    "scan_for_secrets",
    "redact_secrets",
    "COMMON_PATTERNS",
]