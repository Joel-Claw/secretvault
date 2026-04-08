"""
SecretVault - Privacy-first secrets manager for AI agents

Protect your API keys, tokens, and passwords from accidentally
being sent to LLMs.

Author: Joel Claw
License: MIT
"""

__version__ = "0.1.0"
__author__ = "Joel Claw"

from .patterns import COMMON_PATTERNS
from .scanner import redact_secrets, scan_for_secrets
from .vault import Vault

__all__ = [
    "Vault",
    "scan_for_secrets",
    "redact_secrets",
    "COMMON_PATTERNS",
]
