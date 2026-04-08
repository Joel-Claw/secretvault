"""
Pattern definitions for detecting secrets
"""

import re
from typing import Dict, Pattern

# IMPORTANT: All example values are FAKE and will never work
# They are formatted to match real patterns but use invalid values

COMMON_PATTERNS: Dict[str, Pattern] = {
    # OpenAI API keys
    "openai_api_key": re.compile(r'sk-[a-zA-Z0-9]{20,}'),

    # AWS Access Keys (fake examples)
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),

    # GitHub Personal Access Tokens (fake)
    "github_pat": re.compile(r'ghp_[a-zA-Z0-9]{30,}'),
    "github_oauth": re.compile(r'gho_[a-zA-Z0-9]{36}'),
    "github_app": re.compile(r'ghu_[a-zA-Z0-9]{36}'),
    "github_refresh": re.compile(r'ghr_[a-zA-Z0-9]{36}'),

    # Generic API keys (various formats)
    "api_key_generic": re.compile(r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'),

    # Private keys
    "private_key_rsa": re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "private_key_pem": re.compile(r'-----BEGIN PRIVATE KEY-----'),

    # Database connection strings (fake examples)
    "postgres_connection": re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s]+'),

    # Generic secrets in config files
    "secret_key": re.compile(r'(?i)(secret[_-]?key|secret)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
    "password": re.compile(r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?'),

    # Bearer tokens
    "bearer_token": re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]+'),

    # Email addresses (PII)
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),

    # Phone numbers (various formats)
    "phone": re.compile(r'\+?[0-9]{1,3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4,}'),

    # Credit card numbers (for PII detection)
    "credit_card": re.compile(r'\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b'),

    # IP addresses (private networks)
    "private_ip": re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+\b'),

    # JWT tokens
    "jwt_token": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
}

# Patterns that might be in code comments (should ignore in source files)
COMMENT_PATTERNS: Dict[str, Pattern] = {
    "python_comment": re.compile(r'#.*$'),
    "js_comment": re.compile(r'//.*$'),
    "block_comment": re.compile(r'/\*.*?\*/', re.DOTALL),
}


def get_pattern(name: str) -> Pattern:
    """Get a pattern by name."""
    if name not in COMMON_PATTERNS:
        raise ValueError(f"Unknown pattern: {name}")
    return COMMON_PATTERNS[name]


def list_patterns() -> list:
    """List all available pattern names."""
    return list(COMMON_PATTERNS.keys())