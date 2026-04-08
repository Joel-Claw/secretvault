"""
Secret scanning and redaction
"""

import re
from typing import Dict, List, Tuple, Optional
from .patterns import COMMON_PATTERNS


def scan_for_secrets(
    text: str,
    patterns: Optional[Dict[str, re.Pattern]] = None,
    include_pii: bool = True
) -> List[Tuple[str, str, int, int]]:
    """
    Scan text for potential secrets.

    Args:
        text: Text to scan
        patterns: Custom patterns (default: COMMON_PATTERNS)
        include_pii: Whether to include PII patterns like email, phone

    Returns:
        List of (pattern_name, matched_value, start_pos, end_pos)
    """
    patterns = patterns or COMMON_PATTERNS
    results = []

    for name, pattern in patterns.items():
        # Skip PII patterns if not included
        if not include_pii and name in ('email', 'phone', 'credit_card'):
            continue

        for match in pattern.finditer(text):
            results.append((name, match.group(), match.start(), match.end()))

    return results


def redact_secrets(
    text: str,
    patterns: Optional[Dict[str, re.Pattern]] = None,
    replacement: str = "[REDACTED:{name}]",
    include_pii: bool = True,
    known_secrets: Optional[Dict[str, str]] = None
) -> str:
    """
    Redact secrets from text.

    Args:
        text: Text to process
        patterns: Custom patterns (default: COMMON_PATTERNS)
        replacement: Replacement template (use {name} for pattern name)
        include_pii: Whether to include PII patterns
        known_secrets: Dict of {name: value} to redact by name

    Returns:
        Text with secrets redacted
    """
    patterns = patterns or COMMON_PATTERNS
    known_secrets = known_secrets or {}

    # First, redact known secrets by value
    for name, value in known_secrets.items():
        if value and len(value) > 3:  # Skip very short values
            text = text.replace(value, replacement.format(name=name))

    # Then, redact by pattern matching
    for name, pattern in patterns.items():
        if not include_pii and name in ('email', 'phone', 'credit_card'):
            continue

        def replacer(m):
            return replacement.format(name=name)
        text = pattern.sub(replacer, text)

    return text


def scan_file(
    file_path: str,
    patterns: Optional[Dict[str, re.Pattern]] = None,
    include_pii: bool = True
) -> List[Tuple[str, str, int, int]]:
    """
    Scan a file for secrets.

    Args:
        file_path: Path to file
        patterns: Custom patterns
        include_pii: Whether to include PII patterns

    Returns:
        List of (pattern_name, matched_value, line_number, column)
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    results = []
    for line_num, line in enumerate(lines, 1):
        matches = scan_for_secrets(line, patterns, include_pii)
        for name, value, start, end in matches:
            results.append((name, value, line_num, start))

    return results


def redact_file(
    input_path: str,
    output_path: str,
    patterns: Optional[Dict[str, re.Pattern]] = None,
    include_pii: bool = True
) -> int:
    """
    Redact secrets from a file.

    Args:
        input_path: Input file path
        output_path: Output file path
        patterns: Custom patterns
        include_pii: Whether to include PII patterns

    Returns:
        Number of secrets redacted
    """
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    redacted = redact_secrets(content, patterns, include_pii=include_pii)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(redacted)

    # Count redactions
    return content.count('[REDACTED:')


def is_safe_to_share(text: str, patterns: Optional[Dict[str, re.Pattern]] = None) -> bool:
    """
    Check if text is safe to share (no detected secrets).

    Args:
        text: Text to check
        patterns: Custom patterns

    Returns:
        True if no secrets detected, False otherwise
    """
    secrets = scan_for_secrets(text, patterns)
    return len(secrets) == 0