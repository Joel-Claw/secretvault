"""
Command-line interface for SecretVault

Quick scanning of files for potential secrets.
"""

import argparse
import sys
from pathlib import Path

from .scanner import scan_file, scan_for_secrets


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Scan files or text for potential secrets")
    parser.add_argument("path", nargs="?", help="File or directory to scan")
    parser.add_argument("--text", "-t", help="Scan text from command line")
    parser.add_argument("--no-pii", action="store_true", help="Skip PII detection (email, phone)")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    include_pii = not args.no_pii

    if args.text:
        # Scan text from command line
        results = scan_for_secrets(args.text, include_pii=include_pii)
        if results:
            print(f"Found {len(results)} potential secrets:")
            for name, value, start, end in results:
                print(f"  [{name}] {value[:20]}{'...' if len(value) > 20 else ''} (pos {start})")
            sys.exit(1)
        else:
            print("No secrets detected")
            sys.exit(0)

    elif args.path:
        path = Path(args.path)
        if path.is_file():
            # Scan single file
            results = scan_file(str(path), include_pii=include_pii)
            if results:
                print(f"Found {len(results)} potential secrets in {path}:")
                for name, value, line, col in results:
                    print(f"  [{name}] {value[:30]}... (line {line}, col {col})")
                sys.exit(1)
            else:
                print(f"No secrets detected in {path}")
                sys.exit(0)
        elif path.is_dir():
            # Scan directory
            all_results = []
            for file_path in path.rglob("*"):
                if file_path.is_file() and not any(
                    p in str(file_path)
                    for p in [".git", "__pycache__", "node_modules", "venv", ".venv"]
                ):
                    try:
                        results = scan_file(str(file_path), include_pii=include_pii)
                        all_results.extend(
                            (str(file_path), name, value, line, col)
                            for name, value, line, col in results
                        )
                    except Exception:
                        pass  # Skip binary files, etc.

            if all_results:
                print(f"Found {len(all_results)} potential secrets in {path}:")
                for file_path, name, value, line, col in all_results:
                    print(f"  {file_path}: [{name}] (line {line})")
                sys.exit(1)
            else:
                print(f"No secrets detected in {path}")
                sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
