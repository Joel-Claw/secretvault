# SecretVault

🔒 Privacy-first secrets manager for AI agents

**Protect your API keys, tokens, and passwords from accidentally being sent to LLMs.**

## What it does

- **Scans** prompts, files, and inputs for secrets
- **Redacts** sensitive data before it reaches any AI
- **Stores** secrets locally encrypted (AES-256)
- **Injects** secrets securely when needed (never logged)
- **Audits** all secret access

## Why you need it

AI agents and assistants regularly see sensitive data they shouldn't:
- API keys pasted accidentally
- Passwords in config files
- Private keys and tokens
- Personal identifiable information (PII)

SecretVault prevents this from happening.

## Installation

```bash
pip install secretvault
```

## Quick Start

```python
from secretvault import Vault

# Create a vault (encrypted, local only)
vault = Vault()

# Store a secret (never sent to LLMs)
vault.set("api_key", "sk-example-not-real-key-12345")

# Scan a prompt for secrets
prompt = "My API key is sk-example-not-real-key-12345"
safe_prompt = vault.scan(prompt)
# Result: "My API key is [REDACTED:api_key]"

# Retrieve a secret when needed
key = vault.get("api_key")  # Returns the actual key
```

## Features

- ✅ Local-only storage (no cloud, no external services)
- ✅ AES-256 encryption at rest
- ✅ Pattern matching for common secret formats
- ✅ Custom secret patterns
- ✅ Zero external dependencies for core functionality
- ✅ Works with any AI agent or assistant
- ✅ Audit logging
- ✅ Self-destruct mode for sensitive sessions

## Security

- **No network calls** - Everything stays on your machine
- **No telemetry** - We don't track anything
- **No secrets in logs** - Ever
- **Open source** - Fully auditable

## License

MIT License - Use freely, modify freely.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## Disclaimer

**Never use real secrets as examples.** All examples in this project use fake/example values.

---

Built with ❤️ by [Joel Claw](https://github.com/Joel-Claw)