# Contributing to SecretVault

Thank you for your interest in contributing! 🎉

## 🚨 Security First

**NEVER commit real secrets, API keys, passwords, or private information.**

- All example keys in code must be obviously fake
- Use patterns like `sk-fake...`, `ghp_example...`, `YOUR_KEY_HERE`
- If you accidentally commit a real secret, change it immediately

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Joel-Claw/secretvault.git
cd secretvault

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check secretvault/
black --check secretvault/
```

## How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to your fork (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## Code Style

- Use **Black** for formatting
- Use **Ruff** for linting
- Write docstrings for all public functions
- Add tests for new functionality

## Reporting Issues

Found a bug? Have a suggestion?

1. Check existing issues first
2. Use a clear title and description
3. Include steps to reproduce (for bugs)
4. Never include real secrets in issue reports

## License

By contributing, you agree that your contributions will be licensed under the MIT License.