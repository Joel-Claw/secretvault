# Contributing to SecretVault

Thank you for your interest in contributing! 🎉

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

## License

By contributing, you agree that your contributions will be licensed under the MIT License.