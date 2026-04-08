# SecretVault Development

## Branch Structure
- `main` - Stable releases only
- `dev` - Development for next version

## Version History
- v0.1.0 (2026-04-08) - Initial release

## Workflow for Future Versions
1. Work on `dev` branch for new features
2. Spread development over weeks to conserve tokens
3. When ready, merge to `main` and create release
4. Update version in pyproject.toml

## Notes
- Never use real secrets in code/examples
- All examples use FAKE values
- Run tests before each commit
- Keep CI green