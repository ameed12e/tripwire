# Contributing

Thanks for helping! Tripwire is a defensive tool, so contributions must keep it that way.

## Ground rules

Pull requests that add any of the following will be closed:

- self-propagation, worm-like spreading or lateral movement;
- persistence tricks (hidden services, rootkits, autorun abuse) or hiding from the device owner;
- payloads that execute code on a third party's device (macros, scripts, exploits, NTLM/UNC leaks);
- collection of data beyond what is needed to describe a tripwire event.

## Workflow

1. Fork, create a branch, `pip install -e ".[dev]"`.
2. Keep changes focused; add or update tests (`pytest`).
3. Run `ruff check . && ruff format --check . && mypy && pytest` before pushing.
4. Use clear commit messages; describe *why* in the PR.

## Code style

- Python 3.11+, type hints everywhere (`mypy --strict` must pass).
- English for code, comments and docs.
- Use `structlog` (`tripwire.core.logging.get_logger`), never `print`, outside the CLI.
- New collectors and alert channels should be plugins. See [docs/PLUGINS.md](docs/PLUGINS.md).

## Reporting security issues

Please do **not** open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
