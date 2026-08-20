# Contributing

Thank you for helping improve RansomWatch.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the complete local quality gate before opening a pull request:

```bash
ruff check .
mypy
pytest
python -m build
```

## Change expectations

- Keep deployment and tests confined to caller-owned temporary or laboratory directories.
- Preserve the non-destructive default: do not kill processes, delete user data, quarantine files,
  change firewall rules, or claim prevention without evidence.
- Add regression tests for every behavior change and failure path.
- Do not add real malware, encrypted victim data, secrets, personal data, or production telemetry.
- Keep events and reports deterministic enough for offline testing.

## Pull requests

Use a focused branch and explain the security assumptions, user-visible behavior, and validation
commands. Report security-sensitive defects through the process in `SECURITY.md` rather than a
public issue.
