# Changelog

All notable changes to this project are documented here.

## [0.2.0] - 2026-08-20

### Added

- Installable `src/` package and documented command-line interface.
- Descriptor-anchored canary creation and integrity verification.
- Exact event-path matching, periodic audits, and bounded alert cooldowns.
- Text and JSONL console reporting with a stable schema.
- Isolated `self-test` command that only touches a temporary directory.
- Automated tests, Ruff, strict mypy, package builds, and CI for Python 3.10-3.13.
- Security policy, contribution guide, MIT license, and packaging metadata.

### Changed

- Monitoring now requires an explicit, private directory instead of using the home directory.
- Detection is described as an evidence signal, not guaranteed ransomware prevention.
- `sentinel.py` is retained only as a compatibility entry point.

### Removed

- Process enumeration, simulated process termination, and abrupt `os._exit()` shutdown.
- Substring-based canary matching and broad home-directory monitoring defaults.

## [0.1.0]

- Initial behavioral canary proof of concept.
