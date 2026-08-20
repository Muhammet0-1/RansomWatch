"""Backward-compatible entry point for the RansomWatch CLI."""

from ransomwatch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
