"""Validation helpers and immutable application configuration."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError

MIN_CANARIES = 1
MAX_CANARIES = 32


def positive_float(value: str) -> float:
    """Parse a finite, strictly positive command-line number."""

    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigurationError(f"expected a number, got {value!r}") from exc
    if not 0 < parsed < float("inf"):
        raise ConfigurationError("value must be finite and greater than zero")
    return parsed


def non_negative_float(value: str) -> float:
    """Parse a finite, non-negative command-line number."""

    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigurationError(f"expected a number, got {value!r}") from exc
    if not 0 <= parsed < float("inf"):
        raise ConfigurationError("value must be finite and non-negative")
    return parsed


def canary_count(value: str) -> int:
    """Parse a bounded canary count."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"expected an integer, got {value!r}") from exc
    if not MIN_CANARIES <= parsed <= MAX_CANARIES:
        raise ConfigurationError(
            f"canary count must be between {MIN_CANARIES} and {MAX_CANARIES}"
        )
    return parsed


def resolve_watch_directory(raw_path: str | Path) -> Path:
    """Resolve and validate an existing, privately writable directory."""

    try:
        expanded = Path(raw_path).expanduser()
    except RuntimeError as exc:
        raise ConfigurationError(f"could not expand watch directory: {raw_path}") from exc

    if expanded.is_symlink():
        raise ConfigurationError("watch directory must not be a symbolic link")
    try:
        path = expanded.resolve(strict=True)
        metadata = path.stat()
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError(f"watch directory is unavailable: {expanded}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigurationError(f"watch path is not a directory: {path}")
    if metadata.st_mode & 0o022:
        raise ConfigurationError(
            "watch directory must not be writable by group or other users"
        )
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise ConfigurationError("watch directory must be owned by the effective user")
    if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
        raise ConfigurationError("watch directory is not readable and writable")
    return path


def require_unprivileged_user() -> None:
    """Refuse deployment and monitoring with effective root privileges."""

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise ConfigurationError("do not run RansomWatch as root; use a regular account")


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    """Validated values used by the monitoring service."""

    watch_dir: Path
    count: int = 3
    cooldown: float = 10.0
    audit_interval: float = 2.0

    def __post_init__(self) -> None:
        if not MIN_CANARIES <= self.count <= MAX_CANARIES:
            raise ConfigurationError(
                f"canary count must be between {MIN_CANARIES} and {MAX_CANARIES}"
            )
        if not 0 <= self.cooldown < float("inf"):
            raise ConfigurationError("cooldown must be finite and non-negative")
        if not 0 < self.audit_interval < float("inf"):
            raise ConfigurationError("audit interval must be finite and greater than zero")
