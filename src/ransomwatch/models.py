"""Immutable data models shared by the detector and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class IntegrityState(str, Enum):
    """Observed integrity state of a managed canary."""

    HEALTHY = "healthy"
    MISSING = "missing"
    MODIFIED = "modified"
    UNSAFE = "unsafe"


@dataclass(frozen=True, slots=True)
class CanaryCheck:
    """Result of checking one expected canary file."""

    path: Path
    state: IntegrityState
    detail: str


@dataclass(frozen=True, slots=True)
class FileEvent:
    """Normalized filesystem event used without depending on Watchdog types."""

    event_type: str
    src_path: Path
    dest_path: Path | None = None
    is_directory: bool = False


@dataclass(frozen=True, slots=True)
class Alert:
    """Serializable evidence that a managed canary lost integrity."""

    event_type: str
    canary: str
    state: str
    detail: str
    observed_at: str
    severity: str = "high"
    detector: str = "canary_integrity"
    schema_version: int = 1

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        check: CanaryCheck,
        now: datetime | None = None,
    ) -> Alert:
        """Build an alert with a timezone-aware UTC timestamp."""

        observed = now or datetime.now(timezone.utc)
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        return cls(
            event_type=event_type,
            canary=check.path.name,
            state=check.state.value,
            detail=check.detail,
            observed_at=observed.astimezone(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-compatible representation."""

        return asdict(self)
