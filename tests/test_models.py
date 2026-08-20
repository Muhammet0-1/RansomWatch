from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ransomwatch.models import Alert, CanaryCheck, IntegrityState


def test_naive_alert_timestamp_is_normalized_to_utc() -> None:
    alert = Alert.create(
        event_type="deleted",
        check=CanaryCheck(Path("canary"), IntegrityState.MISSING, "missing"),
        now=datetime(2026, 8, 20, 12, 0),
    )
    assert alert.observed_at == "2026-08-20T12:00:00+00:00"


def test_alert_dictionary_contains_no_filesystem_parent() -> None:
    alert = Alert.create(
        event_type="deleted",
        check=CanaryCheck(
            Path("/private/operator/lab/.ransomwatch-canary-01.txt"),
            IntegrityState.MISSING,
            "missing",
        ),
    )
    data = alert.to_dict()
    assert data["canary"] == ".ransomwatch-canary-01.txt"
    assert "/private/operator" not in str(data)
