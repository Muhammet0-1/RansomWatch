from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from ransomwatch.canary import CanaryStore
from ransomwatch.detector import CanaryDetector
from ransomwatch.models import FileEvent


class Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


def test_healthy_and_unrelated_events_do_not_alert(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        detector = CanaryDetector(store, cooldown=10)
        assert detector.handle(FileEvent("modified", store.paths[0])) == ()
        assert detector.handle(FileEvent("modified", private_dir / "unrelated")) == ()
        assert detector.handle(FileEvent("modified", store.paths[0], is_directory=True)) == ()


def test_modified_deleted_and_moved_events_alert(private_dir: Path) -> None:
    with CanaryStore(private_dir, 3) as store:
        store.deploy()
        store.paths[0].write_text("changed", encoding="utf-8")
        store.paths[1].unlink()
        moved = private_dir / "moved-away"
        store.paths[2].rename(moved)
        detector = CanaryDetector(store, cooldown=0)
        assert detector.handle(FileEvent("modified", store.paths[0]))[0].state == "modified"
        assert detector.handle(FileEvent("deleted", store.paths[1]))[0].state == "missing"
        assert detector.handle(FileEvent("moved", store.paths[2], moved))[0].state == "missing"


def test_move_onto_canary_path_is_inspected(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        replacement = private_dir / "replacement"
        replacement.write_text("replacement", encoding="utf-8")
        os.chmod(replacement, 0o600)
        os.replace(replacement, store.paths[0])
        detector = CanaryDetector(store, cooldown=0)
        alerts = detector.handle(
            FileEvent("moved", private_dir / "replacement", store.paths[0])
        )
        assert len(alerts) == 1
        assert alerts[0].state == "modified"


def test_cooldown_uses_monotonic_time(private_dir: Path) -> None:
    clock = Clock()
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        store.paths[0].unlink()
        detector = CanaryDetector(store, cooldown=10, monotonic=clock)
        event = FileEvent("deleted", store.paths[0])
        assert len(detector.handle(event)) == 1
        clock.value = 109.999
        assert detector.handle(event) == ()
        clock.value = 110.0
        assert len(detector.handle(event)) == 1


def test_periodic_audit_reports_missed_event(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        store.paths[0].unlink()
        detector = CanaryDetector(store, cooldown=0)
        alerts = detector.audit()
        assert len(alerts) == 1
        assert alerts[0].event_type == "periodic_audit"


def test_alert_uses_wall_clock_but_does_not_expose_monotonic_value(private_dir: Path) -> None:
    observed = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        store.paths[0].unlink()
        detector = CanaryDetector(
            store,
            cooldown=0,
            monotonic=lambda: 987654.0,
            wall_clock=lambda: observed,
        )
        data = detector.audit()[0].to_dict()
        assert data["observed_at"] == "2026-08-20T12:00:00+00:00"
        assert "monotonic" not in data
