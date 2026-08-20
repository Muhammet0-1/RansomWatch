from __future__ import annotations

import io
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ransomwatch.canary import CanaryStore
from ransomwatch.detector import CanaryDetector
from ransomwatch.errors import ReportingError
from ransomwatch.models import Alert, CanaryCheck, IntegrityState
from ransomwatch.reporting import ConsoleReporter
from ransomwatch.service import CallbackBridge


def sample_alert(private_dir: Path) -> Alert:
    return Alert.create(
        event_type="modified",
        check=CanaryCheck(
            private_dir / ".ransomwatch-canary-01.txt",
            IntegrityState.MODIFIED,
            "content differs",
        ),
    )


def test_jsonl_report_is_valid_and_stable(private_dir: Path) -> None:
    stream = io.StringIO()
    ConsoleReporter(stream, "jsonl").write(sample_alert(private_dir))
    data = json.loads(stream.getvalue())
    assert data["schema_version"] == 1
    assert data["canary"] == ".ransomwatch-canary-01.txt"
    assert data["state"] == "modified"


def test_text_report_is_readable(private_dir: Path) -> None:
    stream = io.StringIO()
    ConsoleReporter(stream).write(sample_alert(private_dir))
    output = stream.getvalue()
    assert "HIGH" in output
    assert "modified" in output
    assert ".ransomwatch-canary-01.txt" in output


class BrokenStream(io.StringIO):
    def write(self, _value: str) -> int:
        raise OSError("disk-like failure")


def test_reporting_failure_is_not_silenced(private_dir: Path) -> None:
    with pytest.raises(ReportingError):
        ConsoleReporter(BrokenStream()).write(sample_alert(private_dir))


def test_callback_bridge_preserves_reporting_failure(private_dir: Path) -> None:
    stop_event = threading.Event()
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        store.paths[0].unlink()
        bridge = CallbackBridge(
            CanaryDetector(store, cooldown=0),
            ConsoleReporter(BrokenStream()),
            stop_event,
        )
        event = SimpleNamespace(
            event_type="deleted",
            src_path=str(store.paths[0]),
            dest_path="",
            is_directory=False,
        )
        bridge.dispatch(event)
    assert isinstance(bridge.failure, ReportingError)
    assert stop_event.is_set()


def test_callback_bridge_preserves_event_normalization_failure(private_dir: Path) -> None:
    stop_event = threading.Event()
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        bridge = CallbackBridge(
            CanaryDetector(store, cooldown=0),
            ConsoleReporter(io.StringIO()),
            stop_event,
        )
        bridge.dispatch(SimpleNamespace(event_type="modified", is_directory=False))
    assert isinstance(bridge.failure, AttributeError)
    assert stop_event.is_set()


def test_callback_bridge_ignores_directory_event(private_dir: Path) -> None:
    stop_event = threading.Event()
    output = io.StringIO()
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        bridge = CallbackBridge(
            CanaryDetector(store, cooldown=0),
            ConsoleReporter(output),
            stop_event,
        )
        bridge.dispatch(
            SimpleNamespace(
                event_type="modified",
                src_path=str(private_dir),
                dest_path="",
                is_directory=True,
            )
        )
    assert bridge.failure is None
    assert output.getvalue() == ""
    assert not stop_event.is_set()
