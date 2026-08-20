"""Watchdog adapter and lifecycle-safe monitoring loop."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from .detector import CanaryDetector
from .errors import MonitoringError
from .models import FileEvent
from .reporting import ConsoleReporter


class CallbackBridge:
    """Normalize Watchdog events and preserve callback failures for the main loop."""

    def __init__(
        self,
        detector: CanaryDetector,
        reporter: ConsoleReporter,
        stop_event: threading.Event,
    ) -> None:
        self._detector = detector
        self._reporter = reporter
        self._stop_event = stop_event
        self._failure: Exception | None = None
        self._lock = threading.Lock()

    @property
    def failure(self) -> Exception | None:
        with self._lock:
            return self._failure

    def dispatch(self, event: Any) -> None:
        """Handle one Watchdog-compatible event without losing exceptions."""

        if self.failure is not None:
            return
        try:
            normalized = FileEvent(
                event_type=str(event.event_type),
                src_path=Path(event.src_path),
                dest_path=Path(event.dest_path) if getattr(event, "dest_path", "") else None,
                is_directory=bool(event.is_directory),
            )
            for alert in self._detector.handle(normalized):
                self._reporter.write(alert)
        except Exception as exc:
            with self._lock:
                if self._failure is None:
                    self._failure = exc
            self._stop_event.set()


def monitor(
    *,
    watch_dir: Path,
    detector: CanaryDetector,
    reporter: ConsoleReporter,
    audit_interval: float,
    stop_event: threading.Event,
) -> None:
    """Run a non-recursive observer and periodic integrity audits."""

    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:  # pragma: no cover - installed package dependency
        raise MonitoringError("Watchdog is required for live monitoring") from exc

    bridge = CallbackBridge(detector, reporter, stop_event)

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event: Any) -> None:
            bridge.dispatch(event)

    observer = Observer()
    try:
        observer.schedule(Handler(), str(watch_dir), recursive=False)
        observer.start()
    except Exception as exc:
        observer.stop()
        raise MonitoringError(f"could not start filesystem observer: {exc}") from exc

    next_audit = time.monotonic() + audit_interval
    try:
        while not stop_event.wait(0.1):
            failure = bridge.failure
            if failure is not None:
                raise failure
            now = time.monotonic()
            if now >= next_audit:
                for alert in detector.audit():
                    reporter.write(alert)
                next_audit = now + audit_interval
        failure = bridge.failure
        if failure is not None:
            raise failure
    finally:
        observer.stop()
        observer.join(timeout=5)
        if observer.is_alive():
            raise MonitoringError("filesystem observer did not stop cleanly")
