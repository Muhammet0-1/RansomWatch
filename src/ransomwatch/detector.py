"""Canary integrity event correlation and bounded alert deduplication."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from datetime import datetime

from .canary import CanaryStore
from .models import Alert, CanaryCheck, FileEvent, IntegrityState


class CanaryDetector:
    """Turn exact canary integrity failures into structured alerts."""

    def __init__(
        self,
        store: CanaryStore,
        *,
        cooldown: float,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._cooldown = cooldown
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._last_alert: dict[tuple[str, str], float] = {}

    def handle(self, event: FileEvent) -> tuple[Alert, ...]:
        """Inspect one normalized event and return at most one alert per canary."""

        if event.is_directory:
            return ()
        names: list[str] = []
        for path in (event.src_path, event.dest_path):
            if path is None:
                continue
            name = self._store.name_for_event_path(path)
            if name is not None and name not in names:
                names.append(name)
        alerts: list[Alert] = []
        for name in names:
            check = self._store.check(name)
            if check.state is IntegrityState.HEALTHY:
                continue
            alert = self._build_alert(event.event_type, check)
            if alert is not None:
                alerts.append(alert)
        return tuple(alerts)

    def audit(self) -> tuple[Alert, ...]:
        """Detect integrity loss even if an observer event was missed."""

        return tuple(
            alert
            for check in self._store.check_all()
            if check.state is not IntegrityState.HEALTHY
            for alert in self._optional_alert("periodic_audit", check)
        )

    def _optional_alert(self, event_type: str, check: CanaryCheck) -> Iterable[Alert]:
        alert = self._build_alert(event_type, check)
        return () if alert is None else (alert,)

    def _build_alert(self, event_type: str, check: CanaryCheck) -> Alert | None:
        now = self._monotonic()
        key = (check.path.name, check.state.value)
        previous = self._last_alert.get(key)
        if previous is not None and now - previous < self._cooldown:
            return None
        self._last_alert[key] = now
        return Alert.create(
            event_type=event_type,
            check=check,
            now=self._wall_clock() if self._wall_clock is not None else None,
        )
