"""Fail-loud console reporting with stable text and JSONL formats."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TextIO

from .errors import ReportingError
from .models import Alert


@dataclass(slots=True)
class ConsoleReporter:
    """Write alerts to a caller-provided stream and flush immediately."""

    stream: TextIO
    output_format: str = "text"

    def write(self, alert: Alert) -> None:
        try:
            if self.output_format == "jsonl":
                line = json.dumps(alert.to_dict(), sort_keys=True, ensure_ascii=False)
            else:
                line = (
                    f"[{alert.observed_at}] {alert.severity.upper()} "
                    f"{alert.canary}: {alert.state} ({alert.event_type}) - {alert.detail}"
                )
            self.stream.write(f"{line}\n")
            self.stream.flush()
        except (OSError, ValueError) as exc:
            raise ReportingError(f"could not write alert: {exc}") from exc
