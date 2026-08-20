"""Command-line interface for safe canary deployment and monitoring."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import tempfile
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType
from typing import TextIO, TypeAlias

from . import __version__
from .canary import CanaryStore
from .config import (
    MonitorConfig,
    canary_count,
    non_negative_float,
    positive_float,
    require_unprivileged_user,
    resolve_watch_directory,
)
from .detector import CanaryDetector
from .errors import ConfigurationError, RansomWatchError
from .models import FileEvent, IntegrityState
from .reporting import ConsoleReporter
from .service import monitor

SignalHandler: TypeAlias = (
    signal.Handlers | int | Callable[[int, FrameType | None], object] | None
)


class SafeArgumentParser(argparse.ArgumentParser):
    """Convert custom type failures into standard argparse errors."""

    def _get_value(self, action: argparse.Action, arg_string: str) -> object:
        try:
            return super()._get_value(action, arg_string)
        except ConfigurationError as exc:
            raise argparse.ArgumentError(action, str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="ransomwatch",
        description=(
            "Defensive canary integrity monitoring for an explicitly selected local directory."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    deploy = subparsers.add_parser("deploy", help="create or verify deterministic canaries")
    _add_directory_arguments(deploy)

    status = subparsers.add_parser("status", help="check canary integrity without monitoring")
    _add_directory_arguments(status)
    status.add_argument(
        "--format",
        choices=("text", "jsonl"),
        default="text",
        help="status output format (default: text)",
    )

    watch = subparsers.add_parser("watch", help="deploy canaries and monitor integrity")
    _add_directory_arguments(watch)
    watch.add_argument(
        "--cooldown",
        type=non_negative_float,
        default=10.0,
        help="duplicate-alert cooldown in seconds (default: 10)",
    )
    watch.add_argument(
        "--audit-interval",
        type=positive_float,
        default=2.0,
        help="periodic integrity interval in seconds (default: 2)",
    )
    watch.add_argument(
        "--format",
        choices=("text", "jsonl"),
        default="text",
        help="alert output format (default: text)",
    )

    self_test = subparsers.add_parser(
        "self-test",
        help="run an isolated temporary-directory detection demonstration",
    )
    self_test.add_argument(
        "--format",
        choices=("text", "jsonl"),
        default="text",
        help="demonstration output format (default: text)",
    )
    return parser


def _add_directory_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--watch-dir",
        required=True,
        help="existing private directory dedicated to RansomWatch canaries",
    )
    parser.add_argument(
        "--count",
        type=canary_count,
        default=3,
        help="number of deterministic canaries, 1-32 (default: 3)",
    )


def _config_from_args(args: argparse.Namespace) -> MonitorConfig:
    return MonitorConfig(
        watch_dir=resolve_watch_directory(args.watch_dir),
        count=args.count,
        cooldown=getattr(args, "cooldown", 10.0),
        audit_interval=getattr(args, "audit_interval", 2.0),
    )


def _deploy(config: MonitorConfig, stdout: TextIO) -> int:
    require_unprivileged_user()
    with CanaryStore(config.watch_dir, config.count) as store:
        checks = store.deploy()
    for check in checks:
        stdout.write(f"OK {check.path.name}: {check.detail}\n")
    stdout.flush()
    return 0


def _status(config: MonitorConfig, output_format: str, stdout: TextIO) -> int:
    with CanaryStore(config.watch_dir, config.count) as store:
        checks = store.check_all()
    all_healthy = True
    for check in checks:
        all_healthy &= check.state is IntegrityState.HEALTHY
        if output_format == "jsonl":
            import json

            stdout.write(
                json.dumps(
                    {
                        "canary": check.path.name,
                        "detail": check.detail,
                        "state": check.state.value,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        else:
            stdout.write(f"{check.state.value.upper()} {check.path.name}: {check.detail}\n")
    stdout.flush()
    return 0 if all_healthy else 1


def _watch(config: MonitorConfig, output_format: str, stdout: TextIO) -> int:
    require_unprivileged_user()
    stop_event = threading.Event()
    previous_handlers: dict[signal.Signals, SignalHandler] = {}

    def request_stop(_signum: int, _frame: FrameType | None) -> None:
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)

    try:
        with CanaryStore(config.watch_dir, config.count) as store:
            store.deploy()
            detector = CanaryDetector(store, cooldown=config.cooldown)
            reporter = ConsoleReporter(stdout, output_format)
            monitor(
                watch_dir=config.watch_dir,
                detector=detector,
                reporter=reporter,
                audit_interval=config.audit_interval,
                stop_event=stop_event,
            )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return 0


def _self_test(output_format: str, stdout: TextIO) -> int:
    """Exercise the real detector only inside a new private temporary directory."""

    with tempfile.TemporaryDirectory(prefix="ransomwatch-self-test-") as raw_dir:
        path = Path(raw_dir).resolve()
        os.chmod(path, 0o700)
        with CanaryStore(path, 1) as store:
            store.deploy()
            canary = store.paths[0]
            canary.write_text("SAFE SELF-TEST MODIFICATION\n", encoding="utf-8")
            os.chmod(canary, 0o600)
            detector = CanaryDetector(store, cooldown=0)
            alerts = detector.handle(FileEvent("modified", canary))
            if len(alerts) != 1:
                raise RansomWatchError("self-test did not produce exactly one alert")
            ConsoleReporter(stdout, output_format).write(alerts[0])
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "self-test":
            return _self_test(args.format, stdout)
        config = _config_from_args(args)
        if args.command == "deploy":
            return _deploy(config, stdout)
        if args.command == "status":
            return _status(config, args.format, stdout)
        if args.command == "watch":
            return _watch(config, args.format, stdout)
        raise ConfigurationError(f"unsupported command: {args.command}")
    except RansomWatchError as exc:
        stderr.write(f"error: {exc}\n")
        stderr.flush()
        return 2 if isinstance(exc, ConfigurationError) else 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
