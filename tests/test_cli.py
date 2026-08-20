from __future__ import annotations

import io
import json
from pathlib import Path

from ransomwatch.cli import build_parser, main


def test_parser_defaults() -> None:
    args = build_parser().parse_args(["watch", "--watch-dir", "/private/lab"])
    assert args.count == 3
    assert args.cooldown == 10.0
    assert args.audit_interval == 2.0
    assert args.format == "text"


def test_self_test_text_and_jsonl() -> None:
    text_output = io.StringIO()
    assert main(["self-test"], stdout=text_output) == 0
    assert "HIGH" in text_output.getvalue()

    json_output = io.StringIO()
    assert main(["self-test", "--format", "jsonl"], stdout=json_output) == 0
    data = json.loads(json_output.getvalue())
    assert data["state"] == "modified"
    assert data["event_type"] == "modified"


def test_status_reports_missing_canaries(private_dir: Path) -> None:
    output = io.StringIO()
    error = io.StringIO()
    result = main(
        ["status", "--watch-dir", str(private_dir), "--count", "2"],
        stdout=output,
        stderr=error,
    )
    assert result == 1
    assert output.getvalue().count("MISSING") == 2
    assert error.getvalue() == ""


def test_status_jsonl_is_machine_readable(private_dir: Path) -> None:
    output = io.StringIO()
    result = main(
        ["status", "--watch-dir", str(private_dir), "--count", "1", "--format", "jsonl"],
        stdout=output,
    )
    assert result == 1
    assert json.loads(output.getvalue())["state"] == "missing"


def test_invalid_directory_has_exit_code_two(tmp_path: Path) -> None:
    error = io.StringIO()
    result = main(
        ["status", "--watch-dir", str(tmp_path / "missing")],
        stdout=io.StringIO(),
        stderr=error,
    )
    assert result == 2
    assert "error:" in error.getvalue()


def test_help_identifies_defensive_scope() -> None:
    assert "Defensive canary" in build_parser().description
