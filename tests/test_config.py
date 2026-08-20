from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from ransomwatch.config import (
    MonitorConfig,
    canary_count,
    non_negative_float,
    positive_float,
    resolve_watch_directory,
)
from ransomwatch.errors import ConfigurationError


@pytest.mark.parametrize("value", ["1", "3", "32"])
def test_accepts_bounded_canary_counts(value: str) -> None:
    assert canary_count(value) == int(value)


@pytest.mark.parametrize("value", ["0", "33", "-1", "word", "1.5"])
def test_rejects_invalid_canary_counts(value: str) -> None:
    with pytest.raises(ConfigurationError):
        canary_count(value)


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "0"])
def test_positive_float_rejects_non_positive_or_non_finite(value: str) -> None:
    with pytest.raises(ConfigurationError):
        positive_float(value)


def test_non_negative_float_accepts_zero() -> None:
    assert non_negative_float("0") == 0


@pytest.mark.parametrize("value", ["nan", "inf", "-0.1"])
def test_non_negative_float_rejects_bad_values(value: str) -> None:
    with pytest.raises(ConfigurationError):
        non_negative_float(value)


def test_resolves_private_owned_directory(private_dir: Path) -> None:
    assert resolve_watch_directory(private_dir) == private_dir


def test_rejects_group_writable_directory(tmp_path: Path) -> None:
    path = tmp_path / "shared"
    path.mkdir()
    os.chmod(path, 0o770)
    with pytest.raises(ConfigurationError, match="group or other"):
        resolve_watch_directory(path)


def test_rejects_symlink_directory(private_dir: Path, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(private_dir, target_is_directory=True)
    with pytest.raises(ConfigurationError, match="symbolic link"):
        resolve_watch_directory(link)


def test_rejects_missing_and_regular_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        resolve_watch_directory(tmp_path / "missing")
    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not a directory"):
        resolve_watch_directory(file_path)


def test_monitor_config_validates_numeric_boundaries(private_dir: Path) -> None:
    MonitorConfig(private_dir, count=1, cooldown=0, audit_interval=0.1)
    for value in (math.nan, math.inf, -1.0):
        with pytest.raises(ConfigurationError):
            MonitorConfig(private_dir, cooldown=value)
    for value in (math.nan, math.inf, 0.0, -1.0):
        with pytest.raises(ConfigurationError):
            MonitorConfig(private_dir, audit_interval=value)
