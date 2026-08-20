from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ransomwatch.canary import CANARY_PREFIX, CanaryStore
from ransomwatch.errors import CanaryError
from ransomwatch.models import IntegrityState


def test_deploys_exact_count_with_private_permissions(private_dir: Path) -> None:
    with CanaryStore(private_dir, 3) as store:
        checks = store.deploy()
        assert len(checks) == 3
        assert all(check.state is IntegrityState.HEALTHY for check in checks)
        for path in store.paths:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert path.name.startswith(CANARY_PREFIX)


def test_redeployment_verifies_without_changing_content(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        path = store.paths[0]
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        checks = store.deploy()
        after = (path.read_bytes(), path.stat().st_mtime_ns)
    assert checks[0].detail == "content and metadata match"
    assert before == after


def test_new_canary_is_verified_after_creation(
    private_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with CanaryStore(private_dir, 1) as store:
        original_create = store._create

        def create_with_racing_hardlink(name: str, content: bytes) -> None:
            original_create(name, content)
            (private_dir / "racing-link").hardlink_to(private_dir / name)

        monkeypatch.setattr(store, "_create", create_with_racing_hardlink)
        with pytest.raises(CanaryError, match="newly created canary failed verification"):
            store.deploy()


def test_modified_canary_is_reported_and_never_overwritten(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        store.paths[0].write_text("changed", encoding="utf-8")
        check = store.check(store.names[0])
        assert check.state is IntegrityState.MODIFIED
        with pytest.raises(CanaryError, match="refusing to overwrite"):
            store.deploy()
        assert store.paths[0].read_text(encoding="utf-8") == "changed"


def test_missing_canary_is_reported(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        store.paths[0].unlink()
        assert store.check_all()[0].state is IntegrityState.MISSING


def test_symlink_canary_is_rejected_without_following(private_dir: Path) -> None:
    target = private_dir / "target"
    target.write_text("do not touch", encoding="utf-8")
    os.chmod(target, 0o600)
    with CanaryStore(private_dir, 1) as store:
        store.paths[0].symlink_to(target)
        check = store.check_all()[0]
        assert check.state is IntegrityState.UNSAFE
        with pytest.raises(CanaryError):
            store.deploy()
    assert target.read_text(encoding="utf-8") == "do not touch"


def test_hard_link_and_nonexact_permissions_are_rejected(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        hardlink = private_dir / "second-link"
        hardlink.hardlink_to(store.paths[0])
        assert store.check_all()[0].state is IntegrityState.UNSAFE
        hardlink.unlink()
        for mode in (0o400, 0o644):
            os.chmod(store.paths[0], mode)
            assert store.check_all()[0].state is IntegrityState.UNSAFE


def test_unknown_name_and_closed_store_fail_loudly(private_dir: Path) -> None:
    store = CanaryStore(private_dir, 1)
    with pytest.raises(CanaryError, match="unknown"):
        store.check("other.txt")
    with pytest.raises(CanaryError, match="closed"):
        store.deploy()


def test_exact_event_path_matching(private_dir: Path) -> None:
    with CanaryStore(private_dir, 1) as store:
        store.deploy()
        expected = store.paths[0]
        assert store.name_for_event_path(expected) == store.names[0]
        assert store.name_for_event_path(Path(f"{expected}.backup")) is None
        assert store.name_for_event_path(private_dir / f"prefix-{expected.name}") is None


def test_expected_digest_is_stable() -> None:
    assert len(CanaryStore.expected_sha256(1)) == 64
    assert CanaryStore.expected_sha256(1) != CanaryStore.expected_sha256(2)
