"""Descriptor-anchored deployment and verification of local canary files."""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import suppress
from pathlib import Path

from .errors import CanaryError
from .models import CanaryCheck, IntegrityState

CANARY_PREFIX = ".ransomwatch-canary-"
CANARY_SUFFIX = ".txt"
CONTENT_TEMPLATE = (
    "RANSOMWATCH CANARY FILE\n"
    "This non-sensitive file is monitored for defensive integrity testing.\n"
    "canary-index={index:02d}\n"
    "format-version=1\n"
)


def _required_open_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if (
        any(not hasattr(os, name) for name in required)
        or os.open not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        raise CanaryError("secure descriptor-based file operations are unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_directory_chain(path: Path) -> int:
    """Open every absolute path component without following symbolic links."""

    flags = _required_open_flags()
    if not path.is_absolute():
        raise CanaryError("watch directory must be an absolute path")
    current_fd: int | None = None
    try:
        current_fd = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        if current_fd is not None:
            os.close(current_fd)
        raise CanaryError(f"could not securely traverse watch directory: {exc}") from exc


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise CanaryError("could not finish writing a canary file")
        view = view[written:]


class CanaryStore:
    """Manage a fixed, bounded set of canaries below one pinned directory."""

    def __init__(self, watch_dir: Path, count: int) -> None:
        self.watch_dir = watch_dir
        self.count = count
        self._dir_fd: int | None = None

    def __enter__(self) -> CanaryStore:
        self.open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            f"{CANARY_PREFIX}{index:02d}{CANARY_SUFFIX}"
            for index in range(1, self.count + 1)
        )

    @property
    def paths(self) -> tuple[Path, ...]:
        return tuple(self.watch_dir / name for name in self.names)

    def open(self) -> None:
        if self._dir_fd is not None:
            return
        try:
            fd = _open_directory_chain(self.watch_dir)
            metadata = os.fstat(fd)
        except OSError as exc:
            raise CanaryError(f"could not securely open watch directory: {exc}") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(fd)
            raise CanaryError("watch directory changed before it could be opened")
        if metadata.st_mode & 0o022:
            os.close(fd)
            raise CanaryError("watch directory permissions became unsafe")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            os.close(fd)
            raise CanaryError("watch directory ownership changed")
        self._dir_fd = fd

    def close(self) -> None:
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None

    def deploy(self) -> tuple[CanaryCheck, ...]:
        """Create missing canaries and verify any existing managed files."""

        self._ensure_open()
        results: list[CanaryCheck] = []
        for index, name in enumerate(self.names, start=1):
            content = self._expected_content(index)
            try:
                self._create(name, content)
            except FileExistsError:
                check = self.check(name)
                if check.state is not IntegrityState.HEALTHY:
                    raise CanaryError(
                        f"refusing to overwrite existing canary {name}: {check.detail}"
                    ) from None
                results.append(check)
            else:
                check = self.check(name)
                if check.state is not IntegrityState.HEALTHY:
                    raise CanaryError(
                        f"newly created canary failed verification {name}: {check.detail}"
                    )
                results.append(
                    CanaryCheck(
                        self.watch_dir / name,
                        IntegrityState.HEALTHY,
                        "created and verified",
                    )
                )
        return tuple(results)

    def check(self, name: str) -> CanaryCheck:
        """Verify type, ownership, permissions, link count, and exact content."""

        self._ensure_known_name(name)
        self._ensure_open()
        path = self.watch_dir / name
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, dir_fd=self._dir_fd)
        except FileNotFoundError:
            return CanaryCheck(path, IntegrityState.MISSING, "canary file is missing")
        except OSError as exc:
            return CanaryCheck(path, IntegrityState.UNSAFE, f"could not open safely: {exc}")
        try:
            metadata = os.fstat(fd)
            unsafe = self._unsafe_reason(metadata)
            if unsafe:
                return CanaryCheck(path, IntegrityState.UNSAFE, unsafe)
            expected = self._expected_content(self.names.index(name) + 1)
            actual = self._read_bounded(fd, len(expected) + 1)
            if actual != expected:
                return CanaryCheck(
                    path,
                    IntegrityState.MODIFIED,
                    "content differs from the deterministic baseline",
                )
            return CanaryCheck(path, IntegrityState.HEALTHY, "content and metadata match")
        finally:
            os.close(fd)

    def check_all(self) -> tuple[CanaryCheck, ...]:
        """Verify every configured canary."""

        return tuple(self.check(name) for name in self.names)

    def name_for_event_path(self, path: Path) -> str | None:
        """Match only exact expected paths; never use substring matching."""

        absolute = Path(os.path.abspath(path))
        for name, expected in zip(self.names, self.paths, strict=True):
            if absolute == expected:
                return name
        return None

    def _create(self, name: str, content: bytes) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(name, flags, 0o600, dir_fd=self._dir_fd)
        try:
            os.fchmod(fd, 0o600)
            _write_all(fd, content)
            os.fsync(fd)
        except BaseException:
            with suppress(OSError):
                os.unlink(name, dir_fd=self._dir_fd)
            raise
        finally:
            os.close(fd)

    @staticmethod
    def _expected_content(index: int) -> bytes:
        return CONTENT_TEMPLATE.format(index=index).encode("utf-8")

    @staticmethod
    def expected_sha256(index: int) -> str:
        """Return the documented deterministic digest for a canary index."""

        return hashlib.sha256(CanaryStore._expected_content(index)).hexdigest()

    @staticmethod
    def _read_bounded(fd: int, limit: int) -> bytes:
        chunks: list[bytes] = []
        remaining = limit
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _unsafe_reason(metadata: os.stat_result) -> str | None:
        if not stat.S_ISREG(metadata.st_mode):
            return "target is not a regular file"
        if metadata.st_nlink != 1:
            return "target must have exactly one hard link"
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            return "target permissions must be exactly 0600"
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            return "target is not owned by the effective user"
        return None

    def _ensure_known_name(self, name: str) -> None:
        if name not in self.names:
            raise CanaryError(f"unknown canary name: {name}")

    def _ensure_open(self) -> None:
        if self._dir_fd is None:
            raise CanaryError("canary store is closed")
