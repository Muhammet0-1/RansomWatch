from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def private_dir(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "lab"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    yield path.resolve()
