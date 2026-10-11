"""Fixtures for the log package's tests. Vectors are read, never written."""

from __future__ import annotations

from pathlib import Path

import pytest

SPEC = Path(__file__).resolve().parents[3] / "spec"


@pytest.fixture
def vectors_dir() -> Path:
    """Path to `spec/vectors`. Does not check that the manifest matches."""
    return SPEC / "vectors"
