"""Verifier tests read ONLY committed fixtures under spec/. Never import audittrail here."""

from __future__ import annotations

from pathlib import Path

import pytest

SPEC = Path(__file__).resolve().parents[3] / "spec"


@pytest.fixture
def spec_dir() -> Path:
    """Path to the committed contract: schema, reasons, keyring, vectors."""
    return SPEC
