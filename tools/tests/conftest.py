"""Loads tools/grep-tests.py as a module; the hyphen keeps it from being imported by name."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "grep-tests.py"


@pytest.fixture(scope="session")
def grep_tests() -> ModuleType:
    """The grep-tests script as a module. Does not run its main()."""
    spec = importlib.util.spec_from_file_location("grep_tests", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
