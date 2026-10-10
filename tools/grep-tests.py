"""Grep tests: fail CI on bypass tokens, key material, or unvalidated text fields.

Deliberately dumb. These catch the Friday-afternoon edit, not the adversary.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = [ROOT / "packages", ROOT / "apps"]
EXEMPT = {ROOT / "spec"}

BYPASS = [
    r"\bstrict\s*=\s*False\b",
    r"\bverify\s*=\s*False\b",
    r"\b(allow|skip|lenient|unsafe)_[a-z_]+\s*=",
    r"except\s*(Exception|BaseException)?\s*:\s*\n\s*(pass|continue)\b",
    r"\bxfail\b",
    r"\bpickle\b",
]
KEY_MATERIAL = [
    r"-----BEGIN (OPENSSH |EC |RSA )?PRIVATE KEY-----",
    r"\bseed\s*=\s*b?['\"][0-9a-fA-F]{32,}",
]


def scan(patterns: list[str]) -> list[str]:
    """Return 'path:line: pattern' for every hit under SRC, skipping EXEMPT."""
    hits: list[str] = []
    for base in SRC:
        for p in base.rglob("*.py"):
            if any(e in p.parents for e in EXEMPT):
                continue
            text = p.read_text(encoding="utf-8")
            for pat in patterns:
                for m in re.finditer(pat, text, flags=re.MULTILINE):
                    line = text.count("\n", 0, m.start()) + 1
                    hits.append(f"{p.relative_to(ROOT)}:{line}: {pat}")
    return hits


def main() -> int:
    """Run all grep tests; non-zero on any hit."""
    hits = scan(BYPASS) + scan(KEY_MATERIAL)
    for h in hits:
        print(h)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
