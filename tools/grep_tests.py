"""Grep tests: fail CI on bypass tokens, key material, or README drift from the spec.

Deliberately dumb. These catch the Friday-afternoon edit, not the adversary.
"""

from __future__ import annotations

import itertools
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = [ROOT / "packages", ROOT / "apps"]
EXEMPT = {ROOT / "spec"}
SPEC = ROOT / "SPEC.md"
README = ROOT / "README.md"
VERBATIM_MARK = "(verbatim in README)"

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


class SpecError(Exception):
    """SPEC.md lacks something a grep test depends on. Does not mean the README is wrong."""


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


def verbatim_block(spec_text: str) -> str:
    """Return the blockquote under the spec heading marked VERBATIM_MARK, '> ' prefixes kept.

    Raises SpecError if no heading carries the mark or its section has no non-empty
    blockquote. Does not look past the next heading, so a quote elsewhere never counts.
    """
    lines = spec_text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.startswith("#") and VERBATIM_MARK in ln)
    except StopIteration:
        raise SpecError(f"SPEC.md has no heading marked {VERBATIM_MARK!r}") from None
    section = itertools.takewhile(lambda ln: not ln.startswith("#"), lines[start + 1 :])
    quote = [ln for ln in section if ln.startswith("> ")]
    if not any(ln[2:].strip() for ln in quote):
        raise SpecError(f"SPEC.md section marked {VERBATIM_MARK!r} has no blockquote")
    return "\n".join(quote)


def readme_drift(spec_text: str, readme_text: str) -> list[str]:
    """Return a hit unless the README has the verbatim block, as whole lines, above its first '## '.

    Does not check any other README wording, and does not see a block hidden inside a
    multi-line HTML comment.
    """
    block = verbatim_block(spec_text)
    fold = readme_text.split("\n## ", 1)[0]
    if f"\n{block}\n" in f"\n{fold}\n":
        return []
    return ["README.md: the spec's verbatim block is missing, altered, or below the first ##"]


def main() -> int:
    """Run all grep tests; non-zero on any hit."""
    spec_text = SPEC.read_text(encoding="utf-8")
    readme_text = README.read_text(encoding="utf-8")
    hits = scan(BYPASS) + scan(KEY_MATERIAL) + readme_drift(spec_text, readme_text)
    for h in hits:
        print(h)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
