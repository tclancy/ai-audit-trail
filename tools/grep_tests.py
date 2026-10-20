"""Grep tests: fail CI on bypass tokens, key material, or README drift from the spec.

Deliberately dumb. These catch the Friday-afternoon edit, not the adversary.
"""

from __future__ import annotations

import itertools
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = [ROOT / "packages", ROOT / "apps"]
EXEMPT = {ROOT / "spec"}
SPEC = ROOT / "SPEC.md"
README = ROOT / "README.md"
VERBATIM_MARK = "(verbatim in README)"

_KEYISH_NAME = r"(?i)\b\w*(?:seed|key|priv|secret)\w*['\"]?\s*(?::[^=\n]*)?[:=]\s*[rbu]{0,2}['\"]"
"""A name containing seed, key, priv or secret, as an assignment, annotation, kwarg or JSON key."""

BYPASS = [
    r"\bstrict\s*=\s*False\b",
    r"\bverify\s*=\s*False\b",
    r"\b(allow|skip|lenient|unsafe)_[a-z_]+\s*=",
    # The same names annotated, as every parameter is under mypy --strict (issue #25).
    r"(?i)\b(allow|skip|lenient|unsafe)_\w+\s*:(?!=)",
    # Any except clause, one line or several, whose whole body is pass, continue or `...`.
    r"\bexcept\b[^:]*:\s*(?:#[^\n]*\s*)*(?:pass|continue|\.\.\.)(?![\w.])",
    # contextlib.suppress in any spelling: a call, an attribute, or an import (aliases too).
    r"\bsuppress\s*\(",
    r"\.\s*suppress\b",
    r"\bimport\b[^\n]*\bsuppress\b|^\s*suppress\b",
    r"\bxfail\b",
    r"\bpickle\b",
]
KEY_MATERIAL = [
    r"-----BEGIN (OPENSSH |EC |RSA )?PRIVATE KEY-----",
    r"\bseed\s*=\s*b?['\"][0-9a-fA-F]{32,}",
    r"\b(?:bytes|bytearray)\s*\.\s*fromhex\s*\(\s*[rRuU]?['\"](?:[0-9a-fA-F]\s*){64,}['\"]",
    _KEYISH_NAME + r"[0-9a-f]{64,}['\"]",
    _KEYISH_NAME + r"[A-Za-z0-9+/_-]{42,}={0,2}['\"]",
    # Twelve or more \xHH escapes in one literal, a few other characters allowed between them:
    # how a 32-byte key looks pasted as bytes or as its repr.
    r"(?:\\x[0-9a-fA-F]{2}(?:[^'\"\\\n]|\\[^x\n]){0,6}){12,}",
]
"""Run over sources and over committed logs. `spec/` is exempt: it holds the published seed."""


class SpecError(Exception):
    """SPEC.md lacks something a grep test depends on. Does not mean the README is wrong."""


def source_files() -> list[Path]:
    """Every `*.py` under SRC, outside EXEMPT. Does not look at tools/ or at non-Python files."""
    return [
        p
        for base in SRC
        for p in sorted(base.rglob("*.py"))
        if not any(e in p.parents for e in EXEMPT)
    ]


def committed_logs(root: Path = ROOT) -> list[Path]:
    """Every tracked `*.jsonl` and `*.log` under `root` outside `spec/` (SPEC §7 I13 "and logs").

    Asks git, so an untracked log is not listed; a git failure raises and the run fails.
    """
    listed = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.jsonl", "*.log"],  # noqa: S607
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return [root / rel for rel in listed.split("\0") if rel and not rel.startswith("spec/")]


def scan_files(files: list[Path], patterns: list[str]) -> list[str]:
    """Return 'path:line: pattern' for every hit of every pattern in `files`. Skips nothing."""
    hits: list[str] = []
    for p in files:
        text = p.read_text(encoding="utf-8")
        for pat in patterns:
            for m in re.finditer(pat, text, flags=re.MULTILINE):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(f"{_shown(p)}:{line}: {pat}")
    return hits


def scan(patterns: list[str]) -> list[str]:
    """Return 'path:line: pattern' for every hit under SRC, skipping EXEMPT."""
    return scan_files(source_files(), patterns)


def _shown(path: Path) -> str:
    """`path` relative to ROOT when it is inside it, else as given. Does not resolve links."""
    return str(path.relative_to(ROOT)) if ROOT in path.parents else str(path)


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
    hits = (
        scan(BYPASS)
        + scan(KEY_MATERIAL)
        + scan_files(committed_logs(), KEY_MATERIAL)
        + readme_drift(spec_text, readme_text)
    )
    for h in hits:
        print(h)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
