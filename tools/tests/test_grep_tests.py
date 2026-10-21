"""Pins the grep tests: README drift (SPEC §9.4), bypass tokens, and key material (I13)."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import grep_tests
import pytest

ROOT = Path(__file__).resolve().parents[2]

STATEMENT = "> The topology is not a boundary. Use a VM-class boundary in production."
SPEC = f"""# Spec

### 9.4 Isolation statement (verbatim in README)

{STATEMENT}

## 10. Threat model

> Some other quote that must never be pinned.
"""
README = f"""# project

One paragraph.

{STATEMENT}

## Status

Text below the fold.
"""


def test_verbatim_above_fold_passes() -> None:
    """The exact block before the first ## heading is accepted."""
    assert grep_tests.readme_drift(SPEC, README) == []


def test_one_word_drift_is_a_hit() -> None:
    """A single changed word is reported."""
    drifted = README.replace("a VM-class", "any VM-class")
    assert grep_tests.readme_drift(SPEC, drifted) != []


def test_missing_statement_is_a_hit() -> None:
    """A README without the block is reported."""
    assert grep_tests.readme_drift(SPEC, README.replace(STATEMENT + "\n\n", "")) != []


def test_below_fold_is_a_hit() -> None:
    """The block after the first ## heading does not count."""
    moved = README.replace(STATEMENT + "\n\n", "") + "\n" + STATEMENT + "\n"
    assert grep_tests.readme_drift(SPEC, moved) != []


def test_bold_wrapping_is_a_hit() -> None:
    """Markdown emphasis around the statement changes the bytes and is reported."""
    bold = README.replace("> The topology", "> **The topology")
    assert grep_tests.readme_drift(SPEC, bold) != []


def test_block_inside_html_comment_on_one_line_is_a_hit() -> None:
    """A block that does not start its own line is not accepted."""
    hidden = README.replace(STATEMENT, f"<!-- {STATEMENT} -->")
    assert grep_tests.readme_drift(SPEC, hidden) != []


def test_two_line_quote_needs_both_lines() -> None:
    """Every line of a multi-line blockquote is pinned, not just the first."""
    two = SPEC.replace(STATEMENT, STATEMENT + "\n> Second line of the statement.")
    assert grep_tests.readme_drift(two, README) != []
    both = README.replace(STATEMENT, STATEMENT + "\n> Second line of the statement.")
    assert grep_tests.readme_drift(two, both) == []


def test_section_number_does_not_matter() -> None:
    """The heading is found by its marker, so renumbering the spec is harmless."""
    renumbered = SPEC.replace("### 9.4 Isolation", "### 9.5 Isolation")
    assert grep_tests.readme_drift(renumbered, README) == []


def test_missing_marked_heading_raises() -> None:
    """A spec with no marked heading is an error, not a pass."""
    with pytest.raises(grep_tests.SpecError):
        grep_tests.readme_drift(SPEC.replace("(verbatim in README)", ""), README)


def test_empty_quote_raises() -> None:
    """A blank blockquote under the marked heading is an error, not a vacuous match."""
    with pytest.raises(grep_tests.SpecError):
        grep_tests.readme_drift(SPEC.replace(STATEMENT, "> "), README)


def test_quote_in_a_later_section_is_not_used() -> None:
    """With no quote under the marked heading, a quote in the next section is not pinned."""
    with pytest.raises(grep_tests.SpecError):
        grep_tests.readme_drift(SPEC.replace(STATEMENT + "\n", ""), README)


def test_committed_readme_matches_committed_spec() -> None:
    """The repository's own README carries SPEC.md's marked block above the fold."""
    spec_text = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert grep_tests.readme_drift(spec_text, readme_text) == []


def test_main_runs_the_readme_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() exits non-zero on a drifted README, so the check cannot be dropped silently."""
    drifted = tmp_path / "README.md"
    drifted.write_text(README.replace("a VM-class", "any VM-class"), encoding="utf-8")
    spec = tmp_path / "SPEC.md"
    spec.write_text(SPEC, encoding="utf-8")
    monkeypatch.setattr(grep_tests, "README", drifted)
    monkeypatch.setattr(grep_tests, "SPEC", spec)
    assert grep_tests.main() == 1
    drifted.write_text(README, encoding="utf-8")
    assert grep_tests.main() == 0


# --- bypass and key-material patterns (I13, issue #25) -------------------------
#
# Every sample is written to tmp_path at run time and scanned there; none is committed to the
# scanned tree. Key-shaped samples are built from short pieces so this file holds no literal
# that looks like a key.

HEX64 = "a1" * 32
B64_32 = "QUJD" * 10 + "QUI="
ESCAPES_32 = "".join(f"\\x{b:02x}" for b in range(200, 232))
PEM = "-----BEGIN " + "PRIVATE KEY-----"

BYPASS_SAMPLES = [
    ("annotated_param", "def f(allow_unsigned: bool = False) -> None:\n    return None\n"),
    ("annotated_param", "def f(\n    x: int,\n    skip_verify: bool,\n) -> None:\n    ...\n"),
    ("annotated_param", "class C:\n    lenient_parse: bool = True\n"),
    ("annotated_param", "def f(*, UNSAFE_mode: bool) -> None:\n    return None\n"),
    ("swallow", "try:\n    f()\nexcept Exception as e:\n    pass\n"),
    ("swallow", "try:\n    f()\nexcept (ValueError, Exception):\n    pass\n"),
    ("swallow", "try:\n    f()\nexcept Exception: ...\n"),
    (
        "swallow",
        "for x in y:\n    try:\n        f()\n    except BaseException:\n        continue\n",
    ),
    ("swallow", "try:\n    f()\nexcept KeyError:  # fine: it is optional\n    pass\n"),
    ("swallow", "try:\n    f()\nexcept (\n    ValueError,\n    Exception,\n) as e:\n    pass\n"),
    ("swallow", "try:\n    f()\nexcept:\n    pass\n"),
    ("suppress", "import contextlib\nwith contextlib.suppress(Exception):\n    f()\n"),
    ("suppress", "from contextlib import suppress\nwith suppress(BaseException):\n    f()\n"),
    ("suppress", "from contextlib import suppress as s\nwith s(ValueError):\n    f()\n"),
    ("suppress", "from contextlib import (\n    suppress as quiet,\n)\n"),
    ("suppress", "import contextlib\nquiet = contextlib.suppress\n"),
    ("suppress", "import contextlib as c\nwith c.suppress(KeyError):\n    f()\n"),
    ("swallow", "try:\n    f()\nexcept KeyError: pass\n"),
    ("swallow", "for x in y:\n    try:\n        f()\n    except* ValueError:\n        break\n"),
    ("swallow", "def g():\n    try:\n        f()\n    except ValueError:\n        return\n"),
    ("swallow", "def g():\n    try:\n        f()\n    except ValueError:\n        return None\n"),
    ("strict", "def f(strict: bool = False) -> None:\n    return None\n"),
    ("no_verify", "def f(no_verify: bool) -> None:\n    return None\n"),
]

KEY_SAMPLES = [
    ("fromhex", f'k = bytes.fromhex("{HEX64}")\n'),
    ("fromhex", f'k = bytes.fromhex("{HEX64.upper()}")\n'),
    ("fromhex", f'k = bytearray.fromhex(\n    "{HEX64[:64]} {HEX64[64:]}"\n)\n'),
    ("hex_named", f'GATE_SEED = "{HEX64}"\n'),
    ("hex_named", f'private_key: str = "{HEX64.upper()}"\n'),
    ("hex_named", f'cfg = {{"signing_secret": "{HEX64}"}}\n'),
    ("hex_named", f'{{"seed":"{HEX64}","kid":"gate-1"}}\n'),
    ("escapes", f'k = b"{ESCAPES_32}"\n'),
    ("base64_named", f'SIGNING_KEY = "{B64_32}"\n'),
    ("base64_named", f'{{"priv":"{B64_32}"}}\n'),
    ("pem", f"x = '''{PEM}\\nMC4CAQ\\n'''\n"),
    ("pem", "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\n"),
    ("pem", "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n"),
    ("fromhex", f'k = bytes.fromhex("{HEX64[:32]}" "{HEX64[32:]}")\n'),
    ("fromhex", f'k = binascii.unhexlify("{HEX64}")\n'),
    ("hex_named", f'signing_key = "{HEX64.upper()}"\n'),
    ("hex_named", f'sk = "{HEX64}"\n'),
    ("base64_named", f'{{"kty":"OKP","d":"{B64_32.replace("+", "-")}"}}\n'),
    ("escapes", "k = b'" + "".join(f"\\{b:03o}" for b in range(200, 232)) + "'\n"),
    ("escapes", "k = b'\\x2d\\x71abcdefgh\\x01\\x02\\x03ijklmnop\\x04\\x05\\x06\\x07\\x08'\n"),
]

CLEAN_SAMPLES = [
    "try:\n    f()\nexcept Exception as e:  # noqa: BLE001  SPEC §5\n    report = {'exit': 3}\n",
    "try:\n    f()\nexcept (OSError, ValueError):\n    return 3\n",
    "try:\n    f()\nexcept InvalidSignature as e:\n    raise KeyringError('no') from e\n",
    "try:\n    f()\nexcept Exception:\n    raise\n",
    "try:\n    f()\nexcept ValueError:\n    passed = False\n    raise\n",
    'DOMAIN_ANCHOR_RECEIPT = b"ai-audit-trail/v1/anchor-receipt\\x00"\n',
    f'ZERO_HASH = "sha256:{HEX64}"\n',
    f'key_hash = "sha256:{HEX64}"\n',
    "seed = bytes.fromhex(fields[0])\n",
    "allow = {'allow_list': 1}\n",
    '"""Docstrings may say we never suppress anything."""\n',
    '"""Refuse the line.\n\n    suppress nothing, ever.\n    """\n',
    "# skip everything except records\nif r.type != 'record':\n    continue\n",
    'class P(Protocol):\n    """Anything except bytes."""\n\n    def b(self) -> bytes: ...\n',
    "try:\n    f()\nexcept InvalidSignature:\n    return False\n",
    "a = 'x' + 'y'\nb = \"z\"\n",
]


def scan_text(tmp_path: Path, text: str, patterns: list[str], name: str = "s.py") -> list[str]:
    """Write `text` into tmp_path and scan only that file."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return grep_tests.scan_files([path], patterns)


@pytest.mark.parametrize(("kind", "text"), BYPASS_SAMPLES)
def test_each_bypass_shape_is_a_hit(tmp_path: Path, kind: str, text: str) -> None:
    """Every planted bypass is reported by BYPASS."""
    assert scan_text(tmp_path, text, grep_tests.BYPASS) != [], kind


@pytest.mark.parametrize(("kind", "text"), KEY_SAMPLES)
def test_each_key_material_shape_is_a_hit(tmp_path: Path, kind: str, text: str) -> None:
    """Every planted key shape is reported by KEY_MATERIAL, in a .py file and in a log."""
    assert scan_text(tmp_path, text, grep_tests.KEY_MATERIAL) != [], kind
    assert scan_text(tmp_path, text, grep_tests.KEY_MATERIAL, "x.jsonl") != [], kind


def test_real_key_reprs_are_hits(tmp_path: Path) -> None:
    """The repr of each of 2000 random-looking 32-byte values, printable runs and all, is a hit."""
    path = tmp_path / "s.py"
    for i in range(2000):
        path.write_text(f"k = {hashlib.sha256(str(i).encode()).digest()!r}\n", encoding="utf-8")
        assert grep_tests.scan_files([path], grep_tests.KEY_MATERIAL) != [], i


@pytest.mark.parametrize("text", CLEAN_SAMPLES)
def test_lookalikes_are_not_hits(tmp_path: Path, text: str) -> None:
    """Re-raises, `return 3`, domain constants, prefixed hashes and fromhex(variable) pass."""
    assert scan_text(tmp_path, text, grep_tests.BYPASS + grep_tests.KEY_MATERIAL) == []


@pytest.mark.parametrize("pattern", grep_tests.BYPASS + grep_tests.KEY_MATERIAL)
def test_no_pattern_hits_the_committed_sources(pattern: str) -> None:
    """The repository's own packages and apps are clean under every pattern, one at a time."""
    assert grep_tests.scan_files(grep_tests.source_files(), [pattern]) == []


@pytest.mark.parametrize("pattern", grep_tests.KEY_MATERIAL)
def test_no_key_pattern_hits_the_committed_logs(pattern: str) -> None:
    """Committed logs outside spec/ are clean (today there are none, which is also clean)."""
    assert grep_tests.scan_files(grep_tests.committed_logs(), [pattern]) == []


def git(root: Path, *args: str) -> None:
    """Run git in `root` with a fixed identity; raise on failure."""
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(root), *args],  # noqa: S607
        check=True,
        capture_output=True,
    )


def test_committed_logs_are_found_outside_spec_only(tmp_path: Path) -> None:
    """Tracked logs and key files are listed whatever the extension case; spec/ is exempt."""
    git(tmp_path, "init", "-q")
    for rel in ["a/x.jsonl", "b/c/y.log", "d/k.PEM", "spec/vectors/z.jsonl", "a/x.py"]:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(f'{{"seed":"{HEX64}"}}\n', encoding="utf-8")
    (tmp_path / "untracked.jsonl").write_text("{}\n", encoding="utf-8")
    git(tmp_path, "add", "a", "b", "d", "spec")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in grep_tests.committed_logs(tmp_path))
    assert found == ["a/x.jsonl", "b/c/y.log", "d/k.PEM"]
    hits = grep_tests.scan_files(grep_tests.committed_logs(tmp_path), grep_tests.KEY_MATERIAL)
    assert len(hits) >= 3


def test_main_scans_committed_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() exits non-zero when a committed log holds key material."""
    log = tmp_path / "x.jsonl"
    log.write_text(f'{{"seed":"{HEX64}"}}\n', encoding="utf-8")
    monkeypatch.setattr(grep_tests, "committed_logs", lambda: [log])
    assert grep_tests.main() == 1
    log.write_text("{}\n", encoding="utf-8")
    assert grep_tests.main() == 0
