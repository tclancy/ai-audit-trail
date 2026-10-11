"""Pins readme_drift(): the README carries the spec's marked blockquote verbatim, above the fold."""

from __future__ import annotations

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
