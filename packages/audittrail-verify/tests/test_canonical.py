"""The verifier's own canonical-bytes and schema rules, checked against the vectors.

This is the second implementation of SPEC §3.1–§3.2 (CLAUDE.md rule 4). The vectors keep it
honest; these tests add the edge cases the vectors do not carry.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from audittrail_verify.canonical import (
    MAX_LINE_BYTES,
    MAX_NESTING_DEPTH,
    NotCanonical,
    canonical_bytes,
    nesting_depth,
    parse_canonical,
)
from audittrail_verify.schema import NotRecord, check_record

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "vectors"


def every_positive_line() -> list[bytes]:
    """All lines of all positive vectors, without newlines."""
    out: list[bytes] = []
    for f in sorted((VECTORS / "positive").rglob("*.jsonl")):
        out.extend(f.read_bytes().removesuffix(b"\n").split(b"\n"))
    return out


def test_every_positive_line_round_trips_and_is_a_record() -> None:
    """parse then canonical_bytes is the identity on every committed positive line."""
    lines = every_positive_line()
    assert len(lines) >= 19
    for line in lines:
        obj = parse_canonical(line)
        assert canonical_bytes(obj) == line
        check_record(obj)


def test_bounds_are_the_spec_numbers() -> None:
    """SPEC §3.1 depth 5 and §3.2 length 1398, derived from the field table here too."""
    assert MAX_NESTING_DEPTH == 5
    assert MAX_LINE_BYTES == 1398


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"{}\n",
        b'{"a":1} ',
        b' {"a":1}',
        b'{"a": 1}',
        b'{"b":1,"a":2}',
        b'{"a":1.0}',
        b'{"a":1e3}',
        b'{"a":-0}',
        b'{"a":9007199254740993}',
        b'{"a":1,"a":2}',
        b'{"a":"\xc3\xa9"}',
        b'{"a":"\\u00e9"}',
        b'{"a":"\\ud800"}',
        b'{"a":"\\/"}',
        b'{"a":"\x7f"}',
        b"[1]",
        b"1",
        b'{"a":[[[[[1]]]]]}',
        b"\xef\xbb\xbf{}",
        b'{"a":1}\r',
        b"{" + b'"a":"' + b"x" * MAX_LINE_BYTES + b'"}',
    ],
)
def test_non_canonical_lines_are_refused(line: bytes) -> None:
    """Each line differs from canonical form in one way."""
    with pytest.raises(NotCanonical):
        parse_canonical(line)


@pytest.mark.parametrize(
    ("line", "depth"),
    [
        (b"{}", 1),
        (b'{"a":[1]}', 2),
        (b'{"a":[[[[1]]]]}', 5),
        (b'{"a":"{{{{{{{{"}', 1),
        (b'{"a":"[\\"[[[[[[["}', 1),
        (b'{"a":"\\\\","b":[[[[[[1]]]]]]}', 7),
        (b"", 0),
    ],
)
def test_nesting_depth_is_structural(line: bytes, depth: int) -> None:
    """The same table as the Go checker's."""
    assert nesting_depth(line) == depth


def test_schema_refuses_a_near_miss_per_field() -> None:
    """One wrong value per field on the approve record, each a NotRecord."""
    [log] = sorted((VECTORS / "positive" / "decision-approve").glob("*.jsonl"))
    good = parse_canonical(log.read_bytes().removesuffix(b"\n").split(b"\n")[1])
    check_record(good)
    bad_values = {
        "v": 2,
        "log_id": "Test",
        "type": "decisions",
        "seq": -1,
        "boot": "01JAB00000000000000000000I",
        "ts": "2026-10-10T00:00:01Z",
        "mono": 1.5,
        "request_id": "x",
        "actor": "spiffe://test.local",
        "app": "",
        "template_hash": "sha256:" + "0" * 63,
        "model_id": "a b",
        "policy_hash": "md5:" + "0" * 64,
        "input_ref": "sha256:" + "G" * 64,
        "cart_hash": None,
        "oracle": "maybe",
        "oracle_ref": "",
        "decision": "approved",
        "reason": "r_oracle_match",
        "reason_v": True,
        "since_hb": 1,
        "canary": "passed",
        "kid": "gate test 1",
        "prev": "sha256:" + "0" * 64 + "0",
        "sig": "ed25519:" + "A" * 86 + "=",
    }
    assert set(bad_values) == set(good)
    for name, value in bad_values.items():
        with pytest.raises(NotRecord):
            check_record({**good, name: value})
    with pytest.raises(NotRecord):
        check_record({k: v for k, v in good.items() if k != "sig"})
    with pytest.raises(NotRecord):
        check_record({**good, "extra": 1})
