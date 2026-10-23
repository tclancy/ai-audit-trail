"""The two canonicalizers agree: `audittrail.record` against `audittrail_verify` (rule 4).

Canonical form is implemented twice in this repository on purpose, and CLAUDE.md promises
that the vectors and a property test keep the copies honest. The vectors pin each copy to the
Go reference at a few dozen points; this file drives generated input through both copies and
requires the same verdict, the same bytes, and the same SPEC §5 check number. Lines here are
serialized by `json.dumps`, not by either copy, so neither copy is the oracle for the other.

This package imports the verifier; the verifier never imports this package. Nothing here
checks a signature, so check 5 is not compared. Hypothesis runs derandomized: the same
examples every run, so a red run is a disagreement and never a lucky seed. The sweeps that
matter for drift are plain parametrized tests, not left to the search: every string rule at
every single-character edit and every length, every record type with every field swapped
for every other value the vectors or an enum offer, every integer boundary, every nesting
depth, the line-length bound, and the shared tables compared directly. A review of the
first draft planted 48 one-line drifts and 22 survived the search alone; these sweeps are
what kill them.
"""

from __future__ import annotations

import json
import re
import tempfile
import typing
from pathlib import Path
from typing import Any

import pytest
from audittrail.record import (
    FIELDS,
    INT_FIELDS,
    MAX_LINE_BYTES,
    MAX_NESTING_DEPTH,
    STRING_RULES,
    ParseError,
    Record,
    RecordError,
    SchemaError,
    canonical_bytes,
    nesting_depth,
    parse_line,
    validate_string_field,
)
from audittrail_verify import canonical, schema
from audittrail_verify.canonical import NotCanonical, parse_canonical
from audittrail_verify.checks import verify
from audittrail_verify.keyring import load_keyring
from hypothesis import example, given, settings
from hypothesis import strategies as st

SPEC = Path(__file__).resolve().parents[3] / "spec"
VECTORS = SPEC / "vectors"
KEYRING = load_keyring(VECTORS / "keyring.json")

EXAMPLES = settings(max_examples=300, derandomize=True, deadline=None, database=None)


def positive_lines() -> list[bytes]:
    """Every record line of every positive vector, without newlines. Fails if there are none."""
    lines: list[bytes] = []
    for f in sorted((VECTORS / "positive").glob("*/*.jsonl")):
        lines.extend(f.read_bytes().removesuffix(b"\n").split(b"\n"))
    assert lines
    return lines


def first_of_each_type(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The first vector record of each `type`, so every §3.4 row has a base to mutate."""
    bases: dict[str, dict[str, Any]] = {}
    for record in records:
        bases.setdefault(record["type"], record)
    assert set(bases) == {"anchor", "boot", "decision", "heartbeat", "rotation"}
    return [bases[t] for t in sorted(bases)]


POSITIVE_LINES = positive_lines()
RECORDS: list[dict[str, Any]] = [json.loads(line) for line in POSITIVE_LINES]
BASES = first_of_each_type(RECORDS)
GENESIS: dict[str, Any] = json.loads(
    (VECTORS / "positive" / "genesis-boot" / "test.0000000000000000.jsonl").read_bytes()
)
DECISION: dict[str, Any] = next(r for r in RECORDS if r["type"] == "decision")
NONZERO_HASH = GENESIS["template_hash"]


def with_field(name: str, value: object) -> dict[str, Any]:
    """The genesis vector as a dict with one field replaced. Does not re-sign."""
    return {**GENESIS, name: value}


def nested(depth: int) -> Any:
    """`0` wrapped in `depth` lists, so a record holding it nests `depth + 1` levels."""
    value: Any = 0
    for _ in range(depth):
        value = [value]
    return value


def dumps(obj: dict[str, Any]) -> bytes:
    """Compact, key-sorted JSON from the standard library: the test's own serializer."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def enum_members(name: str) -> set[str]:
    """Every enum member in either copy: the library's set plus the verifier's alternation."""
    ours = STRING_RULES[name]
    members = set(ours) if isinstance(ours, frozenset) else set()
    theirs = schema.STRING_RULES[name].pattern
    if re.fullmatch(r"[A-Za-z_|]+", theirs):
        members |= set(theirs.split("|"))
    return members


def other_values(name: str) -> list[Any]:
    """Every value the vectors or either enum offer for `name`, plus a few small integers.

    Swapping one of these into a record of another type is how a §3.4 fixed value is probed:
    the result is a record for one copy only if it is a record for the other.
    """
    if name in INT_FIELDS:
        return [0, 1, 2, 2**53 - 1]
    values = {record[name] for record in RECORDS} | enum_members(name)
    if name == "reason":
        values |= {"R_BOOT", "R_BOOT_TRUNCATED"}
    return sorted(values)


# --- strategies ----------------------------------------------------------------------

ascii_text = st.text(st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=40)
any_text = st.text(max_size=20)
INT_BOUNDARIES = [
    -1,
    0,
    1,
    2**53 - 1,
    2**53,
    2**53 + 1,
    10**21 - 1,
    10**21,
    10**21 + 1,
    2**63,
    -(10**21),
]
STRING_EDGES: list[Any] = [0, 1, True, None, 1.0, [], {}, "", "\x7f", "\x00", "\\", '"', "~"]
PROBE_CHARS = '09azAZ-_.:/+=! {}~\x7f\x00\\"é'
ints = st.one_of(st.integers(0, 2**53 - 1), st.integers(), st.sampled_from(INT_BOUNDARIES))
deep_values = st.integers(1, 8).map(nested)
scalars = st.one_of(st.none(), st.booleans(), ints, st.floats(), ascii_text, any_text)
json_values = st.recursive(
    st.one_of(scalars, deep_values),
    lambda inner: st.one_of(
        st.lists(inner, max_size=3), st.dictionaries(ascii_text, inner, max_size=3)
    ),
    max_leaves=8,
)
objects = st.dictionaries(st.one_of(ascii_text, any_text), json_values, max_size=6)


def rule_value(name: str) -> st.SearchStrategy[str]:
    """A value admitted by the library's rule for `name` or by the verifier's; both must agree."""
    ours = STRING_RULES[name]
    from_ours = (
        st.sampled_from(sorted(ours))
        if isinstance(ours, frozenset)
        else st.from_regex(ours, fullmatch=True)
    )
    return st.one_of(from_ours, st.from_regex(schema.STRING_RULES[name], fullmatch=True))


@st.composite
def named_values(draw: st.DrawFn) -> tuple[str, str]:
    """A string field name with a value in its rule, near it, or from anywhere."""
    name = draw(st.sampled_from(sorted(STRING_RULES)))
    value = draw(st.one_of(rule_value(name), ascii_text, any_text, st.text(max_size=300)))
    return name, value


@st.composite
def record_objects(draw: st.DrawFn) -> dict[str, Any]:
    """A positive-vector record with up to two fields replaced, dropped, or added."""
    obj: dict[str, Any] = json.loads(draw(st.sampled_from(POSITIVE_LINES)))
    for _ in range(draw(st.integers(0, 2))):
        name = draw(st.sampled_from(sorted(FIELDS)))
        kind = draw(st.sampled_from(["in-rule", "any-value", "drop"]))
        if kind == "drop":
            obj.pop(name, None)
        elif kind == "any-value":
            obj[name] = draw(json_values)
        elif name in STRING_RULES:
            obj[name] = draw(rule_value(name))
        else:
            obj[name] = draw(st.integers(0, 2**53 - 1))
    if draw(st.integers(0, 9)) == 0:
        obj[draw(ascii_text)] = draw(json_values)
    return obj


@st.composite
def mutated_lines(draw: st.DrawFn) -> bytes:
    """A positive-vector line with one to three bytes inserted, deleted, or replaced."""
    line = bytearray(draw(st.sampled_from(POSITIVE_LINES)))
    for _ in range(draw(st.integers(1, 3))):
        at = draw(st.integers(0, max(len(line) - 1, 0)))
        byte = draw(st.integers(0, 255))
        kind = draw(st.sampled_from(["insert", "delete", "replace"]))
        if kind == "insert":
            line[at:at] = bytes([byte])
        elif kind == "delete" and line:
            del line[at]
        elif line:
            line[at] = byte
    return bytes(line)


lines = st.one_of(
    st.binary(max_size=200),
    ascii_text.map(str.encode),
    mutated_lines(),
    record_objects().map(dumps),
)


# --- verdicts --------------------------------------------------------------------------


def parse_verdict(
    parse: typing.Callable[[bytes], dict[str, Any]], error: type[Exception], line: bytes
) -> tuple[str, dict[str, Any] | None]:
    """`("accepted", obj)` or `("rejected", None)`; any other exception propagates."""
    try:
        return ("accepted", parse(line))
    except error:
        return ("rejected", None)


def bytes_verdict(
    serialize: typing.Callable[[dict[str, Any]], bytes], error: type[Exception], obj: dict[str, Any]
) -> tuple[str, bytes | None]:
    """`("bytes", line)` or `("refused", None)`; any other exception propagates."""
    try:
        return ("bytes", serialize(obj))
    except error:
        return ("refused", None)


def library_admits(name: str, value: str) -> bool:
    """Whether the library's rule for the string field `name` admits `value`."""
    try:
        validate_string_field(name, value)
    except SchemaError:
        return False
    return True


def verifier_admits(name: str, value: str) -> bool:
    """Whether the verifier's rule for the string field `name` admits `value`."""
    return schema.STRING_RULES[name].fullmatch(value) is not None


def library_check(line: bytes) -> int:
    """The SPEC §5 check `Record.from_line` fails `line` on, or 0 if it is a record."""
    try:
        Record.from_line(line)
    except RecordError as e:
        return e.check
    return 0


SCRATCH = tempfile.TemporaryDirectory()
SCRATCH_LOG = Path(SCRATCH.name) / "test.0000000000000000.jsonl"


def verifier_check(line: bytes) -> int:
    """The first check the verifier fails a one-line log on, with check 5 counted as 0.

    Check 5 is the signature, which the library never checks; check 3 and the prev-hash
    half of check 4 need a second line and so cannot fire here. Overwrites one scratch file
    per call; the verifier reads it fresh each time.
    """
    SCRATCH_LOG.write_bytes(line + b"\n")
    first = verify([SCRATCH_LOG], KEYRING)["first_failing_check"]
    assert first != 3, "a one-line log cannot fail check 3"
    return 0 if first in (None, 5) else int(first)


def same_check(obj: dict[str, Any]) -> None:
    """Fail unless both copies name the same check for the line `obj` serializes to."""
    line = dumps(obj)
    assert library_check(line) == verifier_check(line), line


def same_parse(line: bytes) -> None:
    """Fail unless both parsers accept `line` with equal objects, or both reject it."""
    assert parse_verdict(parse_line, ParseError, line) == parse_verdict(
        parse_canonical, NotCanonical, line
    )
    assert nesting_depth(line) == canonical.nesting_depth(line)


# --- the tables both copies derive from ----------------------------------------------


def test_the_field_sets_and_bounds_are_the_same() -> None:
    """Same field names, same integer fields, same depth bound, same derived line maximum."""
    assert FIELDS == schema.FIELDS
    assert INT_FIELDS == schema.INT_FIELDS
    assert set(STRING_RULES) == set(schema.STRING_RULES)
    assert MAX_NESTING_DEPTH == canonical.MAX_NESTING_DEPTH
    assert MAX_LINE_BYTES == canonical.MAX_LINE_BYTES


@pytest.mark.parametrize("name", sorted(STRING_RULES))
def test_every_string_rule_agrees_on_every_single_character_edit(name: str) -> None:
    """The vector's value with one char replaced, inserted, or deleted, at every position."""
    base = GENESIS[name]
    edits = {base[:i] + base[i + 1 :] for i in range(len(base))}
    edits |= {base[:i] + c + base[i + 1 :] for i in range(len(base)) for c in PROBE_CHARS}
    edits |= {base[:i] + c + base[i:] for i in range(len(base) + 1) for c in PROBE_CHARS}
    for value in sorted(edits):
        assert library_admits(name, value) == verifier_admits(name, value), (name, value)


@pytest.mark.parametrize("name", sorted(STRING_RULES))
def test_every_string_rule_agrees_at_every_length(name: str) -> None:
    """The vector's value padded with its own last character, from 0 to 300 extra: same verdict."""
    base = GENESIS[name]
    for extra in range(0, 301):
        value = base + base[-1] * extra
        assert library_admits(name, value) == verifier_admits(name, value), (name, len(value))


# --- one record, one field changed, through both copies -----------------------------


@pytest.mark.parametrize("base", BASES, ids=lambda base: str(base["type"]))
@pytest.mark.parametrize("name", sorted(FIELDS))
def test_every_type_names_the_same_check_with_every_other_value(
    base: dict[str, Any], name: str
) -> None:
    """Each §3.4 row with each field swapped for each value the vectors or an enum offer."""
    for value in other_values(name):
        same_check({**base, name: value})


@pytest.mark.parametrize("name", sorted(STRING_RULES))
def test_every_string_field_names_the_same_check_at_every_edge(name: str) -> None:
    """Wrong types, empty, DEL, NUL, quotes, and the value nudged at either end, in a record.

    The decision vector is the base, since a boot fixes several of these fields and would
    turn every edit into the same check-2 finding.
    """
    value = DECISION[name]
    for edge in [*STRING_EDGES, value + "!", "!" + value, value + value[-1], value[:-1]]:
        same_check({**DECISION, name: edge})


@pytest.mark.parametrize("name", sorted(INT_FIELDS))
@pytest.mark.parametrize("value", [*INT_BOUNDARIES, True, False, 1.0, "0", None, [0], {}])
def test_every_integer_field_names_the_same_check_at_every_boundary(
    name: str, value: object
) -> None:
    """Each int field at each boundary and each wrong type: same check from both copies."""
    same_check(with_field(name, value))


@pytest.mark.parametrize("depth", range(0, 9))
def test_every_nesting_depth_names_the_same_check(depth: int) -> None:
    """A value nested 0 to 8 lists deep inside a record: same check from both copies."""
    same_check(with_field("mono", nested(depth)))
    same_parse(dumps(with_field("mono", nested(depth))))


@pytest.mark.parametrize("extra", [-1, 0, 1])
def test_the_line_length_bound_agrees(extra: int) -> None:
    """A canonical object of MAX_LINE_BYTES - 1, exactly MAX_LINE_BYTES, and one byte over."""
    padding = MAX_LINE_BYTES + extra - len(dumps({"k": ""}))
    line = dumps({"k": "x" * padding})
    assert len(line) == MAX_LINE_BYTES + extra
    same_parse(line)
    assert library_check(line) == verifier_check(line)


@pytest.mark.parametrize(
    "obj",
    [
        {**GENESIS, "cart_hash": NONZERO_HASH, "prev": NONZERO_HASH},
        {**GENESIS, "model_id": "{{{{{{", "prev": NONZERO_HASH},
        {**DECISION, "decision": "approvex", "prev": schema.ZERO_HASH},
    ],
    ids=["bad-cart-hash-and-prev", "bad-model-id-and-prev", "bad-decision-and-zero-prev"],
)
def test_a_line_breaking_checks_2_and_4_at_once_names_the_same_check(obj: dict[str, Any]) -> None:
    """SPEC §5 runs checks in order, so both copies must report 2, not 4, when both fail."""
    same_check(obj)


# --- properties ------------------------------------------------------------------------


@EXAMPLES
@given(named_values())
def test_every_string_rule_admits_the_same_values(named: tuple[str, str]) -> None:
    """Values in, near, and far from each rule: admitted by both copies or by neither."""
    name, value = named
    assert library_admits(name, value) == verifier_admits(name, value)


@EXAMPLES
@given(lines)
def test_both_parsers_give_the_same_verdict_on_any_bytes(line: bytes) -> None:
    """`parse_line` and `parse_canonical` both accept with equal objects, or both reject."""
    same_parse(line)


@EXAMPLES
@given(objects)
def test_both_canonicalizers_give_the_same_bytes_for_any_object(obj: dict[str, Any]) -> None:
    """Same bytes or both refuse; and bytes both produce, both parse back to the object."""
    ours = bytes_verdict(canonical_bytes, ParseError, obj)
    theirs = bytes_verdict(canonical.canonical_bytes, NotCanonical, obj)
    assert ours == theirs
    if ours[1] is not None:
        parsed = parse_verdict(parse_line, ParseError, ours[1])
        assert parsed in (("accepted", obj), ("rejected", None))
        same_parse(ours[1])


@EXAMPLES
@example(GENESIS)
@example(with_field("mono", 10**21))
@example(with_field("seq", 1))
@example(with_field("model_id", "{{{{{{"))
@example(with_field("type", "decision"))
@given(record_objects())
def test_both_implementations_name_the_same_check(obj: dict[str, Any]) -> None:
    """A record, or the same SPEC §5 check number, from the library and from the verifier."""
    same_check(obj)
