# SPDX-License-Identifier: Apache-2.0
"""One log line as a value: strict parse, canonical bytes, hash, and field rules (SPEC §3).

A `Record` cannot hold free text (I8): every `str` field is matched against its SPEC
§3.1 regex or enum at construction, every `int` field is a non-bool integer in
`[0, 2^53)`, and the §3.4 per-type fixed values and the genesis rule are checked too.
Nothing here signs, verifies a signature, or knows about neighbouring records beyond
the genesis rule; `prev` continuity is the chain's job and `sig` is the signer's.
"""

from __future__ import annotations

import dataclasses
import decimal
import hashlib
import json
import re
from typing import Any, ClassVar, NoReturn

ZERO_HASH = "sha256:" + "0" * 64
"""`prev` at genesis and the "not consulted" `oracle_ref` (SPEC §3.1)."""

HEARTBEAT_CART_HASH = "sha256:" + hashlib.sha256(b"audittrail-heartbeat").hexdigest()
"""`cart_hash` of every heartbeat record (SPEC §3.4)."""


class RecordError(ValueError):
    """A line or field set that is not a valid record. `check` is its SPEC §5 number."""

    check: ClassVar[int] = 0


class ParseError(RecordError):
    """Check 1: not printable ASCII, not strict JSON, or not its own canonical bytes."""

    check = 1


class SchemaError(RecordError):
    """Check 2: wrong field set, a value outside its regex, enum, or range, or a §3.4 rule."""

    check = 2


class ChainError(RecordError):
    """Check 4, the part one record can decide alone: the genesis rule (SPEC §3.6)."""

    check = 4


def _regex(pattern: str) -> re.Pattern[str]:
    """Compile a SPEC §3.1 pattern with `re.ASCII`, so `[0-9]`-style classes never widen."""
    return re.compile(pattern, re.ASCII)


_SHA256 = _regex(r"sha256:[0-9a-f]{64}")
_ULID = _regex(r"[0-9A-HJKMNP-TV-Z]{26}")
_ID = _regex(r"[a-z0-9-]{1,32}")

STRING_RULES: dict[str, re.Pattern[str] | frozenset[str]] = {
    "log_id": _ID,
    "type": frozenset({"boot", "decision", "heartbeat", "anchor", "rotation"}),
    "boot": _ULID,
    "ts": _regex(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"),
    "request_id": _ULID,
    "actor": _regex(r"spiffe://[a-z0-9.-]{1,64}/[a-z0-9/_.-]{1,128}"),
    "app": _ID,
    "template_hash": _SHA256,
    "model_id": _regex(r"[A-Za-z0-9._:-]{1,64}"),
    "policy_hash": _SHA256,
    "input_ref": _SHA256,
    "cart_hash": _SHA256,
    "oracle": frozenset({"match", "mismatch", "unavailable", "timeout", "not_consulted"}),
    "oracle_ref": _SHA256,
    "decision": frozenset({"approve", "reject"}),
    "reason": _regex(r"R_[A-Z0-9_]{1,40}"),
    "canary": frozenset({"pass", "fail", "not_run"}),
    "kid": _ID,
    "prev": _SHA256,
    "sig": _regex(r"ed25519:[A-Za-z0-9+/]{86}=="),
}
"""SPEC §3.1, one entry per string field. Deleting an entry opens a text channel (I8)."""

INT_FIELDS: frozenset[str] = frozenset({"v", "seq", "mono", "reason_v", "since_hb"})
"""SPEC §3.1 integer fields; each must be a non-bool `int` in `[0, 2^53)`, and `v == 1`."""

_INT_LIMIT = 2**53

MAX_STRING_LEN: dict[str, int] = {
    "log_id": 32,
    "type": len("heartbeat"),
    "boot": 26,
    "ts": 24,
    "request_id": 26,
    "actor": len("spiffe://") + 64 + 1 + 128,
    "app": 32,
    "template_hash": 7 + 64,
    "model_id": 64,
    "policy_hash": 7 + 64,
    "input_ref": 7 + 64,
    "cart_hash": 7 + 64,
    "oracle": len("not_consulted"),
    "oracle_ref": 7 + 64,
    "decision": len("approve"),
    "reason": 2 + 40,
    "canary": len("not_run"),
    "kid": 32,
    "prev": 7 + 64,
    "sig": 8 + 86 + 2,
}
"""The longest value each STRING_RULES entry admits. A test asks the regex engine to agree."""

MAX_INT_DIGITS = len(str(_INT_LIMIT - 1))
"""Digits of the largest schema integer, 2^53 - 1; `v` is the one-digit exception."""

MAX_NESTING_DEPTH = 5
"""SPEC §3.1: a line nested deeper than this, counting the outer object as 1, is check 1."""

_FIXED_BY_TYPE: dict[str, dict[str, str | int]] = {
    "decision": {"since_hb": 0},
    "boot": {"decision": "reject", "oracle": "not_consulted", "app": "gate", "since_hb": 0},
    "heartbeat": {
        "decision": "reject",
        "oracle": "not_consulted",
        "app": "gate",
        "reason": "R_HEARTBEAT",
        "cart_hash": HEARTBEAT_CART_HASH,
        "oracle_ref": ZERO_HASH,
    },
    "anchor": {
        "decision": "reject",
        "oracle": "not_consulted",
        "app": "gate",
        "reason": "R_ANCHOR",
        "since_hb": 0,
    },
    "rotation": {
        "decision": "reject",
        "oracle": "not_consulted",
        "app": "gate",
        "reason": "R_KEY_ROTATION",
        "oracle_ref": ZERO_HASH,
        "since_hb": 0,
    },
}
"""SPEC §3.1 and §3.4 values that one record fixes by its `type`. Heartbeats carry `since_hb`."""

_BOOT_REASONS = frozenset({"R_BOOT", "R_BOOT_TRUNCATED"})


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Record:
    """One validated log line. Final, immutable, and not copyable by protocol (SPEC §4)."""

    v: int
    log_id: str
    type: str
    seq: int
    boot: str
    ts: str
    mono: int
    request_id: str
    actor: str
    app: str
    template_hash: str
    model_id: str
    policy_hash: str
    input_ref: str
    cart_hash: str
    oracle: str
    oracle_ref: str
    decision: str
    reason: str
    reason_v: int
    since_hb: int
    canary: str
    kid: str
    prev: str
    sig: str

    def __post_init__(self) -> None:
        """Validate every field, then the per-type values, then genesis. Checks no signature."""
        _validate_strings(self)
        _validate_integers(self)
        _validate_type_rules(self)
        _validate_genesis_shape(self)
        _validate_genesis_prev(self)

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass; there is no opt-in, so no subclass can relax a rule."""
        raise TypeError("Record is final")

    def __reduce__(self) -> NoReturn:
        """Refuse the copy and persistence protocols; a Record travels only as its line."""
        raise TypeError("Record cannot be copied or serialized by protocol; use line()")

    @classmethod
    def from_line(cls, line: bytes) -> Record:
        """Parse one canonical line, given without its trailing newline.

        Raises `ParseError` if the bytes are not their own canonical form, `SchemaError`
        or `ChainError` if the fields are not a valid record. Never normalizes input.
        """
        obj = parse_line(line)
        if set(obj) != FIELDS:
            raise SchemaError(f"field set is not SPEC §3.1: {sorted(set(obj) ^ FIELDS)}")
        return cls(**obj)

    def line(self) -> bytes:
        """Return the canonical bytes of this record, without a trailing newline."""
        return canonical_bytes(dataclasses.asdict(self))

    def hash(self) -> str:
        """Return `sha256:<hex>` over `line()` (SPEC §3.2): includes `sig`, excludes the newline."""
        return "sha256:" + hashlib.sha256(self.line()).hexdigest()


FIELDS: frozenset[str] = frozenset(f.name for f in dataclasses.fields(Record))
"""The exact SPEC §3.1 field set; a line with any other set is rejected."""


def _max_line_bytes() -> int:
    """Derive SPEC §3.2's maximum line length from the field tables; never hand-set it.

    Per field in key order: the key plus 3 for its quotes and colon, then the longest value
    plus 2 for its quotes if a string, or its digit count if an integer; plus the commas and
    the braces. Excludes the trailing newline.
    """
    total = 2 + (len(FIELDS) - 1)
    for name in sorted(FIELDS):
        total += len(name) + 3
        if name in MAX_STRING_LEN:
            total += MAX_STRING_LEN[name] + 2
        else:
            total += 1 if name == "v" else MAX_INT_DIGITS
    return total


MAX_LINE_BYTES = _max_line_bytes()
"""SPEC §3.2: a line longer than this, without its newline, is check 1 before parsing."""


def _validate_strings(record: Record) -> None:
    """Every entry in STRING_RULES must match its value exactly. Does not check ints."""
    for name, rule in STRING_RULES.items():
        value = getattr(record, name)
        if type(value) is not str:
            raise SchemaError(f"{name}: not a string")
        ok = value in rule if isinstance(rule, frozenset) else rule.fullmatch(value) is not None
        if not ok:
            raise SchemaError(f"{name}: value does not match its rule")


def _validate_integers(record: Record) -> None:
    """Every INT_FIELDS value is a non-bool int in `[0, 2^53)`; `v` is 1. Does not check strs."""
    for name in INT_FIELDS:
        value = getattr(record, name)
        if type(value) is not int or not 0 <= value < _INT_LIMIT:
            raise SchemaError(f"{name}: not an integer in [0, 2^53)")
    if record.v != 1:
        raise SchemaError("v: schema version is not 1")


def _validate_type_rules(record: Record) -> None:
    """Apply the SPEC §3.4 fixed values for the record's `type`. Does not check genesis."""
    for name, want in _FIXED_BY_TYPE[record.type].items():
        if getattr(record, name) != want:
            raise SchemaError(f"{name}: a {record.type} record fixes this value")
    if record.type == "boot" and record.reason not in _BOOT_REASONS:
        raise SchemaError("reason: a boot record carries R_BOOT or R_BOOT_TRUNCATED")


def _validate_genesis_shape(record: Record) -> None:
    """`seq == 0` is a `boot` with zero-hash `cart_hash` (SPEC §3.4, check 2). Ignores `prev`."""
    if record.seq == 0 and (record.type != "boot" or record.cart_hash != ZERO_HASH):
        raise SchemaError("seq 0 must be a boot record with zero-hash cart_hash")


def _validate_genesis_prev(record: Record) -> None:
    """Zero-hash `prev` exactly at `seq == 0` (SPEC §3.6, check 4). Does not hash a neighbour."""
    if (record.prev == ZERO_HASH) != (record.seq == 0):
        raise ChainError("zero-hash prev exactly at seq 0")


def parse_line(line: bytes) -> dict[str, Any]:
    """Strictly parse one line to a dict, requiring `line == canonical_bytes(parse(line))`.

    Rejects any byte outside printable ASCII (so BOM, CRLF, newline, and non-ASCII), a line
    longer than MAX_LINE_BYTES or nested deeper than MAX_NESTING_DEPTH (both counted over the
    bytes before parsing, SPEC §5 check 1), duplicate keys, floats, exponents, `-0`,
    `NaN`/`Infinity`, non-object top levels, and any byte-level difference from canonical form.
    Negative integers, escaped control characters, and nested values within the depth bound
    round-trip and are left to the schema (check 2), as in the Go reference. Does not check
    the field set.
    """
    if type(line) is not bytes:
        raise ParseError("line is not bytes")
    _require_printable_ascii(line)
    _require_within_bounds(line)
    try:
        obj = json.loads(
            line.decode("ascii"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_float=_refuse_number,
            parse_int=_integer_literal,
            parse_constant=_refuse_number,
        )
    except (json.JSONDecodeError, RecursionError) as e:
        raise ParseError(f"not strict JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ParseError("line is not a JSON object")
    if canonical_bytes(obj) != line:
        raise ParseError("line is not its own canonical form")
    return obj


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS) bytes of `obj` for the record alphabet.

    The alphabet is: string keys and values of chars `0x00..0x7e` only, integers that JCS
    prints verbatim (see `_is_canonical_int`), `true`, `false`, `null`, lists and objects.
    Within it, JCS is exactly compact JSON with keys sorted by code point and the escapes the
    standard library writes. Raises `ParseError` on anything outside it (non-ASCII, DEL, floats,
    other ints, tuples) rather than guessing at JCS number or escape formatting. Does not
    append a newline. The `RecursionError` catch is defensive: on CPython 3.12 the parser
    overflows first, so it is not reachable through `parse_line`.
    """
    _require_canonical_alphabet(obj)
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except RecursionError as e:
        raise ParseError("nested too deeply to serialize") from e
    return text.encode("ascii")


def _require_within_bounds(line: bytes) -> None:
    """Raise `ParseError` if the line is over MAX_LINE_BYTES or nests past MAX_NESTING_DEPTH."""
    if len(line) > MAX_LINE_BYTES:
        raise ParseError("line is longer than any record can be")
    if nesting_depth(line) > MAX_NESTING_DEPTH:
        raise ParseError("line nests deeper than any record can")


def nesting_depth(line: bytes) -> int:
    """Return the deepest container nesting in `line`, the outer object counting as 1.

    Counts `{` and `[` outside strings only, honouring backslash escapes inside strings, so
    a bracket inside a string value is not nesting. Does not parse and does not check that
    brackets balance; an unbalanced line fails later in the JSON parser.
    """
    depth = deepest = 0
    in_string = escaped = False
    for b in line:
        if in_string:
            if escaped:
                escaped = False
            elif b == 0x5C:
                escaped = True
            elif b == 0x22:
                in_string = False
        elif b == 0x22:
            in_string = True
        elif b in (0x7B, 0x5B):
            depth += 1
            deepest = max(deepest, depth)
        elif b in (0x7D, 0x5D):
            depth -= 1
    return deepest


def _require_printable_ascii(line: bytes) -> None:
    """Raise `ParseError` unless every byte is in `0x20..0x7e`. Empty lines are rejected."""
    if not line or any(b < 0x20 or b > 0x7E for b in line):
        raise ParseError("line has a byte outside printable ASCII, or is empty")


_INT_PRINTED_IN_FULL = 10**21
"""JCS (ES6 number formatting) prints an integer as plain digits only below this."""


def _is_canonical_int(n: int) -> bool:
    """Return whether JCS prints `n` verbatim.

    JCS prints the shortest digits that round-trip through a double, zero-padded, so `n` is
    verbatim only when those digits are `n` itself and |n| < 10^21. `repr(float)` is that
    shortest form. Does not decide whether `n` is in the schema's range.
    """
    return abs(n) < _INT_PRINTED_IN_FULL and decimal.Decimal(repr(float(n))) == n


def _require_canonical_alphabet(obj: object) -> None:
    """Raise `ParseError` on any value outside the `canonical_bytes` alphabet, at any depth.

    Walks with an explicit stack, so depth cannot raise `RecursionError` here.
    """
    stack: list[object] = [obj]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for k, v in value.items():
                if type(k) is not str:
                    raise ParseError("object key is not a string")
                stack.append(k)
                stack.append(v)
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, str):
            if any(c > "~" for c in value):
                raise ParseError("string has a char outside ASCII 0x00..0x7e")
        elif value is None or isinstance(value, bool):
            continue
        elif type(value) is int:
            if not _is_canonical_int(value):
                raise ParseError("integer is not printed verbatim by JCS")
        else:
            raise ParseError(f"{type(value).__name__} is not in the canonical alphabet")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object from parsed pairs; a repeated key is a `ParseError`.

    The round-trip check would also catch a duplicate (the canonical form has one key), so
    removing this changes the message, not the verdict; it exists for the clearer error.
    """
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ParseError("duplicate key")
    return obj


def _integer_literal(text: str) -> int:
    """Parse an integer literal; `-0` (JCS writes `0`) and one too long to convert are `ParseError`.

    Other negatives parse, so that range is the schema's finding (check 2), as in the reference.
    The round-trip check would also catch `-0`; the explicit refusal exists for the clearer error.
    """
    if text == "-0":
        raise ParseError("-0 is not canonical")
    try:
        return int(text)
    except ValueError as e:
        raise ParseError("integer literal too long to convert") from e


def _refuse_number(text: str) -> NoReturn:
    """Reject floats, exponents, `NaN` and `Infinity`: the schema has integers only."""
    raise ParseError(f"non-integer number literal {text!r}")
