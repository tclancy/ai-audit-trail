# SPDX-License-Identifier: Apache-2.0
"""Canonical bytes for the verifier: SPEC §3.1 bounds, §3.2 round trip, §5 check 1.

The second implementation of canonical form in this repository, by design (CLAUDE.md rule 4);
the vectors keep it in step with `tools/vectors-go`. Within the record alphabet (printable
ASCII strings, integers JCS prints verbatim, `true`/`false`/`null`, arrays, objects) RFC 8785
is compact JSON with keys sorted by code point, which is what the standard library writes.
Nothing here knows the record fields; that is `schema.py`.
"""

from __future__ import annotations

import decimal
import json
from typing import Any, NoReturn

MAX_NESTING_DEPTH = 5
"""SPEC §3.1: deeper than this, counting the outer object as 1, is not a record line."""

_STRING_MAX: dict[str, int] = {
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
_INT_FIELDS = ("v", "seq", "mono", "reason_v", "since_hb")
_MAX_INT_DIGITS = len(str(2**53 - 1))


def _max_line_bytes() -> int:
    """SPEC §3.2's derivation over the 25 fields; never a hand-set number."""
    names = sorted([*_STRING_MAX, *_INT_FIELDS])
    total = 2 + len(names) - 1
    for name in names:
        total += len(name) + 3
        if name in _STRING_MAX:
            total += _STRING_MAX[name] + 2
        else:
            total += 1 if name == "v" else _MAX_INT_DIGITS
    return total


MAX_LINE_BYTES = _max_line_bytes()
"""SPEC §3.2: 1398 for schema 1; a longer line is not a record line."""


class NotCanonical(ValueError):
    """Check 1: the bytes are not printable ASCII within bounds, or not their own JCS form."""


def parse_canonical(line: bytes) -> dict[str, Any]:
    """Parse one line (no trailing newline) and require `canonical_bytes(result) == line`.

    Refuses: empty input, any byte outside `0x20..0x7e`, a line over `MAX_LINE_BYTES` or
    nested past `MAX_NESTING_DEPTH` (both counted before parsing), duplicate keys, any
    non-integer number, `-0`, a non-object top level, and any byte-level difference from
    canonical form. Does not check the field set or any value against its rule.
    """
    if len(line) > MAX_LINE_BYTES:
        raise NotCanonical("longer than any record line")
    return parse_object(line)


def parse_object(line: bytes) -> dict[str, Any]:
    """Parse one JCS object that is not a record line: the depth bound, not the length bound.

    SPEC §3.7 applies the depth bound to every object the verifier reads and the length bound
    to record lines only, so keyrings and receipts come through here. Otherwise `parse_canonical`.
    """
    if not line or any(b < 0x20 or b > 0x7E for b in line):
        raise NotCanonical("empty, or a byte outside printable ASCII")
    if nesting_depth(line) > MAX_NESTING_DEPTH:
        raise NotCanonical("nested deeper than the bound")
    try:
        obj = json.loads(
            line.decode("ascii"),
            object_pairs_hook=_no_duplicate_keys,
            parse_float=_refuse,
            parse_constant=_refuse,
            parse_int=_integer,
        )
    except (ValueError, RecursionError) as e:
        raise NotCanonical(f"not strict JSON: {e}") from e
    if not isinstance(obj, dict):
        raise NotCanonical("not a JSON object")
    if canonical_bytes(obj) != line:
        raise NotCanonical("not its own canonical form")
    return obj


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Return the JCS bytes of `obj` within the record alphabet; `NotCanonical` outside it.

    Does not append a newline and does not check the field set.
    """
    _require_alphabet(obj)
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except RecursionError as e:
        raise NotCanonical("nested too deeply to serialize") from e
    return text.encode("ascii")


def nesting_depth(line: bytes) -> int:
    """Count SPEC §3.1 structural depth: brackets outside string literals, escapes honoured.

    Does not parse and does not check that brackets balance.
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


def _require_alphabet(obj: object) -> None:
    """Refuse any value JCS would print differently from the standard library, at any depth."""
    stack: list[object] = [obj]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if type(key) is not str:
                    raise NotCanonical("object key is not a string")
                stack.append(key)
                stack.append(item)
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, str):
            if any(c > "~" for c in value):
                raise NotCanonical("string char outside ASCII 0x00..0x7e")
        elif value is None or isinstance(value, bool):
            continue
        elif type(value) is int:
            if abs(value) >= 10**21 or decimal.Decimal(repr(float(value))) != value:
                raise NotCanonical("integer JCS would not print verbatim")
        else:
            raise NotCanonical(f"{type(value).__name__} is outside the canonical alphabet")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object; a repeated key is `NotCanonical`. Does not sort."""
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise NotCanonical("duplicate key")
    return obj


def _integer(text: str) -> int:
    """Parse an integer literal; `-0` and an unconvertible literal are `NotCanonical`.

    Other negatives parse and are the schema's finding, as in the Go reference.
    """
    if text == "-0":
        raise NotCanonical("-0")
    try:
        return int(text)
    except ValueError as e:
        raise NotCanonical("integer literal too long") from e


def _refuse(text: str) -> NoReturn:
    """Floats, exponents, NaN and Infinity are not in the schema."""
    raise NotCanonical(f"non-integer number {text!r}")
