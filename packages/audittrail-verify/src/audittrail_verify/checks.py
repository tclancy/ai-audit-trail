# SPDX-License-Identifier: Apache-2.0
"""SPEC §5 checks 1–5 over an ordered file set, producing the report the CLI prints.

Checks run in order over every line and stop at the first check that fails anywhere, since
a later check on a line that failed an earlier one means nothing; `first_failing_check` is
therefore what a negative vector's `vector.expect` names. Not here: checks 6–10 (M2 and
later), which the report lists under `not_implemented` so nobody mistakes them for passed.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from audittrail_verify.canonical import NotCanonical, canonical_bytes, parse_canonical
from audittrail_verify.keyring import Keyring
from audittrail_verify.schema import ZERO_HASH, NotRecord, check_record

DOMAIN_RECORD = b"ai-audit-trail/v1/record\x00"
CHECKS_RUN = (1, 2, 3, 4, 5)
NOT_IMPLEMENTED = (6, 7, 8, 9, 10)


@dataclasses.dataclass(frozen=True, slots=True)
class Line:
    """One line of one file: where it is and its bytes without the newline."""

    file: str
    number: int
    data: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class Failure:
    """One finding: which check, where, and why."""

    check: int
    file: str
    line: int
    message: str


def verify(files: list[Path], keyring: Keyring) -> dict[str, Any]:
    """Run checks 1–5 over `files` in the order given and return the report as a dict.

    `exit` is 2 if any check failed, else 4 if the first record is not seq 0 (the prefix is
    unverified), else 0. Does not sort or deduplicate the files, does not read the sink, and
    does not apply checks 6–10.
    """
    lines, torn = _read_lines(files)
    failures = list(torn)
    records: list[dict[str, Any]] = []
    hashes: list[str] = []
    if not failures:
        failures, records = _check_1_canonical(lines)
        hashes = [_hash_of(line.data) for line in lines]
    if not failures:
        failures = _check_2_schema(lines, records)
    prefix_unverified = bool(records) and records[0]["seq"] != 0
    if not failures:
        failures = _check_3_seq(lines, records)
    if not failures:
        failures = _check_4_prev(lines, records)
    if not failures:
        failures = _check_5_signatures(lines, records, keyring)
    first = failures[0].check if failures else None
    return {
        "checks_run": list(CHECKS_RUN),
        "checks_passed": [c for c in CHECKS_RUN if first is None or c < first],
        "not_implemented": list(NOT_IMPLEMENTED),
        "failures": [dataclasses.asdict(f) for f in failures],
        "first_failing_check": first,
        "prefix_unverified": prefix_unverified,
        "records": len(records),
        "hashes": hashes if not failures else [],
        "exit": 2 if failures else 4 if prefix_unverified else 0,
    }


def _read_lines(files: list[Path]) -> tuple[list[Line], list[Failure]]:
    """Split each file into lines; an empty file or an unterminated last line is check 1."""
    lines: list[Line] = []
    failures: list[Failure] = []
    for path in files:
        data = Path(path).read_bytes()
        name = str(path)
        if not data:
            failures.append(Failure(1, name, 1, "empty file"))
            continue
        parts = data.split(b"\n")
        if parts[-1] != b"":
            failures.append(Failure(1, name, len(parts), "last line is not newline-terminated"))
        for number, raw in enumerate(parts[:-1], start=1):
            lines.append(Line(name, number, raw))
    return lines, failures


def _check_1_canonical(lines: list[Line]) -> tuple[list[Failure], list[dict[str, Any]]]:
    """Every line is its own canonical form within the §3.1 and §3.2 bounds."""
    failures: list[Failure] = []
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            records.append(parse_canonical(line.data))
        except NotCanonical as e:
            failures.append(Failure(1, line.file, line.number, str(e)))
    return failures, records


def _check_2_schema(lines: list[Line], records: list[dict[str, Any]]) -> list[Failure]:
    """Every record has the §3.1 field set and values and the §3.4 per-type values."""
    failures: list[Failure] = []
    for line, record in zip(lines, records, strict=True):
        try:
            check_record(record)
        except NotRecord as e:
            failures.append(Failure(2, line.file, line.number, str(e)))
    return failures


def _check_3_seq(lines: list[Line], records: list[dict[str, Any]]) -> list[Failure]:
    """`seq` rises by exactly 1 from the first record on, across files. Does not require 0."""
    failures: list[Failure] = []
    for i in range(1, len(records)):
        if records[i]["seq"] != records[i - 1]["seq"] + 1:
            failures.append(
                Failure(3, lines[i].file, lines[i].number, "seq is not the previous seq plus 1")
            )
    return failures


def _check_4_prev(lines: list[Line], records: list[dict[str, Any]]) -> list[Failure]:
    """`prev` is the hash of the previous line; the zero-hash exactly at `seq == 0`."""
    failures: list[Failure] = []
    for i, (line, record) in enumerate(zip(lines, records, strict=True)):
        if (record["prev"] == ZERO_HASH) != (record["seq"] == 0):
            failures.append(Failure(4, line.file, line.number, "zero-hash prev exactly at seq 0"))
        elif i > 0 and record["prev"] != _hash_of(lines[i - 1].data):
            failures.append(
                Failure(4, line.file, line.number, "prev is not the hash of the previous line")
            )
    return failures


def _check_5_signatures(
    lines: list[Line], records: list[dict[str, Any]], keyring: Keyring
) -> list[Failure]:
    """Each `sig` verifies under its kid's gate key within the key's window (§3.3, §3.8).

    A `rotation` record at seq k must be where the old key's window ends, the next record
    must be signed by a key whose window starts at k+1 and whose kid the rotation names in
    `cart_hash`, and the kid never changes between consecutive records otherwise.
    """
    failures: list[Failure] = []
    for i, (line, record) in enumerate(zip(lines, records, strict=True)):
        problem = _signature_problem(record, keyring)
        if problem is None and i > 0:
            problem = _succession_problem(records[i - 1], record, keyring)
        if problem is not None:
            failures.append(Failure(5, line.file, line.number, problem))
    return failures


def _signature_problem(record: dict[str, Any], keyring: Keyring) -> str | None:
    """Return why this record's signature does not verify, or None."""
    if record["log_id"] != keyring.log_id:
        return "record is not from the keyring's log"
    key = keyring.keys.get(record["kid"])
    if key is None:
        return "kid is not in the keyring"
    if key.role != "gate":
        return "kid is not a gate key"
    if not key.covers(record["seq"]):
        return "seq is outside the kid's window"
    encoded = record["sig"].removeprefix("ed25519:")
    signature = base64.b64decode(encoded, validate=True)
    if base64.b64encode(signature).decode("ascii") != encoded:
        return "sig is not canonical base64"
    body = {k: v for k, v in record.items() if k != "sig"}
    try:
        key.pub.verify(signature, DOMAIN_RECORD + canonical_bytes(body))
    except InvalidSignature:
        return "signature does not verify"
    if record["type"] == "rotation" and key.valid_to_seq != record["seq"]:
        return "rotation record is not at the end of its key's window"
    return None


def _succession_problem(
    previous: dict[str, Any], record: dict[str, Any], keyring: Keyring
) -> str | None:
    """Return why `record` may not follow `previous` under the keyring's windows, or None."""
    if previous["type"] == "rotation":
        new_key = keyring.keys[record["kid"]]
        named = "sha256:" + hashlib.sha256(f"new_kid={record['kid']}".encode("ascii")).hexdigest()
        if record["kid"] == previous["kid"]:
            return "record after a rotation is signed by the old key"
        if new_key.valid_from_seq != previous["seq"] + 1:
            return "new key's window does not start right after the rotation"
        if previous["cart_hash"] != named:
            return "rotation record does not name the kid that signed next"
    elif record["kid"] != previous["kid"]:
        return "kid changed without a rotation record"
    return None


def _hash_of(data: bytes) -> str:
    """`sha256:<hex>` of a line's bytes without its newline (SPEC §3.2)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
