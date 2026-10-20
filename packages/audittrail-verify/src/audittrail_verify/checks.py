# SPDX-License-Identifier: Apache-2.0
"""SPEC §5 checks 1–5 over an ordered file set, producing the report the CLI prints.

Checks run in order and each stops at its first failure, since a later check on a line that
failed an earlier one means nothing and a report is about the first thing wrong;
`first_failing_check` is therefore what a negative vector's `vector.expect` names. Not here:
checks 6–10 (M2 and later), which the report lists under `not_implemented` so nobody
mistakes them for passed, and which hold the exit at 4 until they run (SPEC §5).
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
    """One line of one file: where it is and its bytes without the newline. Not parsed."""

    file: str
    number: int
    data: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class Failure:
    """One finding: which check, where, and why. The first of its check; never a list."""

    check: int
    file: str
    line: int
    message: str


def verify(files: list[Path], keyring: Keyring) -> dict[str, Any]:
    """Run checks 1–5 over `files` in the order given and return the report as a dict.

    `exit` is 2 if a check failed, else 4 if the first record is not seq 0 (the prefix is
    unverified) or any check is listed in `not_implemented`, else 0. Never 0 while a check
    is skipped. Does not sort or deduplicate the files, does not read the sink, and does not
    apply checks 6–10.
    """
    lines, records, failure = _check_1_read_canonical(files)
    if failure is None:
        failure = _check_2_schema(lines, records)
    prefix_unverified = failure is None and bool(records) and records[0]["seq"] != 0
    if failure is None:
        failure = _check_3_seq(lines, records)
    if failure is None:
        failure = _check_4_prev(lines, records)
    if failure is None:
        failure = _check_5_signatures(lines, records, keyring)
    first = None if failure is None else failure.check
    return {
        "checks_run": list(CHECKS_RUN),
        "checks_passed": [c for c in CHECKS_RUN if first is None or c < first],
        "not_implemented": list(NOT_IMPLEMENTED),
        "failures": [] if failure is None else [dataclasses.asdict(failure)],
        "first_failing_check": first,
        "prefix_unverified": prefix_unverified,
        "records": len(records),
        "hashes": [_hash_of(line.data) for line in lines] if failure is None else [],
        "exit": 2 if failure is not None else 4 if prefix_unverified or NOT_IMPLEMENTED else 0,
    }


def _check_1_read_canonical(
    files: list[Path],
) -> tuple[list[Line], list[dict[str, Any]], Failure | None]:
    """Read and parse line by line, stopping at the first line that is not canonical.

    An empty file and a last line without its newline are check 1 too. Returns the lines
    and records up to the failure; does not read past it.
    """
    lines: list[Line] = []
    records: list[dict[str, Any]] = []
    for path in files:
        data = Path(path).read_bytes()
        name = str(path)
        if not data:
            return lines, records, Failure(1, name, 1, "empty file")
        parts = data.split(b"\n")
        for number, raw in enumerate(parts[:-1], start=1):
            try:
                records.append(parse_canonical(raw))
            except NotCanonical as e:
                return lines, records, Failure(1, name, number, str(e))
            lines.append(Line(name, number, raw))
        if parts[-1] != b"":
            return (
                lines,
                records,
                Failure(1, name, len(parts), "last line is not newline-terminated"),
            )
    return lines, records, None


def _check_2_schema(lines: list[Line], records: list[dict[str, Any]]) -> Failure | None:
    """First record without the §3.1 field set and values or the §3.4 per-type values."""
    for line, record in zip(lines, records, strict=True):
        try:
            check_record(record)
        except NotRecord as e:
            return Failure(2, line.file, line.number, str(e))
    return None


def _check_3_seq(lines: list[Line], records: list[dict[str, Any]]) -> Failure | None:
    """First record whose `seq` is not the previous plus 1. Does not require the first to be 0."""
    for i in range(1, len(records)):
        if records[i]["seq"] != records[i - 1]["seq"] + 1:
            return Failure(3, lines[i].file, lines[i].number, "seq is not the previous seq plus 1")
    return None


def _check_4_prev(lines: list[Line], records: list[dict[str, Any]]) -> Failure | None:
    """First record whose `prev` is not the previous line's hash, or zero-hash not at seq 0.

    The first record of the set is held to the genesis rule only; its predecessor is unseen.
    """
    for i, (line, record) in enumerate(zip(lines, records, strict=True)):
        if (record["prev"] == ZERO_HASH) != (record["seq"] == 0):
            return Failure(4, line.file, line.number, "zero-hash prev exactly at seq 0")
        if i > 0 and record["prev"] != _hash_of(lines[i - 1].data):
            return Failure(4, line.file, line.number, "prev is not the hash of the previous line")
    return None


def _check_5_signatures(
    lines: list[Line], records: list[dict[str, Any]], keyring: Keyring
) -> Failure | None:
    """First record whose `sig` does not verify under its kid's gate key within the window.

    A `rotation` record at seq k must be where the old key's window ends, the next record
    must be signed by a key whose window starts at k+1 and whose kid the rotation names in
    `cart_hash`, and the kid never changes between consecutive records otherwise. Does not
    apply retired-key grace; that is a consumer rule (§6), not a verifier check.
    """
    for i, (line, record) in enumerate(zip(lines, records, strict=True)):
        problem = _signature_problem(record, keyring)
        if problem is None and i > 0:
            problem = _succession_problem(records[i - 1], record, keyring)
        if problem is not None:
            return Failure(5, line.file, line.number, problem)
    return None


def _signature_problem(record: dict[str, Any], keyring: Keyring) -> str | None:
    """Return why this record's signature does not verify, or None. Looks at no neighbour."""
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
    """Return why `record` may not follow `previous` under the keyring's windows, or None.

    Assumes both records already passed `_signature_problem`, so both kids are in the ring.
    """
    if previous["type"] == "rotation":
        if record["kid"] == previous["kid"]:
            return "record after a rotation is signed by the old key"
        if keyring.keys[record["kid"]].valid_from_seq != previous["seq"] + 1:
            return "new key's window does not start right after the rotation"
        named = hashlib.sha256(f"new_kid={record['kid']}".encode("ascii")).hexdigest()
        if previous["cart_hash"] != "sha256:" + named:
            return "rotation record does not name the kid that signed next"
    elif record["kid"] != previous["kid"]:
        return "kid changed without a rotation record"
    return None


def _hash_of(data: bytes) -> str:
    """`sha256:<hex>` of a line's bytes without its newline (SPEC §3.2). Does not strip one."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
