# SPDX-License-Identifier: Apache-2.0
"""Record schema for the verifier: SPEC §3.1 field rules and §3.4 per-type values, check 2.

Independent of `audittrail.record` by design. Nothing here parses bytes, hashes, or looks at
a neighbouring record; genesis `prev` is check 4 and lives in `checks.py`.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

ZERO_HASH = "sha256:" + "0" * 64
HEARTBEAT_CART_HASH = "sha256:" + hashlib.sha256(b"audittrail-heartbeat").hexdigest()

_SHA256 = r"sha256:[0-9a-f]{64}"
_ULID = r"[0-9A-HJKMNP-TV-Z]{26}"
_ID = r"[a-z0-9-]{1,32}"

STRING_RULES: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern, re.ASCII)
    for name, pattern in {
        "log_id": _ID,
        "type": r"boot|decision|heartbeat|anchor|rotation",
        "boot": _ULID,
        "ts": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
        "request_id": _ULID,
        "actor": r"spiffe://[a-z0-9.-]{1,64}/[a-z0-9/_.-]{1,128}",
        "app": _ID,
        "template_hash": _SHA256,
        "model_id": r"[A-Za-z0-9._:-]{1,64}",
        "policy_hash": _SHA256,
        "input_ref": _SHA256,
        "cart_hash": _SHA256,
        "oracle": r"match|mismatch|unavailable|timeout|not_consulted",
        "oracle_ref": _SHA256,
        "decision": r"approve|reject",
        "reason": r"R_[A-Z0-9_]{1,40}",
        "canary": r"pass|fail|not_run",
        "kid": _ID,
        "prev": _SHA256,
        "sig": r"ed25519:[A-Za-z0-9+/]{86}==",
    }.items()
}
"""SPEC §3.1, one anchored pattern per string field (enums written as alternations)."""

INT_FIELDS: frozenset[str] = frozenset({"v", "seq", "mono", "reason_v", "since_hb"})
FIELDS: frozenset[str] = frozenset(STRING_RULES) | INT_FIELDS
_INT_LIMIT = 2**53

_FIXED: dict[str, dict[str, object]] = {
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
"""SPEC §3.1 and §3.4: the values one record's `type` fixes."""


class NotRecord(ValueError):
    """Check 2: wrong field set, a value outside its rule, or a §3.4 per-type value. Not chain."""


def check_record(obj: dict[str, Any]) -> None:
    """Raise `NotRecord` unless `obj` is a schema-valid record. Does not check `prev` or `sig`."""
    if set(obj) != FIELDS:
        raise NotRecord("field set is not SPEC §3.1")
    for name, rule in STRING_RULES.items():
        value = obj[name]
        if type(value) is not str or rule.fullmatch(value) is None:
            raise NotRecord(f"{name}: not a string matching its rule")
    for name in INT_FIELDS:
        value = obj[name]
        if type(value) is not int or not 0 <= value < _INT_LIMIT:
            raise NotRecord(f"{name}: not an integer in [0, 2^53)")
    if obj["v"] != 1:
        raise NotRecord("v: not 1")
    for name, want in _FIXED[obj["type"]].items():
        if obj[name] != want:
            raise NotRecord(f"{name}: a {obj['type']} record fixes this value")
    if obj["type"] == "boot" and obj["reason"] not in ("R_BOOT", "R_BOOT_TRUNCATED"):
        raise NotRecord("reason: a boot record carries R_BOOT or R_BOOT_TRUNCATED")
    if obj["seq"] == 0 and (obj["type"] != "boot" or obj["cart_hash"] != ZERO_HASH):
        raise NotRecord("seq 0 must be a boot record with the zero-hash cart_hash")
