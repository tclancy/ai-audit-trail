# SPDX-License-Identifier: Apache-2.0
"""The keyring file for the verifier (SPEC §3.8): public keys by kid with seq windows.

Loaded strictly from one canonical line. Independent of `audittrail.keyring` by design.
Nothing here verifies a signature; `checks.py` does, with the keys this returns.
"""

from __future__ import annotations

import base64
import dataclasses
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audittrail_verify.canonical import NotCanonical, parse_object
from audittrail_verify.schema import STRING_RULES

_KEY_FIELDS = frozenset({"alg", "kid", "pub", "role", "valid_from_seq", "valid_to_seq"})
_RING_FIELDS = frozenset({"keys", "log_id", "v"})
_ROLES = frozenset({"gate", "sink"})
_PUB = re.compile(r"[A-Za-z0-9+/]{43}=", re.ASCII)
_SEQ_LIMIT = 2**53


class BadKeyring(ValueError):
    """The keyring file is not SPEC §3.8."""


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Key:
    """One keyring entry; `pub` is the key object, never its bytes or text."""

    kid: str
    pub: Ed25519PublicKey
    role: str
    valid_from_seq: int
    valid_to_seq: int | None

    def covers(self, seq: int) -> bool:
        """Return whether `seq` is inside the window. Ignores the role."""
        return self.valid_from_seq <= seq and (
            self.valid_to_seq is None or seq <= self.valid_to_seq
        )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Keyring:
    """A loaded keyring: `log_id` and keys by kid. Verifies nothing itself."""

    log_id: str
    keys: dict[str, Key]


def load_keyring(path: Path) -> Keyring:
    """Read and validate a keyring file: one canonical line plus one newline, every rule of §3.8.

    Refuses any other field set, `v != 1`, an `alg` other than `ed25519`, a `pub` that is not
    the canonical base64 of 32 bytes, a role outside gate/sink, a window outside `[0, 2^53)`
    or with `from > to`, a repeated kid, a repeated pub, and no keys. The record-line length
    bound does not apply (SPEC §3.7). Does not check who may write the file.
    """
    data = Path(path).read_bytes()
    if not data.endswith(b"\n") or b"\n" in data[:-1]:
        raise BadKeyring("not one newline-terminated line")
    try:
        obj = parse_object(data[:-1])
    except NotCanonical as e:
        raise BadKeyring(f"not a canonical JCS object: {e}") from e
    if set(obj) != _RING_FIELDS:
        raise BadKeyring("field set is not SPEC §3.8")
    if type(obj["v"]) is not int or obj["v"] != 1:
        raise BadKeyring("v is not 1")
    log_id = obj["log_id"]
    if type(log_id) is not str or STRING_RULES["log_id"].fullmatch(log_id) is None:
        raise BadKeyring("log_id does not match its rule")
    if type(obj["keys"]) is not list or not obj["keys"]:
        raise BadKeyring("keys is not a non-empty list")
    keys: dict[str, Key] = {}
    pubs: set[bytes] = set()
    for entry in obj["keys"]:
        key = _key(entry)
        if key.kid in keys:
            raise BadKeyring("a kid is listed twice")
        raw = key.pub.public_bytes_raw()
        if raw in pubs:
            raise BadKeyring("a pub is listed under two kids")
        keys[key.kid] = key
        pubs.add(raw)
    return Keyring(log_id=log_id, keys=keys)


def _key(entry: Any) -> Key:
    """Validate one entry. Does not check uniqueness."""
    if not isinstance(entry, dict) or set(entry) != _KEY_FIELDS:
        raise BadKeyring("key entry field set is not SPEC §3.8")
    if entry["alg"] != "ed25519":
        raise BadKeyring("alg is not ed25519")
    kid = entry["kid"]
    if type(kid) is not str or STRING_RULES["kid"].fullmatch(kid) is None:
        raise BadKeyring("kid does not match its rule")
    role = entry["role"]
    if type(role) is not str or role not in _ROLES:
        raise BadKeyring("role is not gate or sink")
    valid_from_seq = _seq(entry["valid_from_seq"])
    valid_to_seq = None if entry["valid_to_seq"] is None else _seq(entry["valid_to_seq"])
    if valid_to_seq is not None and valid_from_seq > valid_to_seq:
        raise BadKeyring("window is empty")
    return Key(
        kid=kid,
        pub=_public_key(entry["pub"]),
        role=role,
        valid_from_seq=valid_from_seq,
        valid_to_seq=valid_to_seq,
    )


def _seq(value: Any) -> int:
    """Return `value` if it is a non-bool int in `[0, 2^53)`, else `BadKeyring`. Ignores order."""
    if type(value) is not int or not 0 <= value < _SEQ_LIMIT:
        raise BadKeyring("window bound is not an integer in [0, 2^53)")
    return value


def _public_key(text: Any) -> Ed25519PublicKey:
    """Decode canonical standard base64 of exactly 32 bytes, else `BadKeyring`. No other form."""
    if type(text) is not str or _PUB.fullmatch(text) is None:
        raise BadKeyring("pub is not base64 of 32 bytes")
    raw = base64.b64decode(text, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        raise BadKeyring("pub is not canonical base64 of 32 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as e:
        raise BadKeyring("pub is not an Ed25519 public key") from e
