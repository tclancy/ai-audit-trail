# SPDX-License-Identifier: Apache-2.0
"""The keyring file (SPEC §3.8): pinned public keys by `kid` with `seq` windows and roles.

Loads strictly: the file is one canonical JCS line, every field is checked, and a key that
is not a 32-byte Ed25519 public key is refused. Verifies record signatures against the gate
key for a record's `kid` within that key's window. Holds public keys only; nothing here signs,
reads a private key, or applies retired-key grace (SPEC §6 rule 2's `grace_s` is I14, M2).
"""

from __future__ import annotations

import base64
import dataclasses
import re
from pathlib import Path
from typing import Any, NoReturn, final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audittrail.record import (
    ParseError,
    Record,
    SchemaError,
    canonical_bytes,
    parse_object,
    validate_string_field,
)
from audittrail.signing import DOMAIN_RECORD

KEY_FIELDS: frozenset[str] = frozenset(
    {"alg", "kid", "pub", "role", "valid_from_seq", "valid_to_seq"}
)
"""SPEC §3.8: the exact field set of one key entry."""

KEYRING_FIELDS: frozenset[str] = frozenset({"keys", "log_id", "v"})
"""SPEC §3.8: the exact field set of the keyring object."""

ROLES: frozenset[str] = frozenset({"gate", "sink"})
"""SPEC §3.8: a key signs records (`gate`) or anchor receipts (`sink`), never both."""

_PUB = re.compile(r"[A-Za-z0-9+/]{43}=", re.ASCII)
"""Standard base64 with padding of exactly 32 bytes."""

_SEQ_LIMIT = 2**53


class KeyringError(ValueError):
    """A keyring file that is not SPEC §3.8, a kid it cannot answer for, or a bad signature."""


@final
@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Key:
    """One validated keyring entry. `pub` is the key object, never bytes or text."""

    kid: str
    pub: Ed25519PublicKey
    role: str
    valid_from_seq: int
    valid_to_seq: int | None

    def covers(self, seq: int) -> bool:
        """Return whether `seq` lies in this key's window. Ignores retirement."""
        return self.valid_from_seq <= seq and (
            self.valid_to_seq is None or seq <= self.valid_to_seq
        )


@final
class Keyring:
    """Public keys for one `log_id`. Built only by `from_bytes` or `load`; final; not copyable."""

    __slots__ = ("_keys", "_log_id")

    _keys: dict[str, Key]
    _log_id: str

    def __init__(self) -> None:
        """Refuse direct construction; a keyring comes only from validated bytes."""
        raise TypeError("Keyring is built by Keyring.from_bytes or Keyring.load")

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass, so none can widen a window or add a role."""
        raise TypeError("Keyring is final")

    def __reduce__(self) -> NoReturn:
        """Refuse the copy and persistence protocols; a keyring is reloaded from its file."""
        raise TypeError("Keyring cannot be copied or serialized; reload it from the file")

    def __repr__(self) -> str:
        """Name the log and the kids only."""
        return f"Keyring(log_id={self._log_id!r}, kids={sorted(self._keys)!r})"

    @classmethod
    def from_bytes(cls, line: bytes) -> Keyring:
        """Build a keyring from one canonical JCS line, without its trailing newline.

        Raises `KeyringError` on anything that is not exactly SPEC §3.8: non-canonical bytes,
        any other field set, `v != 1`, an `alg` other than `ed25519`, a `pub` that is not the
        standard base64 of 32 bytes, a role outside `ROLES`, a window outside `[0, 2^53)` or
        with `valid_from_seq > valid_to_seq`, a repeated `kid`, a repeated `pub` under another
        kid (retiring one name would not retire the key, issue #19), or no keys at all. Does
        not check that the file is readable by the gate's identity; that is deployment's job.
        """
        if type(line) is not bytes:
            raise KeyringError("keyring is not bytes")
        try:
            obj = parse_object(line)
        except ParseError as e:
            raise KeyringError(f"keyring is not a canonical JCS object: {e}") from e
        if set(obj) != KEYRING_FIELDS:
            raise KeyringError("keyring field set is not SPEC §3.8")
        if type(obj["v"]) is not int or obj["v"] != 1:
            raise KeyringError("keyring v is not 1")
        log_id = obj["log_id"]
        _validate_field("log_id", log_id)
        if type(obj["keys"]) is not list or not obj["keys"]:
            raise KeyringError("keyring keys is not a non-empty list")
        keys: dict[str, Key] = {}
        pubs: set[bytes] = set()
        for entry in obj["keys"]:
            key = _parse_key(entry)
            if key.kid in keys:
                raise KeyringError("keyring repeats a kid")
            if key.pub.public_bytes_raw() in pubs:
                raise KeyringError("keyring lists one pub under two kids")
            keys[key.kid] = key
            pubs.add(key.pub.public_bytes_raw())
        self = object.__new__(cls)
        object.__setattr__(self, "_keys", keys)
        object.__setattr__(self, "_log_id", log_id)
        return self

    @classmethod
    def load(cls, path: Path) -> Keyring:
        """Read a keyring file: exactly one canonical line followed by one newline.

        Follows symlinks and lets OS errors propagate as they are; does not check who owns
        the file or who may write it (SPEC §3.8 says never the gate; that is deployment's job).
        """
        data = Path(path).read_bytes()
        if not data.endswith(b"\n") or b"\n" in data[:-1]:
            raise KeyringError("keyring file is not one newline-terminated line")
        return cls.from_bytes(data[:-1])

    @property
    def log_id(self) -> str:
        """The log this keyring answers for (SPEC §3.8). Not compared with anything here."""
        return self._log_id

    def retired(self, kid: str) -> bool:
        """Return whether `kid` has a `valid_to_seq`. Unknown kid is `KeyringError`; no grace."""
        return self._key(kid).valid_to_seq is not None

    def check_record_signature(self, record: Record) -> None:
        """Raise `KeyringError` unless `record.sig` verifies under its `kid`'s gate key.

        Requires the record's `log_id` to be this keyring's, the key's role to be `gate`,
        and the key's window to cover `record.seq`, then verifies the Ed25519 signature over
        the record domain and the body without `sig` (SPEC §3.2, §5 check 5). The `sig` text
        must be the canonical base64 of the signature bytes, so one signature has one line.
        Does not apply retired-key grace and does not check anything else about the record.
        """
        if type(record) is not Record:
            raise TypeError("record: not a Record")
        if record.log_id != self._log_id:
            raise KeyringError("record is from another log")
        key = self._key(record.kid)
        if key.role != "gate":
            raise KeyringError("kid is not a gate key")
        if not key.covers(record.seq):
            raise KeyringError("seq is outside the kid's window")
        fields = dataclasses.asdict(record)
        signature = _signature_bytes(fields.pop("sig"))
        try:
            key.pub.verify(signature, DOMAIN_RECORD + canonical_bytes(fields))
        except InvalidSignature as e:
            raise KeyringError("signature does not verify") from e

    def _key(self, kid: str) -> Key:
        """Return the entry for `kid`; a kid outside its rule or the ring is `KeyringError`."""
        _validate_field("kid", kid)
        try:
            return self._keys[kid]
        except KeyError as e:
            raise KeyringError("kid is not in the keyring") from e


def _signature_bytes(text: str) -> bytes:
    """Decode `ed25519:<base64>` to 64 bytes; `KeyringError` unless the text re-encodes to itself.

    The §3.1 regex fixes the length and alphabet; this refuses the trailing-bit variants that
    decode to the same bytes, which would be a second valid line for one signature.
    """
    encoded = text.removeprefix("ed25519:")
    raw = base64.b64decode(encoded, validate=True)
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise KeyringError("sig is not canonical base64")
    return raw


def _validate_field(name: str, value: object) -> None:
    """Apply the record rule of the same name; its `SchemaError` becomes `KeyringError`. No more."""
    try:
        validate_string_field(name, value)
    except SchemaError as e:
        raise KeyringError(f"keyring {e}") from e


def _parse_key(entry: object) -> Key:
    """Validate one key entry (SPEC §3.8) and build its `Key`. Does not check uniqueness."""
    if not isinstance(entry, dict) or set(entry) != KEY_FIELDS:
        raise KeyringError("key entry field set is not SPEC §3.8")
    if entry["alg"] != "ed25519":
        raise KeyringError("key alg is not ed25519")
    _validate_field("kid", entry["kid"])
    if type(entry["role"]) is not str or entry["role"] not in ROLES:
        raise KeyringError("key role is not gate or sink")
    valid_from_seq = _seq(entry["valid_from_seq"])
    valid_to_seq = None if entry["valid_to_seq"] is None else _seq(entry["valid_to_seq"])
    if valid_to_seq is not None and valid_from_seq > valid_to_seq:
        raise KeyringError("key window is empty")
    return Key(
        kid=entry["kid"],
        pub=_public_key(entry["pub"]),
        role=entry["role"],
        valid_from_seq=valid_from_seq,
        valid_to_seq=valid_to_seq,
    )


def _seq(value: Any) -> int:
    """Return `value` if it is a non-bool int in `[0, 2^53)`; else `KeyringError`. Ignores order."""
    if type(value) is not int or not 0 <= value < _SEQ_LIMIT:
        raise KeyringError("key window bound is not an integer in [0, 2^53)")
    return value


def _public_key(text: object) -> Ed25519PublicKey:
    """Decode the standard base64 of exactly 32 bytes into a public key; else `KeyringError`.

    The text must re-encode to itself, so non-canonical trailing bits are refused too.
    """
    if type(text) is not str or _PUB.fullmatch(text) is None:
        raise KeyringError("key pub is not base64 of 32 bytes")
    raw = base64.b64decode(text, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        raise KeyringError("key pub is not canonical base64 of 32 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as e:
        raise KeyringError("key pub is not an Ed25519 public key") from e
