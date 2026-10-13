# SPDX-License-Identifier: Apache-2.0
"""`Approved`: the only form an approval takes on the consumer side (SPEC §6 rules 1–7, I1).

`Approved.from_wire` takes receipt bytes and refuses them unless every rule holds, in order:
canonical and approve (1), signed by a current gate key (2), this log (3), this app (4), bound
to the Candidate in hand (5), fresh (6), and never acted on before (7). Any failure is
`GateError` and nothing is recorded as seen. Not here: rule 8, the consumer's own action log,
which is the consumer's; retired-key grace (`grace_s`, I14, M2), until which a retired key
is refused outright; and the freshness lower bound discussed in issue #17, so a `ts` ahead of
`now` passes rule 6 as the spec currently writes it.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from datetime import UTC, datetime, timedelta
from typing import NoReturn, Protocol, final, runtime_checkable

from audittrail.keyring import Keyring, KeyringError
from audittrail.record import Record, RecordError, SchemaError, validate_string_field

_AGE_LIMIT = 2**53
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class GateError(Exception):
    """A receipt that authorizes nothing: one of SPEC §6 rules 1–7 did not hold."""


@runtime_checkable
class Candidate(Protocol):
    """What a consumer is about to act on: a strictly parsed, typed request (SPEC §2, §8).

    The caller's own parser builds it; `audittrail` never sees the request's text, only
    these bytes, and only to hash them against `cart_hash`.
    """

    def canonical_bytes(self) -> bytes:
        """Return the JCS bytes the gate hashed into `cart_hash`."""
        ...


@runtime_checkable
class SeenStore(Protocol):
    """Durable memory of `request_id`s already acted on (SPEC §6 rule 7)."""

    def first_use(self, request_id: str) -> bool:
        """Record `request_id` and return True if it was never seen; False if it was."""
        ...


@final
class InMemorySeenStore:
    """A `SeenStore` for one process, for tests and the stubs. Forgets everything at exit."""

    __slots__ = ("_lock", "_seen")

    def __init__(self) -> None:
        """Start empty."""
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass."""
        raise TypeError("InMemorySeenStore is final")

    def first_use(self, request_id: str) -> bool:
        """Record `request_id` under a lock; the first caller for an id gets True, others False."""
        validate_string_field("request_id", request_id)
        with self._lock:
            if request_id in self._seen:
                return False
            self._seen.add(request_id)
            return True


@final
class Approved:
    """A receipt that passed SPEC §6 rules 1–7. Built only by `from_wire`; final; immutable."""

    __slots__ = ("entry", "line")

    entry: Record
    line: bytes

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Refuse direct construction; `from_wire` is the only way in."""
        raise TypeError("Approved is built only by Approved.from_wire")

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass, so none can skip a rule."""
        raise TypeError("Approved is final")

    def __reduce__(self) -> NoReturn:
        """Refuse the copy and persistence protocols; an approval is for this process, now."""
        raise TypeError("Approved cannot be copied or serialized")

    def __setattr__(self, name: str, value: object) -> NoReturn:
        """Refuse assignment after construction."""
        raise TypeError("Approved is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        """Refuse deletion."""
        raise TypeError("Approved is immutable")

    def __repr__(self) -> str:
        """Name the log, seq, and request only."""
        e = self.entry
        return f"Approved(log_id={e.log_id!r}, seq={e.seq!r}, request_id={e.request_id!r})"

    @classmethod
    def from_wire(
        cls,
        line: bytes,
        keyring: Keyring,
        *,
        candidate: Candidate,
        app: str,
        log_id: str,
        max_age_s: int,
        seen: SeenStore,
    ) -> Approved:
        """Check SPEC §6 rules 1–7 in order on `line` and return the approval, else `GateError`.

        `app` and `log_id` are validated against their §3.1 rules and `max_age_s` must be a
        positive int below 2^53 (`SchemaError` otherwise); a `keyring`, `candidate`, or `seen`
        of the wrong shape is a `TypeError`. These are caller bugs, not refusals. `seen` is
        asked last, so a receipt refused on any other rule leaves its `request_id` unseen.
        Does not write the consumer's action log (rule 8).
        """
        _check_parameters(keyring, candidate, app, log_id, max_age_s, seen)
        record = _rule_1_canonical_approve(line)
        _rule_2_signed_by_current_gate_key(record, keyring)
        _rule_3_this_log(record, keyring, log_id)
        _rule_4_this_app(record, app)
        _rule_5_bound_to_candidate(record, candidate)
        _rule_6_fresh(record, max_age_s)
        _rule_7_unseen(record, seen)
        self = object.__new__(cls)
        object.__setattr__(self, "entry", record)
        object.__setattr__(self, "line", line)
        return self


def _check_parameters(
    keyring: object, candidate: object, app: object, log_id: object, max_age_s: object, seen: object
) -> None:
    """Type-check the binding parameters before any rule runs. Does not look at the line."""
    if type(keyring) is not Keyring:
        raise TypeError("keyring: not a Keyring")
    if not isinstance(candidate, Candidate):
        raise TypeError("candidate: has no canonical_bytes()")
    if not isinstance(seen, SeenStore):
        raise TypeError("seen: has no first_use()")
    validate_string_field("app", app)
    validate_string_field("log_id", log_id)
    if type(max_age_s) is not int or not 0 < max_age_s < _AGE_LIMIT:
        raise SchemaError("max_age_s: not a positive integer below 2^53")


def _rule_1_canonical_approve(line: bytes) -> Record:
    """Parse the line strictly and require a `decision` record that approves."""
    try:
        record = Record.from_line(line)
    except RecordError as e:
        raise GateError(f"rule 1: {e}") from e
    if record.type != "decision":
        raise GateError("rule 1: not a decision record")
    if record.decision != "approve":
        raise GateError("rule 1: not an approval")
    return record


def _rule_2_signed_by_current_gate_key(record: Record, keyring: Keyring) -> None:
    """Signature under the gate key for `kid` within its window, and the key is not retired."""
    try:
        keyring.check_record_signature(record)
        if keyring.retired(record.kid):
            raise GateError("rule 2: kid is retired")
    except KeyringError as e:
        raise GateError(f"rule 2: {e}") from e


def _rule_3_this_log(record: Record, keyring: Keyring, log_id: str) -> None:
    """Require the record and the keyring to name the consumer's configured log."""
    if record.log_id != log_id or keyring.log_id != log_id:
        raise GateError("rule 3: not this log")


def _rule_4_this_app(record: Record, app: str) -> None:
    """Require the record to name the app the consumer acts for."""
    if record.app != app:
        raise GateError("rule 4: not this app")


def _rule_5_bound_to_candidate(record: Record, candidate: Candidate) -> None:
    """`cart_hash` equals the sha256 of the Candidate's canonical bytes."""
    data = candidate.canonical_bytes()
    if type(data) is not bytes:
        raise TypeError("candidate.canonical_bytes(): not bytes")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(record.cart_hash, digest):
        raise GateError("rule 5: receipt is not bound to this candidate")


def _rule_6_fresh(record: Record, max_age_s: int) -> None:
    """`now - ts <= max_age_s`. A `ts` that is no calendar date is refused."""
    try:
        ts = datetime.strptime(record.ts, _TS_FORMAT).replace(tzinfo=UTC)
    except ValueError as e:
        raise GateError("rule 6: ts is not a date") from e
    if _now() - ts > timedelta(seconds=max_age_s):
        raise GateError("rule 6: receipt is older than max_age_s")


def _rule_7_unseen(record: Record, seen: SeenStore) -> None:
    """Mark `request_id` used; a second use is refused. Runs last so refusals leave no mark."""
    if not seen.first_use(record.request_id):
        raise GateError("rule 7: request_id already acted on")


def _now() -> datetime:
    """Return the consumer's wall clock in UTC. Tests replace this; nothing else should."""
    return datetime.now(UTC)
