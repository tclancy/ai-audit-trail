# SPDX-License-Identifier: Apache-2.0
"""The append-only log writer: genesis or boot at init, then `record()` (SPEC §3.6, §4).

Every write takes a file lock, reads the last complete line from disk, checks it is the head
this writer last saw, builds and signs the next record, writes the whole line in one call and
`fsync`s it. Any failure at any step is `LogUnavailable` and nothing is ever rewritten. The
exact guarantee: a line for which `record()` raised may still be on disk, complete and
correctly chained, with no receipt issued; a short write (disk full, size limit) can leave
partial bytes that every writer then refuses until M2's torn-line discard. Not here yet:
heartbeats, anchors, key rotation, file rotation (a directory with more than the first file
is refused), the torn-line discard, and the boot self-check through the verifier (M2, M3).
"""

from __future__ import annotations

import base64
import dataclasses
import fcntl
import hashlib
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, final

from audittrail.keyring import Keyring, KeyringError
from audittrail.record import (
    MAX_LINE_BYTES,
    ZERO_HASH,
    Record,
    RecordError,
    SchemaError,
    canonical_bytes,
    validate_string_field,
)
from audittrail.signing import DOMAIN_RECORD, SIGNATURE_BYTES, Signer, SigningError

REASON_V = 1
"""The `spec/reasons.txt` section every record written by this version names."""

BOOT_CONFIG_TEMPLATE = (
    "heartbeat_s={heartbeat_s};anchor_max_s={anchor_max_s};"
    "anchor_every={anchor_every};truncated_bytes={truncated_bytes}"
)
"""SPEC §3.4: the ASCII string whose sha256 a boot record carries in `oracle_ref`."""

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class LogUnavailable(Exception):
    """The log could not be read, extended, or trusted. The caller rejects; nothing was written."""


@final
@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class DecisionFields:
    """What a gate supplies for one decision; every value is rule-checked at construction (I8).

    The log fills in everything else (`seq`, `prev`, clocks, ids, `kid`, `sig`). This holds no
    free text and no content: hashes and enum values only.
    """

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
    canary: str

    def __post_init__(self) -> None:
        """Check every field against its SPEC §3.1 rule. Does not check the reasons file."""
        for f in dataclasses.fields(self):
            validate_string_field(f.name, getattr(self, f.name))

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass, so none can skip the field rules."""
        raise TypeError("DecisionFields is final")


@final
class Receipt:
    """The bytes of one written decision line and its parsed record. Final; not copyable.

    Proves that this writer signed and wrote the line. Does not prove inclusion to anyone
    else; that is reconciliation's job (SPEC §6 rule 8).
    """

    __slots__ = ("entry", "line")

    def __init__(self, line: bytes, entry: Record) -> None:
        """Hold a line the log just wrote. Not for arbitrary bytes; `Log` is the only caller."""
        self.line = line
        self.entry = entry

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass."""
        raise TypeError("Receipt is final")

    def __reduce__(self) -> NoReturn:
        """Refuse the copy and persistence protocols; a receipt travels as its line."""
        raise TypeError("Receipt cannot be copied or serialized; use .line")

    def verify(self, keyring: Keyring) -> bool:
        """Return whether `sig` verifies under the keyring's gate key for `kid` within its window.

        Proves signing only. Does not check freshness, binding, single use, or inclusion;
        a consumer uses `Approved.from_wire` for SPEC §6. A keyring of the wrong type is a
        `TypeError`, not False.
        """
        if type(keyring) is not Keyring:
            raise TypeError("keyring: not a Keyring")
        try:
            keyring.check_record_signature(self.entry)
        except KeyringError:
            return False
        return True


class Log:
    """One writer for one `log_id` in one directory (SPEC §4). Opening it writes a boot record."""

    def __init__(
        self,
        directory: Path,
        log_id: str,
        signer: Signer,
        *,
        actor: str,
        template_hash: str,
        model_id: str,
        policy_hash: str,
        heartbeat_s: int = 60,
        anchor_every: int = 1000,
        anchor_max_s: int = 900,
    ) -> None:
        """Validate the identity values, read the head from disk, and write the boot record.

        Genesis happens only when no log file exists for `log_id`. An existing file whose last
        line is not a complete, valid record is refused, and so is a directory holding any file
        for `log_id` other than the first (file rotation is M2). Does not verify the chain
        behind the head and does not read the anchor sink; those checks are the verifier's.
        """
        _check_identity(log_id, actor, template_hash, model_id, policy_hash)
        _check_cadence(heartbeat_s, anchor_every, anchor_max_s)
        self._dir = Path(directory)
        self._path = self._dir / f"{log_id}.{0:016d}.jsonl"
        self._log_id = log_id
        self._signer = signer
        self._actor = actor
        self._template_hash = template_hash
        self._model_id = model_id
        self._policy_hash = policy_hash
        config = BOOT_CONFIG_TEMPLATE.format(
            heartbeat_s=heartbeat_s,
            anchor_max_s=anchor_max_s,
            anchor_every=anchor_every,
            truncated_bytes=0,
        )
        self._boot_config_hash = _sha256_of(config.encode("ascii"))
        self._lock = threading.Lock()
        self._mono_base = time.monotonic_ns()
        self._boot = _ulid()
        self._head: Record | None = None
        self._head_hash = ZERO_HASH
        self._write_boot()

    def record(self, fields: DecisionFields) -> Receipt:
        """Append one decision record and return its receipt. The only write path for decisions.

        Raises `LogUnavailable` on any failure, including a head on disk that is not the one
        this writer last wrote. Does not retry and does not return anything partial.
        """
        if type(fields) is not DecisionFields:
            raise SchemaError("fields: not a DecisionFields")
        return self._append("decision", dataclasses.asdict(fields))

    def _write_boot(self) -> None:
        """Create the file with a genesis boot, or append a boot adopting the head on disk.

        Refuses a directory with any other file for this log_id. The existing-file path goes
        through `_append`, so the head is read under the lock like every other write.
        """
        others = [p for p in self._dir.glob(f"{self._log_id}.*.jsonl") if p != self._path]
        if others:
            raise LogUnavailable("the directory holds more than the first log file")
        if self._path.exists():
            self._append("boot", self._boot_fields())
            return
        with self._lock:
            try:
                line = self._signed_line("boot", self._boot_fields(), seq=0, prev=ZERO_HASH)
            except (RecordError, SigningError) as e:
                raise LogUnavailable(f"cannot build genesis: {e}") from e
            _create_with_line(self._path, line)
            self._head, self._head_hash = Record.from_line(line), _sha256_of(line)

    def _boot_fields(self) -> dict[str, Any]:
        """Return the SPEC §3.4 values of a boot record; `cart_hash` is set at write time.

        `R_BOOT` only: the truncated variant waits for M2's discard rule.
        """
        return {
            "actor": self._actor,
            "app": "gate",
            "template_hash": self._template_hash,
            "model_id": self._model_id,
            "policy_hash": self._policy_hash,
            "input_ref": ZERO_HASH,
            "cart_hash": ZERO_HASH,
            "oracle": "not_consulted",
            "oracle_ref": self._boot_config_hash,
            "decision": "reject",
            "reason": "R_BOOT",
            "canary": "not_run",
        }

    def _append(self, record_type: str, specific: dict[str, Any]) -> Receipt:
        """Lock, re-read the head from disk, build, sign, write one line, fsync.

        Raises `LogUnavailable` on any failure. A line may be on disk without a receipt if the
        failure came after the write; it is then the head and this writer refuses to go on.
        """
        with self._lock:
            try:
                fd = os.open(self._path, os.O_RDWR | os.O_APPEND)
            except OSError as e:
                raise LogUnavailable(f"cannot open the log: {e}") from e
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                head = self._require_disk_head_matches(fd)
                if record_type == "boot":
                    specific = {**specific, "cart_hash": self._head_hash}
                line = self._signed_line(
                    record_type, specific, seq=head.seq + 1, prev=self._head_hash
                )
                _write_line(fd, line)
            except (OSError, RecordError, SigningError) as e:
                raise LogUnavailable(f"cannot append to the log: {e}") from e
            finally:
                os.close(fd)
            entry = Record.from_line(line)
            self._head, self._head_hash = entry, _sha256_of(line)
            return Receipt(line, entry)

    def _require_disk_head_matches(self, fd: int) -> Record:
        """Return the head record on disk; raise unless it is the one this writer last wrote.

        Before this writer's first write (its boot on an existing file) it has no head of its
        own and adopts the one on disk. Compares by hash, never by `seq` alone.
        """
        head = _read_head_fd(fd)
        if head is None:
            raise LogUnavailable("the log has no head")
        if self._head is None:
            self._head, self._head_hash = head
        elif head[1] != self._head_hash:
            raise LogUnavailable("the log head on disk is not the one this writer last wrote")
        return head[0]

    def _signed_line(
        self, record_type: str, specific: dict[str, Any], *, seq: int, prev: str
    ) -> bytes:
        """Build the full field set, sign its body, and return the canonical line (SPEC §3.2).

        Raises `SigningError` when the signer misbehaves and `RecordError` when the fields do
        not pass their rules; every caller must turn both into `LogUnavailable` (I2). Does not
        write, and does not read the head.
        """
        ts = _ts_now()
        if self._head is not None and ts < self._head.ts:
            raise LogUnavailable("the wall clock went backwards")
        # `mono` passes 2^53 ns about 104 days into one boot; Record then refuses every write
        # until the process restarts. A policy for long-lived processes is an M2 question.
        fields: dict[str, Any] = {
            "v": 1,
            "log_id": self._log_id,
            "type": record_type,
            "seq": seq,
            "boot": self._boot,
            "ts": ts,
            "mono": time.monotonic_ns() - self._mono_base,
            "request_id": _ulid(),
            "reason_v": REASON_V,
            "since_hb": 0,
            "kid": _kid_of(self._signer),
            "prev": prev,
            **specific,
        }
        signature = _signature_of(self._signer, canonical_bytes(fields))
        fields["sig"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
        return Record(**fields).line()


def _kid_of(signer: Signer) -> str:
    """Return the signer's `kid`, turning any `Exception` it raises into `SigningError`.

    The signer is the one collaborator `Log` does not own, and a remote one can be down at
    the moment a record is built. Does not check the kid's shape: `Record` applies the SPEC
    §3.1 rule, and a kid of the wrong type reaches it unchanged. Does not catch a
    `BaseException`; a `KeyboardInterrupt` through the signer propagates as itself, and
    nothing has been written at that point either.
    """
    try:
        return signer.kid
    except Exception as e:  # noqa: BLE001 - re-raised as the typed error, never continued
        raise SigningError(f"the signer's kid raised {type(e).__name__}") from e


def _signature_of(signer: Signer, data: bytes) -> bytes:
    """Return the signer's signature over `DOMAIN_RECORD || data`, as exactly 64 `bytes`.

    Any `Exception` the signer raises, and any return value that is not 64 `bytes`, is
    `SigningError` with the original chained; both callers turn that into `LogUnavailable`
    (I2). `bytes` exactly: a `bytearray` of the right length encodes to a `sig` that matches
    its rule, so nothing downstream would refuse it. Does not retry, does not verify the
    signature it is given, and does not catch a `BaseException`.
    """
    try:
        signature = signer.sign(DOMAIN_RECORD, data)
    except Exception as e:  # noqa: BLE001 - re-raised as the typed error, never continued
        raise SigningError(f"the signer raised {type(e).__name__}") from e
    if type(signature) is not bytes or len(signature) != SIGNATURE_BYTES:
        raise SigningError("the signer did not return a 64-byte signature")
    return signature


def _check_identity(
    log_id: str, actor: str, template_hash: str, model_id: str, policy_hash: str
) -> None:
    """Raise `SchemaError` unless each identity value matches its SPEC §3.1 rule."""
    for name, value in (
        ("log_id", log_id),
        ("actor", actor),
        ("template_hash", template_hash),
        ("model_id", model_id),
        ("policy_hash", policy_hash),
    ):
        validate_string_field(name, value)


def _check_cadence(heartbeat_s: int, anchor_every: int, anchor_max_s: int) -> None:
    """Raise `SchemaError` unless each cadence value is a positive int below 2^53. Nothing more."""
    for name, value in (
        ("heartbeat_s", heartbeat_s),
        ("anchor_every", anchor_every),
        ("anchor_max_s", anchor_max_s),
    ):
        if type(value) is not int or not 0 < value < 2**53:
            raise SchemaError(f"{name}: not a positive integer below 2^53")


def _read_head_fd(fd: int) -> tuple[Record, str] | None:
    """Return the last complete line of an open file as (record, hash). Reads only the tail.

    Raises `LogUnavailable` on an empty file or a tail without its newline, `RecordError` on
    a last line that is not a record. Does not read or check any earlier line.
    """
    size = os.fstat(fd).st_size
    if size == 0:
        raise LogUnavailable("the log file is empty; a log never re-genesises")
    window = MAX_LINE_BYTES + 2
    tail = os.pread(fd, window, max(0, size - window))
    if not tail.endswith(b"\n"):
        raise LogUnavailable("the last line is not newline-terminated")
    line = tail[:-1].rsplit(b"\n", 1)[-1]
    return Record.from_line(line), _sha256_of(line)


def _create_with_line(path: Path, line: bytes) -> None:
    """Create the file exclusively with one line, fsync it, then fsync the directory."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        raise LogUnavailable(f"cannot create the log: {e}") from e
    try:
        _write_line(fd, line)
    except OSError as e:
        raise LogUnavailable(f"cannot write genesis: {e}") from e
    finally:
        os.close(fd)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as e:
        raise LogUnavailable(f"cannot fsync the log directory: {e}") from e


def _write_line(fd: int, line: bytes) -> None:
    """Write `line` plus newline in one call and fsync. A short write is an OSError.

    Does not retry and does not undo a short write; the bytes that landed stay for the boot
    rules to deal with. On Darwin `fsync` does not flush the drive cache; the spec says fsync.
    """
    data = line + b"\n"
    written = os.write(fd, data)
    if written != len(data):
        raise OSError(f"short write: {written} of {len(data)} bytes")
    os.fsync(fd)


def _sha256_of(data: bytes) -> str:
    """Return `sha256:<hex>` of the bytes. Does not strip a newline; callers pass the line."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _ts_now() -> str:
    """Return the wall clock as SPEC §3.1 `ts`: UTC, millisecond precision, `Z`. Not monotone."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _ulid() -> str:
    """Return a ULID: 48-bit millisecond timestamp, 80 random bits, Crockford base32.

    Not sortable within one millisecond, and not a secret. The timestamp overflows 48 bits in
    the year 10889, where Python's own clock gives out first.
    """
    value = (time.time_ns() // 1_000_000) << 80 | int.from_bytes(os.urandom(10), "big")
    return "".join(_CROCKFORD[(value >> (5 * i)) & 31] for i in range(25, -1, -1))
