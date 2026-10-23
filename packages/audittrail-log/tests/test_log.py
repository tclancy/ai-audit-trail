"""Log.record: genesis boot at init, prev from disk under a lock, fsync, typed failure (I2).

Signatures are checked here with the public key from `spec/vectors/keyring.json` directly, since
the verifier package does not exist yet. Nothing here reads a key seed except the published one.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import typing
from pathlib import Path

import pytest
from audittrail.log import BOOT_CONFIG_TEMPLATE, DecisionFields, Log, LogUnavailable, Receipt
from audittrail.record import STRING_RULES, ZERO_HASH, Record, SchemaError, canonical_bytes
from audittrail.signing import DOMAIN_RECORD, SigningError, SoftwareSigner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SPEC = Path(__file__).resolve().parents[3] / "spec"
GATE = "spiffe://test.local/gate"
TEMPLATE = "sha256:" + hashlib.sha256(b"test-template-v1").hexdigest()
POLICY = "sha256:" + hashlib.sha256(b"test-policy-v1").hexdigest()


def seed(kid: str) -> bytes:
    """The published seed for `kid` from `spec/test-seed.txt`."""
    for raw in (SPEC / "test-seed.txt").read_text(encoding="ascii").splitlines():
        fields = raw.split()
        if fields and not fields[0].startswith("#") and fields[1] == kid:
            return bytes.fromhex(fields[0])
    raise KeyError(kid)


def public_key(kid: str) -> Ed25519PublicKey:
    """The public key for `kid` from the committed keyring."""
    ring = json.loads((SPEC / "vectors" / "keyring.json").read_text(encoding="ascii"))
    [entry] = [k for k in ring["keys"] if k["kid"] == kid]
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["pub"]))


def assert_signed(record: Record) -> None:
    """Fail unless the record's `sig` verifies under its kid's public key and the record domain."""
    fields = dataclasses.asdict(record)
    sig = base64.b64decode(fields.pop("sig").removeprefix("ed25519:"))
    public_key(record.kid).verify(sig, DOMAIN_RECORD + canonical_bytes(fields))


def lines_of(log_dir: Path) -> list[bytes]:
    """Every line of every log file in the directory, in file then line order, without newlines."""
    out: list[bytes] = []
    for f in sorted(log_dir.glob("*.jsonl")):
        data = f.read_bytes()
        assert data.endswith(b"\n"), f.name
        out.extend(data.removesuffix(b"\n").split(b"\n"))
    return out


@pytest.fixture
def signer(monkeypatch: pytest.MonkeyPatch) -> SoftwareSigner:
    """gate-test-1 as a dev signer."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")
    return SoftwareSigner("gate-test-1", seed("gate-test-1"))


def open_log(log_dir: Path, signer: SoftwareSigner) -> Log:
    """A Log on `log_dir` with the vectors' synthetic identity values."""
    return Log(
        log_dir,
        "test",
        signer,
        actor=GATE,
        template_hash=TEMPLATE,
        model_id="test-model-1",
        policy_hash=POLICY,
    )


def approve() -> DecisionFields:
    """The decision the vectors' `decision-approve` record carries."""
    return DecisionFields(
        actor="spiffe://test.local/app/test-app",
        app="test-app",
        template_hash=TEMPLATE,
        model_id="test-model-1",
        policy_hash=POLICY,
        input_ref="sha256:" + hashlib.sha256(b"test-input-0001").hexdigest(),
        cart_hash="sha256:" + hashlib.sha256(b'{"account":"acct-0001","amount":100}').hexdigest(),
        oracle="match",
        oracle_ref="sha256:" + hashlib.sha256(b"acct-0001:100").hexdigest(),
        decision="approve",
        reason="R_ORACLE_MATCH",
        canary="pass",
    )


# --- genesis -----------------------------------------------------------------


def test_init_on_an_empty_directory_writes_a_signed_genesis_boot(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """One file named per SPEC §3.6, one line: a boot at seq 0 with zero prev and cart_hash."""
    open_log(tmp_path, signer)
    [f] = sorted(tmp_path.glob("*.jsonl"))
    assert f.name == "test.0000000000000000.jsonl"
    [line] = lines_of(tmp_path)
    boot = Record.from_line(line)
    assert (boot.type, boot.seq, boot.prev, boot.cart_hash) == ("boot", 0, ZERO_HASH, ZERO_HASH)
    assert (boot.decision, boot.oracle, boot.reason, boot.app) == (
        "reject",
        "not_consulted",
        "R_BOOT",
        "gate",
    )
    assert (boot.actor, boot.kid, boot.since_hb, boot.canary) == (GATE, "gate-test-1", 0, "not_run")
    config = BOOT_CONFIG_TEMPLATE.format(
        heartbeat_s=60, anchor_max_s=900, anchor_every=1000, truncated_bytes=0
    )
    assert boot.oracle_ref == "sha256:" + hashlib.sha256(config.encode("ascii")).hexdigest()
    assert boot.input_ref == ZERO_HASH
    assert_signed(boot)


def test_boot_config_matches_the_genesis_vector_exactly(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """With the vectors' cadence values, `oracle_ref` equals the committed genesis boot's."""
    vector = Record.from_line(
        (SPEC / "vectors/positive/genesis-boot/test.0000000000000000.jsonl")
        .read_bytes()
        .split(b"\n")[0]
    )
    open_log(tmp_path, signer)
    [line] = lines_of(tmp_path)
    assert Record.from_line(line).oracle_ref == vector.oracle_ref


# --- record ------------------------------------------------------------------


def test_record_appends_a_chained_signed_decision_and_returns_its_receipt(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """seq 1, prev is the boot line's hash, fields as given, since_hb 0, signature verifies."""
    log = open_log(tmp_path, signer)
    receipt = log.record(approve())
    boot_line, line = lines_of(tmp_path)
    assert receipt.line == line
    record = receipt.entry
    assert record == Record.from_line(line)
    assert (record.type, record.seq, record.since_hb, record.reason_v) == ("decision", 1, 0, 1)
    assert record.prev == "sha256:" + hashlib.sha256(boot_line).hexdigest()
    assert (record.app, record.decision, record.reason, record.cart_hash) == (
        "test-app",
        "approve",
        "R_ORACLE_MATCH",
        approve().cart_hash,
    )
    assert record.boot == Record.from_line(boot_line).boot
    assert_signed(record)


def test_many_records_chain_and_clocks_never_go_backwards(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """Across 20 records seq steps by one, prev is the previous hash, mono and ts are monotone."""
    log = open_log(tmp_path, signer)
    for _ in range(20):
        log.record(approve())
    records = [Record.from_line(line) for line in lines_of(tmp_path)]
    lines = lines_of(tmp_path)
    for i, r in enumerate(records):
        assert r.seq == i
        if i:
            assert r.prev == "sha256:" + hashlib.sha256(lines[i - 1]).hexdigest()
            assert r.mono >= records[i - 1].mono and r.ts >= records[i - 1].ts
    assert len({r.request_id for r in records}) == len(records)


def test_records_from_threads_still_form_one_chain(tmp_path: Path, signer: SoftwareSigner) -> None:
    """The lock serializes writers: 4 threads x 25 records give 101 lines in one unbroken chain."""
    log = open_log(tmp_path, signer)
    failures: list[BaseException] = []

    def work() -> None:
        """Write 25 records; collect any exception instead of dying silently in the thread."""
        try:
            for _ in range(25):
                log.record(approve())
        except BaseException as e:  # noqa: BLE001 - collected and re-raised below
            failures.append(e)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not failures
    lines = lines_of(tmp_path)
    assert len(lines) == 101
    for i in range(1, len(lines)):
        assert (
            Record.from_line(lines[i]).prev == "sha256:" + hashlib.sha256(lines[i - 1]).hexdigest()
        )


# --- restart and re-genesis ----------------------------------------------------


def test_reopening_writes_a_boot_that_names_the_last_line(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """A second Log continues the chain; its boot has a new ULID and cart_hash of the last line."""
    first = open_log(tmp_path, signer)
    first.record(approve())
    open_log(tmp_path, signer)
    lines = lines_of(tmp_path)
    assert len(lines) == 3
    boot2 = Record.from_line(lines[2])
    last_hash = "sha256:" + hashlib.sha256(lines[1]).hexdigest()
    assert (boot2.type, boot2.seq, boot2.prev, boot2.cart_hash) == ("boot", 2, last_hash, last_hash)
    assert boot2.boot != Record.from_line(lines[0]).boot
    assert_signed(boot2)


@pytest.mark.parametrize(
    "tail",
    [b"", b"not json\n", b'{"v":1}\n', b"garbage"],
    ids=["empty-file", "garbage-line", "non-record-object", "no-trailing-newline"],
)
def test_init_refuses_a_log_whose_last_line_is_not_a_record(
    tmp_path: Path, signer: SoftwareSigner, tail: bytes
) -> None:
    """A file that does not end in a parseable record is never re-genesised or extended."""
    f = tmp_path / "test.0000000000000000.jsonl"
    f.write_bytes(tail)
    before = f.read_bytes()
    with pytest.raises(LogUnavailable):
        open_log(tmp_path, signer)
    assert f.read_bytes() == before


def test_init_refuses_a_torn_last_line_even_after_a_good_one(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """A good genesis followed by a partial line is not extended; M2 adds the discard rule."""
    open_log(tmp_path, signer)
    f = tmp_path / "test.0000000000000000.jsonl"
    with f.open("ab") as fh:
        fh.write(b'{"partial":')
    before = f.read_bytes()
    with pytest.raises(LogUnavailable):
        open_log(tmp_path, signer)
    assert f.read_bytes() == before


# --- I2: raise, never partial ----------------------------------------------------


def test_record_refuses_when_the_disk_head_moved_behind_it(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """Another writer makes this Log's head stale; record() raises and writes nothing."""
    stale = open_log(tmp_path, signer)
    open_log(tmp_path, signer)  # second boot moves the head
    before = lines_of(tmp_path)
    with pytest.raises(LogUnavailable):
        stale.record(approve())
    assert lines_of(tmp_path) == before


def test_record_refuses_when_the_file_was_truncated(tmp_path: Path, signer: SoftwareSigner) -> None:
    """A shortened file is a head mismatch, not a reason to re-genesis."""
    log = open_log(tmp_path, signer)
    log.record(approve())
    f = tmp_path / "test.0000000000000000.jsonl"
    boot_only = f.read_bytes().split(b"\n")[0] + b"\n"
    f.write_bytes(boot_only)
    with pytest.raises(LogUnavailable):
        log.record(approve())
    assert f.read_bytes() == boot_only


def test_record_refuses_when_the_file_is_gone_or_unwritable(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """An I/O failure is LogUnavailable and leaves no partial line behind."""
    log = open_log(tmp_path, signer)
    f = tmp_path / "test.0000000000000000.jsonl"
    before = f.read_bytes()
    f.chmod(0o400)
    try:
        with pytest.raises(LogUnavailable):
            log.record(approve())
    finally:
        f.chmod(0o600)
    assert f.read_bytes() == before
    f.unlink()
    with pytest.raises(LogUnavailable):
        log.record(approve())
    assert not list(tmp_path.glob("*.jsonl"))


def test_init_refuses_an_unwritable_directory(tmp_path: Path, signer: SoftwareSigner) -> None:
    """Genesis must create a file; a directory that refuses is LogUnavailable, nothing created."""
    if os.geteuid() == 0:
        pytest.fail("this test needs a non-root user; root ignores directory modes")
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(LogUnavailable):
            open_log(tmp_path, signer)
    finally:
        tmp_path.chmod(0o700)
    assert not list(tmp_path.glob("*.jsonl"))


# --- I8 on the inputs; hygiene -------------------------------------------------


def test_every_decision_field_is_a_string_with_a_rule_in_record() -> None:
    """DecisionFields is a strict subset of Record's string fields; nothing else gets in."""
    hints = typing.get_type_hints(DecisionFields)
    assert hints
    for name, annotation in hints.items():
        assert annotation is str and name in STRING_RULES, name


@pytest.mark.parametrize("field", sorted(typing.get_type_hints(DecisionFields)))
def test_free_text_in_any_decision_field_is_rejected(field: str) -> None:
    """A value with a space never constructs (I8), whatever the field."""
    change: dict[str, typing.Any] = {field: "free text here"}
    with pytest.raises(SchemaError):
        dataclasses.replace(approve(), **change)


def test_log_init_validates_its_own_identity_values(tmp_path: Path, signer: SoftwareSigner) -> None:
    """Bad actor, template_hash, model_id or policy_hash is a SchemaError before any file exists."""
    with pytest.raises(SchemaError):
        Log(
            tmp_path,
            "test",
            signer,
            actor="not a spiffe id",
            template_hash=TEMPLATE,
            model_id="m",
            policy_hash=POLICY,
        )
    with pytest.raises(SchemaError):
        Log(
            tmp_path,
            "Test Log",
            signer,
            actor=GATE,
            template_hash=TEMPLATE,
            model_id="m",
            policy_hash=POLICY,
        )
    assert not list(tmp_path.glob("*.jsonl"))


def test_receipt_is_final_and_not_copyable_by_protocol(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """Subclassing raises; copy and persistence protocols raise; the line is the only transport."""
    receipt = open_log(tmp_path, signer).record(approve())
    assert isinstance(receipt, Receipt)
    with pytest.raises(TypeError):
        copy.copy(receipt)
    with pytest.raises(TypeError):

        class Sub(Receipt):  # type: ignore[misc]
            """Never constructed; the class statement must raise."""

    with pytest.raises(TypeError):

        class SubFields(DecisionFields):  # type: ignore[misc]
            """Never constructed either; a subclass could skip the field rules."""


def test_request_ids_are_ulids_in_crockford_base32(tmp_path: Path, signer: SoftwareSigner) -> None:
    """Both generated ULIDs match the SPEC §3.1 alphabet and the boot ULID is per Log instance."""
    log = open_log(tmp_path, signer)
    record = log.record(approve()).entry
    for value in (record.boot, record.request_id):
        assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", value)
    assert record.boot == Record.from_line(lines_of(tmp_path)[0]).boot


# --- mechanisms the review found unpinned ------------------------------------


def test_a_directory_with_a_rotated_second_file_is_refused(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """The two-file vector: with both files, or only the later one, init raises, writes nothing."""
    src = SPEC / "vectors" / "positive" / "rotation-two-files"
    both = tmp_path / "both"
    both.mkdir()
    for f in src.glob("*.jsonl"):
        shutil.copy(f, both / f.name)
    before = {f.name: f.read_bytes() for f in both.glob("*.jsonl")}
    with pytest.raises(LogUnavailable):
        open_log(both, signer)
    assert {f.name: f.read_bytes() for f in both.glob("*.jsonl")} == before
    later_only = tmp_path / "later"
    later_only.mkdir()
    shutil.copy(src / "test.0000000000000003.jsonl", later_only)
    with pytest.raises(LogUnavailable):
        open_log(later_only, signer)
    assert sorted(f.name for f in later_only.glob("*.jsonl")) == ["test.0000000000000003.jsonl"]


class FailingSigner:
    """A Signer whose key refuses; the Log must turn that into LogUnavailable."""

    kid = "gate-test-1"

    def sign(self, domain: bytes, data: bytes) -> bytes:
        """Always refuse."""
        raise SigningError("refused")


def test_a_failing_signer_is_log_unavailable_at_genesis_and_at_record(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """A SigningError never escapes as itself, and nothing is written for it."""
    with pytest.raises(LogUnavailable):
        Log(
            tmp_path,
            "test",
            FailingSigner(),
            actor=GATE,
            template_hash=TEMPLATE,
            model_id="test-model-1",
            policy_hash=POLICY,
        )
    assert not list(tmp_path.glob("*.jsonl"))
    log = open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    log._signer = FailingSigner()
    with pytest.raises(LogUnavailable):
        log.record(approve())
    assert lines_of(tmp_path) == before


def test_genesis_fsyncs_the_file_and_the_directory_and_record_fsyncs_the_file(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every write reaches fsync before returning; genesis also fsyncs the directory."""
    synced: list[bool] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        """Record whether the fd is a directory, then really fsync it."""
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    log = open_log(tmp_path, signer)
    assert synced == [False, True]
    synced.clear()
    log.record(approve())
    assert synced == [False]


def test_record_waits_for_a_lock_held_by_another_process(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """With another process holding LOCK_EX on the file, record() blocks until it is released."""
    log = open_log(tmp_path, signer)
    path = tmp_path / "test.0000000000000000.jsonl"
    holder = subprocess.Popen(  # noqa: S603 - fixed argv, our own interpreter
        [
            sys.executable,
            "-c",
            "import fcntl, sys\n"
            f"fd = open({str(path)!r}, 'rb')\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('locked', flush=True)\n"
            "sys.stdin.readline()\n",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdin is not None
        assert holder.stdout.readline().strip() == "locked"
        done = threading.Event()

        def write_one() -> None:
            """Append one record, then flag completion."""
            log.record(approve())
            done.set()

        writer = threading.Thread(target=write_one)
        writer.start()
        assert not done.wait(0.5), "record() returned while another process held the lock"
        holder.stdin.write("go\n")
        holder.stdin.flush()
        writer.join(10)
        assert done.is_set()
    finally:
        holder.kill()
        holder.wait()
    assert len(lines_of(tmp_path)) == 2


def test_genesis_create_is_exclusive(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the file appears between the existence check and the create, the create refuses."""
    open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    with pytest.raises(LogUnavailable):
        open_log(tmp_path, signer)
    assert lines_of(tmp_path) == before


def test_wall_clock_going_backwards_is_refused(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ts earlier than the head's is never written; the file is unchanged."""
    import audittrail.log as log_module

    log = open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    monkeypatch.setattr(log_module, "_ts_now", lambda: "2000-01-01T00:00:00.000Z")
    with pytest.raises(LogUnavailable):
        log.record(approve())
    assert lines_of(tmp_path) == before


def test_head_is_compared_by_hash_not_by_seq(tmp_path: Path, signer: SoftwareSigner) -> None:
    """Another log's genesis at the same seq, swapped in behind the writer, is a mismatch."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    log_a = open_log(a, signer)
    open_log(b, signer)
    swapped = (b / "test.0000000000000000.jsonl").read_bytes()
    assert Record.from_line(swapped.rstrip(b"\n")).seq == 0
    (a / "test.0000000000000000.jsonl").write_bytes(swapped)
    with pytest.raises(LogUnavailable):
        log_a.record(approve())
    assert (a / "test.0000000000000000.jsonl").read_bytes() == swapped


# --- I2: the signer is untrusted ---------------------------------------------


class RaisingSigner:
    """A Signer whose `sign` raises something that is not a SigningError."""

    kid = "gate-test-1"

    def __init__(self, error: Exception) -> None:
        """Hold the exception to raise. An `Exception`: the boundary deliberately stops there."""
        self._error = error

    def sign(self, domain: bytes, data: bytes) -> bytes:
        """Raise the held exception instead of signing."""
        raise self._error


class WrongReturnSigner:
    """A Signer whose `sign` returns something other than a 64-byte signature."""

    kid = "gate-test-1"

    def __init__(self, value: object) -> None:
        """Hold the value to return. Does not check its type; that is the Log's job."""
        self._value = value

    def sign(self, domain: bytes, data: bytes) -> bytes:
        """Return the held value, whatever its type."""
        return self._value  # type: ignore[return-value]


class KidRaisingSigner:
    """A Signer whose `kid` raises, as a remote signer's would when the key service is down."""

    def __init__(self, error: Exception) -> None:
        """Hold the exception the property raises."""
        self._error = error

    @property
    def kid(self) -> str:
        """Raise instead of naming a key."""
        raise self._error

    def sign(self, domain: bytes, data: bytes) -> bytes:
        """Never reached: `_signed_line` reads `kid` before it signs."""
        return b"\x00" * 64


# A signer factory and the exception type the Log must keep in the cause chain, or None
# where the Log's own boundary is the only thing that noticed.
BAD_SIGNERS = [
    pytest.param(
        lambda: RaisingSigner(RuntimeError("the key service is down")),
        RuntimeError,
        id="sign-raises-RuntimeError",
    ),
    pytest.param(
        lambda: RaisingSigner(ValueError("not a SigningError")), ValueError, id="sign-raises-Value"
    ),
    pytest.param(lambda: RaisingSigner(KeyError("kid")), KeyError, id="sign-raises-KeyError"),
    pytest.param(lambda: RaisingSigner(MemoryError()), MemoryError, id="sign-raises-MemoryError"),
    pytest.param(lambda: WrongReturnSigner("ed25519:not-bytes"), None, id="sign-returns-str"),
    pytest.param(lambda: WrongReturnSigner(None), None, id="sign-returns-None"),
    pytest.param(lambda: WrongReturnSigner(bytearray(64)), None, id="sign-returns-bytearray"),
    pytest.param(lambda: WrongReturnSigner(b"\x00" * 63), None, id="sign-returns-63-bytes"),
    pytest.param(lambda: WrongReturnSigner(b"\x00" * 65), None, id="sign-returns-65-bytes"),
    pytest.param(
        lambda: KidRaisingSigner(RuntimeError("the key service is down")),
        RuntimeError,
        id="kid-raises-RuntimeError",
    ),
]


def causes_of(error: BaseException) -> list[BaseException]:
    """The exception and every `__cause__` behind it, outermost first. Ignores `__context__`."""
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None:
        chain.append(current)
        current = current.__cause__
    return chain


@pytest.mark.parametrize(("make_signer", "planted"), BAD_SIGNERS)
def test_a_misbehaving_signer_is_log_unavailable_at_genesis(
    tmp_path: Path,
    make_signer: typing.Callable[[], typing.Any],
    planted: type[BaseException] | None,
) -> None:
    """Genesis refuses as LogUnavailable, creates no file, and chains the signer's own failure."""
    with pytest.raises(LogUnavailable) as caught:
        Log(
            tmp_path,
            "test",
            make_signer(),
            actor=GATE,
            template_hash=TEMPLATE,
            model_id="test-model-1",
            policy_hash=POLICY,
        )
    assert not list(tmp_path.glob("*.jsonl"))
    chain = causes_of(caught.value)
    assert any(isinstance(c, SigningError) for c in chain), chain
    if planted is not None:
        assert any(type(c) is planted for c in chain), chain


@pytest.mark.parametrize(("make_signer", "planted"), BAD_SIGNERS)
def test_a_misbehaving_signer_is_log_unavailable_at_record(
    tmp_path: Path,
    signer: SoftwareSigner,
    make_signer: typing.Callable[[], typing.Any],
    planted: type[BaseException] | None,
) -> None:
    """record() refuses as LogUnavailable and the log is unchanged byte for byte.

    The SigningError in the cause chain is what pins *which layer* refused: a 63-byte
    signature base64-encodes fine, so without the boundary check the first thing to notice
    it is Record's `sig` rule, and the chain would carry a SchemaError instead.
    """
    log = open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    log._signer = make_signer()
    with pytest.raises(LogUnavailable) as caught:
        log.record(approve())
    assert lines_of(tmp_path) == before
    chain = causes_of(caught.value)
    assert any(isinstance(c, SigningError) for c in chain), chain
    if planted is not None:
        assert any(type(c) is planted for c in chain), chain


def test_a_signer_that_works_is_still_the_normal_path(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """The boundary refuses nothing a real signer produces: 64 bytes, and the signature verifies."""
    log = open_log(tmp_path, signer)
    record = log.record(approve()).entry
    assert len(base64.b64decode(record.sig.removeprefix("ed25519:"))) == 64
    assert_signed(record)


# --- genesis, boot and append convert the same failures (#33) --------------------


def raise_oserror() -> str:
    """Stand in for `_ulid` when `os.urandom` has no entropy source: always OSError."""
    raise OSError("no entropy source")


def test_an_entropy_failure_is_log_unavailable_at_genesis(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_ulid` raising OSError is LogUnavailable from `__init__`, and no file is created."""
    import audittrail.log as log_module

    monkeypatch.setattr(log_module, "_ulid", raise_oserror)
    with pytest.raises(LogUnavailable) as caught:
        open_log(tmp_path, signer)
    assert any(type(c) is OSError for c in causes_of(caught.value))
    assert not list(tmp_path.glob("*.jsonl"))


def test_an_entropy_failure_inside_the_genesis_line_is_log_unavailable(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The boot id draws, then the genesis `request_id` fails: LogUnavailable, no file."""
    import audittrail.log as log_module

    real_ulid = log_module._ulid
    calls = iter([real_ulid])
    monkeypatch.setattr(log_module, "_ulid", lambda: next(calls, raise_oserror)())
    with pytest.raises(LogUnavailable) as caught:
        open_log(tmp_path, signer)
    assert any(type(c) is OSError for c in causes_of(caught.value))
    assert not list(tmp_path.glob("*.jsonl"))


def test_an_entropy_failure_is_log_unavailable_at_record(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_ulid` raising OSError is LogUnavailable from `record()`; the file is unchanged."""
    import audittrail.log as log_module

    log = open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    monkeypatch.setattr(log_module, "_ulid", raise_oserror)
    with pytest.raises(LogUnavailable) as caught:
        log.record(approve())
    assert any(type(c) is OSError for c in causes_of(caught.value))
    assert lines_of(tmp_path) == before


# Written out, not imported from `audittrail.log`: the test is the spec for the set, so
# narrowing the module's tuple cannot narrow what is checked.
BUILD_FAILURES = [
    pytest.param(lambda: OSError("planted"), id="OSError"),
    pytest.param(lambda: SchemaError("planted"), id="RecordError"),
    pytest.param(lambda: SigningError("planted"), id="SigningError"),
]


@pytest.mark.parametrize("make_error", BUILD_FAILURES)
@pytest.mark.parametrize("path", ["genesis", "boot", "append"])
def test_every_write_path_converts_the_same_build_failures(
    tmp_path: Path,
    signer: SoftwareSigner,
    monkeypatch: pytest.MonkeyPatch,
    make_error: typing.Callable[[], Exception],
    path: str,
) -> None:
    """Each failure raised while building a line is LogUnavailable on every path, nothing written.

    `genesis` opens an empty directory, `boot` reopens an existing log (boot through
    `_append`), `append` calls `record()`. The failure is planted in `_ts_now`, the first
    call inside `_signed_line`, which all three share. The planted exception in the cause
    chain proves it was this plant, not some other failure, that became LogUnavailable.
    """
    import audittrail.log as log_module

    log = None if path == "genesis" else open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    planted = make_error()

    def fail() -> str:
        """Raise the planted failure instead of reading the clock."""
        raise planted

    monkeypatch.setattr(log_module, "_ts_now", fail)
    with pytest.raises(LogUnavailable) as caught:
        if log is not None and path == "append":
            log.record(approve())
        else:
            open_log(tmp_path, signer)
    assert planted in causes_of(caught.value)
    assert lines_of(tmp_path) == before


# --- failures outside the build: directory reads, close, odd paths ------------------


@pytest.mark.parametrize("existing", [False, True], ids=["genesis", "boot"])
def test_an_unsearchable_directory_is_log_unavailable(
    tmp_path: Path, signer: SoftwareSigner, existing: bool
) -> None:
    """A directory that can be listed but not searched is LogUnavailable; the file is unchanged."""
    if os.geteuid() == 0:
        pytest.fail("this test needs a non-root user; root ignores directory modes")
    if existing:
        open_log(tmp_path, signer)
    before = lines_of(tmp_path)
    tmp_path.chmod(0o600)
    try:
        with pytest.raises(LogUnavailable) as caught:
            open_log(tmp_path, signer)
    finally:
        tmp_path.chmod(0o700)
    assert any(isinstance(c, PermissionError) for c in causes_of(caught.value))
    assert lines_of(tmp_path) == before


def test_a_directory_path_with_a_nul_is_log_unavailable(
    tmp_path: Path, signer: SoftwareSigner
) -> None:
    """A path `os.open` refuses with ValueError is LogUnavailable, and nothing is created."""
    with pytest.raises(LogUnavailable):
        open_log(tmp_path / "a\0b", signer)
    assert not list(tmp_path.iterdir())


def test_a_glob_that_refuses_the_directory_is_log_unavailable(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Path.glob` raising ValueError is LogUnavailable from `__init__`, and nothing is created.

    Planted rather than driven by a real NUL: on 3.12 `glob` swallows the NUL and `os.open`
    refuses it, on 3.13 `glob` itself raises. The plant pins the `glob` case on both.
    """
    planted = ValueError("scandir: embedded null character in path")

    def refuse(self: Path, pattern: str, **kwargs: object) -> typing.Iterator[Path]:
        """Refuse the directory the way 3.13's glob does for a NUL."""
        raise planted

    monkeypatch.setattr(Path, "glob", refuse)
    with pytest.raises(LogUnavailable) as caught:
        open_log(tmp_path, signer)
    assert planted in causes_of(caught.value)
    assert not list(tmp_path.iterdir())


def closing_then_eio(real_close: typing.Callable[[int], None]) -> typing.Callable[[int], None]:
    """An `os.close` that really closes, then reports EIO, as close does on failed write-back."""

    def close(fd: int) -> None:
        """Close for real, then raise EIO."""
        real_close(fd)
        raise OSError(5, "close EIO")

    return close


def test_a_failing_close_is_log_unavailable_at_genesis(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EIO from close after the genesis write is LogUnavailable, not a raw OSError."""
    with monkeypatch.context() as m:
        m.setattr(os, "close", closing_then_eio(os.close))
        with pytest.raises(LogUnavailable):
            open_log(tmp_path, signer)


@pytest.mark.parametrize("signer_works", [True, False], ids=["after-write", "over-refusal"])
def test_a_failing_close_is_log_unavailable_at_record(
    tmp_path: Path, signer: SoftwareSigner, monkeypatch: pytest.MonkeyPatch, signer_works: bool
) -> None:
    """EIO from close is LogUnavailable whether the append wrote or was already refusing."""
    log = open_log(tmp_path, signer)
    if not signer_works:
        log._signer = FailingSigner()
    with monkeypatch.context() as m:
        m.setattr(os, "close", closing_then_eio(os.close))
        with pytest.raises(LogUnavailable):
            log.record(approve())
