"""Approved.from_wire enforces SPEC §6 rules 1–7 (I1); Receipt.verify; Keyring strictness.

Every receipt here is a committed vector line or a re-signing of one with the published
gate-test-1 seed. Nothing parses leniently: malformed keyrings are built from canonical bytes
and then broken on purpose.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from audittrail.approved import (
    Approved,
    Candidate,
    GateError,
    InMemorySeenStore,
    SeenStore,
)
from audittrail.keyring import Keyring, KeyringError
from audittrail.log import DecisionFields, Log, Receipt
from audittrail.record import ZERO_HASH, Record, SchemaError, canonical_bytes, parse_object
from audittrail.signing import DOMAIN_RECORD, SoftwareSigner

SPEC = Path(__file__).resolve().parents[3] / "spec"
VECTORS = SPEC / "vectors"
APPROVE_TS = datetime(2026, 10, 10, 0, 0, 1, tzinfo=UTC)
"""`ts` of the decision-approve vector's decision line."""


def vector_lines(name: str) -> list[bytes]:
    """The lines of one vector's single log file, without newlines."""
    [log] = sorted((VECTORS / name).glob("*.jsonl"))
    data = log.read_bytes()
    assert data.endswith(b"\n")
    return data.removesuffix(b"\n").split(b"\n")


def seed(kid: str) -> bytes:
    """The published seed for `kid` from `spec/test-seed.txt`."""
    for raw in (SPEC / "test-seed.txt").read_text(encoding="ascii").splitlines():
        fields = raw.split()
        if fields and not fields[0].startswith("#") and fields[1] == kid:
            return bytes.fromhex(fields[0])
    raise KeyError(kid)


class Cart:
    """A Candidate whose canonical bytes hash to the decision-approve vector's `cart_hash`."""

    def __init__(self, amount: int = 100) -> None:
        """Hold the one value the tests vary."""
        self.amount = amount

    def canonical_bytes(self) -> bytes:
        """JCS of the synthetic cart the vectors were generated from."""
        return canonical_bytes({"account": "acct-0001", "amount": self.amount})


class EmptyCart:
    """A Candidate with no bytes at all."""

    def canonical_bytes(self) -> bytes:
        """Return nothing."""
        return b""


@pytest.fixture
def keyring() -> Keyring:
    """The shared vector keyring: gate-test-1 for every seq, sink-test-1."""
    return Keyring.load(VECTORS / "keyring.json")


@pytest.fixture
def rotation_keyring() -> Keyring:
    """gate-test-1 valid 0..2, gate-test-2 from 3, sink-test-1."""
    return Keyring.load(VECTORS / "positive" / "rotation" / "keyring.json")


@pytest.fixture
def approve_line() -> bytes:
    """The decision-approve vector's decision line (seq 1, gate-test-1)."""
    return vector_lines("positive/decision-approve")[1]


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze `now` at 30 s after the approve vector's `ts`."""
    monkeypatch.setattr(
        "audittrail.approved._now", lambda: APPROVE_TS.replace(second=31), raising=True
    )


def from_wire(line: bytes, keyring: Keyring, **overrides: Any) -> Approved:
    """`Approved.from_wire` with the approve vector's binding values unless overridden."""
    kwargs: dict[str, Any] = {
        "candidate": Cart(),
        "app": "test-app",
        "log_id": "test",
        "max_age_s": 60,
        "seen": InMemorySeenStore(),
    }
    kwargs.update(overrides)
    return Approved.from_wire(line, keyring, **kwargs)


def resigned(line: bytes, **changes: Any) -> bytes:
    """The line with `changes` applied and re-signed by gate-test-1, as canonical bytes."""
    fields = dataclasses.asdict(Record.from_line(line))
    fields.update(changes)
    del fields["sig"]
    signer = SoftwareSigner("gate-test-1", seed("gate-test-1"))
    signature = signer.sign(DOMAIN_RECORD, canonical_bytes(fields))
    fields["sig"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return canonical_bytes(fields)


def keyring_bytes(**changes: Any) -> bytes:
    """Canonical bytes of the shared vector keyring with top-level `changes` applied."""
    obj = parse_object((VECTORS / "keyring.json").read_bytes().removesuffix(b"\n"))
    obj.update(changes)
    return canonical_bytes(obj)


def key_bytes(**changes: Any) -> bytes:
    """Canonical keyring bytes with `changes` applied to the gate-test-1 entry."""
    obj = parse_object((VECTORS / "keyring.json").read_bytes().removesuffix(b"\n"))
    obj["keys"][0].update(changes)
    return canonical_bytes(obj)


@pytest.fixture
def dev(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set `AUDITTRAIL_DEV=1` for one test."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")


# --- the positive case -------------------------------------------------------


def test_the_approve_vector_is_approved_once(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """Every §6 rule holds for the vector; the same line a second time is rule 7."""
    seen = InMemorySeenStore()
    approved = from_wire(approve_line, keyring, seen=seen)
    assert isinstance(approved, Approved)
    assert approved.line == approve_line
    assert approved.entry.seq == 1
    assert approved.entry.request_id == "01JAR000000000000000000001"
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, seen=seen)


def test_rotation_vector_decision_under_the_new_key_is_approved(
    rotation_keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """seq 3 signed by gate-test-2 verifies under its window; its ts is 00:00:03."""
    monkeypatch.setattr("audittrail.approved._now", lambda: APPROVE_TS.replace(second=10))
    line = vector_lines("positive/rotation")[3]
    assert from_wire(line, rotation_keyring).entry.kid == "gate-test-2"


# --- rule 1: canonical, schema, decision, approve ---------------------------


def test_rule_1_rejects_non_canonical_bytes(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """A trailing newline, a flipped byte, a space: none is the line."""
    for bad in (
        approve_line + b"\n",
        approve_line.replace(b'"canary":"pass"', b'"canary": "pass"'),
        approve_line[:-5] + b"A" + approve_line[-4:],
        b"",
    ):
        with pytest.raises(GateError):
            from_wire(bad, keyring)


def test_rule_1_rejects_a_reject_record_and_a_non_decision_record(
    keyring: Keyring, clock: None
) -> None:
    """A valid, signed `reject` is not an approval; a boot record is not a decision."""
    with pytest.raises(GateError):
        from_wire(vector_lines("positive/decision-reject")[1], keyring)
    with pytest.raises(GateError):
        from_wire(vector_lines("positive/genesis-boot")[0], keyring)


def test_rule_1_a_non_bytes_line_is_refused(keyring: Keyring, clock: None) -> None:
    """A str, even of the right characters, is not wire bytes."""
    with pytest.raises(GateError):
        from_wire(vector_lines("positive/decision-approve")[1].decode("ascii"), keyring)  # type: ignore[arg-type]


# --- rule 2: signature, role, window, not retired ----------------------------


def test_rule_2_rejects_a_kid_outside_its_window(rotation_keyring: Keyring, clock: None) -> None:
    """The retired-kid vector: seq 4 signed by gate-test-1, whose window ends at 2."""
    line = vector_lines("negative/retired-kid")[4]
    with pytest.raises(GateError):
        from_wire(line, rotation_keyring)


def test_rule_2_the_window_belongs_to_the_keyring_not_the_line(
    keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same seq-4 line is approved under a keyring where gate-test-1 is never retired."""
    monkeypatch.setattr("audittrail.approved._now", lambda: APPROVE_TS.replace(second=10))
    line = vector_lines("negative/retired-kid")[4]
    assert from_wire(line, keyring).entry.seq == 4


def test_rule_2_rejects_a_retired_key_even_inside_its_window(
    rotation_keyring: Keyring, clock: None
) -> None:
    """seq 1 by gate-test-1 is inside 0..2, but the key is retired; grace is I14 (M2)."""
    line = vector_lines("positive/rotation")[1]
    with pytest.raises(GateError):
        from_wire(line, rotation_keyring)


def test_rule_2_rejects_a_tampered_signature(
    approve_line: bytes, keyring: Keyring, clock: None, dev: None
) -> None:
    """A changed signature character, and a body signed by another published key, both refuse."""
    fields = dataclasses.asdict(Record.from_line(approve_line))
    sig = fields["sig"]
    changed = sig[:20] + ("A" if sig[20] != "A" else "B") + sig[21:]
    with pytest.raises(GateError):
        from_wire(canonical_bytes({**fields, "sig": changed}), keyring)
    signer = SoftwareSigner("gate-test-2", seed("gate-test-2"))
    del fields["sig"]
    signature = signer.sign(DOMAIN_RECORD, canonical_bytes(fields))
    fields["sig"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    with pytest.raises(GateError):
        from_wire(canonical_bytes(fields), keyring)


def test_rule_2_rejects_a_non_canonical_base64_signature(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """The vector's sig ends `A==`; `B==` decodes to the same 64 bytes but is another line.

    One valid line per (contents, key) (SPEC §3.2) holds only if the encoding is canonical,
    so the malleable copy is refused even though the signature bytes verify.
    """
    fields = dataclasses.asdict(Record.from_line(approve_line))
    sig = fields["sig"]
    assert sig.endswith("A==")
    malleable = sig[:-3] + "B=="
    assert base64.b64decode(malleable[8:]) == base64.b64decode(sig[8:])
    with pytest.raises(GateError):
        from_wire(canonical_bytes({**fields, "sig": malleable}), keyring)


def test_rule_2_rejects_an_unknown_kid_and_a_sink_role(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """A keyring without the kid, and one where the kid's role is sink."""
    without = Keyring.from_bytes(keyring_bytes(keys=[parse_object(keyring_bytes())["keys"][1]]))
    with pytest.raises(GateError):
        from_wire(approve_line, without)
    as_sink = Keyring.from_bytes(key_bytes(role="sink"))
    with pytest.raises(GateError):
        from_wire(approve_line, as_sink)


# --- rule 3: log_id ----------------------------------------------------------


def test_rule_3_rejects_another_log_id(approve_line: bytes, keyring: Keyring, clock: None) -> None:
    """The consumer's configured log_id must equal the record's and the keyring's."""
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, log_id="other")
    other_ring = Keyring.from_bytes(keyring_bytes(log_id="other"))
    with pytest.raises(GateError):
        from_wire(approve_line, other_ring, log_id="test")
    with pytest.raises(GateError):
        from_wire(approve_line, other_ring, log_id="other")


# --- rule 4: app -------------------------------------------------------------


def test_rule_4_rejects_another_app(approve_line: bytes, keyring: Keyring, clock: None) -> None:
    """A receipt for test-app authorizes nothing for other-app."""
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, app="other-app")


# --- rule 5: cart binding ----------------------------------------------------


def test_rule_5_rejects_a_candidate_with_another_hash(
    approve_line: bytes, keyring: Keyring, clock: None, dev: None
) -> None:
    """One field off in the cart refuses; so does a zero-hash `cart_hash`, with any candidate.

    A decision record with the zero-hash in `cart_hash` is schema-valid at seq != 0, so a
    comparison that treated the zero-hash as "unbound, so anything goes" would be a bypass.
    """
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, candidate=Cart(amount=101))
    unbound = resigned(approve_line, cart_hash=ZERO_HASH)
    with pytest.raises(GateError):
        from_wire(unbound, keyring, candidate=Cart())
    with pytest.raises(GateError):
        from_wire(unbound, keyring, candidate=EmptyCart())


def test_rule_5_a_candidate_whose_bytes_are_not_bytes_is_refused(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """`canonical_bytes()` returning a str never hashes; the receipt is not bound to text."""

    class TextCart:
        """A Candidate that returns text."""

        def canonical_bytes(self) -> str:
            """Return the right JSON as a str, which is the wrong type."""
            return '{"account":"acct-0001","amount":100}'

    with pytest.raises(TypeError):
        from_wire(approve_line, keyring, candidate=TextCart())


# --- rule 6: freshness -------------------------------------------------------


def test_rule_6_rejects_a_receipt_older_than_max_age(
    approve_line: bytes, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly max_age_s old passes; one millisecond more does not."""
    monkeypatch.setattr("audittrail.approved._now", lambda: APPROVE_TS.replace(minute=1, second=1))
    assert from_wire(approve_line, keyring).entry.seq == 1
    assert from_wire(approve_line, keyring, max_age_s=2**53 - 1).entry.seq == 1
    monkeypatch.setattr(
        "audittrail.approved._now",
        lambda: APPROVE_TS.replace(minute=1, second=1, microsecond=1000),
    )
    with pytest.raises(GateError):
        from_wire(approve_line, keyring)


def test_rule_6_does_not_floor_the_age_to_whole_milliseconds(
    approve_line: bytes, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One microsecond past either bound is refused (issue #27); exactly at a bound it is not.

    A microsecond is `datetime`'s resolution, so this is the tightest probe there is. The
    age used to be rounded down to milliseconds first, which let a receipt up to 0.999 ms
    too old through.
    """

    def now_is(offset: timedelta) -> None:
        """Put the consumer's clock `offset` after the receipt's ts."""
        monkeypatch.setattr("audittrail.approved._now", lambda: APPROVE_TS + offset)

    now_is(timedelta(seconds=60))
    assert from_wire(approve_line, keyring).entry.seq == 1
    now_is(timedelta(seconds=60, microseconds=1))
    with pytest.raises(GateError, match="older than max_age_s"):
        from_wire(approve_line, keyring)
    now_is(timedelta(seconds=-60))
    assert from_wire(approve_line, keyring).entry.seq == 1
    now_is(timedelta(seconds=-60, microseconds=-1))
    with pytest.raises(GateError, match="ahead of now"):
        from_wire(approve_line, keyring)


def test_rule_6_rejects_a_receipt_dated_further_ahead_than_skew(
    approve_line: bytes, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly skew_s ahead passes; one millisecond more does not; skew_s=0 allows no lead."""

    def now_is(lead: timedelta) -> None:
        """Put the consumer's clock `lead` behind the receipt's ts."""
        monkeypatch.setattr("audittrail.approved._now", lambda: APPROVE_TS - lead)

    now_is(timedelta(seconds=60))
    assert from_wire(approve_line, keyring).entry.seq == 1
    now_is(timedelta(seconds=60, milliseconds=1))
    with pytest.raises(GateError):
        from_wire(approve_line, keyring)
    now_is(timedelta(seconds=5))
    assert from_wire(approve_line, keyring, skew_s=5).entry.seq == 1
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, skew_s=4)
    now_is(timedelta(milliseconds=1))
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, skew_s=0)
    now_is(timedelta(0))
    assert from_wire(approve_line, keyring, skew_s=0).entry.seq == 1


def test_rule_6_a_ts_that_matches_the_regex_but_is_no_date_is_refused(
    keyring: Keyring, clock: None, dev: None
) -> None:
    """Month 13 passes the §3.1 regex and the signature; the freshness check still refuses."""
    line = resigned(vector_lines("positive/decision-approve")[1], ts="2026-13-10T00:00:01.000Z")
    with pytest.raises(GateError):
        from_wire(line, keyring)


# --- rule 7: single use ------------------------------------------------------


def test_rule_7_a_refused_receipt_does_not_burn_its_request_id(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """A copy refused on rule 5 leaves the id unseen; the bound copy then passes once."""
    seen = InMemorySeenStore()
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, seen=seen, candidate=Cart(amount=1))
    assert from_wire(approve_line, keyring, seen=seen).entry.seq == 1
    with pytest.raises(GateError):
        from_wire(approve_line, keyring, seen=seen)


def test_rule_7_the_store_is_asked_last(approve_line: bytes, keyring: Keyring, clock: None) -> None:
    """A store that raises is never reached by a receipt that fails an earlier rule."""

    class Exploding:
        """A SeenStore that fails loudly if consulted."""

        def first_use(self, request_id: str) -> bool:
            """Raise, so the test can tell whether the store was reached."""
            raise RuntimeError("store asked")

    with pytest.raises(GateError):
        from_wire(approve_line, keyring, seen=Exploding(), app="other-app")
    with pytest.raises(RuntimeError):
        from_wire(approve_line, keyring, seen=Exploding())


@pytest.mark.parametrize("result", ["yes", 1, None, 0, object()])
def test_rule_7_only_a_literal_true_from_the_store_is_first_use(
    approve_line: bytes, keyring: Keyring, clock: None, result: object
) -> None:
    """A truthy string or a 1 is not True; a non-bool is a TypeError, False is a refusal."""

    class Answering:
        """A SeenStore that answers with whatever the test says."""

        def first_use(self, request_id: str) -> bool:
            """Return the canned result."""
            return result  # type: ignore[return-value]

    with pytest.raises((GateError, TypeError)):
        from_wire(approve_line, keyring, seen=Answering())


def test_in_memory_seen_store_is_first_use_once_across_threads() -> None:
    """Exactly one of many concurrent first_use calls for one id returns True."""
    store = InMemorySeenStore()
    assert store.first_use("01JAR000000000000000000001")
    assert not store.first_use("01JAR000000000000000000001")
    results: list[bool] = []
    barrier = threading.Barrier(16)

    def race() -> None:
        """Call first_use for one id once every thread has started."""
        barrier.wait()
        results.append(store.first_use("01JAR000000000000000000002"))

    threads = [threading.Thread(target=race) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    with pytest.raises(SchemaError):
        store.first_use("not a ulid")
    assert isinstance(store, SeenStore)
    assert isinstance(Cart(), Candidate)


# --- parameters are rule-checked (I8) and types are exact --------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"app": "Test App"},
        {"app": ""},
        {"log_id": "test\n"},
        {"max_age_s": 0},
        {"max_age_s": -1},
        {"max_age_s": True},
        {"max_age_s": 60.0},
        {"max_age_s": 2**53},
        {"skew_s": -1},
        {"skew_s": False},
        {"skew_s": 60.0},
        {"skew_s": 2**53},
    ],
)
def test_binding_parameters_are_validated(
    approve_line: bytes, keyring: Keyring, clock: None, overrides: dict[str, Any]
) -> None:
    """Free text or an out-of-range age is a SchemaError before any rule runs."""
    with pytest.raises(SchemaError):
        from_wire(approve_line, keyring, **overrides)


def test_wrong_object_types_are_type_errors(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """A keyring, candidate, or store of the wrong shape is a programming error, not a refusal."""
    with pytest.raises(TypeError):
        from_wire(approve_line, {"keys": []})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        from_wire(approve_line, keyring, candidate=b"bytes are not a candidate")
    with pytest.raises(TypeError):
        from_wire(approve_line, keyring, seen=set())


# --- hygiene -----------------------------------------------------------------


def test_approved_has_no_constructor_but_from_wire(
    approve_line: bytes, keyring: Keyring, clock: None
) -> None:
    """Direct construction, subclassing, copying, and attribute assignment all raise."""
    with pytest.raises(TypeError):
        Approved()
    with pytest.raises(TypeError):
        Approved(approve_line)
    with pytest.raises(TypeError):

        class Sub(Approved):  # type: ignore[misc]
            """Never constructed; the class statement must raise."""

    approved = from_wire(approve_line, keyring)
    with pytest.raises(TypeError):
        copy.copy(approved)
    with pytest.raises(TypeError):
        approved.line = b""
    with pytest.raises(TypeError):
        del approved.entry
    assert "sig" not in repr(approved)


# --- Receipt.verify ----------------------------------------------------------


@pytest.fixture
def receipt(tmp_path: Path, dev: None) -> Receipt:
    """A receipt from a fresh log written by gate-test-1."""
    log = Log(
        tmp_path,
        "test",
        SoftwareSigner("gate-test-1", seed("gate-test-1")),
        actor="spiffe://test.local/gate",
        template_hash="sha256:" + hashlib.sha256(b"test-template-v1").hexdigest(),
        model_id="test-model-1",
        policy_hash="sha256:" + hashlib.sha256(b"test-policy-v1").hexdigest(),
    )
    return log.record(
        DecisionFields(
            actor="spiffe://test.local/app/test-app",
            app="test-app",
            template_hash="sha256:" + hashlib.sha256(b"test-template-v1").hexdigest(),
            model_id="test-model-1",
            policy_hash="sha256:" + hashlib.sha256(b"test-policy-v1").hexdigest(),
            input_ref="sha256:" + hashlib.sha256(b"input").hexdigest(),
            cart_hash="sha256:" + hashlib.sha256(Cart().canonical_bytes()).hexdigest(),
            oracle="match",
            oracle_ref="sha256:" + hashlib.sha256(b"oracle").hexdigest(),
            decision="approve",
            reason="R_ORACLE_MATCH",
            canary="pass",
        )
    )


def test_receipt_verifies_under_the_gate_key_only(
    receipt: Receipt, keyring: Keyring, rotation_keyring: Keyring
) -> None:
    """True under any keyring whose gate key window covers seq 1; False otherwise.

    The rotation keyring retires gate-test-1 at seq 2, which still covers this receipt's seq 1:
    `verify` proves signing, and retirement is `Approved.from_wire`'s concern.
    """
    assert receipt.verify(keyring) is True
    assert receipt.verify(rotation_keyring) is True
    seq_zero_only = Keyring.from_bytes(key_bytes(valid_to_seq=0))
    assert receipt.verify(seq_zero_only) is False
    sink_only = Keyring.from_bytes(keyring_bytes(keys=[parse_object(keyring_bytes())["keys"][1]]))
    assert receipt.verify(sink_only) is False
    assert receipt.verify(Keyring.from_bytes(keyring_bytes(log_id="other"))) is False
    assert receipt.verify(Keyring.from_bytes(key_bytes(role="sink"))) is False
    with pytest.raises(TypeError):
        receipt.verify({"keys": []})  # type: ignore[arg-type]


def test_a_fresh_receipt_is_approved_from_its_line(
    receipt: Receipt, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer's receipt bytes and the consumer's from_wire agree on the same keyring."""
    approved = from_wire(receipt.line, keyring)
    assert approved.entry.hash() == receipt.entry.hash()


# --- Keyring strictness (SPEC §3.8) ------------------------------------------


def test_keyring_loads_the_vector_files(keyring: Keyring, rotation_keyring: Keyring) -> None:
    """Both committed keyrings load; log_id and windows are what the files say."""
    assert keyring.log_id == "test"
    assert keyring.retired("gate-test-1") is False
    assert rotation_keyring.retired("gate-test-1") is True
    assert rotation_keyring.retired("gate-test-2") is False
    with pytest.raises(KeyringError):
        keyring.retired("gate-test-9")


def test_keyring_load_requires_one_canonical_line_with_newline(tmp_path: Path) -> None:
    """No trailing newline, two lines, or a non-canonical body are each refused."""
    good = (VECTORS / "keyring.json").read_bytes()
    for bad in (good[:-1], good + good, b" " + good, good.replace(b",", b", ")):
        path = tmp_path / "keyring.json"
        path.write_bytes(bad)
        with pytest.raises(KeyringError):
            Keyring.load(path)
    path = tmp_path / "keyring.json"
    path.write_bytes(good)
    assert Keyring.load(path).log_id == "test"


@pytest.mark.parametrize(
    "data",
    [
        keyring_bytes(v=2),
        keyring_bytes(v=True),
        keyring_bytes(log_id="Test"),
        keyring_bytes(extra=1),
        keyring_bytes(keys=[]),
        keyring_bytes(keys={}),
        canonical_bytes({k: v for k, v in parse_object(keyring_bytes()).items() if k != "v"}),
        key_bytes(alg="ed25519-sha512"),
        key_bytes(alg="rsa"),
        key_bytes(kid="Gate Test 1"),
        key_bytes(kid="sink-test-1"),
        key_bytes(pub="84FibkHnAn6kMb/jAJ6UvdJadGvuxGiUjWw8fF3JpUs="),
        keyring_bytes(
            keys=parse_object(keyring_bytes())["keys"]
            + [{**parse_object(keyring_bytes())["keys"][0], "kid": "gate-test-1b"}]
        ),
        key_bytes(role="admin"),
        key_bytes(role=["gate"]),
        key_bytes(role={"gate": 1}),
        key_bytes(alg=["ed25519"]),
        key_bytes(pub="TLWr9q15+/WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluik"),
        key_bytes(pub="TLWr9q15+/WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluil="),
        key_bytes(pub=base64.b64encode(b"\x01" * 31).decode("ascii")),
        key_bytes(pub=base64.b64encode(b"\x01" * 33).decode("ascii")),
        key_bytes(pub="TLWr9q15+_WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluik="),
        key_bytes(valid_from_seq=-1),
        key_bytes(valid_from_seq=5, valid_to_seq=4),
        key_bytes(valid_from_seq=False),
        key_bytes(valid_to_seq=2**53),
        key_bytes(valid_to_seq="2"),
        key_bytes(note="x"),
        canonical_bytes(
            {
                "keys": [
                    {
                        k: v
                        for k, v in parse_object(keyring_bytes())["keys"][0].items()
                        if k != "role"
                    }
                ],
                "log_id": "test",
                "v": 1,
            }
        ),
        b"[]",
        b"{}",
        b"",
        b'{"keys":[[[[1]]]],"log_id":"test","v":1}',
    ],
)
def test_keyring_rejects_every_malformed_file(data: bytes) -> None:
    """Each variant differs from a valid keyring in exactly one rule and is refused."""
    with pytest.raises(KeyringError):
        Keyring.from_bytes(data)


def test_a_retired_key_cannot_sign_on_under_an_alias(
    rotation_keyring: Keyring, clock: None, dev: None
) -> None:
    """The alias keyring that would let gate-test-1 outlive its retirement does not load (#19)."""
    obj = parse_object((VECTORS / "positive" / "rotation" / "keyring.json").read_bytes()[:-1])
    alias = {**obj["keys"][0], "kid": "gate-test-1b", "valid_to_seq": None}
    with pytest.raises(KeyringError):
        Keyring.from_bytes(canonical_bytes({**obj, "keys": [*obj["keys"], alias]}))
    line = resigned(vector_lines("positive/rotation")[1], kid="gate-test-1b")
    with pytest.raises(GateError):
        from_wire(line, rotation_keyring)


def test_keyring_from_bytes_refuses_non_bytes_and_is_final() -> None:
    """A str is refused; subclassing and copying raise."""
    with pytest.raises(KeyringError):
        Keyring.from_bytes(keyring_bytes().decode("ascii"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):

        class Sub(Keyring):  # type: ignore[misc]
            """Never constructed."""

    with pytest.raises(TypeError):
        copy.copy(Keyring.from_bytes(keyring_bytes()))
    with pytest.raises(TypeError):
        Keyring()


def test_keyring_exposes_no_key_material_in_repr(keyring: Keyring) -> None:
    """repr names kids only; a public key is not secret but still not a text channel."""
    text = repr(keyring)
    assert "gate-test-1" in text
    assert "TLWr9q15" not in text
    assert "pub" not in json.dumps(text)
