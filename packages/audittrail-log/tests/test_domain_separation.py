"""I11: a signature under one SPEC §3.3 domain never verifies under another.

The anchor submission in `spec/vectors/positive/anchor/submission.json` is gate-test-1's
signature under the anchor domain. Presented as a record signature, by `Keyring` and by
`Approved.from_wire`, it is refused. Every key comes from the published seed in
`spec/test-seed.txt`; nothing here generates one.
"""

from __future__ import annotations

import base64
import dataclasses
from pathlib import Path
from typing import Any

import pytest
from audittrail.approved import Approved, GateError, InMemorySeenStore
from audittrail.keyring import Keyring, KeyringError
from audittrail.record import Record, canonical_bytes, parse_line
from audittrail.signing import (
    DOMAIN_ANCHOR,
    DOMAIN_ANCHOR_RECEIPT,
    DOMAIN_RECORD,
    SoftwareSigner,
)

SPEC = Path(__file__).resolve().parents[3] / "spec"
VECTORS = SPEC / "vectors"
SUBMISSION = VECTORS / "positive" / "anchor" / "submission.json"


def seed(kid: str) -> bytes:
    """The published seed for `kid` from `spec/test-seed.txt`. Generates nothing."""
    for raw in (SPEC / "test-seed.txt").read_text(encoding="ascii").splitlines():
        fields = raw.split()
        if fields and not fields[0].startswith("#") and fields[1] == kid:
            return bytes.fromhex(fields[0])
    raise KeyError(kid)


def lines_of(name: str) -> list[bytes]:
    """The lines of one single-file vector, without newlines."""
    [log] = sorted((VECTORS / name).glob("*.jsonl"))
    return log.read_bytes().removesuffix(b"\n").split(b"\n")


def submission() -> dict[str, Any]:
    """The committed anchor submission, parsed strictly."""
    return parse_line(SUBMISSION.read_bytes().removesuffix(b"\n"))


def sig_field(signature: bytes) -> str:
    """`ed25519:<base64>` as SPEC §3.1 writes it."""
    return "ed25519:" + base64.b64encode(signature).decode("ascii")


def with_sig(line: bytes, sig: str) -> bytes:
    """The record line with its `sig` replaced and nothing else changed, as canonical bytes."""
    fields = dataclasses.asdict(Record.from_line(line))
    fields["sig"] = sig
    return canonical_bytes(fields)


def body_of(line: bytes) -> bytes:
    """The record's canonical bytes without `sig` (SPEC §3.2 step 1)."""
    fields = dataclasses.asdict(Record.from_line(line))
    del fields["sig"]
    return canonical_bytes(fields)


@pytest.fixture
def keyring() -> Keyring:
    """The shared vector keyring: gate-test-1 for every seq, sink-test-1."""
    return Keyring.load(VECTORS / "keyring.json")


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> SoftwareSigner:
    """gate-test-1, the key that signed the anchor submission, from the published seed."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")
    return SoftwareSigner("gate-test-1", seed("gate-test-1"))


def from_wire(line: bytes, keyring: Keyring) -> Approved:
    """`Approved.from_wire` with the decision-approve vector's binding values."""
    return Approved.from_wire(
        line,
        keyring,
        candidate=_Cart(),
        app="test-app",
        log_id="test",
        max_age_s=60,
        seen=InMemorySeenStore(),
    )


class _Cart:
    """The Candidate the decision-approve vector's `cart_hash` was computed from."""

    def canonical_bytes(self) -> bytes:
        """JCS of the synthetic cart in the vector generator."""
        return canonical_bytes({"account": "acct-0001", "amount": 100})


def test_the_submission_is_gate_test_1_under_the_anchor_domain(gate: SoftwareSigner) -> None:
    """Python's DOMAIN_ANCHOR and gate-test-1 reproduce the Go-signed submission exactly."""
    obj = submission()
    want = obj.pop("sig")
    assert obj["kid"] == "gate-test-1"
    assert sig_field(gate.sign(DOMAIN_ANCHOR, canonical_bytes(obj))) == want


def test_anchor_submission_signature_presented_as_a_record_signature_is_refused(
    keyring: Keyring,
) -> None:
    """The anchor record and the approve decision, each carrying the submission's sig, fail.

    `Keyring.check_record_signature` raises and `Approved.from_wire` refuses at rule 2. The
    literal SPEC §7 I11 case; its bytes differ from the record's too, so the same-bytes test
    below is the one that pins the domain.
    """
    stolen = submission()["sig"]
    anchor_record = lines_of("positive/anchor")[2]
    approve = lines_of("positive/decision-approve")[1]
    for line in (anchor_record, approve):
        keyring.check_record_signature(Record.from_line(line))
        with pytest.raises(KeyringError, match="does not verify"):
            keyring.check_record_signature(Record.from_line(with_sig(line, stolen)))
    with pytest.raises(GateError):
        from_wire(with_sig(approve, stolen), keyring)


@pytest.mark.parametrize(
    "domain", [DOMAIN_ANCHOR, DOMAIN_ANCHOR_RECEIPT], ids=["anchor", "anchor-receipt"]
)
def test_a_record_body_signed_under_another_domain_is_refused(
    gate: SoftwareSigner, keyring: Keyring, domain: bytes
) -> None:
    """Same key, same bytes: only the record domain verifies; the other two are refused.

    This is the test that fails if the domains are collapsed into one (mutations/I11.diff).
    """
    approve = lines_of("positive/decision-approve")[1]
    body = body_of(approve)
    assert with_sig(approve, sig_field(gate.sign(DOMAIN_RECORD, body))) == approve
    crossed = with_sig(approve, sig_field(gate.sign(domain, body)))
    with pytest.raises(KeyringError, match="does not verify"):
        keyring.check_record_signature(Record.from_line(crossed))
    with pytest.raises(GateError):
        from_wire(crossed, keyring)


def test_the_wrong_domain_vector_is_refused(keyring: Keyring) -> None:
    """The Go-signed decision under the anchor domain (spec/vectors/negative/wrong-domain)."""
    genesis, crossed = lines_of("negative/wrong-domain")
    keyring.check_record_signature(Record.from_line(genesis))
    with pytest.raises(KeyringError, match="does not verify"):
        keyring.check_record_signature(Record.from_line(crossed))
