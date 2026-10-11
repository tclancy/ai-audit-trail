"""Signer protocol and SoftwareSigner: dev-gated (I12), bit-identical to the published vectors.

Seeds come from `spec/test-seed.txt`, which is published and exempt from the key-material grep.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
from pathlib import Path

import pytest
from audittrail.record import Record, SchemaError, canonical_bytes, parse_line
from audittrail.signing import (
    DOMAIN_ANCHOR,
    DOMAIN_ANCHOR_RECEIPT,
    DOMAIN_RECORD,
    DOMAINS,
    Signer,
    SigningError,
    SoftwareSigner,
)

SPEC = Path(__file__).resolve().parents[3] / "spec"


def published_seeds() -> dict[str, bytes]:
    """Parse `spec/test-seed.txt` into kid -> 32-byte seed. Fails on a malformed line."""
    seeds: dict[str, bytes] = {}
    for raw in (SPEC / "test-seed.txt").read_text(encoding="ascii").splitlines():
        fields = raw.split()
        if not fields or fields[0].startswith("#"):
            continue
        seed = bytes.fromhex(fields[0])
        assert len(seed) == 32, raw
        seeds[fields[1]] = seed
    assert set(seeds) == {"gate-test-1", "gate-test-2", "sink-test-1"}
    return seeds


@pytest.fixture
def dev(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set `AUDITTRAIL_DEV=1` for one test."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")


@pytest.fixture
def signers(dev: None) -> dict[str, SoftwareSigner]:
    """One SoftwareSigner per published seed."""
    return {kid: SoftwareSigner(kid, seed) for kid, seed in published_seeds().items()}


def sig_field(signature: bytes) -> str:
    """`ed25519:<base64>` as SPEC §3.1 writes it."""
    return "ed25519:" + base64.b64encode(signature).decode("ascii")


def body_of(record: Record) -> bytes:
    """The record's canonical bytes without `sig` (SPEC §3.2 step 1)."""
    fields = dataclasses.asdict(record)
    del fields["sig"]
    return canonical_bytes(fields)


# --- I12: refuses outside dev ------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "0", "true", "yes", "1 ", " 1"])
def test_software_signer_refuses_unless_dev_is_exactly_one(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    """Only the literal `1` opens the gate; absence and every other value raise RuntimeError."""
    if value is None:
        monkeypatch.delenv("AUDITTRAIL_DEV", raising=False)
    else:
        monkeypatch.setenv("AUDITTRAIL_DEV", value)
    with pytest.raises(RuntimeError):
        SoftwareSigner("gate-test-1", published_seeds()["gate-test-1"])


# --- bit-identical to the vectors ----------------------------------------------


def test_every_positive_vector_signature_is_reproduced(
    vectors_dir: Path, signers: dict[str, SoftwareSigner]
) -> None:
    """Signing each record's body under the record domain with its kid's key gives its `sig`."""
    seen_kids: set[str] = set()
    for vector in sorted(p for p in (vectors_dir / "positive").iterdir() if p.is_dir()):
        for f in sorted(vector.glob("*.jsonl")):
            for line in f.read_bytes().removesuffix(b"\n").split(b"\n"):
                record = Record.from_line(line)
                signer = signers[record.kid]
                assert (
                    sig_field(signer.sign(DOMAIN_RECORD, body_of(record))) == record.sig
                ), vector.name
                seen_kids.add(record.kid)
    assert seen_kids == {"gate-test-1", "gate-test-2"}


def test_anchor_submission_and_receipt_signatures_are_reproduced(
    vectors_dir: Path, signers: dict[str, SoftwareSigner]
) -> None:
    """The submission signs under the anchor domain; the sink receipt under its own domain."""
    anchor = vectors_dir / "positive" / "anchor"
    cases = [
        (anchor / "submission.json", "gate-test-1", DOMAIN_ANCHOR),
        (
            anchor / "anchors" / "test" / "0000000000000001.json",
            "sink-test-1",
            DOMAIN_ANCHOR_RECEIPT,
        ),
    ]
    for path, kid, domain in cases:
        obj = parse_line(path.read_bytes().removesuffix(b"\n"))
        want = obj.pop("sig")
        assert sig_field(signers[kid].sign(domain, canonical_bytes(obj))) == want, path.name


def test_signing_is_deterministic_and_domain_bound(signers: dict[str, SoftwareSigner]) -> None:
    """Same input twice gives the same bytes; a different domain gives different bytes."""
    s = signers["gate-test-1"]
    assert s.sign(DOMAIN_RECORD, b"x") == s.sign(DOMAIN_RECORD, b"x")
    assert len(s.sign(DOMAIN_RECORD, b"x")) == 64
    assert len({s.sign(d, b"x") for d in DOMAINS}) == len(DOMAINS) == 3


# --- construction rules and hygiene ------------------------------------------


def test_unknown_domain_is_refused(signers: dict[str, SoftwareSigner]) -> None:
    """A domain not in SPEC §3.3 never produces a signature."""
    with pytest.raises(SigningError):
        signers["gate-test-1"].sign(b"ai-audit-trail/v1/record", b"x")
    with pytest.raises(SigningError):
        signers["gate-test-1"].sign(b"", b"x")


def test_kid_is_regex_validated_and_seed_must_be_32_bytes(dev: None) -> None:
    """`kid` follows SPEC §3.1; the seed is exactly 32 bytes (I8, no text channel)."""
    seed = published_seeds()["gate-test-1"]
    with pytest.raises(SchemaError):
        SoftwareSigner("Gate Test", seed)
    with pytest.raises(SchemaError):
        SoftwareSigner("a" * 33, seed)
    with pytest.raises(SigningError):
        SoftwareSigner("gate-test-1", seed[:31])
    with pytest.raises(SigningError):
        SoftwareSigner("gate-test-1", seed + b"\x00")


def test_signer_exposes_kid_only(signers: dict[str, SoftwareSigner]) -> None:
    """Nothing on the object returns key material; repr, dir and copy protocols give none."""
    s = signers["gate-test-1"]
    seed = published_seeds()["gate-test-1"]
    assert s.kid == "gate-test-1"
    assert seed.hex() not in repr(s) and "seed" not in repr(s)
    assert not any(getattr(s, a, None) == seed for a in dir(s))
    with pytest.raises(TypeError):
        copy.copy(s)
    with pytest.raises(TypeError):
        copy.deepcopy(s)
    with pytest.raises(TypeError):

        class Sub(SoftwareSigner):
            """Never constructed; the class statement must raise."""


def test_software_signer_satisfies_the_protocol(signers: dict[str, SoftwareSigner]) -> None:
    """A SoftwareSigner is a Signer at runtime as well as for the type checker."""
    assert isinstance(signers["gate-test-1"], Signer)
