"""I11 at the verifier: an anchor-domain signature never passes check 5 as a record signature.

Every input is a committed file under `spec/`, or a copy of one with `sig` replaced by another
committed file's `sig`, in a temporary directory. Nothing here signs: a line signed under the
wrong domain is a vector from `tools/vectors-go` (CLAUDE.md rule 4; issue #21). The other
domains are spelled here from SPEC §3.3 because the verifier has no reason to know them;
nothing is imported from `audittrail`.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from audittrail_verify.canonical import canonical_bytes, parse_canonical, parse_object
from audittrail_verify.checks import DOMAIN_RECORD, _signature_problem
from audittrail_verify.cli import main
from audittrail_verify.keyring import Keyring, load_keyring
from cryptography.exceptions import InvalidSignature

SPEC = Path(__file__).resolve().parents[3] / "spec"
VECTORS = SPEC / "vectors"
SHARED_KEYRING = VECTORS / "keyring.json"
ANCHOR_DOMAIN = b"ai-audit-trail/v1/anchor\x00"
"""SPEC §3.3, anchor submissions."""
RECEIPT_DOMAIN = b"ai-audit-trail/v1/anchor-receipt\x00"
"""SPEC §3.3, sink receipts."""


def submission() -> dict[str, Any]:
    """The committed anchor submission, parsed strictly."""
    path = VECTORS / "positive" / "anchor" / "submission.json"
    return parse_object(path.read_bytes().removesuffix(b"\n"))


def lines_of(name: str) -> list[bytes]:
    """All lines of a single-file vector, without newlines."""
    [log] = sorted((VECTORS / name).glob("*.jsonl"))
    return log.read_bytes().removesuffix(b"\n").split(b"\n")


def signed_bytes(obj: dict[str, Any]) -> tuple[bytes, bytes]:
    """(signature bytes, canonical body without `sig`) of a parsed object. Verifies nothing."""
    signature = base64.b64decode(obj["sig"].removeprefix("ed25519:"), validate=True)
    body = canonical_bytes({k: v for k, v in obj.items() if k != "sig"})
    return signature, body


def run(files: list[Path], capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Run the CLI in-process against the shared keyring; return the report."""
    code = main(["--keyring", str(SHARED_KEYRING), *map(str, files)])
    report: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert report["exit"] == code
    return report


@pytest.fixture
def shared() -> Keyring:
    """The shared vector keyring."""
    return load_keyring(SHARED_KEYRING)


def test_the_record_domain_is_not_the_anchor_domain() -> None:
    """The verifier's one domain is SPEC §3.3's record domain, byte for byte."""
    assert DOMAIN_RECORD == b"ai-audit-trail/v1/record\x00"
    assert DOMAIN_RECORD != ANCHOR_DOMAIN


def test_the_submission_bytes_verify_under_the_anchor_domain_only(shared: Keyring) -> None:
    """gate-test-1's submission signature is valid, and check 5's signature check refuses it.

    Same key, same bytes; only the domain differs, so the refusal is domain separation.
    """
    obj = submission()
    signature, body = signed_bytes(obj)
    pub = shared.keys[obj["kid"]].pub
    pub.verify(signature, ANCHOR_DOMAIN + body)
    with pytest.raises(InvalidSignature):
        pub.verify(signature, DOMAIN_RECORD + body)
    assert _signature_problem(obj, shared) == "signature does not verify"


def test_anchor_submission_signature_on_a_record_line_fails_check_5(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor vector, its last record (the anchor at seq 2) carrying the submission's sig.

    The literal SPEC §7 I11 case. The submission's bytes differ from the record's, so this
    would fail without domains too; the same-bytes tests below are what pin the domain.
    """
    lines = lines_of("positive/anchor")
    path = tmp_path / "test.0000000000000000.jsonl"
    path.write_bytes(b"".join(line + b"\n" for line in lines))
    assert run([path], capsys)["first_failing_check"] is None
    last = parse_canonical(lines[-1])
    assert last["type"] == "anchor" and last["kid"] == submission()["kid"]
    last["sig"] = submission()["sig"]
    path.write_bytes(b"".join(line + b"\n" for line in lines[:-1]) + canonical_bytes(last) + b"\n")
    report = run([path], capsys)
    assert report["exit"] == 2
    assert report["first_failing_check"] == 5
    assert report["failures"][0]["line"] == 3
    assert report["failures"][0]["message"] == "signature does not verify"


@pytest.mark.parametrize(
    ("name", "domain"),
    [
        ("negative/wrong-domain", ANCHOR_DOMAIN),
        ("negative/wrong-domain-anchor-receipt", RECEIPT_DOMAIN),
    ],
    ids=["anchor", "anchor-receipt"],
)
def test_a_record_body_signed_under_another_domain_fails_check_5(
    shared: Keyring, name: str, domain: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same key, same bytes as the approve vector's decision; only the domain differs.

    The wrong-domain vector's decision is byte for byte the body of the decision in
    `positive/decision-approve`, signed by the same `kid`: its signature verifies under the
    domain its name says and under no other, and check 5 is where the verifier refuses it.
    """
    _, approved = (parse_canonical(line) for line in lines_of("positive/decision-approve"))
    _, crossed = (parse_canonical(line) for line in lines_of(name))
    assert {k: v for k, v in crossed.items() if k != "sig"} == {
        k: v for k, v in approved.items() if k != "sig"
    }
    assert crossed["sig"] != approved["sig"]
    signature, body = signed_bytes(crossed)
    pub = shared.keys[crossed["kid"]].pub
    pub.verify(signature, domain + body)
    with pytest.raises(InvalidSignature):
        pub.verify(signature, DOMAIN_RECORD + body)
    assert _signature_problem(crossed, shared) == "signature does not verify"
    report = run(sorted((VECTORS / name).glob("*.jsonl")), capsys)
    assert report["exit"] == 2 and report["first_failing_check"] == 5
    assert report["failures"][0]["line"] == 2
