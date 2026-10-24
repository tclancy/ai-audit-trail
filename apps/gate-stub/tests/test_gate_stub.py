"""The gate stub: every request becomes a signed decision line, or no answer at all (I10).

The log directory and keyring are the test's temp dir; the signer is a `SoftwareSigner`
under `AUDITTRAIL_DEV=1`. Nothing here reads the published test seed.
"""

from __future__ import annotations

import hashlib
import http.client
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from audittrail.keyring import Keyring
from audittrail.log import LogUnavailable
from audittrail.record import ZERO_HASH, Record, canonical_bytes
from audittrail_verify.checks import verify
from audittrail_verify.keyring import load_keyring
from gate_stub import APP, MAX_BODY_BYTES, Gate, open_gate, serve


def cart(account: str, amount: int) -> bytes:
    """The canonical bytes of a cart, as the consumer computes them."""
    return canonical_bytes({"account": account, "amount": amount})


def sha256(data: bytes) -> str:
    """`sha256:<hex>` of `data`."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture
def gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Gate:
    """A gate with its log under tmp_path/log and its keyring at tmp_path/keyring.json."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")
    (tmp_path / "log").mkdir()
    return open_gate(tmp_path / "log", tmp_path / "keyring.json", "skeleton")


def test_a_matching_cart_is_approved_and_bound_to_its_bytes(gate: Gate) -> None:
    """The line is a decision record: approve, oracle match, cart_hash of the request bytes."""
    body = cart("acct-1", 100)
    record = Record.from_line(gate.decide(body))
    assert (record.type, record.decision, record.oracle) == ("decision", "approve", "match")
    assert record.reason == "R_ORACLE_MATCH"
    assert record.cart_hash == sha256(body)
    assert record.app == APP
    assert record.oracle_ref == sha256(canonical_bytes({"account": "acct-1", "amount": 100}))


def test_a_cart_the_oracle_contradicts_is_rejected(gate: Gate) -> None:
    """Same account, different amount: logged as a reject with the oracle's answer hashed."""
    record = Record.from_line(gate.decide(cart("acct-1", 101)))
    assert (record.decision, record.oracle, record.reason) == (
        "reject",
        "mismatch",
        "R_ORACLE_MISMATCH",
    )
    assert record.cart_hash == sha256(cart("acct-1", 101))
    assert record.oracle_ref == sha256(canonical_bytes({"account": "acct-1", "amount": 100}))


def test_an_unknown_account_is_rejected_without_consulting(gate: Gate) -> None:
    """No oracle entry: reject, `not_consulted`, zero-hash oracle_ref."""
    record = Record.from_line(gate.decide(cart("nobody", 1)))
    assert (record.decision, record.oracle, record.reason) == (
        "reject",
        "not_consulted",
        "R_POLICY_DENY",
    )
    assert record.oracle_ref == ZERO_HASH


@pytest.mark.parametrize(
    "body",
    [
        b'{"account": "acct-1", "amount": 100}',
        b'{"amount":100,"account":"acct-1"}',
        b'{"account":"acct-1","amount":100.0}',
        b"[1]",
        b"",
        b"\xff",
        b'{"account":"acct-1","amount":100}\n',
    ],
    ids=["spaces", "unsorted", "float", "array", "empty", "non-ascii", "newline"],
)
def test_a_non_canonical_cart_is_rejected_as_a_parse_failure(gate: Gate, body: bytes) -> None:
    """The gate never normalizes a request; it logs a reject naming the bytes it refused."""
    record = Record.from_line(gate.decide(body))
    assert (record.decision, record.oracle, record.reason) == ("reject", "not_consulted", "R_PARSE")
    assert record.cart_hash == sha256(body)
    assert record.oracle_ref == ZERO_HASH


def test_every_decision_is_on_disk_and_the_verifier_accepts_the_log(
    gate: Gate, tmp_path: Path
) -> None:
    """Boot plus three decisions in seq order, chain intact, signed under the written keyring."""
    for body in (cart("acct-1", 100), cart("acct-1", 5), b"junk"):
        gate.decide(body)
    [log] = sorted((tmp_path / "log").glob("*.jsonl"))
    report = verify([log], load_keyring(tmp_path / "keyring.json"))
    assert report["first_failing_check"] is None
    assert report["records"] == 4
    assert report["prefix_unverified"] is False


def test_the_keyring_file_is_one_canonical_line_for_the_gate_key(
    gate: Gate, tmp_path: Path
) -> None:
    """Loads strictly; names the log and one gate key; the first receipt verifies under it."""
    keyring = Keyring.load(tmp_path / "keyring.json")
    assert keyring.log_id == "skeleton"
    record = Record.from_line(gate.decide(cart("acct-1", 100)))
    keyring.check_record_signature(record)


def test_a_log_failure_is_no_decision(gate: Gate, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the log refuses, the gate raises; it never answers with an unlogged line (I10)."""

    def refuse(fields: object) -> None:
        """Stand in for `Log.record` and refuse."""
        raise LogUnavailable("planted")

    monkeypatch.setattr(gate._log, "record", refuse)
    with pytest.raises(LogUnavailable):
        gate.decide(cart("acct-1", 100))


def test_the_gate_cannot_open_outside_dev(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without `AUDITTRAIL_DEV=1` there is no signer and so no gate (I12)."""
    monkeypatch.delenv("AUDITTRAIL_DEV", raising=False)
    with pytest.raises(RuntimeError):
        open_gate(tmp_path, tmp_path / "keyring.json", "skeleton")


@pytest.fixture
def server(gate: Gate) -> Iterator[tuple[Gate, int]]:
    """The gate served on an ephemeral port in a thread; shut down after the test."""
    httpd = serve(gate, 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield gate, httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def post(port: int, path: str, body: bytes) -> tuple[int, bytes]:
    """POST `body` and return (status, response body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", path, body=body, headers={"Content-Length": str(len(body))})
    response = conn.getresponse()
    return response.status, response.read()


def test_over_http_the_body_is_the_line_and_health_answers(server: tuple[Gate, int]) -> None:
    """POST /decide returns the record line without a newline; GET /health is 200 once booted."""
    _, port = server
    status, line = post(port, "/decide", cart("acct-1", 100))
    assert status == 200
    assert Record.from_line(line).decision == "approve"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/health")
    assert conn.getresponse().status == 200


def test_over_http_a_log_failure_is_503_with_no_body(
    server: tuple[Gate, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HTTP layer adds no answer of its own: a refused log is 503 and nothing else."""
    gate, port = server

    def refuse(fields: object) -> None:
        """Stand in for `Log.record` and refuse."""
        raise LogUnavailable("planted")

    monkeypatch.setattr(gate._log, "record", refuse)
    status, body = post(port, "/decide", cart("acct-1", 100))
    assert (status, body) == (503, b"")


def log_lines(tmp_path: Path) -> int:
    """How many lines the gate's one log file holds."""
    [log] = sorted((tmp_path / "log").glob("*.jsonl"))
    return log.read_bytes().count(b"\n")


def test_over_http_other_paths_and_methods_are_404_and_not_logged(
    server: tuple[Gate, int], tmp_path: Path
) -> None:
    """Only POST /decide decides; anything else is 404 and the log still holds the boot alone."""
    _, port = server
    assert post(port, "/other", cart("acct-1", 100))[0] == 404
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/decide")
    assert conn.getresponse().status == 404
    assert log_lines(tmp_path) == 1


def test_over_http_an_oversized_body_is_413_and_not_logged(
    server: tuple[Gate, int], tmp_path: Path
) -> None:
    """A body over MAX_BODY_BYTES is never read: 413, empty body, nothing written."""
    _, port = server
    assert post(port, "/decide", b"x" * (MAX_BODY_BYTES + 1)) == (413, b"")
    assert log_lines(tmp_path) == 1


def test_the_gate_writes_the_keyring_and_nothing_else_beside_it(gate: Gate, tmp_path: Path) -> None:
    """The keyring's directory holds the keyring and the log directory only: no seed, no sidecar."""
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keyring.json", "log"]
    assert sorted(p.name for p in (tmp_path / "log").iterdir()) == [
        "skeleton.0000000000000000.jsonl"
    ]


def test_a_second_gate_on_the_same_log_is_refused_and_leaves_the_keyring_alone(
    gate: Gate, tmp_path: Path
) -> None:
    """A per-boot key cannot adopt an existing log: the second boot is refused before it draws
    a key, the first keyring still verifies the first receipt, and the log did not grow."""
    receipt = Record.from_line(gate.decide(cart("acct-1", 100)))
    before = (tmp_path / "keyring.json").read_bytes()
    with pytest.raises(LogUnavailable, match="genesis only"):
        open_gate(tmp_path / "log", tmp_path / "keyring.json", "skeleton")
    assert (tmp_path / "keyring.json").read_bytes() == before
    Keyring.load(tmp_path / "keyring.json").check_record_signature(receipt)
    assert log_lines(tmp_path) == 2


def test_no_keyring_is_written_for_a_log_that_did_not_boot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory the log cannot use is `LogUnavailable` and leaves no keyring behind."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")
    with pytest.raises(LogUnavailable):
        open_gate(tmp_path / "missing", tmp_path / "keyring.json", "skeleton")
    assert not (tmp_path / "keyring.json").exists()
