"""The consumer stub acts on a receipt only through `Approved.from_wire` (SPEC §6 rules 1–7).

A real gate stub writes the receipts into the test's temp dir; the consumer loads the keyring
the gate wrote. The skeleton scenario (`make skeleton`) is the same code run against the gate
over HTTP.
"""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from audittrail.approved import Approved, GateError
from audittrail.keyring import Keyring
from audittrail.log import LogUnavailable
from audittrail.record import Record
from consumer_stub import Cart, Consumer, fetch_receipt, scenario, tampered
from gate_stub import APP, Gate, open_gate, serve

LOG_ID = "skeleton"


@pytest.fixture
def gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Gate:
    """A gate with its log and keyring under tmp_path."""
    monkeypatch.setenv("AUDITTRAIL_DEV", "1")
    (tmp_path / "log").mkdir()
    return open_gate(tmp_path / "log", tmp_path / "keyring.json", LOG_ID)


@pytest.fixture
def consumer(gate: Gate, tmp_path: Path) -> Consumer:
    """A consumer for the gate's app and log, with a fresh in-memory seen store."""
    return Consumer(Keyring.load(tmp_path / "keyring.json"), app=APP, log_id=LOG_ID)


GOOD = Cart({"account": "acct-1", "amount": 100})


def test_a_receipt_for_the_cart_is_acted_on(gate: Gate, consumer: Consumer) -> None:
    """The gate's approve line for this cart passes every rule and is acted on once."""
    line = gate.decide(GOOD.canonical_bytes())
    approved = consumer.act(line, GOOD)
    assert type(approved) is Approved
    assert approved.entry.seq == 1 and approved.line == line


def test_a_tampered_receipt_is_refused(gate: Gate, consumer: Consumer) -> None:
    """One changed byte in the receipt and the consumer refuses; nothing is acted on."""
    line = gate.decide(GOOD.canonical_bytes())
    bad = tampered(line)
    assert bad != line and len(bad) == len(line)
    with pytest.raises(GateError):
        consumer.act(bad, GOOD)
    assert consumer.actions == []


def test_tampering_changes_the_cart_binding_and_keeps_the_line_canonical(gate: Gate) -> None:
    """`tampered` edits one hex digit of `cart_hash`, so the line still parses and only rule 5
    or the signature can refuse it; a tamper the parser catches first would prove less."""
    line = gate.decide(GOOD.canonical_bytes())
    record, bad = Record.from_line(line), Record.from_line(tampered(line))
    assert bad.cart_hash != record.cart_hash
    assert bad.sig == record.sig


def test_the_same_receipt_is_refused_the_second_time(gate: Gate, consumer: Consumer) -> None:
    """Rule 7: a replayed receipt authorizes nothing."""
    line = gate.decide(GOOD.canonical_bytes())
    consumer.act(line, GOOD)
    with pytest.raises(GateError, match="rule 7"):
        consumer.act(line, GOOD)
    assert len(consumer.actions) == 1


def test_a_receipt_for_another_cart_is_refused(gate: Gate, consumer: Consumer) -> None:
    """Rule 5: the receipt is bound to the bytes the gate hashed, not to the account."""
    line = gate.decide(GOOD.canonical_bytes())
    with pytest.raises(GateError, match="rule 5"):
        consumer.act(line, Cart({"account": "acct-1", "amount": 101}))


def test_a_rejection_line_is_refused(gate: Gate, consumer: Consumer) -> None:
    """Rule 1: a signed reject is a record, not a receipt."""
    other = Cart({"account": "acct-1", "amount": 101})
    line = gate.decide(other.canonical_bytes())
    assert Record.from_line(line).decision == "reject"
    with pytest.raises(GateError, match="rule 1"):
        consumer.act(line, other)


def test_a_consumer_for_another_app_refuses(gate: Gate, tmp_path: Path) -> None:
    """Rule 4: the receipt names the app it was issued for."""
    line = gate.decide(GOOD.canonical_bytes())
    other = Consumer(Keyring.load(tmp_path / "keyring.json"), app="other-app", log_id=LOG_ID)
    with pytest.raises(GateError, match="rule 4"):
        other.act(line, GOOD)


@pytest.fixture
def port(gate: Gate) -> Iterator[int]:
    """The gate served over HTTP on an ephemeral port, on the loopback interface."""
    httpd = serve(gate, 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_skeleton_scenario_acts_once_and_refuses_twice(port: int, consumer: Consumer) -> None:
    """Against a live gate: act on one receipt, refuse the tampered copy, refuse the replay."""
    assert scenario("127.0.0.1", port, consumer) == 0
    assert len(consumer.actions) == 1


def test_the_scenario_fails_when_a_tampered_receipt_would_be_acted_on(
    port: int, consumer: Consumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scenario is a check, not a demo: a consumer that does not refuse makes it exit 1."""

    def act_anyway(line: bytes, cart: Cart) -> None:
        """Stand in for `Consumer.act` and act without checking anything."""
        consumer.actions.append(line)

    monkeypatch.setattr(consumer, "act", act_anyway)
    assert scenario("127.0.0.1", port, consumer) == 1


def test_the_scenario_fails_when_only_the_tampered_copy_is_acted_on(
    port: int, consumer: Consumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refusing the replay does not excuse acting on the tampered copy."""
    real_act = consumer.act
    seen_lines: list[bytes] = []

    def act_on_tampered(line: bytes, cart: Cart) -> Approved | None:
        """Check the first line and its replays for real; act on any other line unchecked."""
        if seen_lines and line not in seen_lines:
            consumer.actions.append(line)
            return None
        seen_lines.append(line)
        return real_act(line, cart)

    monkeypatch.setattr(consumer, "act", act_on_tampered)
    assert scenario("127.0.0.1", port, consumer) == 1
    assert len(consumer.actions) == 2


def test_the_scenario_fails_when_only_the_replay_is_acted_on(
    port: int, consumer: Consumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refusing the tampered copy does not excuse acting on the replay (a forgetful seen store)."""

    class Forgetful:
        """A SeenStore that remembers nothing, so every receipt is its first use."""

        def first_use(self, request_id: str) -> bool:
            """Always first."""
            return True

    monkeypatch.setattr(consumer, "_seen", Forgetful())
    assert scenario("127.0.0.1", port, consumer) == 1
    assert len(consumer.actions) == 2


def test_an_unexpected_error_in_the_consumer_stops_the_scenario(
    port: int, consumer: Consumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a `GateError` is a refusal; anything else propagates instead of counting as one."""
    real_act = consumer.act

    def act_then_break(line: bytes, cart: Cart) -> Approved:
        """Act for real once, then fail in a way that is not a refusal."""
        if consumer.actions:
            raise RuntimeError("planted")
        return real_act(line, cart)

    monkeypatch.setattr(consumer, "act", act_then_break)
    with pytest.raises(RuntimeError, match="planted"):
        scenario("127.0.0.1", port, consumer)


def test_a_gate_that_answers_anything_but_200_yields_no_receipt(
    port: int, consumer: Consumer, gate: Gate, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 503 from the gate is an error at the consumer, not a line to try `from_wire` on."""

    def refuse(fields: object) -> None:
        """Stand in for `Log.record` and refuse."""
        raise LogUnavailable("planted")

    monkeypatch.setattr(gate._log, "record", refuse)
    with pytest.raises(http.client.HTTPException, match="503"):
        fetch_receipt("127.0.0.1", port, GOOD)
    assert consumer.actions == []


def test_a_consumer_for_another_log_refuses(gate: Gate, tmp_path: Path) -> None:
    """Rule 3: the receipt is meaningful only in its own log; the keyring's log must match too."""
    line = gate.decide(GOOD.canonical_bytes())
    other = Consumer(Keyring.load(tmp_path / "keyring.json"), app=APP, log_id="other-log")
    with pytest.raises(GateError, match="rule 3"):
        other.act(line, GOOD)
