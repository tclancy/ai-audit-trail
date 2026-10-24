# SPDX-License-Identifier: Apache-2.0
"""consumer-stub: acts on a receipt only after `Approved.from_wire` (SPEC §6 rules 1–7).

`scenario` is what `make skeleton` runs: fetch one receipt from the gate, act on it, then
refuse the same receipt with one byte changed and refuse the replay. Acting is printing one
line; the consumer's own append-only action log (rule 8) arrives in M4. Nothing here signs,
writes the gate's log, or parses a receipt by any path but `from_wire`.
"""

from __future__ import annotations

import http.client
import os
import sys
import time
from pathlib import Path
from typing import Any

from audittrail.approved import Approved, GateError, InMemorySeenStore
from audittrail.keyring import Keyring
from audittrail.record import canonical_bytes


class Cart:
    """A Candidate (SPEC §2): the consumer's own strictly built request, held as its JCS bytes."""

    __slots__ = ("_bytes",)

    def __init__(self, obj: dict[str, Any]) -> None:
        """Serialize `obj` once; anything outside the canonical alphabet is refused here."""
        self._bytes = canonical_bytes(obj)

    def canonical_bytes(self) -> bytes:
        """Return the bytes the gate hashed into `cart_hash`."""
        return self._bytes


class Consumer:
    """One consumer for one app and one log. `actions` holds every line it acted on, in order."""

    def __init__(self, keyring: Keyring, *, app: str, log_id: str, max_age_s: int = 60) -> None:
        """Hold the keyring and identity; start with nothing seen and nothing acted on."""
        self._keyring = keyring
        self._app = app
        self._log_id = log_id
        self._max_age_s = max_age_s
        self._seen = InMemorySeenStore()
        self.actions: list[bytes] = []

    def act(self, line: bytes, cart: Cart) -> Approved:
        """Act on `line` for `cart` after every rule 1–7 holds; `GateError` and no action otherwise.

        The action is one printed line. Does not catch the refusal: the caller decides what a
        refusal means for it.
        """
        approved = Approved.from_wire(
            line,
            self._keyring,
            candidate=cart,
            app=self._app,
            log_id=self._log_id,
            max_age_s=self._max_age_s,
            seen=self._seen,
        )
        self.actions.append(approved.line)
        entry = approved.entry
        print(f"consumer-stub: acted on seq={entry.seq} request_id={entry.request_id}", flush=True)
        return approved


def tampered(line: bytes) -> bytes:
    """Return `line` with the first hex digit of `cart_hash` changed: same length, still canonical.

    The copy parses and fails only on the signature or the binding, so refusing it proves
    those checks and not the parser. Raises `ValueError` if the line has no `cart_hash`.
    """
    marker = b'"cart_hash":"sha256:'
    at = line.index(marker) + len(marker)
    digit = b"1" if line[at : at + 1] == b"0" else b"0"
    return line[:at] + digit + line[at + 1 :]


def fetch_receipt(host: str, port: int, cart: Cart) -> bytes:
    """POST the cart's bytes to the gate and return the body: the line the gate logged.

    Any status but 200 is an `http.client.HTTPException`; the consumer never guesses at a line.
    """
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("POST", "/decide", body=cart.canonical_bytes())
    response = conn.getresponse()
    body = response.read()
    if response.status != 200:
        raise http.client.HTTPException(f"gate answered {response.status}")
    return body


def wait_for_gate(host: str, port: int, timeout_s: float = 30) -> None:
    """Poll GET /health until it answers 200, or raise `TimeoutError` after `timeout_s`."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=2)
            conn.request("GET", "/health")
            if conn.getresponse().status == 200:
                return
        except OSError:
            if time.monotonic() > deadline:
                raise TimeoutError(f"gate at {host}:{port} did not become healthy") from None
        time.sleep(0.2)


def _refuses(consumer: Consumer, line: bytes, cart: Cart, name: str) -> bool:
    """Return whether the consumer refuses `line` for `cart`, printing what happened.

    A consumer that does not refuse has acted, and the caller treats that as the failure it is.
    """
    try:
        consumer.act(line, cart)
    except GateError as e:
        print(f"consumer-stub: refused the {name} receipt: {e}", flush=True)
        return True
    print(f"consumer-stub: acted on the {name} receipt", file=sys.stderr, flush=True)
    return False


def scenario(host: str, port: int, consumer: Consumer) -> int:
    """Act on one receipt, then refuse its tampered copy and its replay. 0 if all three, else 1.

    The scenario is a check, not a demo: a consumer that acts on the tampered copy or the
    replay makes it 1. Does not verify the log; that is the verifier service's job.
    """
    cart = Cart({"account": "acct-1", "amount": 100})
    line = fetch_receipt(host, port, cart)
    consumer.act(line, cart)
    refused = [
        _refuses(consumer, tampered(line), cart, "tampered"),
        _refuses(consumer, line, cart, "replayed"),
    ]
    return 0 if all(refused) else 1


def main() -> int:
    """Run the scenario from GATE_HOST, GATE_PORT, CONSUMER_KEYRING, CONSUMER_APP, CONSUMER_LOG_ID.

    Waits for the gate's /health first. A missing variable is a `KeyError` and no run.
    """
    env = os.environ
    host, port = env["GATE_HOST"], int(env["GATE_PORT"])
    wait_for_gate(host, port)
    keyring = Keyring.load(Path(env["CONSUMER_KEYRING"]))
    consumer = Consumer(keyring, app=env["CONSUMER_APP"], log_id=env["CONSUMER_LOG_ID"])
    return scenario(host, port, consumer)
