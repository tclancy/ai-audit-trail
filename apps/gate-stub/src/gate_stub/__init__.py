# SPDX-License-Identifier: Apache-2.0
"""gate-stub: the minimal reference gate of the M1 walking skeleton (SPEC §2 "Gate", §9.1).

Takes a cart over HTTP, consults an in-process oracle table, writes one decision record
through `audittrail.Log`, and answers with the line it wrote. There is no answer that is not
a logged line (I10): a log that refuses is a 503 with an empty body. The oracle is a fixed
table until the oracle stub arrives in M5. Development only: the signer is a `SoftwareSigner`
from a seed drawn at start-up, and the matching keyring is written out for the consumer and
the verifier; Vault and the `init` service replace both in M3.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from audittrail.keyring import Keyring
from audittrail.log import DecisionFields, Log, LogUnavailable
from audittrail.record import ZERO_HASH, ParseError, canonical_bytes, parse_object
from audittrail.signing import SoftwareSigner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP = "skeleton-app"
"""The one app this gate decides for (SPEC §6 rule 4)."""
ACTOR = "spiffe://skeleton.local/agent"
"""The caller identity the skeleton attributes requests to; a real gate reads it off the channel."""
MODEL_ID = "stub-model"
KID = "gate-dev-1"
ORACLE: dict[str, int] = {"acct-1": 100}
"""What the oracle knows: the amount each account is allowed. M1 stand-in for the oracle stub."""
MAX_BODY_BYTES = 65536
"""Requests longer than this are not read; a cart line is bounded like a record line."""


def _sha256(data: bytes) -> str:
    """`sha256:<hex>` of `data`."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


TEMPLATE_HASH = _sha256(b"gate-stub-template")
POLICY_HASH = _sha256(b"gate-stub-policy")


class Gate:
    """One gate process over one `Log`. Decides nothing it does not log."""

    def __init__(self, log: Log) -> None:
        """Hold the open log; `open_gate` is the normal way in."""
        self._log = log

    def decide(self, body: bytes) -> bytes:
        """Log one decision for the request bytes and return the line written, without newline.

        Raises `LogUnavailable` instead of answering when the log refuses; never returns a
        line that is not on disk. Reads nothing from the body but its bytes.
        """
        return self._log.record(_decision(body)).line


def _decision(body: bytes) -> DecisionFields:
    """Parse the cart strictly, consult the oracle, and name the decision. Logs nothing.

    A body that is not its own canonical form is a reject (`R_PARSE`); an account the oracle
    does not know is a reject without consulting (`R_POLICY_DENY`); otherwise the cart is
    approved only when its bytes equal the oracle's canonical answer. Does not normalize.
    """
    try:
        cart = parse_object(body)
    except ParseError:
        return _fields(body, "not_consulted", ZERO_HASH, "reject", "R_PARSE")
    account = cart.get("account")
    expected = ORACLE.get(account) if type(account) is str else None
    if expected is None:
        return _fields(body, "not_consulted", ZERO_HASH, "reject", "R_POLICY_DENY")
    answer = canonical_bytes({"account": account, "amount": expected})
    if body == answer:
        return _fields(body, "match", _sha256(answer), "approve", "R_ORACLE_MATCH")
    return _fields(body, "mismatch", _sha256(answer), "reject", "R_ORACLE_MISMATCH")


def _fields(
    body: bytes, oracle: str, oracle_ref: str, decision: str, reason: str
) -> DecisionFields:
    """Build the record fields for `body`: the gate's fixed identity plus the decision given.

    `cart_hash` and `input_ref` are both the hash of the request bytes, which are the raw
    input and the candidate at once in this stub. Does not look inside `body`.
    """
    return DecisionFields(
        actor=ACTOR,
        app=APP,
        template_hash=TEMPLATE_HASH,
        model_id=MODEL_ID,
        policy_hash=POLICY_HASH,
        input_ref=_sha256(body),
        cart_hash=_sha256(body),
        oracle=oracle,
        oracle_ref=oracle_ref,
        decision=decision,
        reason=reason,
        canary="not_run",
    )


def write_dev_keyring(path: Path, kid: str, seed: bytes, log_id: str) -> None:
    """Write the one-line SPEC §3.8 keyring naming `seed`'s public key as the gate key for `log_id`.

    Development only: derives the public key from the seed in this process. The line is
    checked with `Keyring.from_bytes` before it is written, so a keyring this writes always
    loads. Never writes the seed anywhere.
    """
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    key = {
        "alg": "ed25519",
        "kid": kid,
        "pub": base64.b64encode(pub).decode("ascii"),
        "role": "gate",
        "valid_from_seq": 0,
        "valid_to_seq": None,
    }
    line = canonical_bytes({"keys": [key], "log_id": log_id, "v": 1})
    Keyring.from_bytes(line)
    Path(path).write_bytes(line + b"\n")


def open_gate(directory: Path, keyring_path: Path, log_id: str) -> Gate:
    """Draw a dev seed, open the log (writing its boot record), write the keyring, return the gate.

    Refuses outside `AUDITTRAIL_DEV=1` because `SoftwareSigner` does. Refuses a directory that
    already holds a log for `log_id`: a per-boot key can only sign a log it started, and a
    second boot would leave lines no keyring verifies. Keeps no copy of the seed and writes
    no keyring for a log that did not boot.
    """
    if any(Path(directory).glob(f"{log_id}.*.jsonl")):
        raise LogUnavailable(f"a log for {log_id} exists; a dev gate boots from genesis only")
    seed = os.urandom(32)
    signer = SoftwareSigner(KID, seed)
    log = Log(
        directory,
        log_id,
        signer,
        actor=ACTOR,
        template_hash=TEMPLATE_HASH,
        model_id=MODEL_ID,
        policy_hash=POLICY_HASH,
    )
    write_dev_keyring(keyring_path, KID, seed, log_id)
    return Gate(log)


class _Server(ThreadingHTTPServer):
    """The HTTP server holding the one gate its handlers decide through."""

    def __init__(self, address: tuple[str, int], gate: Gate) -> None:
        """Bind `address` for `_Handler` and keep `gate` for it."""
        super().__init__(address, _Handler)
        self.gate = gate


class _Handler(BaseHTTPRequestHandler):
    """POST /decide answers with the logged line; GET /health with 200; anything else 404.

    Keeps no access log: the record is the log. Does not read a body longer than MAX_BODY_BYTES.
    """

    server: _Server

    def do_POST(self) -> None:
        """Decide one cart. 413 for an unreadable length, 503 when the log refuses."""
        if self.path != "/decide":
            self._answer(404)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._answer(413)
            return
        if not 0 <= length <= MAX_BODY_BYTES:
            self._answer(413)
            return
        body = self.rfile.read(length)
        try:
            line = self.server.gate.decide(body)
        except LogUnavailable as e:
            print(f"gate-stub: log refused, answering 503: {e}", file=sys.stderr, flush=True)
            self._answer(503)
            return
        self._answer(200, line)

    def do_GET(self) -> None:
        """Answer /health once serving; nothing else exists."""
        self._answer(200 if self.path == "/health" else 404)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Write no access log line; the decision log is the only log this process keeps."""

    def _answer(self, status: int, body: bytes = b"") -> None:
        """Send `status` with exactly `body`."""
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(gate: Gate, port: int) -> _Server:
    """Bind every interface on `port` (0 for an ephemeral one); the server is not yet serving."""
    return _Server(("0.0.0.0", port), gate)  # noqa: S104


def main() -> int:
    """Run the gate from GATE_LOG_DIR, GATE_KEYRING, GATE_LOG_ID and GATE_PORT until killed.

    A missing variable is a `KeyError` and no gate. Does not daemonize or write a pid file.
    """
    env = os.environ
    gate = open_gate(Path(env["GATE_LOG_DIR"]), Path(env["GATE_KEYRING"]), env["GATE_LOG_ID"])
    httpd = serve(gate, int(env["GATE_PORT"]))
    print(
        f"gate-stub: {env['GATE_LOG_ID']} on :{httpd.server_address[1]}",
        file=sys.stderr,
        flush=True,
    )
    httpd.serve_forever()
    return 0
