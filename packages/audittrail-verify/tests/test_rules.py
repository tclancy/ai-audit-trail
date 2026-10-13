"""Each verifier mechanism pinned on its own, so deleting one turns a test red (I3, I4, I14).

The vectors prove the whole; these pin the parts the vectors reach only redundantly. Every
input is a committed line or keyring from `spec/`, edited as a dict or as bytes in tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from audittrail_verify.canonical import (
    MAX_LINE_BYTES,
    NotCanonical,
    canonical_bytes,
    parse_canonical,
    parse_object,
)
from audittrail_verify.checks import (
    Line,
    _check_4_prev,
    _signature_problem,
    _succession_problem,
)
from audittrail_verify.cli import main
from audittrail_verify.keyring import BadKeyring, Keyring, load_keyring
from audittrail_verify.schema import ZERO_HASH, NotRecord, check_record

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "vectors"


def lines_of(name: str) -> list[bytes]:
    """All lines of a single-file vector, without newlines."""
    [log] = sorted((VECTORS / name).glob("*.jsonl"))
    return log.read_bytes().removesuffix(b"\n").split(b"\n")


def records_of(name: str) -> list[dict[str, Any]]:
    """The parsed records of a single-file vector."""
    return [parse_canonical(line) for line in lines_of(name)]


def ring_obj(name: str = "keyring.json") -> dict[str, Any]:
    """A committed keyring as a dict."""
    return parse_object((VECTORS / name).read_bytes().removesuffix(b"\n"))


def write_ring(tmp_path: Path, obj: dict[str, Any]) -> Path:
    """Write a keyring dict as a canonical file and return its path."""
    path = tmp_path / "keyring.json"
    path.write_bytes(canonical_bytes(obj) + b"\n")
    return path


def run(files: list[Path], keyring: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Run the CLI in-process; return the report with `exit` in it."""
    code = main(["--keyring", str(keyring), *map(str, files)])
    report: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert report["exit"] == code
    return report


# --- review findings -----------------------------------------------------------


def test_a_canonical_line_without_seq_is_check_2_not_a_crash(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`{}` and `{"a":1}` are canonical; they fail check 2, never raise KeyError on seq."""
    for body in (b"{}\n", b'{"a":1}\n'):
        path = tmp_path / "test.0000000000000000.jsonl"
        path.write_bytes(body)
        report = run([path], VECTORS / "keyring.json", capsys)
        assert report["exit"] == 2
        assert report["first_failing_check"] == 2
        assert report["prefix_unverified"] is False


def test_the_keyring_is_not_held_to_the_record_line_length(tmp_path: Path) -> None:
    """SPEC §3.7: the length bound is for record lines; a long keyring line still parses."""
    long_value = b'{"a":"' + b"x" * MAX_LINE_BYTES + b'"}'
    assert parse_object(long_value) == {"a": "x" * MAX_LINE_BYTES}
    with pytest.raises(NotCanonical):
        parse_canonical(long_value)
    with pytest.raises(NotCanonical):
        parse_object(b'{"a":[[[[[1]]]]]}')
    ring = ring_obj()
    ring["keys"] = [
        {**ring["keys"][0], "kid": f"gate-pad-{i:02d}-{'x' * 20}"} for i in range(12)
    ] + ring["keys"][1:]
    for i, key in enumerate(ring["keys"][:12]):
        key["pub"] = ring_obj("positive/rotation/keyring.json")["keys"][i % 2]["pub"]
    # twelve kids, six distinct pubs: the dup-pub rule must fire, not the length bound
    path = write_ring(tmp_path, ring)
    assert len(path.read_bytes()) > MAX_LINE_BYTES
    with pytest.raises(BadKeyring, match="two kids"):
        load_keyring(path)


def test_garbage_input_stops_at_the_first_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A million empty lines: one failure in the report, nothing collected past it."""
    path = tmp_path / "test.0000000000000000.jsonl"
    path.write_bytes(b"\n" * 1_000_000)
    report = run([path], VECTORS / "keyring.json", capsys)
    assert report["exit"] == 2
    assert report["failures"] == [
        {
            "check": 1,
            "file": str(path),
            "line": 1,
            "message": "empty, or a byte outside printable ASCII",
        }
    ]
    assert report["records"] == 0


def test_a_broken_stdout_is_exit_3(monkeypatch: pytest.MonkeyPatch) -> None:
    """A closed or broken stdout cannot carry the report; the exit code says so."""

    class Broken:
        """A stdout whose write raises BrokenPipeError."""

        def write(self, text: str) -> int:
            """Raise as a closed pipe would."""
            raise BrokenPipeError

        def flush(self) -> None:
            """Never reached."""

    monkeypatch.setattr("sys.stdout", Broken())
    files = sorted((VECTORS / "positive" / "genesis-boot").glob("*.jsonl"))
    assert main(["--keyring", str(VECTORS / "keyring.json"), *map(str, files)]) == 3
    monkeypatch.setattr("sys.stdout", None)
    assert main(["--keyring", str(VECTORS / "keyring.json"), *map(str, files)]) == 3


def test_option_abbreviations_are_refused(capsys: pytest.CaptureFixture[str]) -> None:
    """`--key` is not `--keyring`."""
    files = sorted((VECTORS / "positive" / "genesis-boot").glob("*.jsonl"))
    assert main(["--key", str(VECTORS / "keyring.json"), *map(str, files)]) == 3
    capsys.readouterr()


# --- check 4 on its own --------------------------------------------------------


def test_zero_hash_rule_holds_without_a_neighbour_to_compare_with() -> None:
    """Genesis with a real prev, and a lone seq-5 record with zero-hash prev: both check 4."""
    genesis, decision = records_of("positive/decision-approve")
    line = Line("f", 1, b"")
    assert _check_4_prev([line], [genesis]) is None
    bad_genesis = {**genesis, "prev": decision["prev"]}
    failure = _check_4_prev([line], [bad_genesis])
    assert failure is not None and failure.check == 4 and "seq 0" in failure.message
    lone = {**decision, "seq": 5, "prev": ZERO_HASH}
    failure = _check_4_prev([line], [lone])
    assert failure is not None and failure.check == 4
    assert _check_4_prev([line], [{**decision, "seq": 5}]) is None


# --- check 5 rules on their own ------------------------------------------------


@pytest.fixture
def shared() -> Keyring:
    """The shared vector keyring."""
    return load_keyring(VECTORS / "keyring.json")


@pytest.fixture
def rotated() -> Keyring:
    """gate-test-1 to seq 2, gate-test-2 from seq 3."""
    return load_keyring(VECTORS / "positive" / "rotation" / "keyring.json")


def test_window_check_alone_refuses_a_record_past_its_kid_window(rotated: Keyring) -> None:
    """The approve vector (seq 1) verifies under the rotation keyring; seq 3 by its kid does not."""
    _, decision = records_of("positive/decision-approve")
    assert _signature_problem(decision, rotated) is None
    assert _signature_problem({**decision, "seq": 3}, rotated) == "seq is outside the kid's window"
    assert _signature_problem({**decision, "seq": 3}, rotated) is not None


def test_role_log_id_and_unknown_kid_are_each_refused(
    tmp_path: Path, shared: Keyring, capsys: pytest.CaptureFixture[str]
) -> None:
    """A sink-role kid, a keyring for another log, and a missing kid are check 5."""
    _, decision = records_of("positive/decision-approve")
    ring = ring_obj()
    ring["keys"][0]["role"] = "sink"
    assert (
        _signature_problem(decision, load_keyring(write_ring(tmp_path, ring)))
        == "kid is not a gate key"
    )
    ring = ring_obj()
    ring["log_id"] = "other"
    assert (
        _signature_problem(decision, load_keyring(write_ring(tmp_path, ring)))
        == "record is not from the keyring's log"
    )
    assert (
        _signature_problem({**decision, "kid": "gate-test-9"}, shared)
        == "kid is not in the keyring"
    )
    files = sorted((VECTORS / "positive" / "decision-approve").glob("*.jsonl"))
    ring = ring_obj()
    ring["keys"][0]["role"] = "sink"
    report = run(files, write_ring(tmp_path, ring), capsys)
    assert report["exit"] == 2 and report["first_failing_check"] == 5


def test_non_canonical_base64_signature_is_refused(shared: Keyring) -> None:
    """The approve vector's sig ends `CA==`; `CB==` decodes to the same bytes and is refused."""
    _, decision = records_of("positive/decision-approve")
    assert decision["sig"].endswith("CA==")
    assert _signature_problem(decision, shared) is None
    bent = {**decision, "sig": decision["sig"][:-3] + "B=="}
    assert _signature_problem(bent, shared) == "sig is not canonical base64"


def test_rotation_record_must_end_its_key_window(rotated: Keyring, tmp_path: Path) -> None:
    """The rotation vector's seq-2 rotation verifies; with valid_to_seq 3 it does not."""
    rotation = records_of("positive/rotation")[2]
    assert rotation["type"] == "rotation"
    assert _signature_problem(rotation, rotated) is None
    ring = ring_obj("positive/rotation/keyring.json")
    ring["keys"][0]["valid_to_seq"] = 3
    ring["keys"][1]["valid_from_seq"] = 4
    off = load_keyring(write_ring(tmp_path, ring))
    assert (
        _signature_problem(rotation, off) == "rotation record is not at the end of its key's window"
    )


def test_succession_rules_each_refuse_on_their_own(rotated: Keyring, tmp_path: Path) -> None:
    """Same kid after a rotation, a window not at k+1, a wrong name, a silent kid change."""
    boot, decision, rotation, after = records_of("positive/rotation")[:4]
    assert _succession_problem(rotation, after, rotated) is None
    assert _succession_problem(boot, decision, rotated) is None
    assert (
        _succession_problem(rotation, {**after, "kid": "gate-test-1"}, rotated)
        == "record after a rotation is signed by the old key"
    )
    ring = ring_obj("positive/rotation/keyring.json")
    ring["keys"][1]["valid_from_seq"] = 2
    late = load_keyring(write_ring(tmp_path, ring))
    assert (
        _succession_problem(rotation, after, late)
        == "new key's window does not start right after the rotation"
    )
    misnamed = {**rotation, "cart_hash": decision["cart_hash"]}
    assert (
        _succession_problem(misnamed, after, rotated)
        == "rotation record does not name the kid that signed next"
    )
    assert (
        _succession_problem(decision, {**after, "seq": 2}, rotated)
        == "kid changed without a rotation record"
    )


# --- schema rules on their own -------------------------------------------------


def test_boot_reason_and_genesis_shape_rules() -> None:
    """A boot with R_ANCHOR, a genesis decision, and a genesis boot with a real cart_hash."""
    genesis, decision = records_of("positive/decision-approve")
    check_record(genesis)
    with pytest.raises(NotRecord, match="reason"):
        check_record({**genesis, "reason": "R_ANCHOR"})
    with pytest.raises(NotRecord, match="seq 0"):
        check_record({**decision, "seq": 0, "prev": ZERO_HASH})
    with pytest.raises(NotRecord, match="seq 0"):
        check_record({**genesis, "cart_hash": decision["cart_hash"]})
    check_record({**decision, "seq": 7})


# --- keyring rules, one variant per rule ------------------------------------------


def variants() -> list[tuple[str, dict[str, Any] | bytes]]:
    """Named malformed keyrings, each breaking exactly one §3.8 rule."""
    out: list[tuple[str, dict[str, Any] | bytes]] = []

    def ring(**top: Any) -> dict[str, Any]:
        return {**ring_obj(), **top}

    def key(**entry: Any) -> dict[str, Any]:
        obj = ring_obj()
        obj["keys"][0] = {**obj["keys"][0], **entry}
        return obj

    first = ring_obj()["keys"][0]
    out += [
        ("v2", ring(v=2)),
        ("v-bool", ring(v=True)),
        ("log_id-rule", ring(log_id="Test")),
        ("extra-field", ring(extra=1)),
        ("missing-field", {k: v for k, v in ring_obj().items() if k != "v"}),
        ("no-keys", ring(keys=[])),
        ("keys-not-list", ring(keys={})),
        ("alg", key(alg="rsa")),
        ("alg-list", key(alg=["ed25519"])),
        ("kid-rule", key(kid="Gate")),
        ("kid-dup", key(kid="sink-test-1")),
        ("pub-dup", ring(keys=[first, {**first, "kid": "gate-test-1b"}])),
        ("role", key(role="admin")),
        ("role-list", key(role=["gate"])),
        ("pub-short", key(pub=first["pub"][:-1])),
        ("pub-bits", key(pub=first["pub"][:-2] + "l=")),
        ("pub-31", key(pub="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==")),
        ("pub-urlsafe", key(pub=first["pub"].replace("/", "_"))),
        ("from-negative", key(valid_from_seq=-1)),
        ("from-bool", key(valid_from_seq=False)),
        ("to-string", key(valid_to_seq="2")),
        ("to-huge", key(valid_to_seq=2**53)),
        ("window-empty", key(valid_from_seq=5, valid_to_seq=4)),
        ("entry-extra", key(note="x")),
        ("entry-missing", ring(keys=[{k: v for k, v in first.items() if k != "role"}])),
        ("not-object", b"[]\n"),
        ("two-lines", canonical_bytes(ring_obj()) + b"\n" + canonical_bytes(ring_obj()) + b"\n"),
        ("no-newline", canonical_bytes(ring_obj())),
        ("crlf", canonical_bytes(ring_obj()) + b"\r\n"),
        ("bom", b"\xef\xbb\xbf" + canonical_bytes(ring_obj()) + b"\n"),
        ("spaces", canonical_bytes(ring_obj()).replace(b",", b", ") + b"\n"),
        ("deep", b'{"keys":[[[[1]]]],"log_id":"test","v":1}\n'),
        ("empty", b""),
    ]
    return out


@pytest.mark.parametrize(("name", "variant"), variants(), ids=[n for n, _ in variants()])
def test_every_malformed_keyring_is_refused_and_exits_3(
    name: str, variant: dict[str, Any] | bytes, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each variant is BadKeyring from the loader and exit 3 from the CLI."""
    path = tmp_path / "keyring.json"
    path.write_bytes(variant if isinstance(variant, bytes) else canonical_bytes(variant) + b"\n")
    with pytest.raises(BadKeyring):
        load_keyring(path)
    files = sorted((VECTORS / "positive" / "genesis-boot").glob("*.jsonl"))
    assert main(["--keyring", str(path), *map(str, files)]) == 3
    capsys.readouterr()


def test_the_committed_keyrings_load_and_windows_cover_as_written() -> None:
    """Both committed keyrings load; `covers` honours both ends and the open end."""
    ring = load_keyring(VECTORS / "positive" / "rotation" / "keyring.json")
    old, new = ring.keys["gate-test-1"], ring.keys["gate-test-2"]
    assert (old.covers(0), old.covers(2), old.covers(3)) == (True, True, False)
    assert (new.covers(2), new.covers(3), new.covers(2**53 - 1)) == (False, True, True)
    assert ring.keys["sink-test-1"].role == "sink"
    assert load_keyring(VECTORS / "keyring.json").log_id == "test"
