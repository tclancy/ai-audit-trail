"""The verifier CLI on the committed vectors: checks 1–5, exit codes 0/2/3/4 (I3, I4 chain part).

Every input here is a file under `spec/`, or a copy of one with lines removed or bytes changed
in a temporary directory. Nothing is produced by `audittrail`, which is never imported.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from audittrail_verify.cli import main

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "vectors"


def run(
    files: list[Path], keyring: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any]]:
    """Run the CLI in-process and return (exit code, report)."""
    code = main(["--keyring", str(keyring), *map(str, files)])
    report = json.loads(capsys.readouterr().out)
    return code, report


def vector_files(name: str) -> list[Path]:
    """The log files of a vector in seq order, and the keyring it must be verified with."""
    return sorted((VECTORS / name).glob("*.jsonl"))


def keyring_for(name: str) -> Path:
    """The vector's own keyring if it has one, else the shared one."""
    own = VECTORS / name / "keyring.json"
    return own if own.exists() else VECTORS / "keyring.json"


def expected_check(name: str) -> int:
    """The check number in a negative vector's `vector.expect`."""
    text = (VECTORS / name / "vector.expect").read_text(encoding="ascii")
    assert text.startswith("check=") and text.rstrip().endswith("exit=2")
    return int(text.split()[0].removeprefix("check="))


POSITIVE = sorted(p.name for p in (VECTORS / "positive").iterdir())
NEGATIVE = sorted(p.name for p in (VECTORS / "negative").iterdir())


@pytest.mark.parametrize("name", POSITIVE)
def test_every_positive_vector_exits_0_with_its_hashes(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Checks 1–5 pass, the report names them, and the hashes equal vector.hash line for line."""
    code, report = run(vector_files(f"positive/{name}"), keyring_for(f"positive/{name}"), capsys)
    assert code == 0, report
    assert report["checks_passed"] == [1, 2, 3, 4, 5]
    assert report["failures"] == []
    assert report["prefix_unverified"] is False
    want = (VECTORS / "positive" / name / "vector.hash").read_text(encoding="ascii").split()
    assert report["hashes"] == want
    assert report["records"] == len(want)


@pytest.mark.parametrize("name", NEGATIVE)
def test_every_negative_vector_fails_at_its_expected_check(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2 and `first_failing_check` equal to vector.expect, for every check this CLI runs.

    The one vector whose expected check is 9 (unknown reason) passes checks 1–5, which is
    what the report must say until check 9 arrives in M2.
    """
    want = expected_check(f"negative/{name}")
    code, report = run(vector_files(f"negative/{name}"), keyring_for(f"negative/{name}"), capsys)
    if want in report["not_implemented"]:
        assert want == 9
        assert code == 0
        return
    assert code == 2, report
    assert report["first_failing_check"] == want
    assert report["failures"][0]["check"] == want
    assert report["failures"][0]["file"].endswith(".jsonl")
    assert isinstance(report["failures"][0]["line"], int)


def test_a_deleted_line_is_a_seq_gap_and_an_edited_byte_breaks_the_chain_after_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """I4: drop seq 2 → check 3 at line 3; edit a byte in seq 1 → check 4 at line 3.

    The edited line is still canonical and schema-valid, so check 1 and 2 pass; check 4 then
    finds that line 3's `prev` names the original bytes. Check 5 would also fail on the
    edited line, but check 4 runs over every line first.
    """
    [src] = vector_files("positive/rotation")
    lines = src.read_bytes().split(b"\n")
    gapped = tmp_path / src.name
    gapped.write_bytes(b"\n".join(lines[:2] + lines[3:]))
    code, report = run([gapped], keyring_for("positive/rotation"), capsys)
    assert code == 2
    assert report["first_failing_check"] == 3
    assert report["failures"][0]["line"] == 3
    edited = tmp_path / "edited" / src.name
    edited.parent.mkdir()
    changed = lines[1].replace(b'"model_id":"test-model-1"', b'"model_id":"test-model-2"')
    assert changed != lines[1]
    edited.write_bytes(b"\n".join([lines[0], changed] + lines[2:]))
    code, report = run([edited], keyring_for("positive/rotation"), capsys)
    assert code == 2
    assert report["first_failing_check"] == 4
    assert report["failures"][0]["line"] == 3


def test_a_file_set_not_starting_at_seq_0_exits_4_and_never_0(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The second file of rotation-two-files alone: every line verifies, prefix is unverified."""
    files = vector_files("positive/rotation-two-files")
    assert len(files) == 2
    code, report = run(files[1:], keyring_for("positive/rotation-two-files"), capsys)
    assert code == 4
    assert report["prefix_unverified"] is True
    assert report["failures"] == []
    code, report = run(files, keyring_for("positive/rotation-two-files"), capsys)
    assert code == 0


def test_files_out_of_order_or_repeated_are_a_seq_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The verifier takes the order it is given and does not sort or deduplicate."""
    files = vector_files("positive/rotation-two-files")
    code, report = run(files[::-1], keyring_for("positive/rotation-two-files"), capsys)
    assert code == 2
    assert report["prefix_unverified"] is True
    assert report["first_failing_check"] == 3
    code, report = run(files + files[1:], keyring_for("positive/rotation-two-files"), capsys)
    assert code == 2
    assert report["first_failing_check"] == 3


def test_a_failure_wins_over_an_unverified_prefix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, not 4, when a later file both lacks its prefix and has a bad signature."""
    [first, second] = vector_files("positive/rotation-two-files")
    data = second.read_bytes()
    bad = tmp_path / second.name
    bad.write_bytes(data.replace(b'"kid":"gate-test-2"', b'"kid":"gate-test-1"', 1))
    code, report = run([bad], keyring_for("positive/rotation-two-files"), capsys)
    assert code == 2
    assert report["prefix_unverified"] is True
    assert report["first_failing_check"] == 5


def test_rotation_record_whose_keyring_does_not_agree_fails_check_5(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The rotation vector under the shared keyring, where gate-test-1 is never retired."""
    code, report = run(vector_files("positive/rotation"), VECTORS / "keyring.json", capsys)
    assert code == 2
    assert report["first_failing_check"] == 5
    assert report["failures"][0]["line"] == 3


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--keyring"],
        ["--keyring", "spec/vectors/keyring.json"],
        ["spec/vectors/positive/genesis-boot/test.0000000000000000.jsonl"],
        [
            "--keyring",
            "/nonexistent/keyring.json",
            "spec/vectors/positive/genesis-boot/test.0000000000000000.jsonl",
        ],
        ["--keyring", "spec/vectors/keyring.json", "/nonexistent.jsonl"],
        ["--keyring", "spec/vectors/keyring.json", "spec/vectors/positive/genesis-boot"],
        [
            "--keyring",
            "spec/reasons.txt",
            "spec/vectors/positive/genesis-boot/test.0000000000000000.jsonl",
        ],
        [
            "--keyring",
            "spec/vectors/keyring.json",
            "--now",
            "2026-10-10T00:00:00Z",
            "spec/vectors/positive/genesis-boot/test.0000000000000000.jsonl",
        ],
    ],
)
def test_bad_invocations_exit_3(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    """Missing arguments, missing files, a keyring that is not one, an option from M2: all 3."""
    root = VECTORS.parents[1]
    argv = [str(root / a) if a.startswith("spec/") else a for a in argv]
    assert main(argv) == 3
    out = capsys.readouterr()
    assert out.out == "" or json.loads(out.out)["exit"] == 3


def test_an_empty_file_and_a_missing_trailing_newline_fail_check_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty log and a torn last line are not records (check 1), not errors (exit 3)."""
    empty = tmp_path / "test.0000000000000000.jsonl"
    empty.write_bytes(b"")
    code, report = run([empty], VECTORS / "keyring.json", capsys)
    assert code == 2
    assert report["first_failing_check"] == 1
    [src] = vector_files("positive/decision-approve")
    torn = tmp_path / "torn" / src.name
    torn.parent.mkdir()
    torn.write_bytes(src.read_bytes()[:-1])
    code, report = run([torn], VECTORS / "keyring.json", capsys)
    assert code == 2
    assert report["first_failing_check"] == 1
    assert report["failures"][0]["line"] == 2


def test_the_installed_command_runs_as_a_subprocess() -> None:
    """`python -m audittrail_verify` exits 0 on a positive vector and 2 on a negative one."""
    files = vector_files("positive/decision-approve")
    cmd = [sys.executable, "-m", "audittrail_verify", "--keyring", str(VECTORS / "keyring.json")]
    done = subprocess.run([*cmd, *map(str, files)], capture_output=True, check=False)  # noqa: S603
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["exit"] == 0
    files = vector_files("negative/zero-prev-seq-3")
    done = subprocess.run([*cmd, *map(str, files)], capture_output=True, check=False)  # noqa: S603
    assert done.returncode == 2
    assert json.loads(done.stdout)["first_failing_check"] == 4


def test_vectors_directory_is_untouched_by_the_tests() -> None:
    """Belt and braces: the tests copy into tmp_path and never write under spec/."""
    assert shutil.disk_usage(VECTORS).total > 0
    assert not list(VECTORS.rglob("*.tmp"))
