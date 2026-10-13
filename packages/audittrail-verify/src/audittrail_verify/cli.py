# SPDX-License-Identifier: Apache-2.0
"""The `audittrail-verify` command: checks 1–5, a JSON report on stdout, exit 0/2/3/4.

Exit 3 covers every exception, as SPEC §5 requires, including bad arguments, unreadable
files, and a stdout that cannot take the report; the report then carries `error` when it
could be written at all. Not here yet: the reasons file (check 9), `--now` (checks 7 and 8),
the anchor directory (check 8) and consumer action logs (check 10).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from audittrail_verify.checks import verify
from audittrail_verify.keyring import load_keyring


def main(argv: list[str] | None = None) -> int:
    """Parse `--keyring PATH FILE...`, verify, write the report, return the exit code.

    Never raises: any exception, including argparse's exit, becomes exit 3 with the error
    named in the report; a stdout that is closed or breaks mid-write is exit 3 too, with
    nothing more written. Does not write anything but stdout.
    """
    try:
        args = _parser().parse_args(argv)
        keyring = load_keyring(Path(args.keyring))
        report = verify([Path(f) for f in args.files], keyring)
    except SystemExit as e:  # argparse: usage already on stderr
        report = {"exit": 3, "error": f"usage error ({e.code})"}
    except Exception as e:  # noqa: BLE001  SPEC §5: every exception is exit 3
        report = {"exit": 3, "error": f"{type(e).__name__}: {e}"}
    return _write(report)


def _write(report: dict[str, Any]) -> int:
    """Write the report as one JSON line and flush; a failed write is exit 3, written nowhere."""
    try:
        sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
        sys.stdout.flush()
    except (OSError, AttributeError, ValueError):
        return 3
    return int(report["exit"])


def _parser() -> argparse.ArgumentParser:
    """Build the M1 argument set. Options for later checks are refused until they run."""
    parser = argparse.ArgumentParser(
        prog="audittrail-verify",
        description="Verify an ai-audit-trail log against SPEC §5 checks 1-5.",
    )
    parser.add_argument("--keyring", required=True, help="SPEC §3.8 keyring file")
    parser.add_argument("files", nargs="+", help="log files in seq order")
    return parser


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
