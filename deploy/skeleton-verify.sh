#!/bin/sh
# The verifier step of `make skeleton`. In M1 the verifier runs checks 1-5 only, so on a
# sound log its exit is 4 ("not every check ran", SPEC §5), never 0. The skeleton passes
# only when the report says no check failed, the prefix is verified (the log starts at
# seq 0) and the log holds exactly the boot record and the scenario's one decision. Any
# other exit, or any other report, fails. This script adds no check of its own and relaxes
# none; it reads the verifier's report.
set -u
report=$(audittrail-verify --keyring /keyring/keyring.json /log/skeleton.0000000000000000.jsonl)
rc=$?
printf '%s\n' "$report"
if [ "$rc" -ne 0 ] && [ "$rc" -ne 4 ]; then
  echo "skeleton: verifier exit $rc" >&2
  exit "$rc"
fi
printf '%s' "$report" | python3 -c '
import json, sys
r = json.load(sys.stdin)
sound = r["first_failing_check"] is None and r["prefix_unverified"] is False and r["records"] == 2
print("skeleton: log is sound, boot + 1 decision" if sound else "skeleton: report is not the expected one")
sys.exit(0 if sound else 1)
'
