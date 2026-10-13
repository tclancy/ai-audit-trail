# SPDX-License-Identifier: Apache-2.0
"""`python -m audittrail_verify` runs the CLI."""

import sys

from audittrail_verify.cli import main

sys.exit(main(sys.argv[1:]))
