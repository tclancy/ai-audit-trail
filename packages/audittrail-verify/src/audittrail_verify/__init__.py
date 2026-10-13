"""ai-audit-trail: verify. See SPEC.md §5. Imports nothing from `audittrail`, ever."""

from audittrail_verify.checks import verify
from audittrail_verify.cli import main
from audittrail_verify.keyring import BadKeyring, Keyring, load_keyring

__all__ = ["BadKeyring", "Keyring", "load_keyring", "main", "verify"]
