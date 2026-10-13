"""ai-audit-trail: log. See SPEC.md. Exposes `Record`, `Log`, `Approved`, `Keyring`, errors."""

from audittrail.approved import Approved, Candidate, GateError, InMemorySeenStore, SeenStore
from audittrail.keyring import Key, Keyring, KeyringError
from audittrail.log import DecisionFields, Log, LogUnavailable, Receipt
from audittrail.record import (
    MAX_LINE_BYTES,
    MAX_NESTING_DEPTH,
    ChainError,
    ParseError,
    Record,
    RecordError,
    SchemaError,
    canonical_bytes,
    nesting_depth,
    parse_object,
)
from audittrail.signing import (
    DOMAIN_ANCHOR,
    DOMAIN_ANCHOR_RECEIPT,
    DOMAIN_RECORD,
    Signer,
    SigningError,
    SoftwareSigner,
)

__all__ = [
    "Approved",
    "Candidate",
    "GateError",
    "InMemorySeenStore",
    "Key",
    "Keyring",
    "KeyringError",
    "SeenStore",
    "DOMAIN_ANCHOR",
    "DOMAIN_ANCHOR_RECEIPT",
    "DOMAIN_RECORD",
    "DecisionFields",
    "Log",
    "LogUnavailable",
    "MAX_LINE_BYTES",
    "MAX_NESTING_DEPTH",
    "ChainError",
    "ParseError",
    "Receipt",
    "Record",
    "RecordError",
    "SchemaError",
    "Signer",
    "SigningError",
    "SoftwareSigner",
    "canonical_bytes",
    "nesting_depth",
    "parse_object",
]
