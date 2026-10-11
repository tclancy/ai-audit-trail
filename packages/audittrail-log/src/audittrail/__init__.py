"""ai-audit-trail: log. See SPEC.md. Exposes `Record`, the signing protocol, and their errors."""

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
    "DOMAIN_ANCHOR",
    "DOMAIN_ANCHOR_RECEIPT",
    "DOMAIN_RECORD",
    "MAX_LINE_BYTES",
    "MAX_NESTING_DEPTH",
    "ChainError",
    "ParseError",
    "Record",
    "RecordError",
    "SchemaError",
    "Signer",
    "SigningError",
    "SoftwareSigner",
    "canonical_bytes",
    "nesting_depth",
]
