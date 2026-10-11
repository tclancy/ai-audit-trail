"""ai-audit-trail: log. See SPEC.md. Exposes `Record` and its errors; nothing signs yet."""

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

__all__ = [
    "MAX_LINE_BYTES",
    "MAX_NESTING_DEPTH",
    "ChainError",
    "ParseError",
    "Record",
    "RecordError",
    "SchemaError",
    "canonical_bytes",
    "nesting_depth",
]
