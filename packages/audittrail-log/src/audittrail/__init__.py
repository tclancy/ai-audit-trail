"""ai-audit-trail: log. See SPEC.md. Exposes `Record` and its errors; nothing signs yet."""

from audittrail.record import (
    ChainError,
    ParseError,
    Record,
    RecordError,
    SchemaError,
    canonical_bytes,
)

__all__ = [
    "ChainError",
    "ParseError",
    "Record",
    "RecordError",
    "SchemaError",
    "canonical_bytes",
]
