# SPDX-License-Identifier: Apache-2.0
"""Signing: the `Signer` protocol, SPEC §3.3 domains, and the dev-only `SoftwareSigner`.

Schema `v == 1` is Ed25519 only, so there is no algorithm parameter anywhere. Nothing here
returns, prints, or serializes key material; a signer exposes its `kid` and a `sign` method and
nothing else. Nothing here builds a record line or verifies a signature.
"""

from __future__ import annotations

import os
from typing import NoReturn, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audittrail.record import STRING_RULES, SchemaError

DOMAIN_RECORD = b"ai-audit-trail/v1/record\x00"
DOMAIN_ANCHOR = b"ai-audit-trail/v1/anchor\x00"
DOMAIN_ANCHOR_RECEIPT = b"ai-audit-trail/v1/anchor-receipt\x00"
DOMAINS: frozenset[bytes] = frozenset({DOMAIN_RECORD, DOMAIN_ANCHOR, DOMAIN_ANCHOR_RECEIPT})
"""SPEC §3.3: a signature is always over DOMAIN || data; a signer refuses any other domain."""

SIGNATURE_BYTES = 64
"""An Ed25519 signature is exactly this long, so `v == 1` has no other legal length."""

_SEED_LEN = 32
_DEV_FLAG = "AUDITTRAIL_DEV"


class SigningError(ValueError):
    """A signer refused, failed, or answered wrongly; the caller rejects.

    A bad seed or an unknown domain, and also a `sign` or `kid` call that raised an
    `Exception` or returned something that is not a 64-byte signature. Not raised for a
    `BaseException` such as `KeyboardInterrupt`, which propagates as itself.
    """


@runtime_checkable
class Signer(Protocol):
    """What `Log` needs from a key: its `kid` and a signature over `domain || data`.

    Implementations never expose key material. The protocol does not cover key generation,
    rotation, or verification; verification lives in the verifier with public keys only.
    """

    @property
    def kid(self) -> str:
        """The key id this signer writes into `kid` (SPEC §3.1 regex)."""
        ...

    def sign(self, domain: bytes, data: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over `domain || data`. Refuses unknown domains."""
        ...


class SoftwareSigner:
    """An in-process Ed25519 key for development and tests only (I12).

    Constructs only when the environment variable `AUDITTRAIL_DEV` is exactly `1`; any other
    value or its absence is a `RuntimeError`, with no override. Holds the key object privately,
    never returns it, and cannot be copied, subclassed, or serialized by protocol.
    """

    __slots__ = ("_key", "_kid")

    def __init__(self, kid: str, seed: bytes) -> None:
        """Build the key from a 32-byte seed. Does not read the seed from anywhere itself."""
        if os.environ.get(_DEV_FLAG) != "1":
            raise RuntimeError(f"SoftwareSigner is for development only; {_DEV_FLAG}=1 is not set")
        rule = STRING_RULES["kid"]
        if isinstance(rule, frozenset) or type(kid) is not str or rule.fullmatch(kid) is None:
            raise SchemaError("kid: value does not match its rule")
        if type(seed) is not bytes or len(seed) != _SEED_LEN:
            raise SigningError("seed is not 32 bytes")
        self._kid = kid
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        """Refuse every subclass, so none can add an export path."""
        raise TypeError("SoftwareSigner is final")

    def __reduce__(self) -> NoReturn:
        """Refuse the copy and persistence protocols; a key is never moved between processes."""
        raise TypeError("SoftwareSigner cannot be copied or serialized")

    def __repr__(self) -> str:
        """Name the kid only; never any part of the key."""
        return f"SoftwareSigner(kid={self._kid!r})"

    @property
    def kid(self) -> str:
        """The key id this signer writes into `kid`."""
        return self._kid

    def sign(self, domain: bytes, data: bytes) -> bytes:
        """Return the Ed25519 signature over `domain || data`; an unknown domain is refused."""
        if domain not in DOMAINS:
            raise SigningError("unknown signature domain")
        return self._key.sign(domain + data)
