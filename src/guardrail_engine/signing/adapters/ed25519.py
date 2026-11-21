"""Ed25519 behind the ports in :mod:`guardrail_engine.guard.signed_context` (M2-01).

The scheme itself (token format, claims, keyset, rotation) is plain Python in
``signed_context``; this module is the only place that imports the ``cryptography`` library."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from guardrail_engine.guard.context import _b64encode


class Ed25519Verifier:
    """A public key: ``verify`` is False for any signature that does not match."""

    def __init__(self, public: Ed25519PublicKey) -> None:
        self._public = public

    @classmethod
    def from_raw(cls, raw: bytes) -> Ed25519Verifier:
        """From the 32-byte public key. Raises ``ValueError`` for anything else."""
        if len(raw) != 32:
            raise ValueError("an Ed25519 public key is 32 bytes")
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self._public.verify(signature, data)
        except InvalidSignature:
            return False
        return True

    def __repr__(self) -> str:
        return "Ed25519Verifier()"


class Ed25519Key:
    """A private key (the gateway's, and tests'). Never in ``repr``."""

    def __init__(self, private: Ed25519PrivateKey) -> None:
        self.__private = private

    @classmethod
    def generate(cls) -> Ed25519Key:
        return cls(Ed25519PrivateKey.generate())

    def sign(self, data: bytes) -> bytes:
        return self.__private.sign(data)

    def verifier(self) -> Ed25519Verifier:
        return Ed25519Verifier(self.__private.public_key())

    def public_text(self) -> str:
        """The ``x`` field of a keyset entry: base64url of the 32-byte public key."""
        raw = self.__private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _b64encode(raw)

    def __repr__(self) -> str:
        return "Ed25519Key(<redacted>)"
