"""Signing primitives for the platform's own tokens. The schemes are plain Python in the
packages that use them (``guard/signed_context.py``); the cryptography library is imported
only in ``signing/adapters``, wired in by the composition root."""
