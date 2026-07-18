"""Password hashing helpers.

Secure baseline stores only password digests (PBKDF2-HMAC-SHA256 via hashlib;
no third-party crypto dependency required). Lab mode still uses hashed storage
in SQLite so "plaintext-only story" is not the demo design — the intentional
lab flaws live in authz/response contracts, not credential storage.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


_PBKDF2_ITERATIONS = 120_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Return salt$hash hex digest suitable for DB storage."""
    salt = secrets.token_hex(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify against salt$hash storage format."""
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return hmac.compare_digest(candidate, expected)


def weak_sha256(password: str) -> str:
    """LAB only: weak one-shot SHA-256 (intentionally leakable material)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()
