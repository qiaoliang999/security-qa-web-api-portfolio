"""Helpers for sensitive-field response contracts.

Used by secure-mode suites to assert response DTO allow-lists hold under nested
JSON (login envelopes, list endpoints, admin aggregates). Lab-mode tests may
invert the check via ``find_forbidden_keys`` to prove oversharing is detectable.
"""

from __future__ import annotations

from typing import Any, Iterable

# Keys that must never appear in secure-mode API responses.
# Keep this list aligned with app.models.SENSITIVE_USER_KEYS plus lab-only leaks.
FORBIDDEN_SECURE_KEYS = frozenset(
    {
        "ssn",
        "api_key",
        "password",
        "password_hash",
        "password_sha256",
    }
)


def find_forbidden_keys(
    payload: Any,
    forbidden: frozenset[str] | Iterable[str] = FORBIDDEN_SECURE_KEYS,
) -> list[str]:
    """Return dotted paths of any forbidden keys found in nested JSON.

    Paths use object-key dots and list indices, e.g. ``user.ssn`` or
    ``users[0].api_key``. Matching is on the exact dict key name only — not
    substring matching — so legitimate keys like ``password_policy`` would not
    false-positive (those keys are simply not in the forbidden set).
    """
    forbidden_set = frozenset(forbidden)
    found: list[str] = []

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else str(k)
                if k in forbidden_set:
                    found.append(key_path)
                walk(v, key_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(payload)
    return found


def assert_no_sensitive_fields(
    payload: Any,
    forbidden: frozenset[str] | Iterable[str] = FORBIDDEN_SECURE_KEYS,
) -> None:
    """Assert ``payload`` contains none of the forbidden sensitive keys."""
    leaked = find_forbidden_keys(payload, forbidden=forbidden)
    assert not leaked, f"Sensitive fields leaked in response: {leaked}"
