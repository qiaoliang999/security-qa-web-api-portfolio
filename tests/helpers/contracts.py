"""Helpers for sensitive-field response contracts."""

from __future__ import annotations

from typing import Any

# Keys that must never appear in secure-mode API responses
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
    forbidden: frozenset[str] = FORBIDDEN_SECURE_KEYS,
) -> list[str]:
    """Return dotted paths of any forbidden keys found in nested JSON."""
    found: list[str] = []

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else str(k)
                if k in forbidden:
                    found.append(key_path)
                walk(v, key_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(payload)
    return found


def assert_no_sensitive_fields(payload: Any) -> None:
    leaked = find_forbidden_keys(payload)
    assert not leaked, f"Sensitive fields leaked in response: {leaked}"
