"""Application settings for the Security QA lab.

LAB_MODE=true (default): intentional vulnerabilities for authorized Security QA practice.
LAB_MODE=false: real secure baseline (authz dependencies, hashed passwords, DTO allow-lists).

Authorized local lab only — do not deploy as production.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import FrozenSet


def lab_mode_enabled() -> bool:
    """Return True when intentional lab flaws should be active."""
    value = os.environ.get("LAB_MODE", "true").strip().lower()
    return value in {"1", "true", "yes", "on"}


def database_url() -> str:
    """SQLite URL. Tests override via env or fixture to isolate per-run state."""
    return os.environ.get("DATABASE_URL", "sqlite:///./security_qa_lab.db")


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings snapshot."""

    lab_mode: bool = True
    database_url: str = "sqlite:///./security_qa_lab.db"
    app_name: str = "Security QA Lab API"
    app_version: str = "2.0.0"
    # Named internal destinations only — open-redirect control is an allow-list map,
    # not a blacklist of evil hostnames.
    redirect_allowlist: FrozenSet[str] = field(
        default_factory=lambda: frozenset({"/", "/health", "/docs", "/login", "/redoc"})
    )
    max_search_query_len: int = 100
    session_token_bytes: int = 32


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings. Clear cache in tests after env changes: get_settings.cache_clear()."""
    return Settings(
        lab_mode=lab_mode_enabled(),
        database_url=database_url(),
    )


def clear_settings_cache() -> None:
    get_settings.cache_clear()


# Seed credentials for the local lab ONLY (fictional demo data).
# Stored hashed in SQLite at seed time; these plaintext values never leave seed code.
SEED_USERS = (
    {
        "id": 1,
        "username": "alice",
        "password": "password123",
        "role": "user",
        "email": "alice@example.local",
        "ssn": "111-22-3333",
        "api_key": "alice-secret-key-demo-only",
        "org_id": 10,
        "bio": "",
    },
    {
        "id": 2,
        "username": "bob",
        "password": "password123",
        "role": "user",
        "email": "bob@example.local",
        "ssn": "222-33-4444",
        "api_key": "bob-secret-key-demo-only",
        "org_id": 10,
        "bio": "",
    },
    {
        "id": 3,
        "username": "admin",
        "password": "admin",
        "role": "admin",
        "email": "admin@example.local",
        "ssn": "999-99-9999",
        "api_key": "admin-secret-key-demo-only",
        "org_id": 10,
        "bio": "",
    },
    {
        "id": 4,
        "username": "carol",
        "password": "password123",
        "role": "user",
        "email": "carol@example.local",
        "ssn": "444-55-6666",
        "api_key": "carol-secret-key-demo-only",
        "org_id": 20,  # different tenant for tenancy-scope exercises
        "bio": "",
    },
)

SEED_ORDERS = (
    {
        "id": 101,
        "owner_id": 1,
        "org_id": 10,
        "item": "Laptop",
        "amount": 999.0,
        "notes": "Ship to Alice home",
        "status": "open",
    },
    {
        "id": 102,
        "owner_id": 1,
        "org_id": 10,
        "item": "Mouse",
        "amount": 29.0,
        "notes": "Gift wrap",
        "status": "open",
    },
    {
        "id": 201,
        "owner_id": 2,
        "org_id": 10,
        "item": "Keyboard",
        "amount": 79.0,
        "notes": "Bob office delivery",
        "status": "open",
    },
    {
        "id": 301,
        "owner_id": 3,
        "org_id": 10,
        "item": "Server",
        "amount": 4500.0,
        "notes": "Admin warehouse",
        "status": "open",
    },
    {
        "id": 401,
        "owner_id": 4,
        "org_id": 20,
        "item": "Monitor",
        "amount": 320.0,
        "notes": "Carol remote office",
        "status": "open",
    },
)
