"""Shared pytest fixtures and helpers for Security QA lab tests.

Each test gets a fresh in-memory SQLite database (schema + seed) so global
mutable state does not leak between cases.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _build_client(monkeypatch: pytest.MonkeyPatch, lab_mode: bool) -> TestClient:
    monkeypatch.setenv("LAB_MODE", "true" if lab_mode else "false")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    # Fresh imports / cache so LAB_MODE and DB path are observed.
    import app.config as config
    import app.db as db_mod

    config.clear_settings_cache()
    db_mod.set_db_path(db_mod._MEMORY_URI)
    db_mod.reset_database()

    # Recreate app so lifespan/state is clean
    import importlib
    import app.main as main_mod

    importlib.reload(main_mod)
    # Force lab_mode function to match fixture (import-time env already set)
    monkeypatch.setattr(main_mod, "lab_mode_enabled", lambda: lab_mode)
    monkeypatch.setattr(config, "lab_mode_enabled", lambda: lab_mode)
    # Also patch routers that import lab_mode_enabled by name
    for mod_name in (
        "app.routers.auth",
        "app.routers.users",
        "app.routers.orders",
        "app.routers.admin",
        "app.routers.search",
        "app.auth",
    ):
        mod = importlib.import_module(mod_name)
        if hasattr(mod, "lab_mode_enabled"):
            monkeypatch.setattr(mod, "lab_mode_enabled", lambda: lab_mode)

    client = TestClient(main_mod.app)
    return client


@pytest.fixture
def lab_client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """App client with intentional vulnerabilities enabled + isolated DB."""
    client = _build_client(monkeypatch, lab_mode=True)
    with client:
        yield client
    import app.db as db_mod

    db_mod.reset_database()


@pytest.fixture
def secure_client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """App client with secure baseline controls + isolated DB."""
    client = _build_client(monkeypatch, lab_mode=False)
    with client:
        yield client
    import app.db as db_mod

    db_mod.reset_database()


def login(client: TestClient, username: str, password: str) -> str:
    res = client.post("/api/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    token = res.json()["token"]
    assert token
    return token


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# Demo credentials (local lab only)
ALICE = ("alice", "password123")
BOB = ("bob", "password123")
ADMIN = ("admin", "admin")
CAROL = ("carol", "password123")
