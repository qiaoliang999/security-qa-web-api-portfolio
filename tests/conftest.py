"""Shared pytest fixtures and helpers for Security QA lab tests.

Isolation contract
------------------
Each fixture rebuilds the app against a **shared in-memory SQLite URI** and
calls ``reset_database()`` so schema + seed are fresh. After the test, the
fixture resets again so mutations (PATCH/DELETE orders, profile updates,
sessions) do not bleed into the next case even if a test aborts early.

Dual mode
---------
``lab_client`` forces intentional flaws; ``secure_client`` forces the real
baseline. Both monkeypatch ``lab_mode_enabled`` on the factory and on every
router that imported it by name, so import-time caching cannot drift.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Generator, Optional

import pytest
from fastapi.testclient import TestClient
from httpx import Response

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Modules that bind ``lab_mode_enabled`` at import time and must be re-patched
# after each ``importlib.reload`` of the app factory.
_LAB_MODE_MODULES = (
    "app.routers.auth",
    "app.routers.users",
    "app.routers.orders",
    "app.routers.admin",
    "app.routers.search",
    "app.auth",
)


def _build_client(monkeypatch: pytest.MonkeyPatch, lab_mode: bool) -> TestClient:
    """Construct an isolated TestClient for the requested mode."""
    monkeypatch.setenv("LAB_MODE", "true" if lab_mode else "false")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    import app.config as config
    import app.db as db_mod

    config.clear_settings_cache()
    db_mod.set_db_path(db_mod._MEMORY_URI)
    db_mod.reset_database()

    import importlib
    import app.main as main_mod

    importlib.reload(main_mod)
    # Force lab_mode function to match fixture (import-time env already set).
    monkeypatch.setattr(main_mod, "lab_mode_enabled", lambda: lab_mode)
    monkeypatch.setattr(config, "lab_mode_enabled", lambda: lab_mode)
    for mod_name in _LAB_MODE_MODULES:
        mod = importlib.import_module(mod_name)
        if hasattr(mod, "lab_mode_enabled"):
            monkeypatch.setattr(mod, "lab_mode_enabled", lambda: lab_mode)

    return TestClient(main_mod.app)


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
    """Authenticate and return the session token (asserts HTTP 200)."""
    res = client.post("/api/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    token = res.json()["token"]
    assert token
    return token


def auth_header(token: str) -> dict[str, str]:
    """Build a standard Authorization Bearer header map."""
    return {"Authorization": f"Bearer {token}"}


def api_request(
    client: TestClient,
    method: str,
    path: str,
    *,
    token: Optional[str] = None,
    json_body: Any = None,
    headers: Optional[dict[str, str]] = None,
) -> Response:
    """Dispatch an API call with optional Bearer auth.

    Centralizes method dispatch used by the authz matrix and edge-case tests so
    each case does not re-implement GET/PATCH/DELETE branching.
    """
    hdrs: dict[str, str] = dict(headers or {})
    if token is not None:
        hdrs.update(auth_header(token))

    method_u = method.upper()
    if method_u == "GET":
        return client.get(path, headers=hdrs)
    if method_u == "POST":
        return client.post(path, headers=hdrs, json=json_body)
    if method_u == "PATCH":
        return client.patch(path, headers=hdrs, json=json_body if json_body is not None else {})
    if method_u == "DELETE":
        return client.delete(path, headers=hdrs)
    raise AssertionError(f"unsupported method {method}")


# Demo credentials (local lab only — fictional)
ALICE = ("alice", "password123")
BOB = ("bob", "password123")
ADMIN = ("admin", "admin")
CAROL = ("carol", "password123")
