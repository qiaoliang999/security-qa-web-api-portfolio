"""Shared pytest fixtures for Security QA lab tests."""

from __future__ import annotations

import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Ensure package root is importable when pytest runs from repo root.
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def lab_client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """App client with intentional vulnerabilities enabled."""
    monkeypatch.setenv("LAB_MODE", "true")
    # Reload config/module state for isolation
    import app.config as config
    import app.main as main

    monkeypatch.setattr(config, "lab_mode_enabled", lambda: True)
    monkeypatch.setattr(main, "lab_mode_enabled", lambda: True)
    main.SESSIONS.clear()
    with TestClient(main.app) as client:
        yield client
    main.SESSIONS.clear()


@pytest.fixture
def secure_client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    """App client with secure baseline controls enabled."""
    monkeypatch.setenv("LAB_MODE", "false")
    import app.config as config
    import app.main as main

    monkeypatch.setattr(config, "lab_mode_enabled", lambda: False)
    monkeypatch.setattr(main, "lab_mode_enabled", lambda: False)
    main.SESSIONS.clear()
    with TestClient(main.app) as client:
        yield client
    main.SESSIONS.clear()


def login(client: TestClient, username: str, password: str) -> str:
    res = client.post("/api/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    token = res.json()["token"]
    assert token
    return token


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
