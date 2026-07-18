"""
Optional UI smoke tests with Playwright.

These tests start an in-process uvicorn server against the lab app.
They are skipped automatically if Playwright browsers are not installed.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.ui


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server():
    port = _free_port()
    env = {
        **os.environ,
        "LAB_MODE": "true",
        "DATABASE_URL": "sqlite:///:memory:",
        "PYTHONPATH": str(ROOT),
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    import urllib.request

    deadline = time.time() + 15
    last_err = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=1) as resp:
                if resp.status == 200:
                    break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError(f"Server failed to start: {last_err}")

    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_ui_login_page_renders(live_server):
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Playwright browser not installed: {exc}")
        page = browser.new_page()
        page.goto(f"{live_server}/login")
        assert "Login" in page.content()
        page.fill("#username", "alice")
        page.fill("#password", "password123")
        page.click("button[type=submit]")
        page.wait_for_function(
            "() => document.getElementById('result').textContent.includes('token')",
            timeout=5000,
        )
        result_text = page.inner_text("#result")
        assert "token" in result_text
        assert "alice" in result_text
        browser.close()


def test_ui_home_shows_lab_mode(live_server):
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Playwright browser not installed: {exc}")
        page = browser.new_page()
        page.goto(live_server + "/")
        content = page.content()
        assert "Security QA Lab" in content
        assert "LAB" in content or "lab" in content.lower()
        browser.close()
