"""
Security QA Lab API — application factory.

AUTHORIZED LOCAL SECURITY LAB ONLY.
Do not deploy publicly. Do not use real credentials or production data.

Architecture:
  app/main.py       — factory + HTML chrome only
  app/config.py     — settings / LAB_MODE / seed metadata
  app/db.py         — SQLite + seed + isolation
  app/security.py   — password hashing (PBKDF2)
  app/models.py     — Pydantic DTOs (response allow-lists)
  app/auth.py       — central authn/authz dependencies
  app/routers/*     — auth, users, orders, admin, search
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import clear_settings_cache, get_settings, lab_mode_enabled
from app.db import ensure_database
from app.routers import admin, auth, orders, search, users


@asynccontextmanager
async def lifespan(_app: FastAPI):
    clear_settings_cache()
    ensure_database()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        description=(
            "Intentionally dual-mode demo for authorized local Security QA practice. "
            "Set LAB_MODE=false for secure baseline controls "
            "(central authz, hashed passwords, DTO allow-lists, redirect path map)."
        ),
        version=settings.app_version,
        lifespan=lifespan,
    )

    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(orders.router)
    application.include_router(admin.router)
    application.include_router(search.router)

    @application.get("/", response_class=HTMLResponse)
    def home() -> str:
        mode = "LAB (intentionally vulnerable)" if lab_mode_enabled() else "SECURE baseline"
        return f"""<!DOCTYPE html>
<html>
<head><title>Security QA Lab</title></head>
<body>
  <h1>Security QA Lab API</h1>
  <p><strong>Mode:</strong> {mode}</p>
  <p>Authorized local security testing only. No real secrets. Passwords are hashed at rest.</p>
  <ul>
    <li><a href="/docs">OpenAPI docs</a></li>
    <li><a href="/health">Health</a></li>
    <li><a href="/login">Login page</a></li>
  </ul>
</body>
</html>"""

    @application.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "lab_mode": lab_mode_enabled(),
            "notice": "Authorized local lab application only",
        }

    @application.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return """<!DOCTYPE html>
<html>
<head><title>Login - Security QA Lab</title></head>
<body>
  <h1>Login</h1>
  <p>Demo users: alice / password123, bob / password123, admin / admin, carol / password123</p>
  <form id="loginForm">
    <label>Username <input id="username" name="username" /></label><br/>
    <label>Password <input id="password" name="password" type="password" /></label><br/>
    <button type="submit">Login</button>
  </form>
  <pre id="result"></pre>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
      });
      const data = await res.json();
      document.getElementById('result').textContent = JSON.stringify(data, null, 2);
      if (data.token) {
        localStorage.setItem('token', data.token);
      }
    });
  </script>
</body>
</html>"""

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        if lab_mode_enabled():
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal error",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "path": str(request.url.path),
                },
            )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return application


app = create_app()
