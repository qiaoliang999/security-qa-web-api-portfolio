"""
Intentionally vulnerable demo web/API application.

AUTHORIZED LOCAL SECURITY LAB ONLY.
Do not deploy publicly. Do not use real credentials or production data.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.config import DEMO_ORDERS, DEMO_USERS, lab_mode_enabled

app = FastAPI(
    title="Security QA Lab API",
    description=(
        "Intentionally vulnerable demo for authorized local Security QA practice. "
        "Set LAB_MODE=false to enable secure baseline controls."
    ),
    version="1.0.0",
)

# session_token -> user_id
SESSIONS: dict[str, int] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class ProfileUpdateRequest(BaseModel):
    email: Optional[str] = None
    bio: Optional[str] = Field(default=None, max_length=2000)


class SearchRequest(BaseModel):
    query: str = ""


class RedirectRequest(BaseModel):
    next: str = "/"


def _find_user_by_username(username: str) -> Optional[dict[str, Any]]:
    for user in DEMO_USERS.values():
        if user["username"] == username:
            return user
    return None


def _get_user_from_token(authorization: Optional[str]) -> Optional[dict[str, Any]]:
    if not authorization:
        return None
    token = authorization
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    user_id = SESSIONS.get(token)
    if user_id is None:
        return None
    return DEMO_USERS.get(user_id)


def _public_user(user: dict[str, Any], include_sensitive: bool = False) -> dict[str, Any]:
    data = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
    }
    if include_sensitive:
        # LAB: sensitive fields intentionally exposed
        data["ssn"] = user["ssn"]
        data["api_key"] = user["api_key"]
        data["password_sha256"] = hashlib.sha256(user["password"].encode()).hexdigest()
    return data


def _is_safe_redirect(url: str) -> bool:
    """Allow only relative same-origin paths."""
    if not url.startswith("/") or url.startswith("//"):
        return False
    parsed = urlparse(url)
    return parsed.scheme == "" and parsed.netloc == ""


def _contains_injection_payload(value: str) -> bool:
    patterns = [
        r"(?i)('|\").*or.*('|\").*=",
        r"(?i)\bunion\b.*\bselect\b",
        r"(?i)<script\b",
        r"(?i)javascript:",
        r"(?i)\.\./",
        r"(?i);.*drop\b",
    ]
    return any(re.search(p, value) for p in patterns)


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    mode = "LAB (intentionally vulnerable)" if lab_mode_enabled() else "SECURE baseline"
    return f"""<!DOCTYPE html>
<html>
<head><title>Security QA Lab</title></head>
<body>
  <h1>Security QA Lab API</h1>
  <p><strong>Mode:</strong> {mode}</p>
  <p>Authorized local security testing only. No real secrets.</p>
  <ul>
    <li><a href="/docs">OpenAPI docs</a></li>
    <li><a href="/health">Health</a></li>
    <li><a href="/login">Login page</a></li>
  </ul>
</body>
</html>"""


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "lab_mode": lab_mode_enabled(),
        "notice": "Authorized local lab application only",
    }


@app.get("/login", response_class=HTMLResponse)
def login_page() -> str:
    return """<!DOCTYPE html>
<html>
<head><title>Login - Security QA Lab</title></head>
<body>
  <h1>Login</h1>
  <p>Demo users: alice / password123, bob / password123, admin / admin</p>
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


@app.post("/api/login")
def api_login(body: LoginRequest) -> dict[str, Any]:
    user = _find_user_by_username(body.username)

    # LAB: no rate limiting, no lockout, weak credentials accepted as-is
    if user is None or user["password"] != body.password:
        # LAB: user-enumeration via distinct messages
        if lab_mode_enabled():
            if user is None:
                raise HTTPException(status_code=401, detail="Username not found")
            raise HTTPException(status_code=401, detail="Incorrect password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if lab_mode_enabled():
        # LAB: predictable, non-rotating token derived from username
        token = f"lab-token-{user['username']}"
    else:
        token = secrets.token_urlsafe(32)

    SESSIONS[token] = user["id"]

    response: dict[str, Any] = {
        "token": token,
        "user": _public_user(user, include_sensitive=lab_mode_enabled()),
    }
    if lab_mode_enabled():
        # LAB: oversharing role/internal fields on login
        response["session_store_size"] = len(SESSIONS)
    return response


@app.get("/api/me")
def api_me(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    user = _get_user_from_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return _public_user(user, include_sensitive=lab_mode_enabled())


@app.get("/api/users/{user_id}")
def get_user(user_id: int, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """
    Profile lookup.

    LAB_MODE: Broken Object Level Authorization (IDOR) — any authenticated user
    can read any profile including sensitive fields.
    SECURE: only self or admin; sensitive fields withheld for non-admin.
    """
    current = _get_user_from_token(authorization)
    if not current:
        raise HTTPException(status_code=401, detail="Unauthorized")

    target = DEMO_USERS.get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if not lab_mode_enabled():
        if current["id"] != target["id"] and current["role"] != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        include_sensitive = current["role"] == "admin" and current["id"] == target["id"]
        # Admins may see limited sensitive fields only for themselves in this baseline.
        return _public_user(target, include_sensitive=False)

    return _public_user(target, include_sensitive=True)


@app.get("/api/orders/{order_id}")
def get_order(order_id: int, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """
    Order detail.

    LAB_MODE: IDOR — any authenticated user can read any order.
    SECURE: only owner or admin.
    """
    current = _get_user_from_token(authorization)
    if not current:
        raise HTTPException(status_code=401, detail="Unauthorized")

    order = DEMO_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if not lab_mode_enabled():
        if order["owner_id"] != current["id"] and current["role"] != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")

    return order


@app.get("/api/orders")
def list_orders(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    current = _get_user_from_token(authorization)
    if not current:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if lab_mode_enabled():
        # LAB: returns all orders regardless of ownership
        return {"orders": list(DEMO_ORDERS.values())}

    if current["role"] == "admin":
        return {"orders": list(DEMO_ORDERS.values())}
    owned = [o for o in DEMO_ORDERS.values() if o["owner_id"] == current["id"]]
    return {"orders": owned}


@app.post("/api/search")
def search(body: SearchRequest, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """
    Product/order note search.

    LAB_MODE: no input validation; reflected payload echo (XSS-ish / injection training surface).
    SECURE: reject obvious injection patterns; sanitize reflection.
    """
    current = _get_user_from_token(authorization)
    if not current:
        raise HTTPException(status_code=401, detail="Unauthorized")

    query = body.query
    if not lab_mode_enabled():
        if len(query) > 100:
            raise HTTPException(status_code=400, detail="Query too long")
        if _contains_injection_payload(query):
            raise HTTPException(status_code=400, detail="Invalid query")
        safe_query = re.sub(r"[<>\"'`]", "", query)
    else:
        safe_query = query  # LAB: unsanitized

    hits = []
    for order in DEMO_ORDERS.values():
        hay = f"{order['item']} {order['notes']}".lower()
        if safe_query.lower() in hay:
            hits.append(order)

    return {
        "query": safe_query,
        "reflected": f"Results for: {safe_query}",
        "count": len(hits),
        "results": hits if lab_mode_enabled() or current["role"] == "admin" else [
            h for h in hits if h["owner_id"] == current["id"]
        ],
    }


@app.get("/api/redirect")
def open_redirect(next: str = "/") -> RedirectResponse:
    """
    Redirect helper.

    LAB_MODE: open redirect — any next URL accepted.
    SECURE: only relative same-origin paths.
    """
    if lab_mode_enabled():
        return RedirectResponse(url=next, status_code=302)

    if not _is_safe_redirect(next):
        raise HTTPException(status_code=400, detail="Unsafe redirect target")
    return RedirectResponse(url=next, status_code=302)


@app.patch("/api/me")
def update_me(
    body: ProfileUpdateRequest,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    current = _get_user_from_token(authorization)
    if not current:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if body.email is not None:
        if not lab_mode_enabled():
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", body.email):
                raise HTTPException(status_code=400, detail="Invalid email")
        current["email"] = body.email

    return _public_user(current, include_sensitive=False)


@app.get("/api/admin/users")
def admin_list_users(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """
    Admin endpoint.

    LAB_MODE: missing authorization — any authenticated user can list all users with sensitive fields.
    SECURE: admin role required; no sensitive fields.
    """
    current = _get_user_from_token(authorization)
    if not current:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not lab_mode_enabled():
        if current["role"] != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        return {"users": [_public_user(u, include_sensitive=False) for u in DEMO_USERS.values()]}

    return {"users": [_public_user(u, include_sensitive=True) for u in DEMO_USERS.values()]}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # LAB: verbose errors; SECURE: generic
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


def create_app() -> FastAPI:
    return app
