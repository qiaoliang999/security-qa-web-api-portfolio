"""Central authentication and authorization dependencies.

Secure mode relies on these helpers for every protected route:
  - get_current_user
  - require_roles
  - require_owner / require_order_access

Lab mode may short-circuit some of these checks intentionally in routers.
"""

from __future__ import annotations

import secrets
import sqlite3
from typing import Annotated, Any, Callable, Optional

from fastapi import Depends, Header, HTTPException

from app import db
from app.config import lab_mode_enabled

# NOTE: get_optional_user was removed — unauthenticated optional paths should
# call public handlers without invoking the session store.


def get_db() -> sqlite3.Connection:
    """Yield a DB connection; commit on success, rollback on error."""
    conn = db.connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


DbDep = Annotated[sqlite3.Connection, Depends(get_db)]


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    """Extract a Bearer token.

    Only the ``Authorization: Bearer <token>`` form is accepted (RFC 6750).
    Bare tokens, alternate schemes (``Token``, ``Basic``, …), or whitespace-only
    credentials are rejected so scheme-less header smuggling cannot succeed.
    """
    if not authorization:
        return None
    scheme, _, remainder = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = remainder.strip()
    return token or None


def get_current_user(
    conn: DbDep,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Require a valid Bearer session token. Raises 401 otherwise."""
    token = _extract_bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = db.get_user_by_token(conn, token)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]


def require_roles(*roles: str) -> Callable[..., dict[str, Any]]:
    """Dependency factory: current user must have one of the given roles."""

    def _checker(user: CurrentUser) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return _checker


def require_admin(user: CurrentUser) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return user


AdminUser = Annotated[dict[str, Any], Depends(require_admin)]


def require_self_or_admin(current: dict[str, Any], target_user_id: int) -> None:
    """Object-level check for user resources."""
    if current["id"] != target_user_id and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")


def require_order_access(current: dict[str, Any], order: dict[str, Any]) -> None:
    """Object-level check for order resources (owner or admin)."""
    if order["owner_id"] != current["id"] and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")


def require_order_write(current: dict[str, Any], order: dict[str, Any]) -> None:
    """Write-side ownership check: owner or admin may mutate; others 403."""
    require_order_access(current, order)


def issue_session_token(conn: sqlite3.Connection, user: dict[str, Any]) -> str:
    """Create a session. Lab tokens are predictable; secure tokens are random."""
    if lab_mode_enabled():
        token = f"lab-token-{user['username']}"
    else:
        token = secrets.token_urlsafe(32)
    db.create_session(conn, token, user["id"])
    return token
