"""Admin routes — vertical privilege escalation training surface."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from app import db
from app.auth import CurrentUser, DbDep, require_admin
from app.config import SEED_USERS, lab_mode_enabled
from app.models import to_lab_user, to_public_user

router = APIRouter(tags=["admin"])

_SEED_PLAINTEXT = {u["username"]: u["password"] for u in SEED_USERS}


@router.get("/api/admin/users")
def admin_list_users(current: CurrentUser, conn: DbDep) -> dict[str, Any]:
    """
    LAB: missing function-level authorization — any authenticated user may list.
    SECURE: admin role required; allow-list projection (no ssn/api_key/hash).
    """
    if not lab_mode_enabled():
        if current["role"] != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        users = [to_public_user(u) for u in db.list_users(conn)]
        return {"users": users}

    users = [
        to_lab_user(u, plaintext_password=_SEED_PLAINTEXT.get(u["username"]))
        for u in db.list_users(conn)
    ]
    return {"users": users}


@router.get("/api/admin/stats")
def admin_stats(
    _admin: Annotated[dict[str, Any], Depends(require_admin)],
    conn: DbDep,
) -> dict[str, Any]:
    """Always requires admin (even in lab) — control endpoint for vertical tests."""
    users = db.list_users(conn)
    orders = db.list_orders(conn)
    return {
        "user_count": len(users),
        "order_count": len(orders),
        "org_ids": sorted({u["org_id"] for u in users}),
    }
