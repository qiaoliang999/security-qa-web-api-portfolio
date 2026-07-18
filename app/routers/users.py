"""User profile routes — horizontal authz exercises."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app import db
from app.auth import CurrentUser, DbDep, require_self_or_admin
from app.config import SEED_USERS, lab_mode_enabled
from app.models import to_lab_user, to_public_user

router = APIRouter(tags=["users"])

_SEED_PLAINTEXT = {u["username"]: u["password"] for u in SEED_USERS}


@router.get("/api/users/{user_id}")
def get_user(user_id: int, current: CurrentUser, conn: DbDep) -> dict[str, Any]:
    """
    Profile lookup.

    LAB: Broken Object Level Authorization (IDOR) — any authenticated user
    can read any profile including sensitive fields.
    SECURE: self or admin only; public allow-list projection.
    """
    target = db.get_user_by_id(conn, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if not lab_mode_enabled():
        require_self_or_admin(current, target["id"])
        return to_public_user(target)

    plaintext = _SEED_PLAINTEXT.get(target["username"])
    return to_lab_user(target, plaintext_password=plaintext)
