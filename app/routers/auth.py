"""Authentication routes: login and current profile."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException

from app import db
from app.auth import CurrentUser, DbDep, issue_session_token
from app.config import SEED_USERS, lab_mode_enabled
from app.models import LoginRequest, ProfileUpdateRequest, to_lab_user, to_public_user
from app.security import verify_password

router = APIRouter(tags=["auth"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Map username -> seed plaintext password for LAB weak-hash leakage only.
_SEED_PLAINTEXT = {u["username"]: u["password"] for u in SEED_USERS}


@router.post("/api/login")
def api_login(body: LoginRequest, conn: DbDep) -> dict[str, Any]:
    user = db.get_user_by_username(conn, body.username)

    if user is None or not verify_password(body.password, user["password_hash"]):
        if lab_mode_enabled():
            # LAB: username enumeration via distinct messages
            if user is None:
                raise HTTPException(status_code=401, detail="Username not found")
            raise HTTPException(status_code=401, detail="Incorrect password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = issue_session_token(conn, user)

    if lab_mode_enabled():
        plaintext = _SEED_PLAINTEXT.get(user["username"])
        response: dict[str, Any] = {
            "token": token,
            "user": to_lab_user(user, plaintext_password=plaintext),
            "session_store_size": db.count_sessions(conn),
        }
        return response

    return {
        "token": token,
        "user": to_public_user(user),
    }


@router.get("/api/me")
def api_me(user: CurrentUser) -> dict[str, Any]:
    if lab_mode_enabled():
        plaintext = _SEED_PLAINTEXT.get(user["username"])
        return to_lab_user(user, plaintext_password=plaintext)
    return to_public_user(user)


@router.patch("/api/me")
def update_me(body: ProfileUpdateRequest, user: CurrentUser, conn: DbDep) -> dict[str, Any]:
    updated = user
    if body.email is not None:
        if not lab_mode_enabled():
            if not _EMAIL_RE.match(body.email):
                raise HTTPException(status_code=400, detail="Invalid email")
        updated = db.update_user_email(conn, user["id"], body.email) or user
    if body.bio is not None:
        updated = db.update_user_bio(conn, user["id"], body.bio) or updated
    return to_public_user(updated)
