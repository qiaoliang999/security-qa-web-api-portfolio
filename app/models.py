"""Pydantic request/response DTOs.

Response models are allow-lists: sensitive fields (ssn, api_key, password_hash)
are never part of PublicUserResponse. Lab endpoints may return raw dicts with
extra fields when LAB_MODE is on — that is intentional training signal only.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ProfileUpdateRequest(BaseModel):
    email: Optional[str] = Field(default=None, max_length=254)
    bio: Optional[str] = Field(default=None, max_length=2000)


class SearchRequest(BaseModel):
    query: str = Field(default="", max_length=2000)


class OrderUpdateRequest(BaseModel):
    item: Optional[str] = Field(default=None, max_length=200)
    amount: Optional[float] = Field(default=None, ge=0)
    notes: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[str] = Field(default=None, max_length=32)


# ---------------------------------------------------------------------------
# Responses (allow-listed)
# ---------------------------------------------------------------------------


class PublicUserResponse(BaseModel):
    """Safe user projection — never includes ssn / api_key / password_hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    email: str
    org_id: int
    bio: str = ""


class OrderResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    org_id: int
    item: str
    amount: float
    notes: str
    status: str


class LoginResponse(BaseModel):
    token: str
    user: PublicUserResponse


class OrdersListResponse(BaseModel):
    orders: list[OrderResponse]


class UsersListResponse(BaseModel):
    users: list[PublicUserResponse]


class SearchResponse(BaseModel):
    query: str
    count: int
    results: list[OrderResponse]
    # `reflected` only present in lab-style payloads; not part of secure contract


class HealthResponse(BaseModel):
    status: str
    lab_mode: bool
    notice: str


class MessageResponse(BaseModel):
    detail: str


# ---------------------------------------------------------------------------
# Helpers for building safe projections from DB rows
# ---------------------------------------------------------------------------

# Align with tests.helpers.contracts.FORBIDDEN_SECURE_KEYS (response allow-list).
SENSITIVE_USER_KEYS = frozenset({"ssn", "api_key", "password_hash", "password", "password_sha256"})


def to_public_user(user: dict[str, Any]) -> dict[str, Any]:
    """Allow-list projection used by secure responses."""
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "org_id": user["org_id"],
        "bio": user.get("bio") or "",
    }


def to_lab_user(user: dict[str, Any], plaintext_password: Optional[str] = None) -> dict[str, Any]:
    """LAB projection that intentionally overshares — for training only."""
    from app.security import weak_sha256

    data = to_public_user(user)
    data["ssn"] = user["ssn"]
    data["api_key"] = user["api_key"]
    # Intentionally weak material for lab detection (not the stored hash)
    if plaintext_password is not None:
        data["password_sha256"] = weak_sha256(plaintext_password)
    else:
        # Fall back to truncated stored hash fingerprint (still lab-only leak)
        data["password_sha256"] = "lab-leak:" + (user.get("password_hash") or "")[:16]
    return data


def to_order(order: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": order["id"],
        "owner_id": order["owner_id"],
        "org_id": order["org_id"],
        "item": order["item"],
        "amount": order["amount"],
        "notes": order["notes"],
        "status": order["status"],
    }
