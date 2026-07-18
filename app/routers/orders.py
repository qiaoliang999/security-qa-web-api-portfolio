"""Order routes — ownership, write-side IDOR, and listing scope."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app import db
from app.auth import CurrentUser, DbDep, require_order_access, require_order_write
from app.config import lab_mode_enabled
from app.models import OrderUpdateRequest, to_order

router = APIRouter(tags=["orders"])


@router.get("/api/orders")
def list_orders(current: CurrentUser, conn: DbDep) -> dict[str, Any]:
    """
    LAB: returns every order regardless of ownership/tenant.
    SECURE: admin sees all; user sees own orders in own org only.
    """
    if lab_mode_enabled():
        orders = db.list_orders(conn)
        return {"orders": [to_order(o) for o in orders]}

    if current["role"] == "admin":
        orders = db.list_orders(conn)
    else:
        orders = db.list_orders(conn, owner_id=current["id"], org_id=current["org_id"])
    return {"orders": [to_order(o) for o in orders]}


@router.get("/api/orders/{order_id}")
def get_order(order_id: int, current: CurrentUser, conn: DbDep) -> dict[str, Any]:
    """
    LAB: IDOR — any authenticated user may read any order.
    SECURE: owner or admin.
    """
    order = db.get_order_by_id(conn, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if not lab_mode_enabled():
        require_order_access(current, order)

    return to_order(order)


@router.patch("/api/orders/{order_id}")
def update_order(
    order_id: int,
    body: OrderUpdateRequest,
    current: CurrentUser,
    conn: DbDep,
) -> dict[str, Any]:
    """
    Write-side authorization.

    LAB: any authenticated user may mutate any order (horizontal write IDOR).
    SECURE: owner or admin only.
    """
    order = db.get_order_by_id(conn, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if not lab_mode_enabled():
        require_order_write(current, order)

    updated = db.update_order(
        conn,
        order_id,
        item=body.item,
        amount=body.amount,
        notes=body.notes,
        status=body.status,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Order not found")
    return to_order(updated)


@router.delete("/api/orders/{order_id}")
def delete_order(order_id: int, current: CurrentUser, conn: DbDep) -> dict[str, Any]:
    """
    LAB: any authenticated user may delete any order.
    SECURE: owner or admin only.
    """
    order = db.get_order_by_id(conn, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if not lab_mode_enabled():
        require_order_write(current, order)

    deleted = db.delete_order(conn, order_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"detail": "deleted", "id": order_id}
