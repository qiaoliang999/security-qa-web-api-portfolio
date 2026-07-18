"""Search and redirect routes.

Secure mode controls:
  - Redirect: path allow-list map (named internal destinations), NOT a blacklist
  - Search: max length + parameterized SQL; no regex SQLi/XSS blacklist theater
    (search is not rendered as HTML here; reflection is omitted in secure mode)
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse

from app import db
from app.auth import CurrentUser, DbDep
from app.config import get_settings, lab_mode_enabled
from app.models import SearchRequest, to_order

router = APIRouter(tags=["search"])


def _is_allowed_redirect(target: str) -> bool:
    """Allow-list of relative internal paths (exact match or known prefixes)."""
    settings = get_settings()
    if not target.startswith("/") or target.startswith("//"):
        return False
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return False
    path = parsed.path or "/"
    if path in settings.redirect_allowlist:
        return True
    # Allow /docs subpaths used by Swagger UI assets in local lab only
    if path.startswith("/docs") or path.startswith("/redoc"):
        return True
    return False


@router.post("/api/search")
def search(body: SearchRequest, current: CurrentUser, conn: DbDep) -> dict[str, Any]:
    """
    Order note/item search.

    Uses parameterized SQL always. Secure mode enforces max length and does not
    echo raw input as a "reflected" HTML-like field. Lab mode reflects the
    query for training (JSON API reflection — not a real browser XSS sink).
    """
    query = body.query
    settings = get_settings()

    if not lab_mode_enabled():
        if len(query) > settings.max_search_query_len:
            raise HTTPException(status_code=400, detail="Query too long")
        # No regex blacklist for "SQLi/XSS". Real control = length + param SQL + no HTML sink.
        hits = db.search_orders(conn, query)
        if current["role"] != "admin":
            hits = [h for h in hits if h["owner_id"] == current["id"]]
        return {
            "query": query[: settings.max_search_query_len],
            "count": len(hits),
            "results": [to_order(h) for h in hits],
        }

    # LAB: no length limit; reflect unsanitized input; return unscoped hits
    hits = db.search_orders(conn, query)
    return {
        "query": query,
        "reflected": f"Results for: {query}",
        "count": len(hits),
        "results": [to_order(h) for h in hits],
    }


@router.get("/api/redirect")
def open_redirect(next: str = "/") -> RedirectResponse:
    """
    LAB: open redirect — any next URL accepted.
    SECURE: only allow-listed relative paths (map), not hostname blacklist.
    """
    if lab_mode_enabled():
        return RedirectResponse(url=next, status_code=302)

    if not _is_allowed_redirect(next):
        raise HTTPException(status_code=400, detail="Unsafe redirect target")
    return RedirectResponse(url=next, status_code=302)
