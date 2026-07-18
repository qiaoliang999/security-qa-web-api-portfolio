"""Parametrized authorization matrix: roles × resources × methods × expected status.

Readable table-driven coverage for horizontal and vertical access control in
secure mode. Lab mode detection for the same surfaces lives in other modules.
"""

from __future__ import annotations

import pytest
from tests.conftest import ALICE, BOB, ADMIN, CAROL, auth_header, login

# (actor, method, path, body_or_None, expected_status, note)
# actor: alice | bob | admin | carol | anon
SECURE_AUTHZ_MATRIX = [
    # --- users object ---
    ("alice", "GET", "/api/users/1", None, 200, "self profile"),
    ("alice", "GET", "/api/users/2", None, 403, "horizontal user IDOR blocked"),
    ("alice", "GET", "/api/users/3", None, 403, "user cannot read admin profile"),
    ("bob", "GET", "/api/users/1", None, 403, "bob cannot read alice"),
    ("bob", "GET", "/api/users/2", None, 200, "bob self"),
    ("admin", "GET", "/api/users/1", None, 200, "admin reads alice"),
    ("admin", "GET", "/api/users/2", None, 200, "admin reads bob"),
    ("anon", "GET", "/api/users/1", None, 401, "unauthenticated user profile"),
    # --- orders object read ---
    ("alice", "GET", "/api/orders/101", None, 200, "own order"),
    ("alice", "GET", "/api/orders/201", None, 403, "foreign order read"),
    ("alice", "GET", "/api/orders/401", None, 403, "cross-tenant order read"),
    ("bob", "GET", "/api/orders/201", None, 200, "bob own order"),
    ("bob", "GET", "/api/orders/101", None, 403, "bob cannot read alice order"),
    ("admin", "GET", "/api/orders/201", None, 200, "admin read any"),
    ("carol", "GET", "/api/orders/401", None, 200, "carol own org order"),
    ("carol", "GET", "/api/orders/101", None, 403, "carol cannot read org10 order"),
    ("anon", "GET", "/api/orders/101", None, 401, "unauthenticated order"),
    # --- orders write (PATCH) ---
    ("alice", "PATCH", "/api/orders/101", {"notes": "n"}, 200, "owner patch"),
    ("alice", "PATCH", "/api/orders/201", {"notes": "n"}, 403, "write IDOR patch"),
    ("bob", "PATCH", "/api/orders/101", {"notes": "n"}, 403, "bob cannot patch alice"),
    ("admin", "PATCH", "/api/orders/101", {"notes": "admin-n"}, 200, "admin patch"),
    ("anon", "PATCH", "/api/orders/101", {"notes": "n"}, 401, "anon patch"),
    # --- orders write (DELETE) — use disposable: only assert status; setup creates none ---
    # We test delete against bob's order 201 carefully: only non-destructive actors
    ("alice", "DELETE", "/api/orders/201", None, 403, "write IDOR delete"),
    ("bob", "DELETE", "/api/orders/101", None, 403, "bob cannot delete alice order"),
    ("anon", "DELETE", "/api/orders/101", None, 401, "anon delete"),
    # --- admin function ---
    ("alice", "GET", "/api/admin/users", None, 403, "vertical privilege blocked"),
    ("bob", "GET", "/api/admin/users", None, 403, "vertical privilege blocked bob"),
    ("carol", "GET", "/api/admin/users", None, 403, "vertical privilege blocked carol"),
    ("admin", "GET", "/api/admin/users", None, 200, "admin allowed"),
    ("anon", "GET", "/api/admin/users", None, 401, "anon admin"),
    ("alice", "GET", "/api/admin/stats", None, 403, "stats vertical blocked"),
    ("admin", "GET", "/api/admin/stats", None, 200, "stats admin ok"),
    ("anon", "GET", "/api/admin/stats", None, 401, "stats anon"),
    # --- listing ---
    ("alice", "GET", "/api/orders", None, 200, "list own scope"),
    ("admin", "GET", "/api/orders", None, 200, "list all as admin"),
    ("anon", "GET", "/api/orders", None, 401, "list anon"),
    # --- me ---
    ("alice", "GET", "/api/me", None, 200, "me ok"),
    ("anon", "GET", "/api/me", None, 401, "me anon"),
]


_CREDS = {
    "alice": ALICE,
    "bob": BOB,
    "admin": ADMIN,
    "carol": CAROL,
}


@pytest.mark.authz
@pytest.mark.security
@pytest.mark.parametrize(
    "actor,method,path,body,expected,note",
    SECURE_AUTHZ_MATRIX,
    ids=[f"{a}:{m}:{p}:{e}:{n}" for a, m, p, _, e, n in SECURE_AUTHZ_MATRIX],
)
def test_secure_authz_matrix(secure_client, actor, method, path, body, expected, note):
    headers = {}
    if actor != "anon":
        user, pw = _CREDS[actor]
        token = login(secure_client, user, pw)
        headers = auth_header(token)

    if method == "GET":
        res = secure_client.get(path, headers=headers)
    elif method == "PATCH":
        res = secure_client.patch(path, headers=headers, json=body or {})
    elif method == "DELETE":
        res = secure_client.delete(path, headers=headers)
    else:
        raise AssertionError(f"unsupported method {method}")

    assert res.status_code == expected, (
        f"[{note}] {actor} {method} {path} expected {expected}, got {res.status_code}: {res.text}"
    )


@pytest.mark.authz
@pytest.mark.security
@pytest.mark.parametrize(
    "actor,path,expected",
    [
        ("alice", "/api/admin/users", 200),  # lab: missing function auth
        ("bob", "/api/admin/users", 200),
        ("alice", "/api/orders/201", 200),  # lab: read IDOR
        ("alice", "/api/users/2", 200),  # lab: user IDOR
    ],
)
def test_lab_authz_failures_detectable(lab_client, actor, path, expected):
    """Lab mode still authenticates but intentionally skips object/function authz."""
    user, pw = _CREDS[actor]
    token = login(lab_client, user, pw)
    res = lab_client.get(path, headers=auth_header(token))
    assert res.status_code == expected
