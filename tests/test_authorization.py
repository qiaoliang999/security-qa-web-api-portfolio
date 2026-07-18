"""Authorization / IDOR / BFLA tests (non-matrix focused cases)."""

import pytest
from tests.conftest import ALICE, BOB, ADMIN, auth_header, login
from tests.helpers.contracts import assert_no_sensitive_fields


@pytest.mark.authz
@pytest.mark.security
def test_lab_idor_user_profile(lab_client):
    """Lab finding: authenticated user can read another user's sensitive profile."""
    alice_token = login(lab_client, *ALICE)
    res = lab_client.get("/api/users/2", headers=auth_header(alice_token))
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == "bob"
    assert "ssn" in body
    assert "api_key" in body


@pytest.mark.authz
@pytest.mark.security
def test_secure_blocks_idor_user_profile(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/users/2", headers=auth_header(alice_token))
    assert res.status_code == 403


@pytest.mark.authz
def test_secure_allows_self_profile(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/users/1", headers=auth_header(alice_token))
    assert res.status_code == 200
    assert res.json()["username"] == "alice"
    assert_no_sensitive_fields(res.json())


@pytest.mark.authz
@pytest.mark.security
def test_lab_idor_order_access(lab_client):
    """Lab finding: alice can read bob's order details."""
    alice_token = login(lab_client, *ALICE)
    res = lab_client.get("/api/orders/201", headers=auth_header(alice_token))
    assert res.status_code == 200
    body = res.json()
    assert body["owner_id"] == 2
    assert body["item"] == "Keyboard"


@pytest.mark.authz
@pytest.mark.security
def test_secure_blocks_foreign_order(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/orders/201", headers=auth_header(alice_token))
    assert res.status_code == 403


@pytest.mark.authz
def test_secure_allows_own_order(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/orders/101", headers=auth_header(alice_token))
    assert res.status_code == 200
    assert res.json()["owner_id"] == 1


@pytest.mark.authz
@pytest.mark.security
def test_lab_list_orders_returns_all(lab_client):
    alice_token = login(lab_client, *ALICE)
    res = lab_client.get("/api/orders", headers=auth_header(alice_token))
    assert res.status_code == 200
    owners = {o["owner_id"] for o in res.json()["orders"]}
    assert {1, 2, 3}.issubset(owners)


@pytest.mark.authz
@pytest.mark.security
def test_secure_list_orders_scoped(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/orders", headers=auth_header(alice_token))
    assert res.status_code == 200
    owners = {o["owner_id"] for o in res.json()["orders"]}
    assert owners == {1}


@pytest.mark.authz
@pytest.mark.security
def test_lab_missing_admin_authorization(lab_client):
    """Lab finding: non-admin can call /api/admin/users."""
    alice_token = login(lab_client, *ALICE)
    res = lab_client.get("/api/admin/users", headers=auth_header(alice_token))
    assert res.status_code == 200
    users = res.json()["users"]
    assert len(users) >= 3
    assert any("ssn" in u for u in users)


@pytest.mark.authz
@pytest.mark.security
def test_secure_admin_endpoint_forbidden_for_user(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/admin/users", headers=auth_header(alice_token))
    assert res.status_code == 403


@pytest.mark.authz
def test_secure_admin_endpoint_allowed_for_admin(secure_client):
    admin_token = login(secure_client, *ADMIN)
    res = secure_client.get("/api/admin/users", headers=auth_header(admin_token))
    assert res.status_code == 200
    assert_no_sensitive_fields(res.json())


@pytest.mark.authz
@pytest.mark.security
def test_lab_horizontal_write_idor_patch_order(lab_client):
    """Lab finding: alice can PATCH bob's order."""
    alice_token = login(lab_client, *ALICE)
    res = lab_client.patch(
        "/api/orders/201",
        headers=auth_header(alice_token),
        json={"notes": "hijacked by alice"},
    )
    assert res.status_code == 200
    assert res.json()["notes"] == "hijacked by alice"
    assert res.json()["owner_id"] == 2


@pytest.mark.authz
@pytest.mark.security
def test_secure_blocks_horizontal_write_idor_patch(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.patch(
        "/api/orders/201",
        headers=auth_header(alice_token),
        json={"notes": "should fail"},
    )
    assert res.status_code == 403


@pytest.mark.authz
def test_secure_owner_can_patch_own_order(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.patch(
        "/api/orders/101",
        headers=auth_header(alice_token),
        json={"notes": "alice update ok"},
    )
    assert res.status_code == 200
    assert res.json()["notes"] == "alice update ok"


@pytest.mark.authz
@pytest.mark.security
def test_lab_horizontal_write_idor_delete_order(lab_client):
    alice_token = login(lab_client, *ALICE)
    res = lab_client.delete("/api/orders/201", headers=auth_header(alice_token))
    assert res.status_code == 200
    assert res.json()["detail"] == "deleted"


@pytest.mark.authz
@pytest.mark.security
def test_secure_blocks_horizontal_delete_idor(secure_client):
    alice_token = login(secure_client, *ALICE)
    res = secure_client.delete("/api/orders/201", headers=auth_header(alice_token))
    assert res.status_code == 403
    # Order still exists for bob
    bob_token = login(secure_client, *BOB)
    check = secure_client.get("/api/orders/201", headers=auth_header(bob_token))
    assert check.status_code == 200


@pytest.mark.authz
def test_secure_admin_can_read_any_order(secure_client):
    admin_token = login(secure_client, *ADMIN)
    res = secure_client.get("/api/orders/201", headers=auth_header(admin_token))
    assert res.status_code == 200
    assert res.json()["owner_id"] == 2


@pytest.mark.authz
def test_secure_admin_can_patch_any_order(secure_client):
    admin_token = login(secure_client, *ADMIN)
    res = secure_client.patch(
        "/api/orders/201",
        headers=auth_header(admin_token),
        json={"status": "reviewed"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "reviewed"


@pytest.mark.authz
def test_admin_stats_requires_admin_even_in_lab(lab_client):
    alice_token = login(lab_client, *ALICE)
    res = lab_client.get("/api/admin/stats", headers=auth_header(alice_token))
    assert res.status_code == 403


@pytest.mark.authz
def test_admin_stats_ok_for_admin(secure_client):
    admin_token = login(secure_client, *ADMIN)
    res = secure_client.get("/api/admin/stats", headers=auth_header(admin_token))
    assert res.status_code == 200
    body = res.json()
    assert body["user_count"] >= 3
    assert body["order_count"] >= 3


@pytest.mark.authz
def test_secure_me_no_sensitive_fields(secure_client):
    token = login(secure_client, *ALICE)
    res = secure_client.get("/api/me", headers=auth_header(token))
    assert res.status_code == 200
    assert_no_sensitive_fields(res.json())


@pytest.mark.authz
def test_cross_tenant_order_not_listed_for_alice(secure_client):
    """Carol (org 20) order must not appear in alice (org 10) listing."""
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/orders", headers=auth_header(alice_token))
    ids = {o["id"] for o in res.json()["orders"]}
    assert 401 not in ids
    assert 101 in ids


@pytest.mark.authz
@pytest.mark.security
def test_secure_blocks_cross_tenant_order_read(secure_client):
    """Alice (org 10) cannot read carol's order 401 even with a valid token."""
    from tests.conftest import CAROL

    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/orders/401", headers=auth_header(alice_token))
    assert res.status_code == 403

    # Owner still has access — control is ownership, not "object missing".
    carol_token = login(secure_client, *CAROL)
    own = secure_client.get("/api/orders/401", headers=auth_header(carol_token))
    assert own.status_code == 200
    assert own.json()["owner_id"] == 4


@pytest.mark.authz
@pytest.mark.security
def test_secure_blocks_cross_tenant_order_write(secure_client):
    """Write-side authz also denies cross-tenant PATCH/DELETE."""
    alice_token = login(secure_client, *ALICE)
    patch = secure_client.patch(
        "/api/orders/401",
        headers=auth_header(alice_token),
        json={"notes": "should not stick"},
    )
    assert patch.status_code == 403

    delete = secure_client.delete("/api/orders/401", headers=auth_header(alice_token))
    assert delete.status_code == 403


@pytest.mark.authz
@pytest.mark.security
def test_secure_user_cannot_elevate_via_admin_listing(secure_client):
    """Vertical: non-admin listing must not return any user rows or secrets."""
    alice_token = login(secure_client, *ALICE)
    res = secure_client.get("/api/admin/users", headers=auth_header(alice_token))
    assert res.status_code == 403
    # Error body must not include user inventory either
    body = res.json()
    assert "users" not in body
    assert_no_sensitive_fields(body)