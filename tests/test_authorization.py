"""Authorization / IDOR and broken access control tests."""

from tests.conftest import auth_header, login


def test_lab_idor_user_profile(lab_client):
    """Lab finding: authenticated user can read another user's sensitive profile."""
    alice_token = login(lab_client, "alice", "password123")
    res = lab_client.get("/api/users/2", headers=auth_header(alice_token))
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == "bob"
    assert "ssn" in body
    assert "api_key" in body


def test_secure_blocks_idor_user_profile(secure_client):
    alice_token = login(secure_client, "alice", "password123")
    res = secure_client.get("/api/users/2", headers=auth_header(alice_token))
    assert res.status_code == 403


def test_secure_allows_self_profile(secure_client):
    alice_token = login(secure_client, "alice", "password123")
    res = secure_client.get("/api/users/1", headers=auth_header(alice_token))
    assert res.status_code == 200
    assert res.json()["username"] == "alice"
    assert "ssn" not in res.json()


def test_lab_idor_order_access(lab_client):
    """Lab finding: alice can read bob's order details."""
    alice_token = login(lab_client, "alice", "password123")
    res = lab_client.get("/api/orders/201", headers=auth_header(alice_token))
    assert res.status_code == 200
    body = res.json()
    assert body["owner_id"] == 2
    assert body["item"] == "Keyboard"


def test_secure_blocks_foreign_order(secure_client):
    alice_token = login(secure_client, "alice", "password123")
    res = secure_client.get("/api/orders/201", headers=auth_header(alice_token))
    assert res.status_code == 403


def test_secure_allows_own_order(secure_client):
    alice_token = login(secure_client, "alice", "password123")
    res = secure_client.get("/api/orders/101", headers=auth_header(alice_token))
    assert res.status_code == 200
    assert res.json()["owner_id"] == 1


def test_lab_list_orders_returns_all(lab_client):
    alice_token = login(lab_client, "alice", "password123")
    res = lab_client.get("/api/orders", headers=auth_header(alice_token))
    assert res.status_code == 200
    owners = {o["owner_id"] for o in res.json()["orders"]}
    assert owners == {1, 2, 3}


def test_secure_list_orders_scoped(secure_client):
    alice_token = login(secure_client, "alice", "password123")
    res = secure_client.get("/api/orders", headers=auth_header(alice_token))
    assert res.status_code == 200
    owners = {o["owner_id"] for o in res.json()["orders"]}
    assert owners == {1}


def test_lab_missing_admin_authorization(lab_client):
    """Lab finding: non-admin can call /api/admin/users."""
    alice_token = login(lab_client, "alice", "password123")
    res = lab_client.get("/api/admin/users", headers=auth_header(alice_token))
    assert res.status_code == 200
    users = res.json()["users"]
    assert len(users) >= 3
    assert any("ssn" in u for u in users)


def test_secure_admin_endpoint_forbidden_for_user(secure_client):
    alice_token = login(secure_client, "alice", "password123")
    res = secure_client.get("/api/admin/users", headers=auth_header(alice_token))
    assert res.status_code == 403


def test_secure_admin_endpoint_allowed_for_admin(secure_client):
    admin_token = login(secure_client, "admin", "admin")
    res = secure_client.get("/api/admin/users", headers=auth_header(admin_token))
    assert res.status_code == 200
    for user in res.json()["users"]:
        assert "ssn" not in user
        assert "api_key" not in user
