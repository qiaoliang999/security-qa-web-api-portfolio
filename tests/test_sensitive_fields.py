"""Sensitive field contract tests — secure responses must never leak secrets/PII keys."""

import pytest
from tests.conftest import ALICE, ADMIN, auth_header, login
from tests.helpers.contracts import assert_no_sensitive_fields, find_forbidden_keys


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/api/me",
        "/api/users/1",
        "/api/orders",
        "/api/orders/101",
        "/api/admin/users",
        "/api/admin/stats",
    ],
)
def test_secure_endpoints_no_sensitive_keys(secure_client, path):
    token = login(secure_client, *ADMIN)
    res = secure_client.get(path, headers=auth_header(token))
    assert res.status_code == 200, res.text
    assert_no_sensitive_fields(res.json())


@pytest.mark.security
def test_secure_login_body_contract(secure_client):
    res = secure_client.post(
        "/api/login",
        json={"username": "alice", "password": "password123"},
    )
    assert res.status_code == 200
    assert_no_sensitive_fields(res.json())
    user_keys = set(res.json()["user"].keys())
    assert "ssn" not in user_keys
    assert "api_key" not in user_keys
    assert "password_hash" not in user_keys
    assert "password_sha256" not in user_keys


@pytest.mark.security
def test_lab_login_contains_sensitive_keys(lab_client):
    res = lab_client.post(
        "/api/login",
        json={"username": "alice", "password": "password123"},
    )
    leaked = find_forbidden_keys(res.json())
    assert any(k.endswith("ssn") or k == "ssn" or "ssn" in k for k in leaked)
    assert any("api_key" in k for k in leaked)


@pytest.mark.security
def test_secure_search_no_sensitive_keys(secure_client):
    token = login(secure_client, *ALICE)
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "Mouse"},
    )
    assert res.status_code == 200
    assert_no_sensitive_fields(res.json())


@pytest.mark.security
def test_secure_patch_order_no_sensitive_keys(secure_client):
    token = login(secure_client, *ALICE)
    res = secure_client.patch(
        "/api/orders/101",
        headers=auth_header(token),
        json={"notes": "contract check"},
    )
    assert res.status_code == 200
    assert_no_sensitive_fields(res.json())
