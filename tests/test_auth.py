"""Authentication security and functional tests."""

import pytest
from tests.conftest import ALICE, ADMIN, BOB, auth_header, login
from tests.helpers.contracts import assert_no_sensitive_fields


@pytest.mark.smoke
def test_health_exposes_lab_mode(lab_client):
    res = lab_client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["lab_mode"] is True


@pytest.mark.smoke
def test_health_secure_mode(secure_client):
    res = secure_client.get("/health")
    assert res.status_code == 200
    assert res.json()["lab_mode"] is False


@pytest.mark.authn
@pytest.mark.smoke
def test_login_happy_path(lab_client):
    res = lab_client.post("/api/login", json={"username": "alice", "password": "password123"})
    assert res.status_code == 200
    body = res.json()
    assert "token" in body
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "user"


@pytest.mark.authn
def test_login_wrong_password(lab_client):
    res = lab_client.post("/api/login", json={"username": "alice", "password": "wrong"})
    assert res.status_code == 401


@pytest.mark.authn
def test_login_unknown_user(lab_client):
    res = lab_client.post("/api/login", json={"username": "nobody", "password": "x"})
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_lab_user_enumeration_via_distinct_errors(lab_client):
    """Lab finding: distinct error messages enable username enumeration."""
    missing = lab_client.post("/api/login", json={"username": "no-such-user", "password": "x"})
    wrong = lab_client.post("/api/login", json={"username": "alice", "password": "bad"})
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert missing.json()["detail"] != wrong.json()["detail"]
    assert "not found" in missing.json()["detail"].lower()
    assert "password" in wrong.json()["detail"].lower()


@pytest.mark.authn
@pytest.mark.security
def test_secure_mode_no_user_enumeration(secure_client):
    missing = secure_client.post("/api/login", json={"username": "no-such-user", "password": "x"})
    wrong = secure_client.post("/api/login", json={"username": "alice", "password": "bad"})
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert missing.json()["detail"] == wrong.json()["detail"]
    assert missing.json()["detail"] == "Invalid username or password"


@pytest.mark.authn
@pytest.mark.security
def test_lab_predictable_session_token(lab_client):
    """Lab finding: session token is predictable from username."""
    token = login(lab_client, *ALICE)
    assert token == "lab-token-alice"


@pytest.mark.authn
@pytest.mark.security
def test_secure_mode_random_session_token(secure_client):
    token = login(secure_client, *ALICE)
    assert token != "lab-token-alice"
    assert len(token) >= 20


@pytest.mark.authn
def test_me_requires_auth(lab_client):
    res = lab_client.get("/api/me")
    assert res.status_code == 401


@pytest.mark.authn
def test_me_with_valid_token(lab_client):
    token = login(lab_client, *ALICE)
    res = lab_client.get("/api/me", headers=auth_header(token))
    assert res.status_code == 200
    assert res.json()["username"] == "alice"


@pytest.mark.authn
@pytest.mark.security
def test_lab_login_leaks_sensitive_fields(lab_client):
    """Lab finding: login response exposes ssn/api_key/password material."""
    res = lab_client.post("/api/login", json={"username": "alice", "password": "password123"})
    body = res.json()["user"]
    assert "ssn" in body
    assert "api_key" in body
    assert "password_sha256" in body


@pytest.mark.authn
@pytest.mark.security
def test_secure_login_no_sensitive_fields(secure_client):
    res = secure_client.post("/api/login", json={"username": "alice", "password": "password123"})
    body = res.json()
    assert_no_sensitive_fields(body)
    user = body["user"]
    assert set(user.keys()) >= {"id", "username", "role", "email", "org_id"}


@pytest.mark.authn
@pytest.mark.security
def test_token_abuse_missing_bearer(secure_client):
    res = secure_client.get("/api/me")
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_token_abuse_wrong_token(secure_client):
    res = secure_client.get("/api/me", headers=auth_header("totally-not-a-real-token"))
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_token_abuse_forged_lab_style_token_in_secure(secure_client):
    """Predictable lab token format must not work in secure mode."""
    res = secure_client.get("/api/me", headers=auth_header("lab-token-alice"))
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_token_abuse_empty_bearer(secure_client):
    res = secure_client.get("/api/me", headers={"Authorization": "Bearer "})
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_token_abuse_malformed_header(secure_client):
    res = secure_client.get("/api/me", headers={"Authorization": "Token abc"})
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_token_abuse_bearer_case_insensitive_prefix(secure_client):
    """Prefix matching is case-insensitive, but a random body still must fail."""
    res = secure_client.get("/api/me", headers={"Authorization": "bearer not-a-real-token"})
    assert res.status_code == 401


@pytest.mark.authn
@pytest.mark.security
def test_token_from_other_session_does_not_cross_users(secure_client):
    """Alice's token must not resolve to bob's profile via /api/me."""
    alice_token = login(secure_client, *ALICE)
    bob_token = login(secure_client, *BOB)
    assert alice_token != bob_token

    alice_me = secure_client.get("/api/me", headers=auth_header(alice_token))
    bob_me = secure_client.get("/api/me", headers=auth_header(bob_token))
    assert alice_me.status_code == 200
    assert bob_me.status_code == 200
    assert alice_me.json()["username"] == "alice"
    assert bob_me.json()["username"] == "bob"
    assert alice_me.json()["id"] != bob_me.json()["id"]


@pytest.mark.authn
@pytest.mark.security
def test_token_reuse_after_db_session_clear_fails(secure_client):
    """Clearing the sessions table invalidates previously issued tokens."""
    from app import db as db_mod

    token = login(secure_client, *ALICE)
    assert secure_client.get("/api/me", headers=auth_header(token)).status_code == 200

    with db_mod.get_connection() as conn:
        db_mod.clear_sessions(conn)

    res = secure_client.get("/api/me", headers=auth_header(token))
    assert res.status_code == 401


@pytest.mark.authn
def test_admin_login(secure_client):
    token = login(secure_client, *ADMIN)
    res = secure_client.get("/api/me", headers=auth_header(token))
    assert res.status_code == 200
    assert res.json()["role"] == "admin"


@pytest.mark.authn
def test_password_is_hashed_not_plaintext(secure_client):
    """Stored credential verification works; login does not echo password."""
    res = secure_client.post("/api/login", json={"username": "alice", "password": "password123"})
    assert res.status_code == 200
    dumped = res.text.lower()
    assert "password123" not in dumped
    assert "password_hash" not in dumped
