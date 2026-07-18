"""Authentication security and functional tests."""

from tests.conftest import auth_header, login


def test_health_exposes_lab_mode(lab_client):
    res = lab_client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["lab_mode"] is True


def test_login_happy_path(lab_client):
    res = lab_client.post("/api/login", json={"username": "alice", "password": "password123"})
    assert res.status_code == 200
    body = res.json()
    assert "token" in body
    assert body["user"]["username"] == "alice"


def test_login_wrong_password(lab_client):
    res = lab_client.post("/api/login", json={"username": "alice", "password": "wrong"})
    assert res.status_code == 401


def test_login_unknown_user(lab_client):
    res = lab_client.post("/api/login", json={"username": "nobody", "password": "x"})
    assert res.status_code == 401


def test_lab_user_enumeration_via_distinct_errors(lab_client):
    """Lab finding: distinct error messages enable username enumeration."""
    missing = lab_client.post("/api/login", json={"username": "no-such-user", "password": "x"})
    wrong = lab_client.post("/api/login", json={"username": "alice", "password": "bad"})
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert missing.json()["detail"] != wrong.json()["detail"]
    assert "not found" in missing.json()["detail"].lower()
    assert "password" in wrong.json()["detail"].lower()


def test_secure_mode_no_user_enumeration(secure_client):
    missing = secure_client.post("/api/login", json={"username": "no-such-user", "password": "x"})
    wrong = secure_client.post("/api/login", json={"username": "alice", "password": "bad"})
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert missing.json()["detail"] == wrong.json()["detail"]


def test_lab_predictable_session_token(lab_client):
    """Lab finding: session token is predictable from username."""
    token = login(lab_client, "alice", "password123")
    assert token == "lab-token-alice"


def test_secure_mode_random_session_token(secure_client):
    token = login(secure_client, "alice", "password123")
    assert token != "lab-token-alice"
    assert len(token) >= 20


def test_me_requires_auth(lab_client):
    res = lab_client.get("/api/me")
    assert res.status_code == 401


def test_me_with_valid_token(lab_client):
    token = login(lab_client, "alice", "password123")
    res = lab_client.get("/api/me", headers=auth_header(token))
    assert res.status_code == 200
    assert res.json()["username"] == "alice"


def test_lab_login_leaks_sensitive_fields(lab_client):
    """Lab finding: login response exposes ssn/api_key."""
    res = lab_client.post("/api/login", json={"username": "alice", "password": "password123"})
    body = res.json()["user"]
    assert "ssn" in body
    assert "api_key" in body
    assert "password_sha256" in body


def test_secure_login_no_sensitive_fields(secure_client):
    res = secure_client.post("/api/login", json={"username": "alice", "password": "password123"})
    body = res.json()["user"]
    assert "ssn" not in body
    assert "api_key" not in body
    assert "password_sha256" not in body
