"""Input validation, injection boundaries, open redirect, and regression tests."""

from tests.conftest import auth_header, login


def test_lab_search_reflects_unsanitized_payload(lab_client):
    """Lab finding: search reflects unsanitized input."""
    token = login(lab_client, "alice", "password123")
    payload = "<script>alert(1)</script>"
    res = lab_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": payload},
    )
    assert res.status_code == 200
    body = res.json()
    assert payload in body["query"]
    assert payload in body["reflected"]


def test_secure_search_rejects_script_payload(secure_client):
    token = login(secure_client, "alice", "password123")
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "<script>alert(1)</script>"},
    )
    assert res.status_code == 400


def test_secure_search_rejects_sqli_ish_payload(secure_client):
    token = login(secure_client, "alice", "password123")
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "' OR '1'='1"},
    )
    assert res.status_code == 400


def test_secure_search_rejects_overlong_query(secure_client):
    token = login(secure_client, "alice", "password123")
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "a" * 101},
    )
    assert res.status_code == 400


def test_lab_search_accepts_overlong_query(lab_client):
    token = login(lab_client, "alice", "password123")
    res = lab_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "a" * 200},
    )
    assert res.status_code == 200


def test_lab_open_redirect(lab_client):
    """Lab finding: open redirect accepts external URL."""
    res = lab_client.get("/api/redirect", params={"next": "https://evil.example"}, follow_redirects=False)
    assert res.status_code in (302, 307)
    assert res.headers["location"] == "https://evil.example"


def test_secure_blocks_open_redirect(secure_client):
    res = secure_client.get(
        "/api/redirect",
        params={"next": "https://evil.example"},
        follow_redirects=False,
    )
    assert res.status_code == 400


def test_secure_allows_relative_redirect(secure_client):
    res = secure_client.get("/api/redirect", params={"next": "/health"}, follow_redirects=False)
    assert res.status_code in (302, 307)
    assert res.headers["location"] == "/health"


def test_lab_profile_update_accepts_invalid_email(lab_client):
    token = login(lab_client, "alice", "password123")
    res = lab_client.patch(
        "/api/me",
        headers=auth_header(token),
        json={"email": "not-an-email"},
    )
    assert res.status_code == 200
    assert res.json()["email"] == "not-an-email"


def test_secure_profile_update_rejects_invalid_email(secure_client):
    token = login(secure_client, "alice", "password123")
    res = secure_client.patch(
        "/api/me",
        headers=auth_header(token),
        json={"email": "not-an-email"},
    )
    assert res.status_code == 400


def test_unauthenticated_endpoints_blocked(lab_client):
    assert lab_client.get("/api/orders").status_code == 401
    assert lab_client.get("/api/users/1").status_code == 401
    assert lab_client.post("/api/search", json={"query": "x"}).status_code == 401
