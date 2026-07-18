"""Input validation, redirect allow-list, search contracts, and negative auth gates."""

import pytest
from tests.conftest import ALICE, auth_header, login
from tests.helpers.contracts import assert_no_sensitive_fields


@pytest.mark.security
def test_lab_search_reflects_unsanitized_payload(lab_client):
    """Lab finding: search reflects unsanitized input in JSON."""
    token = login(lab_client, *ALICE)
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


@pytest.mark.security
def test_secure_search_enforces_max_length(secure_client):
    """Secure control is length limit + param SQL — not a regex SQLi blacklist."""
    token = login(secure_client, *ALICE)
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "a" * 101},
    )
    assert res.status_code == 400


@pytest.mark.security
def test_secure_search_accepts_normal_query(secure_client):
    token = login(secure_client, *ALICE)
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "Laptop"},
    )
    assert res.status_code == 200
    body = res.json()
    assert "reflected" not in body  # secure contract does not echo HTML-ish field
    assert body["count"] >= 1
    # Scoped to alice's orders
    for r in body["results"]:
        assert r["owner_id"] == 1


@pytest.mark.security
def test_secure_search_uses_parameterized_path_not_blacklist(secure_client):
    """SQLi-shaped strings are accepted as *data* (param SQL) — not rejected by regex theater."""
    token = login(secure_client, *ALICE)
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "' OR '1'='1"},
    )
    # Must not 500; returns 200 with zero or some results — never executes as SQL logic
    assert res.status_code == 200
    assert isinstance(res.json()["results"], list)


@pytest.mark.security
def test_secure_search_script_shaped_string_is_data_not_html_sink(secure_client):
    """No HTML sink: script-shaped input is just a search string (or empty hits)."""
    token = login(secure_client, *ALICE)
    res = secure_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "<script>alert(1)</script>"},
    )
    assert res.status_code == 200
    assert "reflected" not in res.json()


@pytest.mark.security
def test_lab_search_accepts_overlong_query(lab_client):
    token = login(lab_client, *ALICE)
    res = lab_client.post(
        "/api/search",
        headers=auth_header(token),
        json={"query": "a" * 200},
    )
    assert res.status_code == 200


@pytest.mark.security
def test_lab_open_redirect(lab_client):
    """Lab finding: open redirect accepts external URL."""
    res = lab_client.get("/api/redirect", params={"next": "https://evil.example"}, follow_redirects=False)
    assert res.status_code in (302, 307)
    assert res.headers["location"] == "https://evil.example"


@pytest.mark.security
def test_secure_blocks_open_redirect_external(secure_client):
    res = secure_client.get(
        "/api/redirect",
        params={"next": "https://evil.example"},
        follow_redirects=False,
    )
    assert res.status_code == 400


@pytest.mark.security
def test_secure_blocks_protocol_relative_redirect(secure_client):
    res = secure_client.get(
        "/api/redirect",
        params={"next": "//evil.example/phish"},
        follow_redirects=False,
    )
    assert res.status_code == 400


@pytest.mark.security
def test_secure_allows_allowlisted_redirect(secure_client):
    res = secure_client.get("/api/redirect", params={"next": "/health"}, follow_redirects=False)
    assert res.status_code in (302, 307)
    assert res.headers["location"] == "/health"


@pytest.mark.security
def test_secure_blocks_unknown_relative_path(secure_client):
    """Allow-list map: arbitrary relative paths not in the map are rejected."""
    res = secure_client.get(
        "/api/redirect",
        params={"next": "/not-in-allowlist"},
        follow_redirects=False,
    )
    assert res.status_code == 400


@pytest.mark.security
def test_lab_profile_update_accepts_invalid_email(lab_client):
    token = login(lab_client, *ALICE)
    res = lab_client.patch(
        "/api/me",
        headers=auth_header(token),
        json={"email": "not-an-email"},
    )
    assert res.status_code == 200
    assert res.json()["email"] == "not-an-email"


@pytest.mark.security
def test_secure_profile_update_rejects_invalid_email(secure_client):
    token = login(secure_client, *ALICE)
    res = secure_client.patch(
        "/api/me",
        headers=auth_header(token),
        json={"email": "not-an-email"},
    )
    assert res.status_code == 400


@pytest.mark.security
def test_secure_profile_update_accepts_valid_email(secure_client):
    token = login(secure_client, *ALICE)
    res = secure_client.patch(
        "/api/me",
        headers=auth_header(token),
        json={"email": "alice.new@example.local"},
    )
    assert res.status_code == 200
    assert res.json()["email"] == "alice.new@example.local"
    assert_no_sensitive_fields(res.json())


@pytest.mark.authn
def test_unauthenticated_endpoints_blocked(lab_client):
    assert lab_client.get("/api/orders").status_code == 401
    assert lab_client.get("/api/users/1").status_code == 401
    assert lab_client.post("/api/search", json={"query": "x"}).status_code == 401
    assert lab_client.patch("/api/orders/101", json={"notes": "x"}).status_code == 401
    assert lab_client.delete("/api/orders/101").status_code == 401
    assert lab_client.get("/api/admin/users").status_code == 401


@pytest.mark.smoke
def test_home_page(lab_client):
    res = lab_client.get("/")
    assert res.status_code == 200
    assert "Security QA Lab" in res.text
