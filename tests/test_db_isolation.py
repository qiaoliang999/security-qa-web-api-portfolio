"""DB isolation and password hashing unit/integration tests."""

import pytest
from tests.conftest import ALICE, auth_header, login


@pytest.mark.smoke
def test_db_reset_isolates_mutations(secure_client):
    """Mutations in one logical flow do not permanently poison seed for next client rebuild.

    Within a single fixture the DB is shared, but reset_database restores seed.
    """
    from app import db as db_mod

    token = login(secure_client, *ALICE)
    secure_client.patch(
        "/api/orders/101",
        headers=auth_header(token),
        json={"notes": "mutated-in-test"},
    )
    db_mod.reset_database()
    token2 = login(secure_client, *ALICE)
    res = secure_client.get("/api/orders/101", headers=auth_header(token2))
    assert res.status_code == 200
    assert res.json()["notes"] == "Ship to Alice home"


def test_password_hash_roundtrip():
    from app.security import hash_password, verify_password

    h = hash_password("password123")
    assert "$" in h
    assert verify_password("password123", h)
    assert not verify_password("wrong", h)
    assert h != hash_password("password123")  # unique salt


def test_seed_users_use_hashed_storage(secure_client):
    from app import db as db_mod

    with db_mod.get_connection() as conn:
        user = db_mod.get_user_by_username(conn, "alice")
        assert user is not None
        assert "password" not in user or user.get("password") is None
        assert user["password_hash"]
        assert "$" in user["password_hash"]
        assert user["password_hash"] != "password123"
