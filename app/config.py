"""Lab configuration.

LAB_MODE=true (default): intentional vulnerabilities for Security QA practice.
LAB_MODE=false: baseline secure controls for regression testing.
"""

import os


def lab_mode_enabled() -> bool:
    """Return True when the app should expose intentional lab flaws."""
    value = os.environ.get("LAB_MODE", "true").strip().lower()
    return value in {"1", "true", "yes", "on"}


# In-memory demo data only — no real secrets or PII.
DEMO_USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "password123",
        "role": "user",
        "email": "alice@example.local",
        "ssn": "111-22-3333",
        "api_key": "alice-secret-key-demo-only",
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "password123",
        "role": "user",
        "email": "bob@example.local",
        "ssn": "222-33-4444",
        "api_key": "bob-secret-key-demo-only",
    },
    3: {
        "id": 3,
        "username": "admin",
        "password": "admin",
        "role": "admin",
        "email": "admin@example.local",
        "ssn": "999-99-9999",
        "api_key": "admin-secret-key-demo-only",
    },
}

DEMO_ORDERS = {
    101: {"id": 101, "owner_id": 1, "item": "Laptop", "amount": 999.0, "notes": "Ship to Alice home"},
    102: {"id": 102, "owner_id": 1, "item": "Mouse", "amount": 29.0, "notes": "Gift wrap"},
    201: {"id": 201, "owner_id": 2, "item": "Keyboard", "amount": 79.0, "notes": "Bob office delivery"},
    301: {"id": 301, "owner_id": 3, "item": "Server", "amount": 4500.0, "notes": "Admin warehouse"},
}
