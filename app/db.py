"""SQLite persistence with seed data and isolation helpers for tests.

Uses the stdlib sqlite3 module (no ORM dependency). Connection is scoped per
request via FastAPI dependency, and tests recreate the schema + seed on each
fixture to avoid global mutable demo state leakage.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Iterable, Optional
from urllib.parse import urlparse

from app.config import SEED_ORDERS, SEED_USERS, database_url
from app.security import hash_password

# Module-level override used by tests (file path or ":memory:" / "file:...").
_DB_PATH_OVERRIDE: Optional[str] = None

# Keep :memory: shared across connections in the same process when selected.
_MEMORY_URI = "file:security_qa_lab_mem?mode=memory&cache=shared"
_memory_anchor: Optional[sqlite3.Connection] = None


def set_db_path(path: Optional[str]) -> None:
    """Override DB path for the current process (tests). Pass None to reset."""
    global _DB_PATH_OVERRIDE, _memory_anchor
    _DB_PATH_OVERRIDE = path
    if _memory_anchor is not None:
        try:
            _memory_anchor.close()
        except Exception:  # noqa: BLE001
            pass
        _memory_anchor = None


def _resolve_path() -> str:
    if _DB_PATH_OVERRIDE is not None:
        return _DB_PATH_OVERRIDE
    url = database_url()
    if url == "sqlite:///:memory:" or url.endswith(":memory:"):
        return _MEMORY_URI
    if url.startswith("sqlite:///"):
        return url[len("sqlite:///") :]
    parsed = urlparse(url)
    if parsed.scheme == "sqlite":
        return parsed.path.lstrip("/") or ":memory:"
    return url


def connect() -> sqlite3.Connection:
    path = _resolve_path()
    global _memory_anchor
    if path == _MEMORY_URI or path.startswith("file:"):
        if _memory_anchor is None:
            _memory_anchor = sqlite3.connect(path, uri=True, check_same_thread=False)
        conn = sqlite3.connect(path, uri=True, check_same_thread=False)
    elif path == ":memory:":
        conn = sqlite3.connect(":memory:", check_same_thread=False)
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            ssn TEXT NOT NULL,
            api_key TEXT NOT NULL,
            org_id INTEGER NOT NULL,
            bio TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            org_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            amount REAL NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )


def seed_data(conn: sqlite3.Connection) -> None:
    """Insert seed users/orders. Password is hashed; plaintext never stored."""
    for user in SEED_USERS:
        conn.execute(
            """
            INSERT OR REPLACE INTO users
            (id, username, password_hash, role, email, ssn, api_key, org_id, bio)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                user["username"],
                hash_password(user["password"]),
                user["role"],
                user["email"],
                user["ssn"],
                user["api_key"],
                user["org_id"],
                user.get("bio", ""),
            ),
        )
    for order in SEED_ORDERS:
        conn.execute(
            """
            INSERT OR REPLACE INTO orders
            (id, owner_id, org_id, item, amount, notes, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order["id"],
                order["owner_id"],
                order["org_id"],
                order["item"],
                order["amount"],
                order["notes"],
                order["status"],
            ),
        )


def reset_database() -> None:
    """Drop, recreate, and reseed — primary isolation primitive for tests."""
    with get_connection() as conn:
        conn.executescript(
            """
            DROP TABLE IF EXISTS sessions;
            DROP TABLE IF EXISTS orders;
            DROP TABLE IF EXISTS users;
            """
        )
        init_schema(conn)
        seed_data(conn)


def ensure_database() -> None:
    """Idempotent init used at app startup."""
    with get_connection() as conn:
        init_schema(conn)
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        if row and row["c"] == 0:
            seed_data(conn)


def row_to_dict(row: Optional[sqlite3.Row]) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [{k: r[k] for k in r.keys()} for r in rows]


# ---- query helpers ---------------------------------------------------------


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return row_to_dict(row)


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return row_to_dict(row)


def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    return rows_to_dicts(rows)


def update_user_email(conn: sqlite3.Connection, user_id: int, email: str) -> Optional[dict[str, Any]]:
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
    return get_user_by_id(conn, user_id)


def update_user_bio(conn: sqlite3.Connection, user_id: int, bio: str) -> Optional[dict[str, Any]]:
    conn.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
    return get_user_by_id(conn, user_id)


def get_order_by_id(conn: sqlite3.Connection, order_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return row_to_dict(row)


def list_orders(
    conn: sqlite3.Connection,
    *,
    owner_id: Optional[int] = None,
    org_id: Optional[int] = None,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM orders WHERE 1=1"
    params: list[Any] = []
    if owner_id is not None:
        sql += " AND owner_id = ?"
        params.append(owner_id)
    if org_id is not None:
        sql += " AND org_id = ?"
        params.append(org_id)
    sql += " ORDER BY id"
    return rows_to_dicts(conn.execute(sql, params).fetchall())


def update_order(
    conn: sqlite3.Connection,
    order_id: int,
    *,
    item: Optional[str] = None,
    amount: Optional[float] = None,
    notes: Optional[str] = None,
    status: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    order = get_order_by_id(conn, order_id)
    if not order:
        return None
    new_item = item if item is not None else order["item"]
    new_amount = amount if amount is not None else order["amount"]
    new_notes = notes if notes is not None else order["notes"]
    new_status = status if status is not None else order["status"]
    conn.execute(
        """
        UPDATE orders SET item = ?, amount = ?, notes = ?, status = ?
        WHERE id = ?
        """,
        (new_item, new_amount, new_notes, new_status, order_id),
    )
    return get_order_by_id(conn, order_id)


def delete_order(conn: sqlite3.Connection, order_id: int) -> bool:
    cur = conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    return cur.rowcount > 0


def search_orders(conn: sqlite3.Connection, query: str) -> list[dict[str, Any]]:
    """Parameterized LIKE search — never concatenate untrusted input into SQL."""
    pattern = f"%{query.lower()}%"
    rows = conn.execute(
        """
        SELECT * FROM orders
        WHERE lower(item) LIKE ? OR lower(notes) LIKE ?
        ORDER BY id
        """,
        (pattern, pattern),
    ).fetchall()
    return rows_to_dicts(rows)


def create_session(conn: sqlite3.Connection, token: str, user_id: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO sessions (token, user_id) VALUES (?, ?)",
        (token, user_id),
    )


def get_user_by_token(conn: sqlite3.Connection, token: str) -> Optional[dict[str, Any]]:
    row = conn.execute(
        """
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = ?
        """,
        (token,),
    ).fetchone()
    return row_to_dict(row)


def clear_sessions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions")


def count_sessions(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()
    return int(row["c"]) if row else 0
