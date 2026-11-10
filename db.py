"""Storage for activations: Postgres (e.g. Neon) when DATABASE_URL is set, otherwise SQLite.

Postgres keeps activations across restarts/redeploys without a disk — ideal for Render.
Each operation uses a short-lived connection, which suits Neon (it closes idle connections
and scales to zero) and its connection pooler.
"""
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

URL = os.environ.get("DATABASE_URL", "").strip()
IS_PG = URL.startswith(("postgres://", "postgresql://"))
_lock = threading.Lock()
_sqlite: sqlite3.Connection | None = None

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS activations (
        key_id TEXT PRIMARY KEY, machine_id TEXT NOT NULL, device_name TEXT, app_version TEXT,
        activated_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
        last_seen TEXT, activations INTEGER NOT NULL DEFAULT 1)""",
    """CREATE TABLE IF NOT EXISTS events (
        at TEXT, key_id TEXT, machine_id TEXT, ip TEXT, outcome TEXT)""",
]


class _Cursor:
    """Same API for both engines; SQL is written with '?' placeholders."""

    def __init__(self, cur):
        self._c = cur

    def execute(self, sql: str, params: tuple = ()):
        if IS_PG:
            # psycopg uses %s placeholders: escape literal % (e.g. LIKE 'TRV-%') first.
            sql = sql.replace("%", "%%").replace("?", "%s")
        self._c.execute(sql, params)
        return self

    def fetchone(self):
        return self._c.fetchone()

    def fetchall(self):
        return self._c.fetchall()

    @property
    def rowcount(self) -> int:
        return self._c.rowcount


@contextmanager
def tx():
    """One transaction: commits on success, rolls back on error."""
    if IS_PG:
        import psycopg
        # prepare_threshold=None: no server-side prepared statements (safe behind Neon's pooler).
        with psycopg.connect(URL, connect_timeout=20, prepare_threshold=None) as conn:
            with conn.cursor() as cur:
                yield _Cursor(cur)
        return
    with _lock:
        cur = _sqlite.cursor()
        try:
            yield _Cursor(cur)
            _sqlite.commit()
        except Exception:
            _sqlite.rollback()
            raise


def init(sqlite_path: str | None = None) -> str:
    """Connect and create tables. Returns a short description of the storage in use."""
    global _sqlite
    if not IS_PG:
        folder = Path(sqlite_path).resolve().parent
        if not folder.is_dir() or not os.access(folder, os.W_OK):
            if os.environ.get("TROVE_ALLOW_EPHEMERAL") == "1":
                folder.mkdir(parents=True, exist_ok=True)
            else:
                raise SystemExit(
                    f"No database: set DATABASE_URL (e.g. your Neon connection string) in the service's "
                    f"environment, or attach a persistent disk at {folder}. Without one, every restart "
                    "forgets which computer owns each key.")
        _sqlite = sqlite3.connect(sqlite_path, check_same_thread=False)
    with tx() as c:
        for stmt in SCHEMA:
            c.execute(stmt)
    if IS_PG:
        host = URL.split("@")[-1].split("/")[0]          # never log the password
        return f"Postgres at {host}"
    return f"SQLite at {sqlite_path}"
