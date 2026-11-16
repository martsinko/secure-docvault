import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from app.config import DB_PATH


@contextmanager
def connection():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()


def initialize() -> None:
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user',
          created_at TEXT NOT NULL,
          is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS revoked_tokens (
          jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
          id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, original_name TEXT NOT NULL,
          storage_name TEXT NOT NULL, content_type TEXT NOT NULL, signature BLOB,
          signer_public_key BLOB, created_at TEXT NOT NULL,
          FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        """)


def create_user(username: str, email: str, password_hash: str) -> int | None:
    try:
        with connection() as db:
            cursor = db.execute(
                "INSERT INTO users(username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(username: str):
    with connection() as db:
        return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def revoke_token(jti: str, expires_at: int) -> None:
    with connection() as db:
        db.execute("INSERT OR REPLACE INTO revoked_tokens(jti, expires_at) VALUES (?, ?)", (jti, expires_at))


def is_revoked(jti: str) -> bool:
    with connection() as db:
        db.execute("DELETE FROM revoked_tokens WHERE expires_at < strftime('%s','now')")
        return db.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone() is not None


def save_document(*values) -> None:
    with connection() as db:
        db.execute("""INSERT INTO documents(id,owner_id,original_name,storage_name,content_type,signature,signer_public_key,created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", values)


def get_document(document_id: str):
    with connection() as db:
        return db.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
