"""API keys for a self-hosted `secfoo serve` (#66).

`secfoo serve key create` issues a key that both runtime sensors and the
CLI (`secfoo cloud login --api-key <key> --portal-url <server>`) use, so a
project has one key and one view. Only a SHA-256 of the key is stored; the
plaintext is shown once and never logged.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

KEY_PREFIX = "sfk_"
SCOPES = ("all", "runtime")


@dataclass(frozen=True)
class ApiKey:
    id: int
    name: str
    key_prefix: str
    scope: str
    project_id: int | None
    created_at: str
    last_used_at: str | None
    revoked_at: str | None

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def can_access(self, project_id: int) -> bool:
        return self.active and (self.project_id is None or self.project_id == project_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _row(row) -> ApiKey:
    return ApiKey(*row)


_COLUMNS = "id, name, key_prefix, scope, project_id, created_at, last_used_at, revoked_at"


def create_key(conn: sqlite3.Connection, *, name: str, scope: str = "all", project_id: int | None = None) -> tuple[str, ApiKey]:
    """(plaintext key, record). The plaintext is not recoverable later."""
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
    if not name.strip():
        raise ValueError("a key needs a name")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    cur = conn.execute(
        "INSERT INTO runtime_api_keys (name, key_prefix, key_hash, scope, project_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (name.strip(), key[:10], hash_key(key), scope, project_id, _now()),
    )
    conn.commit()
    record = conn.execute(f"SELECT {_COLUMNS} FROM runtime_api_keys WHERE id = ?", (cur.lastrowid,)).fetchone()  # nosec B608
    return key, _row(record)


def list_keys(conn: sqlite3.Connection) -> list[ApiKey]:
    return [_row(r) for r in conn.execute(f"SELECT {_COLUMNS} FROM runtime_api_keys ORDER BY id").fetchall()]  # nosec B608


def revoke_key(conn: sqlite3.Connection, key_id: int) -> bool:
    cur = conn.execute(
        "UPDATE runtime_api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (_now(), key_id)
    )
    conn.commit()
    return cur.rowcount == 1


def verify_key(conn: sqlite3.Connection, key: str) -> ApiKey | None:
    """The active key record for `key`, or None (unknown or revoked)."""
    if not key or not key.startswith(KEY_PREFIX):
        return None
    row = conn.execute(
        f"SELECT {_COLUMNS} FROM runtime_api_keys WHERE key_hash = ?", (hash_key(key),)  # nosec B608
    ).fetchone()
    if row is None:
        return None
    record = _row(row)
    if not record.active:
        return None
    conn.execute("UPDATE runtime_api_keys SET last_used_at = ? WHERE id = ?", (_now(), record.id))
    conn.commit()
    return record
