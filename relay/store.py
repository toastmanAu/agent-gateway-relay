"""
Thin SQLite store for the agent-gateway relay.

Tables
------
devices         – paired devices (token stored as sha256 hash, never plaintext)
intents         – push-intent queue (PK = sha256(token_id ‖ nonce), caller-supplied)
revocations     – revoked biscuit token_ids
advisory_ledger – non-binding spend records per token / asset
"""

import hashlib
import sqlite3
from typing import Optional


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    root_pub_hex     TEXT NOT NULL,
    device_token_hash TEXT NOT NULL UNIQUE,
    fcm_token        TEXT NOT NULL DEFAULT '',
    paired_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS intents (
    intent_id  TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL,
    token      TEXT NOT NULL,
    intent_json TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'queued',
    tx_hash    TEXT,
    error      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS revocations (
    token_id TEXT PRIMARY KEY,
    at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS advisory_ledger (
    token_id TEXT NOT NULL,
    asset    TEXT NOT NULL,
    amount   INTEGER NOT NULL,
    at       TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Store:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def pair_device(
        self,
        device_id: str,
        root_pub_hex: str,
        device_token_hash: str,
        fcm_token: str = "",
    ) -> None:
        """Register or update a paired device.

        ``device_token_hash`` must already be the sha256 hex digest of the
        plaintext device token — the store never sees the plaintext.
        """
        self._conn.execute(
            """
            INSERT INTO devices (device_id, root_pub_hex, device_token_hash, fcm_token)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                root_pub_hex      = excluded.root_pub_hex,
                device_token_hash = excluded.device_token_hash,
                fcm_token         = excluded.fcm_token
            """,
            (device_id, root_pub_hex, device_token_hash, fcm_token),
        )
        self._conn.commit()

    def device_by_token(self, device_token: str) -> Optional[sqlite3.Row]:
        """Look up a device by its plaintext token (hashed internally)."""
        token_hash = _hash_token(device_token)
        cur = self._conn.execute(
            "SELECT * FROM devices WHERE device_token_hash = ?",
            (token_hash,),
        )
        return cur.fetchone()

    def device_root_pub(self, device_id: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT root_pub_hex FROM devices WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        return row["root_pub_hex"] if row else None

    def device_fcm_token(self, device_id: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT fcm_token FROM devices WHERE device_id = ?",
            (device_id,),
        )
        row = cur.fetchone()
        return row["fcm_token"] if row else None

    # ------------------------------------------------------------------
    # Intents
    # ------------------------------------------------------------------

    def enqueue(
        self,
        intent_id: str,
        device_id: str,
        token: str,
        intent_json: str,
        source_ip: str,
    ) -> bool:
        """Insert a new intent.  Returns False if intent_id already exists."""
        try:
            self._conn.execute(
                """
                INSERT INTO intents
                    (intent_id, device_id, token, intent_json, source_ip, status)
                VALUES (?, ?, ?, ?, ?, 'queued')
                """,
                (intent_id, device_id, token, intent_json, source_ip),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def next_for_device(self, device_id: str) -> Optional[sqlite3.Row]:
        """Return the oldest queued intent for *device_id* and mark it in-flight.

        Uses a single atomic UPDATE … RETURNING statement (SQLite ≥3.35) to
        avoid the SELECT-then-UPDATE TOCTOU race that could hand the same
        intent to two concurrent WebSocket drains.
        """
        row = self._conn.execute(
            """
            UPDATE intents
               SET status = 'in-flight'
             WHERE intent_id = (
                   SELECT intent_id
                     FROM intents
                    WHERE device_id = ? AND status = 'queued'
                    ORDER BY created_at ASC
                    LIMIT 1
                   )
            RETURNING *
            """,
            (device_id,),
        ).fetchone()
        self._conn.commit()
        return row

    def get_intent(self, intent_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM intents WHERE intent_id = ?",
            (intent_id,),
        )
        return cur.fetchone()

    def set_result(
        self,
        intent_id: str,
        status: str,
        tx_hash: Optional[str],
        error: Optional[str],
    ) -> None:
        self._conn.execute(
            """
            UPDATE intents
            SET status = ?, tx_hash = ?, error = ?
            WHERE intent_id = ?
            """,
            (status, tx_hash, error, intent_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Revocations
    # ------------------------------------------------------------------

    def revoke(self, token_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO revocations (token_id) VALUES (?)",
            (token_id,),
        )
        self._conn.commit()

    def is_revoked(self, token_id: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM revocations WHERE token_id = ?",
            (token_id,),
        )
        return cur.fetchone() is not None

    # ------------------------------------------------------------------
    # Advisory ledger
    # ------------------------------------------------------------------

    def record_spend(self, token_id: str, asset: str, amount: int) -> None:
        self._conn.execute(
            "INSERT INTO advisory_ledger (token_id, asset, amount) VALUES (?, ?, ?)",
            (token_id, asset, amount),
        )
        self._conn.commit()

    def advisory_cumulative(self, token_id: str, asset: str) -> int:
        cur = self._conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM advisory_ledger WHERE token_id = ? AND asset = ?",
            (token_id, asset),
        )
        return cur.fetchone()[0]
