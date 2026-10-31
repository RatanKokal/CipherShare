from __future__ import annotations

import secrets
import sqlite3
import time
from pathlib import Path


class ShareStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.ciphertext_dir = self.data_dir / "ciphertext"
        self.ciphertext_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "ciphershare.sqlite3"
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS shares (
                    share_id TEXT PRIMARY KEY,
                    ciphertext_path TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    salt_b64 TEXT,
                    kdf_iterations INTEGER
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS shares_expires_at ON shares (expires_at)"
            )
            existing = {
                row["name"] for row in connection.execute("PRAGMA table_info(shares)")
            }
            if "salt_b64" not in existing:
                connection.execute("ALTER TABLE shares ADD COLUMN salt_b64 TEXT")
            if "kdf_iterations" not in existing:
                connection.execute(
                    "ALTER TABLE shares ADD COLUMN kdf_iterations INTEGER"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recipients (
                    share_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    token TEXT
                )
                """
            )
            recipient_existing = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(recipients)")
            }
            if "token" not in recipient_existing:
                connection.execute("ALTER TABLE recipients ADD COLUMN token TEXT")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS recipients_token ON recipients (token)"
            )

    def create_share(
        self,
        *,
        ciphertext: bytes,
        nonce_b64: str,
        filename: str,
        mime_type: str,
        lifetime_seconds: int,
        now: int | None = None,
        salt_b64: str | None = None,
        kdf_iterations: int | None = None,
    ) -> dict:
        share_id = secrets.token_urlsafe(24)
        created_at = int(time.time()) if now is None else int(now)
        expires_at = created_at + int(lifetime_seconds)
        stored_name = f"{share_id}.bin"
        target = self.ciphertext_dir / stored_name

        with open(target, "xb") as handle:
            handle.write(ciphertext)

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO shares (
                        share_id, ciphertext_path, nonce_b64, original_filename,
                        mime_type, created_at, expires_at, revoked,
                        salt_b64, kdf_iterations
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        share_id,
                        stored_name,
                        nonce_b64,
                        filename,
                        mime_type,
                        created_at,
                        expires_at,
                        salt_b64,
                        kdf_iterations,
                    ),
                )
        except Exception:
            target.unlink(missing_ok=True)
            raise

        return {
            "share_id": share_id,
            "expires_at": expires_at,
            "created_at": created_at,
        }

    def get_share(self, share_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM shares WHERE share_id = ?", (share_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def read_ciphertext(self, share: dict) -> bytes | None:
        target = (self.ciphertext_dir / share["ciphertext_path"]).resolve()
        if target.parent != self.ciphertext_dir.resolve():
            return None
        if not target.is_file():
            return None
        return target.read_bytes()

    def add_recipients(self, share_id: str, names: list[str]) -> list[dict]:
        created = []
        with self._connect() as connection:
            for name in names:
                label = secrets.token_urlsafe(6)
                token = secrets.token_urlsafe(16)
                connection.execute(
                    """
                    INSERT INTO recipients (share_id, label, display_name, created_at, token)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (share_id, label, name, int(time.time()), token),
                )
                created.append({"label": label, "name": name, "token": token})
        return created

    def get_recipients(self, share_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT share_id, label, display_name, token FROM recipients
                WHERE share_id = ?
                """,
                (share_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_all_recipients(self) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT share_id, label, display_name, token FROM recipients"
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_share(self, share_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE shares SET revoked = 1 WHERE share_id = ?", (share_id,)
            )
        return cursor.rowcount == 1
