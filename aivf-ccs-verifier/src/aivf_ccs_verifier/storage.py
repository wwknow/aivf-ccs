from __future__ import annotations
import json, sqlite3, threading, time
from pathlib import Path
from typing import Any, Dict

class SQLiteStore:
    """Durable evidence, sequence, and replay state."""

    def __init__(self, path: str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init()

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA foreign_keys=ON")
        return con

    def _init(self):
        with self._connect() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO meta(key,value) VALUES('sequence',0);

            CREATE TABLE IF NOT EXISTS evidence (
                issuer TEXT NOT NULL,
                nonce TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                created_at REAL NOT NULL,
                receipt_json TEXT NOT NULL,
                PRIMARY KEY(issuer, nonce, status)
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_trace
                ON evidence(trace_id, created_at);

            CREATE TABLE IF NOT EXISTS consumed (
                issuer TEXT NOT NULL,
                nonce TEXT NOT NULL,
                consumed_at REAL NOT NULL,
                PRIMARY KEY(issuer, nonce)
            );
            """)

    def next_sequence(self) -> int:
        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT value FROM meta WHERE key='sequence'").fetchone()
            n = int(row[0]) + 1
            con.execute("UPDATE meta SET value=? WHERE key='sequence'", (n,))
            con.execute("COMMIT")
            return n

    def save_receipt(self, receipt: Dict[str, Any]) -> None:
        payload = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock, self._connect() as con:
            con.execute(
                """INSERT OR REPLACE INTO evidence
                   (issuer,nonce,trace_id,sequence,status,verdict,created_at,receipt_json)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (receipt["issuer"], receipt["nonce"], receipt["trace_id"],
                 int(receipt["sequence"]), receipt["receipt_status"],
                 receipt["verdict"], time.time(), payload),
            )

    def is_consumed(self, issuer: str, nonce: str) -> bool:
        with self._connect() as con:
            return con.execute(
                "SELECT 1 FROM consumed WHERE issuer=? AND nonce=?",
                (issuer, nonce),
            ).fetchone() is not None

    def mark_consumed(self, issuer: str, nonce: str) -> None:
        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            if con.execute(
                "SELECT 1 FROM consumed WHERE issuer=? AND nonce=?",
                (issuer, nonce),
            ).fetchone():
                con.execute("ROLLBACK")
                raise ValueError("receipt replay/consumed")
            con.execute(
                "INSERT INTO consumed(issuer,nonce,consumed_at) VALUES(?,?,?)",
                (issuer, nonce, time.time()),
            )
            con.execute("COMMIT")

    def latest_receipts(self, limit: int = 20):
        limit=max(1,min(int(limit),500))
        with self._connect() as con:
            rows=con.execute(
                "SELECT receipt_json FROM evidence ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def count_evidence(self) -> int:
        with self._connect() as con:
            return int(con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])
