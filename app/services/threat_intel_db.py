from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

from app.core.config import Config


def _db_path() -> Path:
    path = Path(Config.THREAT_INTEL_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def init_db() -> None:
    with sqlite3.connect(_db_path()) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_cache (
                provider TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(provider, indicator_type, indicator)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT,
                indicator_type TEXT,
                indicator TEXT,
                threat_score INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'Low',
                created_at INTEGER NOT NULL
            )
            """
        )
        con.commit()


def get_cached(provider: str, indicator_type: str, indicator: str, ttl_seconds: int) -> Optional[dict]:
    init_db()
    with sqlite3.connect(_db_path()) as con:
        row = con.execute(
            "SELECT response_json, created_at FROM threat_cache WHERE provider=? AND indicator_type=? AND indicator=?",
            (provider, indicator_type, indicator),
        ).fetchone()
    if not row:
        return None
    response_json, created_at = row
    if int(time.time()) - int(created_at) > ttl_seconds:
        return None
    try:
        return json.loads(response_json)
    except Exception:
        return None


def set_cached(provider: str, indicator_type: str, indicator: str, response: dict) -> None:
    init_db()
    with sqlite3.connect(_db_path()) as con:
        con.execute(
            """
            INSERT OR REPLACE INTO threat_cache(provider, indicator_type, indicator, response_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (provider, indicator_type, indicator, json.dumps(response, default=str), int(time.time())),
        )
        con.commit()


def save_ioc_history(source_name: str, correlated_iocs: list[dict[str, Any]]) -> None:
    init_db()
    with sqlite3.connect(_db_path()) as con:
        for item in correlated_iocs:
            con.execute(
                "INSERT INTO ioc_history(source_name, indicator_type, indicator, threat_score, severity, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (source_name, item.get("type"), item.get("indicator"), int(item.get("score", 0)), item.get("severity", "Low"), int(time.time())),
            )
        con.commit()
