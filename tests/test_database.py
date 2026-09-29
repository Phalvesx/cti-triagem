"""Testes da camada SQLite (inclui migração de bancos antigos)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from app.database import Database


def test_migrates_legacy_schema_without_mb_column(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT NOT NULL,
               created_at TEXT NOT NULL, source TEXT NOT NULL, engine TEXT NOT NULL, verdict TEXT NOT NULL,
               malware_family TEXT NOT NULL, confidence INTEGER NOT NULL, heuristic_score INTEGER NOT NULL,
               features_json TEXT NOT NULL, triage_json TEXT NOT NULL, raw_vt_json TEXT NOT NULL)"""
        )
    db = Database(str(path))
    saved = db.save_scan(
        file_hash="A" * 64, source="malwarebazaar", engine="heuristic", heuristic_score=20,
        features={}, triage={"verdict": "malicious", "malware_family": "X", "confidence": 50,
                             "iocs": {"domains": ["Evil.com"], "ips": [], "urls": []}},
        raw_vt=None, raw_mb={"query_status": "ok"},
    )
    assert saved["scan_id"] == 1
    assert db.find_scans_by_ioc("evil.com")[0]["hash"] == "a" * 64
