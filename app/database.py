"""Camada de persistência SQLite3 (scans, IoCs extraídos e log de requisições)."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hash             TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    source           TEXT NOT NULL,
    engine           TEXT NOT NULL,
    verdict          TEXT NOT NULL,
    malware_family   TEXT NOT NULL,
    confidence       INTEGER NOT NULL,
    heuristic_score  INTEGER NOT NULL,
    features_json    TEXT NOT NULL,
    triage_json      TEXT NOT NULL,
    raw_vt_json      TEXT NOT NULL,
    raw_mb_json      TEXT NOT NULL DEFAULT 'null'
);
CREATE INDEX IF NOT EXISTS idx_scans_hash ON scans(hash);

CREATE TABLE IF NOT EXISTS iocs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type     TEXT NOT NULL CHECK (type IN ('domain', 'ip', 'url')),
    value    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('baixa', 'media', 'alta', 'critica')),
    status          TEXT NOT NULL,
    scan_hash       TEXT,
    family          TEXT,
    owner           TEXT,
    hosts_json      TEXT NOT NULL DEFAULT '[]',
    summary         TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_tasks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    phase        TEXT NOT NULL,
    position     INTEGER NOT NULL,
    title        TEXT NOT NULL,
    detail       TEXT,
    status       TEXT NOT NULL DEFAULT 'pendente',
    owner        TEXT,
    updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ts           TEXT NOT NULL,
    author       TEXT,
    kind         TEXT NOT NULL,
    message      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_incident ON incident_tasks(incident_id);
CREATE INDEX IF NOT EXISTS idx_events_incident ON incident_events(incident_id);

CREATE TABLE IF NOT EXISTS request_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    status_code  INTEGER NOT NULL,
    duration_ms  REAL NOT NULL,
    client_ip    TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Wrapper fino sobre sqlite3. Uma conexão por operação => seguro entre threads."""

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Migrações leves e idempotentes para bancos criados por versões anteriores."""
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
        if "raw_mb_json" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN raw_mb_json TEXT NOT NULL DEFAULT 'null'")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------ scans
    def save_scan(
        self,
        *,
        file_hash: str,
        source: str,
        engine: str,
        heuristic_score: int,
        features: dict[str, Any],
        triage: dict[str, Any],
        raw_vt: dict[str, Any] | None,
        raw_mb: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO scans (hash, created_at, source, engine, verdict, malware_family,
                   confidence, heuristic_score, features_json, triage_json, raw_vt_json, raw_mb_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    file_hash.lower(),
                    created_at,
                    source,
                    engine,
                    triage.get("verdict", "unknown"),
                    triage.get("malware_family", "unknown"),
                    int(triage.get("confidence", 0)),
                    heuristic_score,
                    json.dumps(features, ensure_ascii=False),
                    json.dumps(triage, ensure_ascii=False),
                    json.dumps(raw_vt, ensure_ascii=False),
                    json.dumps(raw_mb, ensure_ascii=False),
                ),
            )
            scan_id = int(cur.lastrowid or 0)
            iocs = triage.get("iocs", {}) or {}
            rows = {
                (kind, str(v).strip().lower())
                for kind, key in (("domain", "domains"), ("domain", "abused_services"), ("ip", "ips"), ("url", "urls"))
                for v in iocs.get(key, []) or []
                if str(v).strip()
            }
            conn.executemany(
                "INSERT INTO iocs (scan_id, type, value) VALUES (?, ?, ?)",
                [(scan_id, kind, value) for kind, value in sorted(rows)],
            )
        return {"scan_id": scan_id, "created_at": created_at}

    def get_latest_scan(self, file_hash: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE hash = ? ORDER BY id DESC LIMIT 1",
                (file_hash.lower(),),
            ).fetchone()
        return self._full_row(row) if row else None

    def list_scans(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        verdict: str | None = None,
        family: str | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        where, params = [], []
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if family:
            where.append("LOWER(malware_family) LIKE ?")
            params.append(f"%{family.lower()}%")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM scans {clause}", params).fetchone()[0]
            rows = conn.execute(
                f"""SELECT id, hash, created_at, verdict, malware_family, confidence,
                           heuristic_score, source, engine
                    FROM scans {clause} ORDER BY id DESC LIMIT ? OFFSET ?""",
                [*params, limit, offset],
            ).fetchall()
        return int(total), [self._summary_row(r) for r in rows]

    def find_scans_by_ioc(self, value: str) -> list[dict[str, Any]]:
        v = value.strip().lower()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT DISTINCT s.id, s.hash, s.created_at, s.verdict, s.malware_family,
                          s.confidence, s.heuristic_score, s.source, s.engine
                   FROM iocs i JOIN scans s ON s.id = i.scan_id
                   WHERE i.value = ? OR i.value LIKE ?
                   ORDER BY s.id DESC""",
                (v, f"%{v}%"),
            ).fetchall()
        return [self._summary_row(r) for r in rows]

    def list_latest_full(self, verdict: str | None = None) -> list[dict[str, Any]]:
        """Último scan completo de cada hash (para heatmap ATT&CK)."""
        clause, params = ("AND verdict = ?", [verdict]) if verdict else ("", [])
        with self._conn() as conn:
            rows = conn.execute(
                f"""SELECT * FROM scans WHERE id IN (SELECT MAX(id) FROM scans GROUP BY hash) {clause}
                    ORDER BY id DESC""",
                params,
            ).fetchall()
        return [self._full_row(r) for r in rows]

    def update_triage(self, scan_id: int, triage: dict[str, Any]) -> None:
        """Atualiza a triagem de um scan (ex.: técnicas ATT&CK editadas/importadas pelo analista)."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET triage_json = ?, verdict = ?, malware_family = ?, confidence = ? WHERE id = ?",
                (json.dumps(triage, ensure_ascii=False), triage.get("verdict", "unknown"),
                 triage.get("malware_family", "unknown"), int(triage.get("confidence", 0)), scan_id),
            )

    # ------------------------------------------------------------- request log
    def log_request(
        self, method: str, path: str, status_code: int, duration_ms: float, client_ip: str | None
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO request_log (ts, method, path, status_code, duration_ms, client_ip)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (_now(), method, path, status_code, round(duration_ms, 2), client_ip),
            )

    def list_requests(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM request_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _summary_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "scan_id": row["id"],
            "hash": row["hash"],
            "created_at": row["created_at"],
            "verdict": row["verdict"],
            "malware_family": row["malware_family"],
            "confidence": row["confidence"],
            "heuristic_score": row["heuristic_score"],
            "source": row["source"],
            "engine": row["engine"],
        }

    @classmethod
    def _full_row(cls, row: sqlite3.Row) -> dict[str, Any]:
        data = cls._summary_row(row)
        data["features"] = json.loads(row["features_json"])
        data["triage"] = json.loads(row["triage_json"])
        return data
