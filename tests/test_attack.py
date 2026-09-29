"""Testes de exportação/importação ATT&CK (Navigator + CSV)."""
from __future__ import annotations

import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from app.attack import AttackImportError, merge_techniques, parse_import, tactic_shortname

from .conftest import TARGET_HASH


def test_tactic_shortnames() -> None:
    assert tactic_shortname("Command and Control") == "command-and-control"
    assert tactic_shortname("credential-access") == "credential-access"
    assert tactic_shortname("inexistente") is None


def test_export_navigator_layer_and_csv(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    layer = client.get(f"/api/v1/attack/{TARGET_HASH}?format=navigator")
    assert layer.status_code == 200 and "attachment" in layer.headers["content-disposition"]
    data = layer.json()
    assert data["domain"] == "enterprise-attack" and data["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"] for t in data["techniques"]}
    assert {"T1543.001", "T1102.001"} <= ids
    assert all(t.get("tactic") for t in data["techniques"])
    rows = list(csv.DictReader(io.StringIO(client.get(f"/api/v1/attack/{TARGET_HASH}?format=csv").text)))
    assert {r["technique_id"] for r in rows} == ids


def test_roundtrip_navigator_import(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    layer = client.get(f"/api/v1/attack/{TARGET_HASH}?format=navigator").json()
    layer["techniques"].append({"techniqueID": "T1056.002", "tactic": "credential-access", "comment": "GUI Input Capture"})
    r = client.post(f"/api/v1/attack/{TARGET_HASH}/import?mode=replace", content=json.dumps(layer),
                    headers={"content-type": "application/json"})
    assert r.status_code == 200
    ids = {t["id"] for t in client.get(f"/api/v1/attack/{TARGET_HASH}").json()["techniques"]}
    assert "T1056.002" in ids and "T1543.001" in ids


def test_csv_import_merge_and_errors(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    body = "technique_id,technique_name,tactic\nT1486,Data Encrypted for Impact,Impact\nlixo,x,y\n"
    r = client.post(f"/api/v1/attack/{TARGET_HASH}/import", content=body, headers={"content-type": "text/csv"})
    assert r.status_code == 200 and r.json()["imported"] == 1
    assert "ATT&CK importado" in client.get(f"/api/v1/history/{TARGET_HASH}").json()["triage"]["analyst_notes"]
    bad = client.post(f"/api/v1/attack/{TARGET_HASH}/import", content="{\"x\":1}", headers={"content-type": "application/json"})
    assert bad.status_code == 422


def test_heatmap(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    h = client.get("/api/v1/attack/heatmap").json()
    assert h["scans"] == 1 and h["techniques"][0]["scans"] == 1
    layer = client.get("/api/v1/attack/heatmap?format=navigator").json()
    assert layer["gradient"]["maxValue"] == 1
    assert client.get("/api/v1/attack/heatmap?format=csv").text.startswith("technique_id,technique_name,tactic,scans")


def test_parse_import_rejects_other_domains() -> None:
    with pytest.raises(AttackImportError):
        parse_import(json.dumps({"domain": "ics-attack", "techniques": [{"techniqueID": "T0800"}]}))
    with pytest.raises(AttackImportError):
        parse_import("")


def test_merge_keeps_names() -> None:
    cur = [{"id": "T1059.002", "name": "AppleScript", "tactic": "Execution"}]
    out = merge_techniques(cur, [{"id": "T1059.002", "name": "", "tactic": "Execution"}], "merge")
    assert out == [{"id": "T1059.002", "name": "AppleScript", "tactic": "Execution"}]
