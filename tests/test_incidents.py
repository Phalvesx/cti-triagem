"""Testes do módulo de resposta a incidentes."""
from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import TARGET_HASH


def _open(client: TestClient, **extra) -> dict:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    r = client.post("/api/v1/incidents", json={"hash": TARGET_HASH, "owner": "phillipe", **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_create_builds_nist_playbook(client: TestClient) -> None:
    inc = _open(client, hosts=["mbp-dev-01"])
    assert inc["status"] == "aberto" and inc["severity"] == "critica"  # malicioso + host confirmado
    phases = [p["phase"] for p in inc["phases"] if p["total"]]
    assert phases == ["Detecção e Análise", "Contenção", "Erradicação", "Recuperação", "Pós-incidente"]
    titles = " ".join(t["title"] for t in inc["tasks"])
    assert "Executar hunt H1" in titles and "Revogar sessões" in titles and "Remover persistência" in titles
    assert "URLs específicas do Dead Drop Resolver" in titles
    assert inc["events"][0]["kind"] == "criacao"


def test_task_status_progress_and_timeline(client: TestClient) -> None:
    inc = _open(client)
    tid = inc["tasks"][0]["id"]
    r = client.patch(f"/api/v1/incidents/{inc['id']}/tasks/{tid}", json={"status": "concluida", "note": "ok", "author": "ana"})
    assert r.status_code == 200
    body = r.json()
    assert body["tasks_done"] == 1 and body["progress"] > 0
    assert body["events"][-1]["author"] == "ana" and "concluida" in body["events"][-1]["message"]
    assert client.patch(f"/api/v1/incidents/{inc['id']}/tasks/99999", json={"status": "concluida"}).status_code == 404
    assert client.patch(f"/api/v1/incidents/{inc['id']}/tasks/{tid}", json={"status": "feito"}).status_code == 422


def test_update_incident_and_notes(client: TestClient) -> None:
    inc = _open(client)
    r = client.patch(f"/api/v1/incidents/{inc['id']}", json={"status": "contido", "hosts": ["a", "b"], "author": "ana"})
    assert r.json()["status"] == "contido" and r.json()["hosts"] == ["a", "b"]
    r = client.post(f"/api/v1/incidents/{inc['id']}/events", json={"message": "Host isolado às 10h", "author": "ana"})
    assert r.json()["events"][-1]["message"] == "Host isolado às 10h"
    listed = client.get("/api/v1/incidents").json()
    assert listed[0]["id"] == inc["id"] and listed[0]["status"] == "contido"
    assert client.get("/api/v1/incidents?status=encerrado").json() == []
    assert client.get("/api/v1/incidents/999").status_code == 404


def test_exports(client: TestClient) -> None:
    inc = _open(client)
    md = client.get(f"/api/v1/incidents/{inc['id']}/export?format=markdown")
    assert md.status_code == 200 and "## Contenção" in md.text and "- [ ]" in md.text
    assert "Linha do tempo" in client.get(f"/api/v1/incidents/{inc['id']}/export?format=html").text
    pdf = client.get(f"/api/v1/incidents/{inc['id']}/export?format=pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_create_requires_analyzed_hash(client: TestClient) -> None:
    assert client.post("/api/v1/incidents", json={"hash": "c" * 64}).status_code == 404
    assert client.post("/api/v1/incidents", json={"hash": "xyz"}).status_code == 422
