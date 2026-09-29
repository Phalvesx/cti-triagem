"""Testes dos endpoints da API."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app.agent import TriageAgent
from app.config import Settings
from app.database import Database
from app.main import classify_indicator, create_app, refang
from app.mb_client import MalwareBazaarClient, MBError
from app.vt_client import VirusTotalClient, VTNotFoundError, VTRateLimitError

from .conftest import TARGET_HASH


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["vt_source"] == "mock"
    assert r.json()["engine"] == "heuristic"
    assert r.json()["mb_source"] == "mock"


def test_index_is_served(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "Malware Triage" in r.text


def test_analyze_heuristic_and_persist(client: TestClient, db: Database) -> None:
    r = client.get(f"/api/v1/analyze/{TARGET_HASH}")
    assert r.status_code == 200
    body = r.json()
    assert body["cached"] is False
    assert body["source"] == "virustotal:mock+malwarebazaar:mock"
    assert body["source_errors"] == {}
    assert body["features"]["malwarebazaar"]["signature"] == "Phexia"
    assert body["triage"]["verdict"] == "malicious"
    assert body["triage"]["malware_family"] == "Phexia"
    assert "nfs8u9aw.shop" in body["triage"]["iocs"]["domains"]
    assert db.get_latest_scan(TARGET_HASH) is not None


def test_analyze_uses_cache_and_force(client: TestClient) -> None:
    first = client.get(f"/api/v1/analyze/{TARGET_HASH}").json()
    cached = client.get(f"/api/v1/analyze/{TARGET_HASH.upper()}").json()
    assert cached["cached"] is True and cached["scan_id"] == first["scan_id"]
    forced = client.get(f"/api/v1/analyze/{TARGET_HASH}?force=true").json()
    assert forced["cached"] is False and forced["scan_id"] != first["scan_id"]


def test_analyze_with_llm_agent(llm_client: TestClient) -> None:
    body = llm_client.get(f"/api/v1/analyze/{TARGET_HASH}").json()
    assert body["engine"] == "llm:fake/test"
    assert body["triage"]["confidence"] == 82
    assert {t["id"] for t in body["triage"]["mitre_attack"]} == {"T1102.001", "T1543.001"}
    # IoCs do LLM + IoCs observados pelo VT são mesclados
    assert {"kys.li", "nfs8u9aw.shop"} <= set(body["triage"]["iocs"]["domains"])


def test_analyze_invalid_hash_returns_422(client: TestClient) -> None:
    assert client.get("/api/v1/analyze/not-a-hash").status_code == 422
    assert client.get("/api/v1/analyze/" + "z" * 64).status_code == 422


def test_analyze_unknown_hash_returns_404(client: TestClient) -> None:
    r = client.get("/api/v1/analyze/" + "a" * 64)
    assert r.status_code == 404
    assert r.json()["source"] == "virustotal"


class RateLimitedVT(VirusTotalClient):
    async def get_file_report(self, file_hash: str) -> dict[str, Any]:
        raise VTRateLimitError("QuotaExceededError")


class NotFoundVT(VirusTotalClient):
    async def get_file_report(self, file_hash: str) -> dict[str, Any]:
        raise VTNotFoundError("NotFoundError")


class EmptyMB(MalwareBazaarClient):
    async def get_info(self, file_hash: str) -> dict[str, Any] | None:
        return None


class BrokenMB(MalwareBazaarClient):
    async def get_info(self, file_hash: str) -> dict[str, Any] | None:
        raise MBError("MalwareBazaar retornou HTTP 500")


def test_vt_rate_limit_degrades_to_malwarebazaar(settings: Settings, db: Database) -> None:
    app = create_app(settings=settings, db=db, vt=RateLimitedVT(settings), agent=TriageAgent())
    with TestClient(app) as c:
        body = c.get(f"/api/v1/analyze/{TARGET_HASH}").json()
    assert body["source"] == "malwarebazaar:mock"
    assert "QuotaExceeded" in body["source_errors"]["virustotal"]
    assert body["triage"]["verdict"] == "malicious"


def test_vt_rate_limit_propagates_when_no_other_source(settings: Settings, db: Database) -> None:
    app = create_app(settings=settings, db=db, vt=RateLimitedVT(settings), mb=EmptyMB(settings), agent=TriageAgent())
    with TestClient(app) as c:
        assert c.get(f"/api/v1/analyze/{TARGET_HASH}").status_code == 429


def test_hash_only_in_malwarebazaar(settings: Settings, db: Database) -> None:
    app = create_app(settings=settings, db=db, vt=NotFoundVT(settings), agent=TriageAgent())
    with TestClient(app) as c:
        body = c.get(f"/api/v1/analyze/{TARGET_HASH}").json()
    assert body["source_errors"] == {"virustotal": "not_found"}
    assert body["triage"]["malware_family"] == "Phexia"
    assert body["features"]["sources"] == {"virustotal": False, "malwarebazaar": True}


def test_malwarebazaar_failure_is_not_fatal(settings: Settings, db: Database) -> None:
    app = create_app(settings=settings, db=db, mb=BrokenMB(settings), agent=TriageAgent())
    with TestClient(app) as c:
        body = c.get(f"/api/v1/analyze/{TARGET_HASH}").json()
    assert body["source"] == "virustotal:mock"
    assert "HTTP 500" in body["source_errors"]["malwarebazaar"]


def test_report_html(client: TestClient) -> None:
    assert client.get(f"/api/v1/report/{TARGET_HASH}").status_code == 404
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    r = client.get(f"/api/v1/report/{TARGET_HASH}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "Phexia" in r.text and "SIMULADOS" in r.text
    assert "MalwareBazaar" in r.text and "ReversingLabs" in r.text


def test_history_and_filters(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    client.get(f"/api/v1/analyze/{TARGET_HASH}?force=true")
    h = client.get("/api/v1/history").json()
    assert h["total"] == 2 and len(h["items"]) == 2
    assert client.get("/api/v1/history?verdict=benign").json()["total"] == 0
    assert client.get("/api/v1/history?family=phex").json()["total"] == 2
    assert client.get("/api/v1/history?limit=1").json()["items"][0]["scan_id"] == h["items"][0]["scan_id"]
    assert client.get(f"/api/v1/history/{TARGET_HASH}").status_code == 200
    assert client.get("/api/v1/history/" + "b" * 64).status_code == 404


def test_search_domain_links_to_scans(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    r = client.get("/api/v1/search", params={"q": "nfs8u9aw[.]shop"})
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "domain" and body["query"] == "nfs8u9aw.shop"
    assert body["reputation"]["last_analysis_stats"]["malicious"] > 0
    assert body["related_scans"][0]["hash"] == TARGET_HASH


def test_search_ip_and_invalid(client: TestClient) -> None:
    r = client.get("/api/v1/search", params={"q": "8.8.8.8"})
    assert r.status_code == 200 and r.json()["type"] == "ip"
    assert client.get("/api/v1/search", params={"q": "not a domain!"}).status_code == 422


def test_request_log(client: TestClient) -> None:
    client.get("/api/v1/history")
    logs = client.get("/api/v1/requests").json()
    assert any(entry["path"] == "/api/v1/history" for entry in logs)


def test_helpers() -> None:
    assert refang("hxxps://evil[.]com/path") == "evil.com"
    assert classify_indicator("2001:db8::1") == "ip"
    assert classify_indicator("kys.li") == "domain"


def test_report_pdf_export(client: TestClient) -> None:
    assert client.get(f"/api/v1/report/{TARGET_HASH}/pdf").status_code == 404
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    r = client.get(f"/api/v1/report/{TARGET_HASH}/pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert 'filename="triagem_Phexia_7a8fc48ce4df.pdf"' in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")


def test_report_html_has_pdf_button_and_defanged_iocs(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    html = client.get(f"/api/v1/report/{TARGET_HASH}").text
    assert f"/api/v1/report/{TARGET_HASH}/pdf" in html
    assert "nfs8u9aw[.]shop" in html and "hxxps://t[.]me/phefuckxiabot" in html
    assert "TLP:AMBER" in html


def test_brand_logo_slot(settings: Settings, db: Database, tmp_path) -> None:
    from dataclasses import replace

    from app.report import Brand, render_report_html

    no_logo = replace(settings, brand_logo_path=str(tmp_path / "missing.png"))
    with TestClient(create_app(settings=no_logo, db=db, agent=TriageAgent())) as c:
        assert c.get("/api/v1/brand").json()["logo_url"] is None  # sem arquivo => emblema neutro

    logo = tmp_path / "logo.svg"
    logo.write_text("<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'/>")
    branded = replace(settings, brand_logo_path=str(logo), brand_name="Minha Empresa")
    with TestClient(create_app(settings=branded, db=db, agent=TriageAgent())) as c:
        info = c.get("/api/v1/brand").json()
        assert info == {"name": "Minha Empresa", "tlp": "TLP:AMBER", "logo_url": "/api/v1/brand/logo"}
        assert c.get("/api/v1/brand/logo").status_code == 200
        c.get(f"/api/v1/analyze/{TARGET_HASH}")
        scan = db.get_latest_scan(TARGET_HASH)
    html = render_report_html(scan, Brand(name="Minha Empresa", logo_path=str(logo)))  # type: ignore[arg-type]
    assert "data:image/svg+xml;base64," in html


def test_pdf_fallback_to_print_when_weasyprint_missing(client: TestClient, monkeypatch) -> None:
    import app.main as main_mod

    def boom(_: str) -> bytes:
        raise OSError("cannot load library 'libgobject-2.0-0'")

    monkeypatch.setattr(main_mod, "html_to_pdf", boom)
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    assert client.get(f"/api/v1/report/{TARGET_HASH}/pdf").status_code == 501
    r = client.get(f"/api/v1/report/{TARGET_HASH}/pdf?fallback=print")
    assert r.status_code == 200 and "window.print()" in r.text
