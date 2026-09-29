"""Testes do gerador de hunts e dos endpoints de hunting."""
from __future__ import annotations

from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from app.hunting import SIEMS, build_context, build_hunt_pack, hunt_pack_markdown

from .conftest import TARGET_HASH


@pytest.fixture
def scan(client: TestClient, db) -> dict[str, Any]:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    return db.get_latest_scan(TARGET_HASH)


def test_context_separates_ddr_from_c2(scan: dict[str, Any]) -> None:
    c = build_context(scan)
    assert c.hashes == [TARGET_HASH]  # md5/sha1 "(simulado)" são descartados
    assert c.domains == ["ad4rchr39w8f.fun", "nfs8u9aw.shop"]
    assert "t.me" not in c.domains and "t.me" in c.abused_services
    assert c.ddr_needles == ["phefuckxia", "phefuckxiabot"]
    assert c.is_macos


def test_pack_has_all_hunts_and_siems(scan: dict[str, Any]) -> None:
    pack = build_hunt_pack(scan)
    assert [h["id"] for h in pack["hunts"]] == ["H1", "H2", "H3", "H4", "H5", "H6"]
    for h in pack["hunts"]:
        assert set(h["queries"]) == set(SIEMS), h["id"]
        assert all(q.strip() for q in h["queries"].values())
        # KQL/AQL não aceitam comentários: eles viram notas
        assert not any(ln.lstrip().startswith("--") for ln in h["queries"]["qradar"].splitlines())
        assert not any(ln.lstrip().startswith("//") for ln in h["queries"]["elastic"].splitlines()
                       if not h["queries"]["elastic"].startswith(("process", "file", "sequence")))


def test_sigma_rules_are_valid_yaml(scan: dict[str, Any]) -> None:
    for h in build_hunt_pack(scan, "sigma")["hunts"]:
        docs = list(yaml.safe_load_all(h["queries"]["sigma"]))
        assert all("title" in d for d in docs)
        assert all("detection" in d or "correlation" in d for d in docs)


def test_wazuh_rules_are_valid_xml(scan: dict[str, Any]) -> None:
    import xml.etree.ElementTree as ET

    for h in build_hunt_pack(scan, "wazuh")["hunts"]:
        ET.fromstring(f"<root>{h['queries']['wazuh']}</root>")


def test_filter_and_markdown(scan: dict[str, Any]) -> None:
    pack = build_hunt_pack(scan, "sentinel")
    assert all(list(h["queries"]) == ["sentinel"] for h in pack["hunts"])
    md = hunt_pack_markdown(pack)
    assert "```kql" in md and "## H6" in md
    with pytest.raises(ValueError):
        build_hunt_pack(scan, "arcsight")


def test_non_mac_benign_gets_only_ioc_hunts() -> None:
    scan = {"hash": "b" * 64, "features": {"meta": {}},
            "triage": {"verdict": "benign", "malware_family": "unknown", "platform": "Windows",
                       "iocs": {"domains": [], "ips": [], "urls": []}, "mitre_attack": []}}
    assert [h["id"] for h in build_hunt_pack(scan)["hunts"]] == ["H1"]


def test_hunt_endpoints(client: TestClient) -> None:
    assert client.get(f"/api/v1/hunt/{TARGET_HASH}").status_code == 404
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    r = client.get(f"/api/v1/hunt/{TARGET_HASH}?siem=splunk")
    assert r.status_code == 200 and list(r.json()["siems"]) == ["splunk"]
    md = client.get(f"/api/v1/hunt/{TARGET_HASH}?format=markdown")
    assert md.headers["content-type"].startswith("text/markdown") and "Google SecOps" in md.text
    assert client.get(f"/api/v1/hunt/{TARGET_HASH}?siem=arcsight").status_code == 422
    html = client.get(f"/api/v1/report/{TARGET_HASH}?siem=elastic").text
    assert "Apêndice — Threat Hunting" in html and "sequence by host.id" in html
    assert "Apêndice" not in client.get(f"/api/v1/report/{TARGET_HASH}?siem=none").text
