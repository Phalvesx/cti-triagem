"""Diagnóstico das chaves de API (app.healthcheck) e melhorias da heurística."""
from __future__ import annotations

import httpx

from app.features import _pretty_family, heuristic_triage
from app.healthcheck import check_mb, check_vt, mask, run_all
from tests.conftest import make_settings

VT_KEY = "a" * 64
MB_KEY = "b" * 48


def _vt_transport(status: int, body: dict) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path.endswith(f"/users/{VT_KEY}")
        assert req.headers["x-apikey"] == VT_KEY
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def test_mask() -> None:
    assert mask(None) == "—"
    assert mask(VT_KEY) == "aaaa…aaaa"


def test_vt_ok_reports_quota(tmp_path) -> None:
    s = make_settings(str(tmp_path / "db"), vt_api_key=VT_KEY, vt_mock=False)
    body = {"data": {"attributes": {"quotas": {"api_requests_daily": {"allowed": 500, "used": 3}}}}}
    r = check_vt(s, transport=_vt_transport(200, body))
    assert r["status"] == "ok" and "3/500" in r["detail"]


def test_vt_invalid_key(tmp_path) -> None:
    s = make_settings(str(tmp_path / "db"), vt_api_key=VT_KEY, vt_mock=False)
    r = check_vt(s, transport=_vt_transport(401, {"error": {"code": "WrongCredentialsError"}}))
    assert r["status"] == "invalid"


def test_vt_network_error(tmp_path) -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns", request=req)

    s = make_settings(str(tmp_path / "db"), vt_api_key=VT_KEY, vt_mock=False)
    r = check_vt(s, transport=httpx.MockTransport(boom))
    assert r["status"] == "error" and "internet" in r["detail"]


def test_vt_missing_key(tmp_path) -> None:
    s = make_settings(str(tmp_path / "db"), vt_api_key=None, vt_mock=False)
    assert check_vt(s)["status"] == "missing"


def test_mb_ok_and_invalid(tmp_path) -> None:
    s = make_settings(str(tmp_path / "db"), mb_api_key=MB_KEY)
    ok = httpx.MockTransport(lambda req: httpx.Response(200, json={"query_status": "hash_not_found"}))
    bad = httpx.MockTransport(lambda req: httpx.Response(200, json={"query_status": "unknown_auth_key"}))
    assert check_mb(s, transport=ok)["status"] == "ok"
    assert check_mb(s, transport=bad)["status"] == "invalid"


def test_run_all_offline(tmp_path) -> None:
    s = make_settings(str(tmp_path / "db"), vt_api_key=VT_KEY, mb_api_key=MB_KEY, vt_mock=False)
    res = {r["service"]: r["status"] for r in run_all(s, online=False)}
    assert res["VirusTotal"] == "ok" and res["MalwareBazaar"] == "ok"


def test_pretty_family() -> None:
    assert _pretty_family("agenttesla") == "AgentTesla"
    assert _pretty_family("qakbot", "QakBot") == "QakBot"
    assert _pretty_family("somethingnew") == "Somethingnew"


def _features(mal: int, total: int, type_desc: str = "Win32 EXE") -> dict:
    return {
        "detection": {"malicious": mal, "suspicious": 0, "analysed_engines": total, "ratio": f"{mal}/{total}",
                      "family_candidates": [("agenttesla", 8)] if mal else [], "labels_by_engine": {},
                      "popular_threat_categories": []},
        "sandbox": {}, "rules": {"yara": [], "sigma": []}, "malwarebazaar": {"found": False},
        "meta": {"tags": [], "type": type_desc, "type_tag": "peexe"},
        "network": {"domains": [], "ips": [], "urls": []},
    }


def test_benign_confidence_and_platform() -> None:
    _, rep = heuristic_triage(_features(0, 70))
    assert rep["verdict"] == "benign" and rep["confidence"] == 70
    assert rep["platform"] == "Windows"
    assert "nenhum indício" in rep["summary"]


def test_malicious_family_casing() -> None:
    _, rep = heuristic_triage(_features(40, 70))
    assert rep["malware_family"] == "AgentTesla"
