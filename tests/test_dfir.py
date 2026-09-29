"""Testes do módulo DFIR (plano de coleta e scripts por SO)."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.cli as cli
from app.dfir import build_plan, render_script

from .conftest import TARGET_HASH

NETWORK_CMD = re.compile(r"^\s*(curl|wget|nc|ncat|scp|ssh|Invoke-WebRequest|Invoke-RestMethod|iwr|Start-BitsTransfer)\b", re.M)
DESTRUCTIVE = re.compile(r"^\s*(Remove-Item|Stop-Process|Set-ItemProperty|kill|pkill|launchctl (bootout|unload)|rm -rf /)\b", re.M)


@pytest.fixture
def scan(client: TestClient, db) -> dict[str, Any]:  # noqa: ANN001
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    return db.get_latest_scan(TARGET_HASH)


def test_plan_defaults_to_detected_os(scan: dict[str, Any]) -> None:
    p = build_plan(scan)
    assert p["os"] == "macos" == p["recommended_os"] and p["script"] == "triagem_macos.sh"
    assert "RFC 3227 (ordem de volatilidade)" in p["standards"]
    assert any(c["technique"].startswith("T1543") for c in p["technique_checks"])
    w = build_plan(scan, "windows")
    assert w["script"] == "triagem_windows.ps1" and "Get-CimInstance" in " ".join(c["command"] for c in w["technique_checks"])
    with pytest.raises(ValueError):
        build_plan(scan, "solaris")


@pytest.mark.parametrize("os_name", ["macos", "linux", "windows"])
def test_scripts_embed_iocs_and_are_safe(scan: dict[str, Any], os_name: str, tmp_path: Path) -> None:
    s = render_script(scan, os_name)
    assert "@@" not in s and TARGET_HASH in s and "nfs8u9aw.shop" in s and "phefuckxiabot" in s
    assert "MANIFESTO_SHA256" in s
    assert not NETWORK_CMD.search(s), "script não pode usar a rede"
    assert not DESTRUCTIVE.search(s), "script tem que ser somente leitura"
    f = tmp_path / ("t.ps1" if os_name == "windows" else "t.sh")
    f.write_text(s, encoding="utf-8")
    if os_name == "windows":
        assert s.startswith("﻿")  # BOM para o PowerShell 5.1
        if shutil.which("pwsh"):
            cmd = ("$e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile("
                   f"'{f}',[ref]$t,[ref]$e)|Out-Null;exit $e.Count")
            assert subprocess.run(["pwsh", "-NoProfile", "-Command", cmd], check=False).returncode == 0
    else:
        assert subprocess.run(["bash", "-n", str(f)], check=False).returncode == 0
        if shutil.which("shellcheck"):
            assert subprocess.run(["shellcheck", "-s", "bash", "-S", "warning", str(f)], check=False,
                                  env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}).returncode == 0


def test_script_rejects_injection_in_iocs(scan: dict[str, Any]) -> None:
    scan = dict(scan)
    scan["triage"] = {**scan["triage"], "malware_family": 'X"; rm -rf ~; echo "',
                      "iocs": {**scan["triage"]["iocs"], "domains": ['evil.com"; rm -rf /; "', "ok.com"]}}
    for os_name in ("macos", "linux", "windows"):
        s = render_script(scan, os_name)
        assert "rm -rf ~" not in s and "rm -rf /;" not in s and "ok.com" in s


def test_dfir_endpoints_and_incident_task(client: TestClient) -> None:
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    assert client.get(f"/api/v1/dfir/{TARGET_HASH}").json()["os"] == "macos"
    r = client.get(f"/api/v1/dfir/{TARGET_HASH}/script?os=linux")
    assert r.status_code == 200 and 'filename="triagem_linux.sh"' in r.headers["content-disposition"]
    assert client.get(f"/api/v1/dfir/{TARGET_HASH}?os=bsd").status_code == 422
    inc = client.post("/api/v1/incidents", json={"hash": TARGET_HASH}).json()
    assert any("triagem DFIR" in t["title"] for t in inc["tasks"])


def test_cli_dfir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    monkeypatch.setattr(cli, "_client", lambda: client)
    client.get(f"/api/v1/analyze/{TARGET_HASH}")
    out = tmp_path / "t.ps1"
    cli.main(["dfir", TARGET_HASH, "--os", "windows", "--out", str(out)])
    assert out.read_text(encoding="utf-8-sig").lstrip().startswith("<#")
