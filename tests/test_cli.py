"""Testes da linha de comando (sem servidor)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.cli as cli
from app.agent import TriageAgent
from app.main import create_app

from .conftest import TARGET_HASH, make_settings


@pytest.fixture(autouse=True)
def _isolated_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = make_settings(str(tmp_path / "cli.db"))
    monkeypatch.setattr(cli, "_client", lambda: TestClient(create_app(settings=settings, agent=TriageAgent())))


def test_cli_full_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["analyze", TARGET_HASH, "--json", str(tmp_path / "a.json")])
    assert "Phexia" in capsys.readouterr().out
    assert json.loads((tmp_path / "a.json").read_text())["triage"]["verdict"] == "malicious"

    cli.main(["hunt", TARGET_HASH, "--siem", "wazuh", "--out", str(tmp_path / "h.md")])
    assert "<group name=" in (tmp_path / "h.md").read_text()

    cli.main(["attack", TARGET_HASH, "--navigator", str(tmp_path / "l.json")])
    assert json.loads((tmp_path / "l.json").read_text())["domain"] == "enterprise-attack"

    (tmp_path / "in.csv").write_text("technique_id,technique_name,tactic\nT1486,Data Encrypted for Impact,Impact\n")
    cli.main(["attack-import", TARGET_HASH, str(tmp_path / "in.csv")])
    cli.main(["incident", "open", TARGET_HASH, "--host", "mbp-01"])
    cli.main(["incident", "task", "1", "1", "--status", "concluida"])
    cli.main(["incident", "export", "1", "--md", str(tmp_path / "i.md")])
    assert "- [x] **Validar a triagem" in (tmp_path / "i.md").read_text()


def test_cli_error_exit() -> None:
    with pytest.raises(SystemExit):
        cli.main(["hunt", "a" * 64])
