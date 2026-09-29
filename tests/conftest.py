from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from app.agent import TriageAgent
from app.config import Settings
from app.database import Database
from app.main import create_app
from app.vt_client import VirusTotalClient

TARGET_HASH = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"
FIXTURES = Path(__file__).resolve().parents[1] / "app" / "fixtures"


def make_settings(db_path: str, **overrides: Any) -> Settings:
    base: dict[str, Any] = dict(
        vt_api_key=None,
        vt_base_url="https://www.virustotal.com/api/v3",
        vt_timeout=5.0,
        vt_mock=True,
        llm_provider="none",
        llm_model="",
        llm_temperature=0.0,
        db_path=db_path,
        log_level="WARNING",
        vt_max_retries=0,
        vt_retry_backoff=0.0,
        rate_limit_per_min=0,
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(str(tmp_path / "test.db"))


@pytest.fixture
def db(settings: Settings) -> Database:
    return Database(settings.db_path)


@pytest.fixture
def vt_report() -> dict[str, Any]:
    return json.loads((FIXTURES / f"file_{TARGET_HASH}.json").read_text(encoding="utf-8"))


@pytest.fixture
def mb_report() -> dict[str, Any]:
    return json.loads((FIXTURES / f"mb_{TARGET_HASH}.json").read_text(encoding="utf-8"))


@pytest.fixture
def llm_json() -> str:
    return json.dumps(
        {
            "verdict": "malicious",
            "confidence": 82,
            "malware_family": "Phexia",
            "family_aliases": ["Phebot", "mac.c"],
            "platform": "macOS",
            "threat_category": "stealer/backdoor",
            "summary": "Stealer macOS com backdoor AppleScript e DDR via Telegram/Steam.",
            "key_findings": ["Rótulo VT trojan.phexia/phebot", "Sandbox classifica como STEALER"],
            "mitre_attack": [
                {"id": "T1102.001", "name": "Dead Drop Resolver", "tactic": "Command and Control"},
                {"id": "T1543.001", "name": "Launch Agent", "tactic": "Persistence"},
            ],
            "iocs": {"domains": ["kys.li"], "ips": [], "urls": []},
            "recommended_actions": ["Isolar host", "Revogar sessões"],
            "analyst_notes": None,
        }
    )


@pytest.fixture
def fake_llm_agent(llm_json: str) -> TriageAgent:
    return TriageAgent(llm=FakeListChatModel(responses=[llm_json] * 10), engine_label="llm:fake/test")


@pytest.fixture
def client(settings: Settings, db: Database) -> Iterator[TestClient]:
    app = create_app(settings=settings, db=db, vt=VirusTotalClient(settings), agent=TriageAgent(llm=None))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def llm_client(settings: Settings, db: Database, fake_llm_agent: TriageAgent) -> Iterator[TestClient]:
    app = create_app(settings=settings, db=db, vt=VirusTotalClient(settings), agent=fake_llm_agent)
    with TestClient(app) as c:
        yield c
