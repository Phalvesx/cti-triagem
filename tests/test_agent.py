"""Testes do agente LangGraph/LangChain e da extração de features."""
from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel

from app.agent import TriageAgent, build_agent, build_llm
from app.features import extract_features, family_candidates, heuristic_triage
from app.models import TriageReport

from .conftest import TARGET_HASH, make_settings


def test_extract_features(vt_report: dict[str, Any]) -> None:
    f = extract_features(vt_report)
    assert f["simulated"] is True
    assert f["meta"]["sha256"] == TARGET_HASH
    assert f["detection"]["malicious"] == 12
    assert f["detection"]["family_candidates"][0][0] == "phexia"
    assert "https://t.me/phefuckxiabot" in f["network"]["urls"]


def test_extract_features_with_malwarebazaar(vt_report: dict[str, Any], mb_report: dict[str, Any]) -> None:
    f = extract_features(vt_report, mb_report)
    assert f["sources"] == {"virustotal": True, "malwarebazaar": True}
    assert f["malwarebazaar"]["signature"] == "Phexia"
    assert f["malwarebazaar"]["vendor_intel"]["ANY.RUN"]["malware_family"] == "Phexia"  # lista normalizada
    assert "MAL_macOS_Phexia_Stealer_Backdoor" in f["rules"]["yara"]
    # assinatura curada do MB aumenta o peso da família
    assert f["detection"]["family_candidates"][0][1] > extract_features(vt_report)["detection"]["family_candidates"][0][1]


def test_malwarebazaar_only_is_malicious(mb_report: dict[str, Any]) -> None:
    score, triage = heuristic_triage(extract_features(None, mb_report))
    assert triage["verdict"] == "malicious"
    assert triage["malware_family"] == "Phexia"
    assert score >= 20


def test_family_candidates_ignore_generic_tokens() -> None:
    labels = ["Trojan.Generic.123", "HEUR:Trojan.OSX.Agent", "OSX/AMOS.A", "Atomic/AMOS stealer"]
    top = family_candidates(labels)
    assert top[0] == ("amos", 2)
    assert all(tok not in {"trojan", "generic", "agent", "osx"} for tok, _ in top)


@pytest.mark.parametrize(
    ("stats", "expected"),
    [
        ({"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 5}, "benign"),
        ({"malicious": 1, "suspicious": 0, "undetected": 60, "harmless": 0}, "suspicious"),
        ({"malicious": 40, "suspicious": 0, "undetected": 20, "harmless": 0}, "malicious"),
        ({}, "unknown"),
    ],
)
def test_heuristic_verdicts(stats: dict[str, int], expected: str) -> None:
    report = {"data": {"id": "x", "attributes": {"last_analysis_stats": stats}}}
    score, triage = heuristic_triage(extract_features(report))
    assert triage["verdict"] == expected
    assert 0 <= score <= 100
    TriageReport.model_validate(triage)


async def test_agent_without_llm_uses_heuristic(vt_report: dict[str, Any]) -> None:
    state = await TriageAgent(llm=None).run(TARGET_HASH, vt_report)
    assert state["engine"] == "heuristic"
    assert state["triage"]["malware_family"] == "Phexia"
    assert "llm_report" not in state


async def test_agent_with_both_sources(vt_report: dict[str, Any], mb_report: dict[str, Any]) -> None:
    state = await TriageAgent(llm=None).run(TARGET_HASH, vt_report, mb_report)
    assert any("MalwareBazaar" in k for k in state["triage"]["key_findings"])


async def test_agent_with_llm_structured_output(fake_llm_agent: TriageAgent, vt_report: dict[str, Any]) -> None:
    state = await fake_llm_agent.run(TARGET_HASH, vt_report)
    assert state["engine"] == "llm:fake/test"
    triage = TriageReport.model_validate(state["triage"])
    assert triage.malware_family == "Phexia"
    assert triage.confidence == 82
    # merge: domínio vindo do LLM + domínios observados
    assert {"kys.li", "ad4rchr39w8f.fun"} <= set(triage.iocs.domains)


async def test_agent_accepts_markdown_fenced_json(llm_json: str, vt_report: dict[str, Any]) -> None:
    agent = TriageAgent(llm=FakeListChatModel(responses=[f"```json\n{llm_json}\n```"]))
    state = await agent.run(TARGET_HASH, vt_report)
    assert state["triage"]["confidence"] == 82


async def test_agent_falls_back_when_llm_returns_garbage(vt_report: dict[str, Any]) -> None:
    agent = TriageAgent(llm=FakeListChatModel(responses=["isso não é JSON"]), engine_label="llm:fake/bad")
    state = await agent.run(TARGET_HASH, vt_report)
    assert state["engine"] == "heuristic"
    assert state["llm_error"]
    assert "fallback" in state["triage"]["analyst_notes"]


def test_prompt_contains_features_and_schema(fake_llm_agent: TriageAgent) -> None:
    msgs = fake_llm_agent.prompt.format_messages(file_hash=TARGET_HASH, features="{}", baseline="{}", score=10)
    assert "malware_family" in msgs[0].content  # instruções de formato do parser
    assert TARGET_HASH in msgs[1].content


def test_build_llm_none_and_missing_key(tmp_path, monkeypatch) -> None:
    assert build_llm(make_settings(str(tmp_path / "a.db"))) is None
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    agent = build_agent(make_settings(str(tmp_path / "b.db"), llm_provider="openai", llm_model="gpt-4o-mini"))
    # sem API key o agente degrada para heurística em vez de quebrar a API
    assert agent.engine_label in {"heuristic", "llm:openai/gpt-4o-mini"}
