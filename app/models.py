"""Modelos Pydantic (contratos da API e saída estruturada do agente)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["malicious", "suspicious", "benign", "unknown"]


class AttackTechnique(BaseModel):
    id: str = Field(description="ID MITRE ATT&CK, ex.: T1059.002")
    name: str
    tactic: str | None = None


class TriageIOCs(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    abused_services: list[str] = Field(
        default_factory=list,
        description="Domínios de serviços legítimos abusados (ex.: DDR em t.me/Steam) — monitorar, não bloquear inteiro",
    )


class TriageReport(BaseModel):
    """Saída estruturada que o LLM deve produzir."""

    verdict: Verdict
    confidence: int = Field(ge=0, le=100, description="Confiança 0-100 no veredito/atribuição")
    malware_family: str = Field(description="Família atribuída ou 'unknown'")
    family_aliases: list[str] = Field(default_factory=list)
    platform: str = "unknown"
    threat_category: str = Field(default="unknown", description="ex.: stealer, backdoor, ransomware")
    summary: str
    key_findings: list[str] = Field(default_factory=list)
    mitre_attack: list[AttackTechnique] = Field(default_factory=list)
    iocs: TriageIOCs = Field(default_factory=TriageIOCs)
    recommended_actions: list[str] = Field(default_factory=list)
    analyst_notes: str | None = None


class AnalysisResponse(BaseModel):
    scan_id: int
    hash: str
    created_at: datetime
    cached: bool
    source: str = Field(description="Fontes usadas, ex.: 'virustotal+malwarebazaar' (':mock' = simulado)")
    source_errors: dict[str, str] = Field(default_factory=dict, description="Falhas não-fatais por fonte")
    engine: str = Field(description="'llm:<provider>/<model>' ou 'heuristic'")
    heuristic_score: int
    features: dict[str, Any]
    triage: TriageReport


class HistoryItem(BaseModel):
    scan_id: int
    hash: str
    created_at: datetime
    verdict: str
    malware_family: str
    confidence: int
    heuristic_score: int
    source: str
    engine: str


class HistoryResponse(BaseModel):
    total: int
    items: list[HistoryItem]


class SearchResponse(BaseModel):
    query: str
    type: Literal["ip", "domain", "url"]
    reputation: dict[str, Any]
    related_scans: list[HistoryItem]
    source: Literal["virustotal", "mock"]



class IncidentCreate(BaseModel):
    hash: str = Field(pattern=r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
    title: str | None = Field(default=None, max_length=200)
    severity: Literal["baixa", "media", "alta", "critica"] | None = None
    owner: str | None = Field(default=None, max_length=100)
    hosts: list[str] = Field(default_factory=list, max_length=500)


class IncidentUpdate(BaseModel):
    status: Literal["aberto", "em_analise", "contido", "erradicado", "recuperado", "encerrado"] | None = None
    severity: Literal["baixa", "media", "alta", "critica"] | None = None
    owner: str | None = Field(default=None, max_length=100)
    hosts: list[str] | None = Field(default=None, max_length=500)
    author: str | None = Field(default=None, max_length=100)


class TaskUpdate(BaseModel):
    status: Literal["pendente", "em_andamento", "concluida", "nao_aplicavel"] | None = None
    owner: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=2000)
    author: str | None = Field(default=None, max_length=100)


class EventCreate(BaseModel):
    message: str = Field(min_length=1, max_length=5000)
    author: str | None = Field(default=None, max_length=100)
