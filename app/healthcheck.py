"""Diagnóstico das integrações: valida as chaves do VirusTotal e do MalwareBazaar.

Usado por `python -m app.cli check` e pelo instalador. Faz no máximo 1 requisição por serviço:
- VirusTotal: GET /users/{api_key} (retorna também a cota diária da chave);
- MalwareBazaar: POST get_info com o hash de exemplo do desafio.
"""
from __future__ import annotations

from typing import Any

import httpx

from app.config import Settings

SAMPLE_HASH = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"


def mask(key: str | None) -> str:
    if not key:
        return "—"
    return f"{key[:4]}…{key[-4:]}" if len(key) > 10 else "****"


def _net_error(exc: Exception) -> str:
    if isinstance(exc, httpx.ProxyError):
        return "sem conexão: o proxy/firewall bloqueou o acesso"
    if isinstance(exc, httpx.TimeoutException):
        return "sem resposta (timeout) — verifique a internet"
    if isinstance(exc, httpx.ConnectError):
        return "sem conexão — verifique a internet/DNS"
    return f"falha de rede: {type(exc).__name__}"


def check_vt(s: Settings, timeout: float = 10.0, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    if not s.vt_api_key:
        return {"service": "VirusTotal", "status": "missing", "detail": "VT_API_KEY vazia: modo simulado"}
    if s.vt_mock:
        return {"service": "VirusTotal", "status": "mock", "detail": "VT_MOCK=true: modo simulado forçado"}
    try:
        with httpx.Client(base_url=s.vt_base_url, timeout=timeout, transport=transport) as c:
            r = c.get(f"/users/{s.vt_api_key}", headers={"x-apikey": s.vt_api_key, "accept": "application/json"})
    except httpx.HTTPError as exc:
        return {"service": "VirusTotal", "status": "error", "detail": _net_error(exc)}
    if r.status_code == 200:
        attrs = r.json().get("data", {}).get("attributes", {})
        daily = attrs.get("quotas", {}).get("api_requests_daily", {})
        detail = f"chave {mask(s.vt_api_key)} válida"
        if daily.get("allowed"):
            detail += f" · cota diária {daily.get('used', 0)}/{daily['allowed']}"
        return {"service": "VirusTotal", "status": "ok", "detail": detail, "quota": daily}
    if r.status_code in (401, 403):
        return {"service": "VirusTotal", "status": "invalid", "detail": f"chave {mask(s.vt_api_key)} recusada (HTTP {r.status_code})"}
    if r.status_code == 429:
        return {"service": "VirusTotal", "status": "ok", "detail": "chave aceita; limite de 4 req/min atingido agora"}
    return {"service": "VirusTotal", "status": "error", "detail": f"HTTP {r.status_code}"}


def check_mb(s: Settings, timeout: float = 10.0, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    if s.mb_mock:
        return {"service": "MalwareBazaar", "status": "mock", "detail": "MB_MOCK=true: modo simulado forçado"}
    if not s.mb_api_key:
        return {"service": "MalwareBazaar", "status": "missing", "detail": "MB_API_KEY vazia: fonte desativada"}
    try:
        with httpx.Client(timeout=timeout, transport=transport) as c:
            r = c.post(s.mb_base_url, data={"query": "get_info", "hash": SAMPLE_HASH},
                       headers={"Auth-Key": s.mb_api_key, "accept": "application/json"})
    except httpx.HTTPError as exc:
        return {"service": "MalwareBazaar", "status": "error", "detail": _net_error(exc)}
    if r.status_code in (401, 403):
        return {"service": "MalwareBazaar", "status": "invalid", "detail": f"Auth-Key {mask(s.mb_api_key)} recusada"}
    try:
        status = r.json().get("query_status")
    except ValueError:
        return {"service": "MalwareBazaar", "status": "error", "detail": f"HTTP {r.status_code}, resposta inválida"}
    if status in ("unknown_auth_key", "user_blacklisted"):
        return {"service": "MalwareBazaar", "status": "invalid", "detail": f"Auth-Key {mask(s.mb_api_key)}: {status}"}
    if status in ("ok", "hash_not_found", "no_results"):
        return {"service": "MalwareBazaar", "status": "ok", "detail": f"Auth-Key {mask(s.mb_api_key)} válida"}
    return {"service": "MalwareBazaar", "status": "error", "detail": f"query_status={status}"}


def check_llm(s: Settings) -> dict[str, Any]:
    import os

    if s.llm_provider in ("", "none"):
        return {"service": "IA (LLM)", "status": "off", "detail": "LLM_PROVIDER=none: motor heurístico"}
    key = os.getenv("OPENAI_API_KEY" if s.llm_provider == "openai" else "ANTHROPIC_API_KEY")
    if not key:
        return {"service": "IA (LLM)", "status": "missing", "detail": f"{s.llm_provider}: chave não definida (usa heurística)"}
    return {"service": "IA (LLM)", "status": "ok", "detail": f"{s.llm_provider} · {s.llm_model}"}


def check_pdf() -> dict[str, Any]:
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001 - OSError quando falta GTK/Pango no Windows
        return {"service": "PDF nativo", "status": "off", "detail": "via navegador (Imprimir > Salvar como PDF)"}
    return {"service": "PDF nativo", "status": "ok", "detail": "WeasyPrint disponível"}


def run_all(s: Settings, online: bool = True) -> list[dict[str, Any]]:
    if online:
        vt, mb = check_vt(s), check_mb(s)
    else:
        vt = {"service": "VirusTotal", "status": "ok" if s.vt_api_key else "missing",
              "detail": f"chave {mask(s.vt_api_key)} configurada" if s.vt_api_key else "VT_API_KEY vazia: modo simulado"}
        mb = {"service": "MalwareBazaar", "status": "ok" if s.mb_api_key else "missing",
              "detail": f"Auth-Key {mask(s.mb_api_key)} configurada" if s.mb_api_key else "MB_API_KEY vazia: fonte desativada"}
    return [vt, mb, check_llm(s), check_pdf()]
