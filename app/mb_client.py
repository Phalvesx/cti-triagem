"""Cliente assíncrono para a API do MalwareBazaar (abuse.ch) — modo real ou simulado.

Documentação: https://bazaar.abuse.ch/api/
Todas as requisições são POST form-encoded com o header `Auth-Key` (gratuito em https://auth.abuse.ch/).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class MBError(Exception):
    """Erro genérico ao consultar o MalwareBazaar."""

    status_code: int = 502


class MBAuthError(MBError):
    status_code = 401


class MalwareBazaarClient:
    """Wrapper do endpoint `get_info` (consulta por hash)."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.mode = settings.mb_mode  # "real" | "mock" | "disabled"
        self._transport = transport

    @property
    def enabled(self) -> bool:
        return self.mode != "disabled"

    @property
    def source(self) -> str:
        return {"real": "malwarebazaar", "mock": "mock"}.get(self.mode, "disabled")

    # ------------------------------------------------------------ public API
    async def get_info(self, file_hash: str) -> dict[str, Any] | None:
        """Retorna o registro da amostra ou None se o hash não existir no MalwareBazaar."""
        if self.mode == "disabled":
            return None
        if self.mode == "mock":
            path = FIXTURES_DIR / f"mb_{file_hash.lower()}.json"
            return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

        body = await self._post({"query": "get_info", "hash": file_hash})
        status = body.get("query_status")
        if status == "ok" and body.get("data"):
            return {"query_status": status, "data": body["data"][0]}
        if status in {"hash_not_found", "no_results"}:
            return None
        if status == "illegal_hash":
            raise MBError("MalwareBazaar: hash inválido")
        raise MBError(f"MalwareBazaar retornou query_status={status}")

    # --------------------------------------------------------------- internals
    async def _post(self, form: dict[str, str]) -> dict[str, Any]:
        headers = {"Auth-Key": self.settings.mb_api_key or "", "accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.settings.mb_timeout, transport=self._transport) as client:
                resp = await client.post(self.settings.mb_base_url, data=form, headers=headers)
        except httpx.HTTPError as exc:
            raise MBError(f"Falha de rede ao consultar MalwareBazaar: {exc}") from exc

        if resp.status_code in (401, 403):
            raise MBAuthError("MalwareBazaar: Auth-Key ausente ou inválida")
        if resp.status_code != 200:
            raise MBError(f"MalwareBazaar retornou HTTP {resp.status_code}")
        try:
            body: dict[str, Any] = resp.json()
        except json.JSONDecodeError as exc:
            raise MBError("MalwareBazaar retornou JSON inválido") from exc
        if body.get("query_status") in {"unknown_auth_key", "user_blacklisted"}:
            raise MBAuthError(f"MalwareBazaar: {body['query_status']}")
        return body

