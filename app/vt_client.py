"""Cliente assíncrono para a API v3 do VirusTotal (modo real ou simulado)."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Any

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class VTError(Exception):
    """Erro genérico ao consultar o VirusTotal."""

    status_code: int = 502


class VTNotFoundError(VTError):
    status_code = 404


class VTRateLimitError(VTError):
    status_code = 429


class VTAuthError(VTError):
    status_code = 401


class VirusTotalClient:
    """Wrapper mínimo dos endpoints usados pela triagem."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.mock = settings.use_mock_vt
        self._transport = transport

    @property
    def source(self) -> str:
        return "mock" if self.mock else "virustotal"

    # ------------------------------------------------------------ public API
    async def get_file_report(self, file_hash: str) -> dict[str, Any]:
        """Retorna o objeto `file` + relacionamentos de rede (best effort)."""
        if self.mock:
            return self._load_fixture(f"file_{file_hash.lower()}.json")

        report = await self._get(f"/files/{file_hash}")
        relationships: dict[str, Any] = {}
        for rel in ("contacted_domains", "contacted_ips", "contacted_urls"):
            try:
                rel_data = await self._get(f"/files/{file_hash}/{rel}", params={"limit": 20})
                relationships[rel] = rel_data.get("data", [])
            except VTError as exc:  # relacionamentos podem exigir licença premium
                logger.info("Relacionamento %s indisponível: %s", rel, exc)
                relationships[rel] = []
        report["relationships"] = relationships
        return report

    async def get_ip_report(self, ip: str) -> dict[str, Any]:
        if self.mock:
            return self._mock_network_object("ip_address", ip)
        return await self._get(f"/ip_addresses/{ip}")

    async def get_url_report(self, url: str) -> dict[str, Any]:
        """Reputação de uma URL. O VT identifica a URL pelo base64url dela, sem padding."""
        if self.mock:
            return self._mock_network_object("url", url)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._get(f"/urls/{url_id}")

    async def get_domain_report(self, domain: str) -> dict[str, Any]:
        if self.mock:
            return self._mock_network_object("domain", domain)
        return await self._get(f"/domains/{domain}")

    # --------------------------------------------------------------- internals
    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET com retry/backoff em 429 (a API pública do VT permite 4 req/min)."""
        attempt = 0
        while True:
            try:
                return await self._get_once(path, params)
            except VTRateLimitError:
                if attempt >= self.settings.vt_max_retries:
                    raise
                attempt += 1
                wait = self.settings.vt_retry_backoff * attempt
                logger.info("VT 429 em %s; nova tentativa %d em %.0fs", path, attempt, wait)
                await asyncio.sleep(wait)

    async def _get_once(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"x-apikey": self.settings.vt_api_key or "", "accept": "application/json"}
        try:
            async with httpx.AsyncClient(
                base_url=self.settings.vt_base_url,
                timeout=self.settings.vt_timeout,
                transport=self._transport,
            ) as client:
                resp = await client.get(path, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise VTError(f"Falha de rede ao consultar VirusTotal: {exc}") from exc

        if resp.status_code == 200:
            return resp.json()
        message = self._error_message(resp)
        if resp.status_code == 404:
            raise VTNotFoundError(message)
        if resp.status_code == 429:
            raise VTRateLimitError(message)
        if resp.status_code in (401, 403):
            raise VTAuthError(message)
        raise VTError(f"VirusTotal retornou HTTP {resp.status_code}: {message}")

    @staticmethod
    def _error_message(resp: httpx.Response) -> str:
        try:
            err = resp.json().get("error", {})
            return f"{err.get('code', 'Error')}: {err.get('message', resp.text)}"
        except (json.JSONDecodeError, AttributeError):
            return resp.text[:200]

    @staticmethod
    def _load_fixture(name: str) -> dict[str, Any]:
        path = FIXTURES_DIR / name
        if not path.exists():
            raise VTNotFoundError(
                "Modo simulado: só o hash do desafio tem dados de exemplo. "
                "Configure VT_API_KEY (e MB_API_KEY) no .env para analisar qualquer hash."
            )
        return json.loads(path.read_text(encoding="utf-8"))

    def _mock_network_object(self, obj_type: str, value: str) -> dict[str, Any]:
        fixture = FIXTURES_DIR / f"{obj_type}_{value.lower()}.json"
        if obj_type != "url" and fixture.exists():
            return json.loads(fixture.read_text(encoding="utf-8"))
        return {
            "_simulated": True,
            "data": {
                "id": value,
                "type": obj_type,
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                    "reputation": 0,
                    "tags": [],
                },
            },
        }
