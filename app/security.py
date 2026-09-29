"""Guardrails de segurança da ferramenta.

Princípios (simples e verificáveis):
1. **Nunca tocar na ameaça.** A ferramenta só aceita *texto* (hash, IP, domínio, URL). Não recebe upload de
   arquivo, não executa nada e **nunca se conecta** aos IoCs: só consulta as APIs do VirusTotal/MalwareBazaar.
2. **Dados de ameaça são não confiáveis.** Nomes de arquivo, comentários e rótulos vêm de terceiros (inclusive do
   atacante). Antes de ir para a IA, são truncados e limpos (anti *prompt injection*); na saída, tudo é escapado
   (HTML) e neutralizado (CSV).
3. **Superfície mínima.** Cabeçalhos de segurança (CSP), limite de tamanho de requisição, limite de taxa nos
   endpoints que gastam cota externa e token de acesso opcional.
"""
from __future__ import annotations

import hmac
import re
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse

# ------------------------------------------------------------------ 1. entrada da IA (anti prompt injection)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INJECTION = re.compile(
    r"(?i)(ignore (all |the )?(previous|above|prior) (instructions|prompts?)|ignore as instru[cç][õo]es|"
    r"system prompt|you are now|voc[eê] agora [eé]|</?(system|assistant|instructions?)>|disregard (all|the))"
)
MAX_STR = 300


def sanitize_untrusted(value: Any, max_len: int = MAX_STR) -> Any:
    """Limpa recursivamente dados de terceiros antes de enviá-los ao LLM."""
    if isinstance(value, str):
        v = _CTRL.sub(" ", value)
        v = _INJECTION.sub("[removido]", v)
        return v[:max_len] + ("…" if len(v) > max_len else "")
    if isinstance(value, dict):
        return {str(k)[:80]: sanitize_untrusted(v, max_len) for k, v in list(value.items())[:60]}
    if isinstance(value, (list, tuple)):
        return [sanitize_untrusted(v, max_len) for v in list(value)[:60]]
    return value


_FAMILY_OK = re.compile(r"[^A-Za-z0-9 ._()+/-]")


def sanitize_family(name: str | None) -> str:
    """Nome de família vindo do LLM: só caracteres seguros e tamanho curto."""
    clean = _FAMILY_OK.sub("", (name or "").strip())[:64].strip()
    return clean or "unknown"


# ------------------------------------------------------------------ 2. saída CSV (anti formula injection)
def csv_safe(value: Any) -> Any:
    """Evita que planilhas executem fórmulas (=, +, -, @) vindas de dados de ameaça."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


# ------------------------------------------------------------------ 3. HTTP
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; "
        "form-action 'self'; base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")  # Swagger carrega JS de CDN: sem CSP restritiva
_LIMITED_PATHS = ("/api/v1/analyze/", "/api/v1/search")  # gastam cota das APIs externas


class RateLimiter:
    """Janela deslizante de 60 s por IP (em memória: suficiente para uma instância)."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        return True


def build_guard(*, api_token: str | None, max_body_bytes: int, rate_per_minute: int
                ) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    limiter = RateLimiter(rate_per_minute)

    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        # tamanho da requisição
        if int(request.headers.get("content-length") or 0) > max_body_bytes:
            return JSONResponse({"detail": f"Requisição maior que {max_body_bytes // 1024} KB"}, status_code=413)
        # token de acesso (opcional): header X-API-Key ou ?token= (para links de download)
        if api_token and path.startswith("/api/"):
            given = request.headers.get("x-api-key") or request.query_params.get("token") or ""
            if not hmac.compare_digest(given, api_token):
                return JSONResponse({"detail": "Token de acesso ausente ou inválido (X-API-Key)"}, status_code=401)
        # limite de taxa nos endpoints que consultam VT/MB
        if path.startswith(_LIMITED_PATHS):
            client = request.client.host if request.client else "?"
            if not limiter.allow(client):
                return JSONResponse({"detail": "Muitas requisições. Tente de novo em 1 minuto."}, status_code=429,
                                    headers={"Retry-After": "60"})
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            if k == "Content-Security-Policy" and path.startswith(_DOCS_PATHS):
                continue
            response.headers.setdefault(k, v)
        return response

    return guard
