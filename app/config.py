"""Configuração centralizada da aplicação (lida de variáveis de ambiente)."""
from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass
from functools import lru_cache


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    vt_api_key: str | None
    vt_base_url: str
    vt_timeout: float
    vt_mock: bool
    llm_provider: str  # "openai" | "anthropic" | "none"
    llm_model: str
    llm_temperature: float
    db_path: str
    log_level: str
    mb_api_key: str | None = None
    mb_base_url: str = "https://mb-api.abuse.ch/api/v1/"
    mb_timeout: float = 20.0
    mb_mock: bool = False
    brand_name: str = "CTI · Threat Intelligence"
    brand_logo_path: str = "app/static/logo.png"
    report_tlp: str = "TLP:AMBER"
    vt_max_retries: int = 2
    vt_retry_backoff: float = 16.0  # API pública: 4 req/min
    cache_ttl_hours: float = 24.0
    api_token: str | None = None  # se definido, exige header X-API-Key em /api/*
    rate_limit_per_min: int = 30  # por IP, nos endpoints que consultam VT/MB (0 = sem limite)
    max_body_kb: int = 2048

    @property
    def use_mock_vt(self) -> bool:
        """Usa dados simulados quando forçado ou quando não há API key."""
        return self.vt_mock or not self.vt_api_key

    @property
    def mb_mode(self) -> str:
        """'real' com Auth-Key; 'mock' se forçado ou se todo o app está simulado; senão 'disabled'."""
        if self.mb_mock:
            return "mock"
        if self.mb_api_key:
            return "real"
        return "mock" if self.use_mock_vt else "disabled"


def load_dotenv(path: str | os.PathLike[str] | None = None) -> None:
    """Carrega um arquivo .env simples (CHAVE=valor) sem sobrescrever variáveis já definidas.

    Evita dependência extra (python-dotenv) e permite rodar no PC só com `python -m app.cli serve`.
    """
    env = Path(path) if path else Path(__file__).resolve().parents[1] / ".env"
    if not env.is_file():
        return
    for raw in env.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().removeprefix("export ").strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@lru_cache
def get_settings() -> Settings:
    load_dotenv()
    provider = os.getenv("LLM_PROVIDER", "none").lower()
    default_model = {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-sonnet-4-5",
    }.get(provider, "")
    return Settings(
        vt_api_key=os.getenv("VT_API_KEY") or None,
        vt_base_url=os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3"),
        vt_timeout=float(os.getenv("VT_TIMEOUT", "20")),
        vt_mock=_as_bool(os.getenv("VT_MOCK"), default=False),
        llm_provider=provider,
        llm_model=os.getenv("LLM_MODEL", default_model),
        llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0")),
        db_path=os.getenv("DB_PATH", str(Path(__file__).resolve().parents[1] / "data" / "cti.db")),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        mb_api_key=os.getenv("MB_API_KEY") or None,
        mb_base_url=os.getenv("MB_BASE_URL", "https://mb-api.abuse.ch/api/v1/"),
        mb_timeout=float(os.getenv("MB_TIMEOUT", "20")),
        mb_mock=_as_bool(os.getenv("MB_MOCK"), default=False),
        brand_name=os.getenv("BRAND_NAME", "CTI · Threat Intelligence"),
        brand_logo_path=os.getenv("BRAND_LOGO_PATH", "app/static/logo.png"),
        report_tlp=os.getenv("REPORT_TLP", "TLP:AMBER"),
        vt_max_retries=int(os.getenv("VT_MAX_RETRIES", "2")),
        vt_retry_backoff=float(os.getenv("VT_RETRY_BACKOFF", "16")),
        cache_ttl_hours=float(os.getenv("CACHE_TTL_HOURS", "24")),
        api_token=os.getenv("API_TOKEN") or None,
        rate_limit_per_min=int(os.getenv("RATE_LIMIT_PER_MIN", "30")),
        max_body_kb=int(os.getenv("MAX_BODY_KB", "2048")),
    )
