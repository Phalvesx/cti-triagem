"""API REST (FastAPI) de triagem de malware: VirusTotal + MalwareBazaar + LangGraph + SQLite."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

from app import __version__
from app.agent import TriageAgent, build_agent
from app.config import Settings, get_settings
from app.database import Database
from app.mb_client import MalwareBazaarClient, MBError
from app.attack import AttackImportError, aggregate, heatmap_layer, merge_techniques, parse_import, scan_to_layer, to_csv
from app.dfir import build_plan as build_dfir_plan
from app.dfir import render_script
from app.hunting import build_hunt_pack, hunt_pack_markdown
from app.incidents import IncidentError, IncidentStore, incident_html, incident_markdown
from app.models import (
    AnalysisResponse,
    EventCreate,
    HistoryItem,
    HistoryResponse,
    IncidentCreate,
    IncidentUpdate,
    SearchResponse,
    TaskUpdate,
    TriageReport,
)
from app.report import CSS as REPORT_CSS
from app.security import build_guard
from app.report import Brand, band_html, find_logo, html_to_pdf, render_report_html
from app.vt_client import VirusTotalClient, VTError, VTNotFoundError

logger = logging.getLogger("cti_api")

HASH_RE = r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE)
STATIC_DIR = Path(__file__).parent / "static"

HashParam = Annotated[str, PathParam(pattern=HASH_RE, description="MD5, SHA-1 ou SHA-256")]
OsParam = Annotated[Literal["macos", "windows", "linux"] | None,
                    Query(description="SO do host (padrão: o detectado na triagem)")]
SiemParam = Annotated[
    Literal["all", "none", "splunk", "sentinel", "elastic", "qradar", "secops", "wazuh", "sigma"],
    Query(description="SIEM das consultas de hunting no apêndice ('none' omite o apêndice)"),
]


# ----------------------------------------------------------------- dependências
def get_db(request: Request) -> Database:
    return request.app.state.db


def get_vt(request: Request) -> VirusTotalClient:
    return request.app.state.vt


def get_mb(request: Request) -> MalwareBazaarClient:
    return request.app.state.mb


def get_agent(request: Request) -> TriageAgent:
    return request.app.state.agent


def classify_indicator(value: str) -> Literal["ip", "domain", "url"]:
    """Identifica se o indicador é IP ou domínio (aceita formato defanged `[.]`)."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if DOMAIN_RE.match(value):
        return "domain"
    raise HTTPException(status_code=422, detail=f"'{value[:100]}' não é um hash, IP, domínio ou URL válido")


def refang_url(value: str) -> str | None:
    """Normaliza uma URL defanged (hxxp, [.], [:]) ou devolve None se não for URL válida."""
    v = value.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    if "://" not in v:
        return None
    parsed = urlparse(v)
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() not in ("http", "https") or not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not DOMAIN_RE.match(host):
            return None
    return v


def _is_fresh(created_at: str, ttl_hours: float) -> bool:
    """Cache válido se o scan tem menos de `ttl_hours` (0 = cache infinito)."""
    if ttl_hours <= 0:
        return True
    ts = datetime.fromisoformat(str(created_at))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - ts < timedelta(hours=ttl_hours)


def refang(value: str) -> str:
    return (
        value.strip().lower()
        .replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
        .removeprefix("https://").removeprefix("http://").split("/")[0]
    )


# ------------------------------------------------------------------ app factory
def create_app(
    settings: Settings | None = None,
    db: Database | None = None,
    vt: VirusTotalClient | None = None,
    agent: TriageAgent | None = None,
    mb: MalwareBazaarClient | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("weasyprint", "fontTools", "httpx", "httpx2", "langchain_openai"):  # avisos de CSS/fontes do gerador de PDF
        logging.getLogger(noisy).setLevel(logging.ERROR)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        app.state.db = db or Database(settings.db_path)
        app.state.vt = vt or VirusTotalClient(settings)
        app.state.mb = mb or MalwareBazaarClient(settings)
        app.state.agent = agent or build_agent(settings)
        logger.info(
            "API iniciada | VT=%s | MB=%s | engine=%s | db=%s",
            app.state.vt.source, app.state.mb.mode, app.state.agent.engine_label, settings.db_path,
        )
        yield

    app = FastAPI(
        title="MELI CTI — Malware Triage API",
        version=__version__,
        description="Busca artefatos no VirusTotal e no MalwareBazaar, faz triagem com GenAI (LangGraph) e persiste em SQLite.",
        lifespan=lifespan,
    )
    # Sem CORS: a interface é servida pela própria API (mesma origem), então nenhum outro site
    # aberto no navegador consegue chamar a ferramenta local.
    app.middleware("http")(build_guard(api_token=settings.api_token, max_body_bytes=settings.max_body_kb * 1024,
                                       rate_per_minute=settings.rate_limit_per_min))

    # ---------------------------------------------------------- middleware/erros
    @app.middleware("http")
    async def request_logger(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            if request.url.path.startswith("/api/"):
                try:
                    request.app.state.db.log_request(
                        request.method, request.url.path, status,
                        (time.perf_counter() - start) * 1000,
                        request.client.host if request.client else None,
                    )
                except Exception:
                    logger.exception("Falha ao registrar request")

    @app.exception_handler(VTError)
    async def vt_error_handler(_: Request, exc: VTError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc), "source": "virustotal"})

    @app.exception_handler(MBError)
    async def mb_error_handler(_: Request, exc: MBError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc), "source": "malwarebazaar"})

    # ------------------------------------------------------------------ rotas
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    def brand() -> Brand:
        return Brand(name=settings.brand_name, logo_path=settings.brand_logo_path, tlp=settings.report_tlp)

    @app.get("/api/v1/brand", tags=["infra"])
    async def brand_info() -> dict[str, Any]:
        """Identidade visual usada pelo frontend e pelos relatórios."""
        logo = find_logo(settings.brand_logo_path)
        return {"name": settings.brand_name, "tlp": settings.report_tlp,
                "logo_url": "/api/v1/brand/logo" if logo else None}

    @app.get("/api/v1/brand/logo", include_in_schema=False)
    async def brand_logo() -> FileResponse:
        logo = find_logo(settings.brand_logo_path)
        if not logo:
            raise HTTPException(404, "Logo não configurado (app/static/logo.svg|png ou BRAND_LOGO_PATH)")
        return FileResponse(logo)

    @app.get("/health", tags=["infra"])
    async def health(request: Request) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "vt_source": request.app.state.vt.source,
            "mb_source": request.app.state.mb.mode,
            "engine": request.app.state.agent.engine_label,
        }

    @app.get("/api/v1/analyze/{file_hash}", response_model=AnalysisResponse, tags=["análise"])
    async def analyze(
        file_hash: HashParam,
        db: Annotated[Database, Depends(get_db)],
        vt: Annotated[VirusTotalClient, Depends(get_vt)],
        mb: Annotated[MalwareBazaarClient, Depends(get_mb)],
        agent: Annotated[TriageAgent, Depends(get_agent)],
        force: Annotated[bool, Query(description="Ignora cache e reanalisa")] = False,
    ) -> AnalysisResponse:
        """Consulta VirusTotal e MalwareBazaar em paralelo, executa o agente de triagem e persiste.

        Uma fonte pode falhar sem derrubar a análise, desde que a outra tenha dados.
        """
        file_hash = file_hash.lower()
        cached = None if force else db.get_latest_scan(file_hash)
        if cached and _is_fresh(cached["created_at"], settings.cache_ttl_hours):
            return AnalysisResponse(**cached, cached=True)

        vt_res, mb_res = await asyncio.gather(
            vt.get_file_report(file_hash), mb.get_info(file_hash), return_exceptions=True
        )
        errors: dict[str, str] = {}
        vt_report: dict[str, Any] | None = None
        mb_report: dict[str, Any] | None = None

        if isinstance(vt_res, BaseException):
            errors["virustotal"] = "not_found" if isinstance(vt_res, VTNotFoundError) else str(vt_res)
        else:
            vt_report = vt_res
        if isinstance(mb_res, BaseException):
            errors["malwarebazaar"] = str(mb_res)
        elif mb_res is None:
            if mb.enabled:
                errors["malwarebazaar"] = "not_found"
        else:
            mb_report = mb_res

        if vt_report is None and mb_report is None:
            # nenhuma fonte tem o artefato: propaga o erro do VT (404, 429, 401...)
            raise vt_res if isinstance(vt_res, VTError) else VTNotFoundError("Hash não encontrado nas fontes")

        sources = []
        if vt_report is not None:
            sources.append("virustotal" + (":mock" if vt.mock else ""))
        if mb_report is not None:
            sources.append("malwarebazaar" + (":mock" if mb.mode == "mock" else ""))
        source = "+".join(sources)

        state = await agent.run(file_hash, vt_report, mb_report)
        saved = db.save_scan(
            file_hash=file_hash,
            source=source,
            engine=state["engine"],
            heuristic_score=state["heuristic_score"],
            features=state["features"],
            triage=state["triage"],
            raw_vt=vt_report,
            raw_mb=mb_report,
        )
        return AnalysisResponse(
            scan_id=saved["scan_id"],
            hash=file_hash,
            created_at=saved["created_at"],
            cached=False,
            source=source,
            source_errors=errors,
            engine=state["engine"],
            heuristic_score=state["heuristic_score"],
            features=state["features"],
            triage=state["triage"],
        )

    # ------------------------------------------------------------ helpers
    def latest_or_404(db: Database, file_hash: str) -> dict[str, Any]:
        scan = db.get_latest_scan(file_hash)
        if not scan:
            raise HTTPException(404, "Hash ainda não analisado. Chame /api/v1/analyze/{hash} primeiro.")
        return scan

    def pdf_response(pdf: bytes, filename: str) -> Response:
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    async def to_pdf(html: str) -> bytes:
        try:
            return await asyncio.to_thread(html_to_pdf, html)
        except (ImportError, OSError) as exc:  # WeasyPrint ou libs nativas (Pango) ausentes
            raise HTTPException(501, f"Exportação PDF indisponível: {exc}. Use o HTML e 'Imprimir > Salvar como PDF'.") from exc

    async def pdf_or_print(html: str, filename: str, fallback: str) -> Response:
        """PDF nativo; se o WeasyPrint não estiver disponível (ex.: Windows sem GTK) e fallback=print,
        devolve o HTML já abrindo a caixa 'Imprimir > Salvar como PDF' do navegador."""
        try:
            return pdf_response(await to_pdf(html), filename)
        except HTTPException:
            if fallback != "print":
                raise
            banner = ("<div class='toolbar' style='justify-content:center'><span class='btn alt'>PDF nativo indisponível "
                      "neste PC — use <b>Salvar como PDF</b> na janela de impressão.</span></div>"
                      "<script>window.addEventListener('load',()=>setTimeout(()=>window.print(),400))</script>")
            return HTMLResponse(html.replace("<body>", "<body>" + banner, 1))

    def hunt_pack_or_none(scan: dict[str, Any], siem: str) -> dict[str, Any] | None:
        return None if siem == "none" else build_hunt_pack(scan, siem)

    # ------------------------------------------------------------ relatórios
    @app.get("/api/v1/report/{file_hash}", response_class=HTMLResponse, tags=["relatórios"])
    async def report_html(file_hash: HashParam, db: Annotated[Database, Depends(get_db)], siem: SiemParam = "all") -> HTMLResponse:
        """Relatório de triagem em HTML (com apêndice de hunting)."""
        scan = latest_or_404(db, file_hash)
        return HTMLResponse(render_report_html(scan, brand(), hunt_pack=hunt_pack_or_none(scan, siem)))

    @app.get("/api/v1/report/{file_hash}/pdf", response_class=Response,
             responses={200: {"content": {"application/pdf": {}}}}, tags=["relatórios"])
    async def report_pdf(file_hash: HashParam, db: Annotated[Database, Depends(get_db)], siem: SiemParam = "all",
                         fallback: Annotated[Literal["error", "print"], Query()] = "error") -> Response:
        """Relatório de triagem em PDF (A4, cabeçalho/rodapé, numeração, apêndice de hunting)."""
        scan = latest_or_404(db, file_hash)
        html = render_report_html(scan, brand(), for_pdf=True, hunt_pack=hunt_pack_or_none(scan, siem))
        family = re.sub(r"[^A-Za-z0-9_-]", "", scan["triage"].get("malware_family", "unknown")) or "unknown"
        return await pdf_or_print(html, f"triagem_{family}_{file_hash[:12].lower()}.pdf", fallback)

    # ------------------------------------------------------------ hunting
    @app.get("/api/v1/hunt/{file_hash}", tags=["hunting"])
    async def hunt(
        file_hash: HashParam, db: Annotated[Database, Depends(get_db)],
        siem: Annotated[Literal["all", "splunk", "sentinel", "elastic", "qradar", "secops", "wazuh", "sigma"], Query()] = "all",
        format: Annotated[Literal["json", "markdown"], Query()] = "json",
    ) -> Any:
        """Pacote de threat hunting (hipóteses + consultas) para Splunk, Sentinel, Elastic, QRadar, SecOps, Wazuh e Sigma."""
        pack = build_hunt_pack(latest_or_404(db, file_hash), siem)
        if format == "markdown":
            return PlainTextResponse(hunt_pack_markdown(pack), media_type="text/markdown; charset=utf-8",
                                     headers={"Content-Disposition": f'attachment; filename="hunts_{file_hash[:12]}_{siem}.md"'})
        return pack

    # ------------------------------------------------------------ DFIR
    @app.get("/api/v1/dfir/{file_hash}", tags=["dfir"])
    async def dfir_plan(file_hash: HashParam, db: Annotated[Database, Depends(get_db)], os: OsParam = None) -> dict[str, Any]:  # noqa: A002
        """Plano de coleta forense no host: ordem de volatilidade, regras de forense segura e
        verificações por técnica ATT&CK para o SO escolhido."""
        return build_dfir_plan(latest_or_404(db, file_hash), os)

    @app.get("/api/v1/dfir/{file_hash}/script", tags=["dfir"])
    async def dfir_script(file_hash: HashParam, db: Annotated[Database, Depends(get_db)], os: OsParam = None) -> PlainTextResponse:  # noqa: A002
        """Script de triagem pronto (somente leitura, sem rede, manifesto SHA-256) com os IoCs embutidos."""
        scan = latest_or_404(db, file_hash)
        plan = build_dfir_plan(scan, os)
        return PlainTextResponse(render_script(scan, plan["os"]), media_type="text/plain; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{plan["script"]}"'})

    # ------------------------------------------------------------ MITRE ATT&CK
    @app.get("/api/v1/attack/heatmap", tags=["mitre"])
    async def attack_heatmap(
        db: Annotated[Database, Depends(get_db)],
        format: Annotated[Literal["json", "navigator", "csv"], Query()] = "json",
        verdict: Annotated[Literal["malicious", "suspicious", "benign", "unknown"] | None, Query()] = None,
    ) -> Any:
        """Técnicas agregadas de todo o histórico (score = nº de scans). `navigator` = layer para o ATT&CK Navigator."""
        scans = db.list_latest_full(verdict)
        if format == "navigator":
            return JSONResponse(heatmap_layer(scans),
                                headers={"Content-Disposition": 'attachment; filename="attack_heatmap_layer.json"'})
        if format == "csv":
            return PlainTextResponse(to_csv(aggregate(scans), aggregate_mode=True), media_type="text/csv; charset=utf-8",
                                     headers={"Content-Disposition": 'attachment; filename="attack_heatmap.csv"'})
        return {"scans": len(scans), "techniques": aggregate(scans)}

    @app.get("/api/v1/attack/{file_hash}", tags=["mitre"])
    async def attack_export(
        file_hash: HashParam, db: Annotated[Database, Depends(get_db)],
        format: Annotated[Literal["json", "navigator", "csv"], Query()] = "json",
    ) -> Any:
        """Exporta as técnicas do scan: JSON, layer do ATT&CK Navigator ou CSV."""
        scan = latest_or_404(db, file_hash)
        if format == "navigator":
            return JSONResponse(scan_to_layer(scan),
                                headers={"Content-Disposition": f'attachment; filename="attack_layer_{file_hash[:12]}.json"'})
        if format == "csv":
            return PlainTextResponse(to_csv(scan["triage"].get("mitre_attack", [])), media_type="text/csv; charset=utf-8",
                                     headers={"Content-Disposition": f'attachment; filename="attack_{file_hash[:12]}.csv"'})
        return {"hash": scan["hash"], "family": scan["triage"].get("malware_family"),
                "techniques": scan["triage"].get("mitre_attack", [])}

    @app.post("/api/v1/attack/{file_hash}/import", tags=["mitre"])
    async def attack_import(
        file_hash: HashParam, request: Request, db: Annotated[Database, Depends(get_db)],
        mode: Annotated[Literal["merge", "replace"], Query(description="merge = somar; replace = substituir")] = "merge",
    ) -> dict[str, Any]:
        """Importa técnicas (layer JSON do Navigator ou CSV) no corpo da requisição e atualiza o scan."""
        scan = latest_or_404(db, file_hash)
        body = (await request.body())[:5_000_000].decode("utf-8", errors="replace")
        try:
            imported = parse_import(body, request.headers.get("content-type", ""))
            merged = merge_techniques(scan["triage"].get("mitre_attack", []), imported, mode)
        except AttackImportError as exc:
            raise HTTPException(422, str(exc)) from exc
        triage = dict(scan["triage"])
        triage["mitre_attack"] = merged
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        triage["analyst_notes"] = ((triage.get("analyst_notes") or "") +
                                   f" [ATT&CK importado ({mode}, {len(imported)} técnicas) em {stamp}]").strip()
        TriageReport.model_validate(triage)
        db.update_triage(scan["scan_id"], triage)
        return {"hash": scan["hash"], "mode": mode, "imported": len(imported), "total": len(merged), "techniques": merged}

    # ------------------------------------------------------------ incidentes
    def store(request: Request) -> IncidentStore:
        return IncidentStore(request.app.state.db)

    def incident_call(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except IncidentError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc

    @app.post("/api/v1/incidents", status_code=201, tags=["incidentes"])
    async def incident_create(body: IncidentCreate, request: Request, db: Annotated[Database, Depends(get_db)]) -> dict[str, Any]:
        """Abre um incidente a partir de um scan, com playbook NIST 800-61 e tarefas dos hunts."""
        scan = latest_or_404(db, body.hash.lower())
        pack = build_hunt_pack(scan)
        return incident_call(lambda: store(request).create_from_scan(
            scan, title=body.title, severity=body.severity, owner=body.owner, hosts=body.hosts, hunts=pack["hunts"]))

    @app.get("/api/v1/incidents", tags=["incidentes"])
    async def incident_list(request: Request, status: Annotated[str | None, Query(max_length=20)] = None) -> list[dict[str, Any]]:
        return store(request).list(status)

    @app.get("/api/v1/incidents/{incident_id}", tags=["incidentes"])
    async def incident_get(incident_id: int, request: Request) -> dict[str, Any]:
        return incident_call(lambda: store(request).get(incident_id))

    @app.patch("/api/v1/incidents/{incident_id}", tags=["incidentes"])
    async def incident_update(incident_id: int, body: IncidentUpdate, request: Request) -> dict[str, Any]:
        changes = body.model_dump(exclude_none=True)
        author = changes.pop("author", None)
        return incident_call(lambda: store(request).update(incident_id, author=author, **changes))

    @app.patch("/api/v1/incidents/{incident_id}/tasks/{task_id}", tags=["incidentes"])
    async def incident_task(incident_id: int, task_id: int, body: TaskUpdate, request: Request) -> dict[str, Any]:
        return incident_call(lambda: store(request).update_task(
            incident_id, task_id, status=body.status, owner=body.owner, note=body.note, author=body.author))

    @app.post("/api/v1/incidents/{incident_id}/events", tags=["incidentes"])
    async def incident_event(incident_id: int, body: EventCreate, request: Request) -> dict[str, Any]:
        return incident_call(lambda: store(request).add_event(incident_id, body.message, body.author))

    @app.get("/api/v1/incidents/{incident_id}/export", tags=["incidentes"])
    async def incident_export(
        incident_id: int, request: Request,
        format: Annotated[Literal["json", "markdown", "html", "pdf"], Query()] = "pdf",
        fallback: Annotated[Literal["error", "print"], Query()] = "error",
    ) -> Any:
        """Exporta o incidente (checklist + linha do tempo) em JSON, Markdown, HTML ou PDF."""
        inc = incident_call(lambda: store(request).get(incident_id))
        name = f"incidente_{incident_id}"
        if format == "json":
            return JSONResponse(inc, headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
        if format == "markdown":
            return PlainTextResponse(incident_markdown(inc), media_type="text/markdown; charset=utf-8",
                                     headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
        html = incident_html(inc, REPORT_CSS, band_html(brand(), "Incidente", f"IR-{incident_id:04d}"))
        if format == "html":
            return HTMLResponse(html)
        return await pdf_or_print(html, f"{name}.pdf", fallback)

    @app.get("/api/v1/history", response_model=HistoryResponse, tags=["histórico"])
    async def history(
        db: Annotated[Database, Depends(get_db)],
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
        verdict: Annotated[Literal["malicious", "suspicious", "benign", "unknown"] | None, Query()] = None,
        family: Annotated[str | None, Query(max_length=64)] = None,
    ) -> HistoryResponse:
        total, items = db.list_scans(limit=limit, offset=offset, verdict=verdict, family=family)
        return HistoryResponse(total=total, items=[HistoryItem(**i) for i in items])

    @app.get("/api/v1/history/{file_hash}", response_model=AnalysisResponse, tags=["histórico"])
    async def history_detail(file_hash: HashParam, db: Annotated[Database, Depends(get_db)]) -> AnalysisResponse:
        scan = db.get_latest_scan(file_hash)
        if not scan:
            raise HTTPException(404, "Hash não encontrado no histórico")
        return AnalysisResponse(**scan, cached=True)

    @app.get("/api/v1/search", response_model=SearchResponse, tags=["busca"])
    async def search(
        db: Annotated[Database, Depends(get_db)],
        vt: Annotated[VirusTotalClient, Depends(get_vt)],
        q: Annotated[str, Query(min_length=3, max_length=2048, description="IP, domínio ou URL (aceita defang)")],
    ) -> SearchResponse:
        """Reputação do IP/domínio/URL no VT + scans locais em que o indicador apareceu.

        Guardrail: a ferramenta NUNCA acessa o indicador; só pergunta ao VirusTotal sobre ele.
        """
        url = refang_url(q)
        if url:
            value, kind = url, "url"
            raw = await vt.get_url_report(url)
        else:
            value = refang(q)
            kind = classify_indicator(value)
            raw = await (vt.get_ip_report(value) if kind == "ip" else vt.get_domain_report(value))
        attrs = raw.get("data", {}).get("attributes", {})
        reputation = {
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "registrar": attrs.get("registrar"),
            "categories": attrs.get("categories", {}),
            "last_dns_records": attrs.get("last_dns_records", [])[:20],
        }
        related = [HistoryItem(**s) for s in db.find_scans_by_ioc(value)]
        return SearchResponse(query=value, type=kind, reputation=reputation, related_scans=related, source=vt.source)

    @app.get("/api/v1/requests", tags=["histórico"])
    async def request_log(
        db: Annotated[Database, Depends(get_db)], limit: Annotated[int, Query(ge=1, le=1000)] = 100
    ) -> list[dict[str, Any]]:
        """Log de auditoria das requisições feitas à API."""
        return db.list_requests(limit)

    return app


app = create_app()
