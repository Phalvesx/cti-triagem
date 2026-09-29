"""Relatório de triagem: um único template HTML (A4) usado na web e na exportação para PDF.

* Web:  GET /api/v1/report/{hash}      -> HTML (visual de "folha" sobre fundo cinza)
* PDF:  GET /api/v1/report/{hash}/pdf  -> mesmo HTML renderizado pelo WeasyPrint (html_to_pdf) (@page A4,
        cabeçalho/rodapé repetidos, numeração "página X de Y").

Logo: coloque o arquivo oficial em `app/static/logo.svg` ou `app/static/logo.png`
(ou aponte `BRAND_LOGO_PATH`). Ele é embutido como data URI, então aparece também no PDF.
Sem arquivo, é usado um emblema neutro de escudo + o texto de BRAND_NAME.
"""
from __future__ import annotations

import base64
import mimetypes
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = Path(__file__).resolve().parent / "static"

VERDICT_STYLE: dict[str, tuple[str, str]] = {
    "malicious": ("#D92D20", "Malicioso"),
    "suspicious": ("#DC6803", "Suspeito"),
    "benign": ("#039855", "Benigno"),
    "unknown": ("#667085", "Indeterminado"),
}

# Emblema neutro (escudo + pulso) — desenho próprio, usado quando não há logo configurado
DEFAULT_EMBLEM = (
    "<svg class='emblem' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg' aria-hidden='true'>"
    "<path d='M20 3 35 9v10c0 9.5-6.4 16.2-15 18-8.6-1.8-15-8.5-15-18V9z' fill='#2D3277'/>"
    "<path d='M9 21h6l2.5-5 4 10 2.5-5H31' fill='none' stroke='#FFE600' stroke-width='2.6' "
    "stroke-linecap='round' stroke-linejoin='round'/></svg>"
)


@dataclass(frozen=True)
class Brand:
    name: str = "CTI · Threat Intelligence"
    logo_path: str | None = None
    tlp: str = "TLP:AMBER"


def find_logo(configured: str | None) -> Path | None:
    candidates: list[Path] = []
    if configured:
        p = Path(configured)
        candidates += [p] if p.is_absolute() else [Path.cwd() / p, PROJECT_ROOT / p]
    candidates += [STATIC_DIR / "logo.svg", STATIC_DIR / "logo.png"]
    return next((c for c in candidates if c.is_file()), None)


def _logo_html(brand: Brand) -> str:
    logo = find_logo(brand.logo_path)
    if logo:
        mime = mimetypes.guess_type(logo.name)[0] or "image/png"
        data = base64.b64encode(logo.read_bytes()).decode()
        return f"<img class='logo' src='data:{mime};base64,{data}' alt='{escape(brand.name)}'>"
    return f"{DEFAULT_EMBLEM}<span class='wordmark'>{escape(brand.name)}</span>"


def defang(value: str) -> str:
    """Indicadores 'desarmados' para leitura segura em PDF/e-mail."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def _ul(items: list[Any], cls: str = "") -> str:
    if not items:
        return "<p class='muted'>—</p>"
    return f"<ul class='{cls}'>" + "".join(f"<li>{escape(str(i))}</li>" for i in items) + "</ul>"


def _ol(items: list[Any]) -> str:
    if not items:
        return "<p class='muted'>—</p>"
    return "<ol class='steps'>" + "".join(f"<li>{escape(str(i))}</li>" for i in items) + "</ol>"


CSS = """
@page {
  size: A4; margin: 22mm 16mm 20mm;
  @top-left { content: element(runhead); }
  @bottom-left { content: "Gerado por CTI Triage API · Uso interno"; font: 7.5pt Inter, Arial, "DejaVu Sans", sans-serif; color: #98A2B3; }
  @bottom-right { content: "Página " counter(page) " de " counter(pages); font: 7.5pt Inter, Arial, "DejaVu Sans", sans-serif; color: #98A2B3; }
}
@page :first { margin-top: 12mm; @top-left { content: none; } }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font-family: Inter, "Helvetica Neue", Arial, "DejaVu Sans", sans-serif;
       color: #1D2939; font-size: 10pt; line-height: 1.5; background: #EEF0F4; }
.sheet { background: #fff; max-width: 210mm; margin: 24px auto; padding: 0 0 18px;
         box-shadow: 0 8px 30px rgba(16,24,40,.12); border-radius: 6px; overflow: hidden; }
.runhead { position: running(runhead); display: none; }
.band { background: #FFE600; padding: 14px 28px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
.emblem { width: 34px; height: 34px; flex: none; }
.logo { height: 36px; max-width: 180px; object-fit: contain; }
.wordmark { white-space: nowrap; font-weight: 800; color: #2D3277; font-size: 12.5pt; letter-spacing: -.01em; }
.band-meta { text-align: right; font-size: 8pt; color: #2D3277; line-height: 1.35; }
.tlp { display: inline-block; background: #1D2939; color: #FFC000; font-weight: 700; font-size: 7.5pt;
       padding: 2px 8px; border-radius: 3px; letter-spacing: .06em; margin-bottom: 3px; }
.stripe { height: 5px; background: #2D3277; }
.content { padding: 22px 28px 0; }
.eyebrow { font-size: 8pt; text-transform: uppercase; letter-spacing: .12em; color: #667085; font-weight: 600; }
.hero { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; margin: 4px 0 6px; }
h1 { font-size: 24pt; margin: 0; color: #101828; letter-spacing: -.02em; line-height: 1.1; }
.pill { display: inline-block; color: #fff; font-weight: 700; font-size: 8.5pt; padding: 5px 12px;
        border-radius: 999px; text-transform: uppercase; letter-spacing: .06em; white-space: nowrap; }
.hash { font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace; font-size: 8pt; color: #475467;
        background: #F2F4F7; padding: 6px 10px; border-radius: 4px; word-break: break-all; margin: 8px 0 0; }
.warn { background: #FFFAEB; border: 1px solid #FEC84B; color: #93370D; font-size: 8.5pt;
        padding: 7px 10px; border-radius: 4px; margin-top: 10px; }
.kpis { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin: 16px 0 4px; }
.kpi { border: 1px solid #EAECF0; border-radius: 6px; padding: 9px 10px; }
.kpi .l { font-size: 7.5pt; color: #667085; text-transform: uppercase; letter-spacing: .05em; }
.kpi .v { font-size: 13pt; font-weight: 700; color: #101828; margin-top: 2px; overflow-wrap: anywhere; }
.bar { height: 5px; background: #EAECF0; border-radius: 3px; margin-top: 6px; overflow: hidden; }
.bar > span { display: block; height: 100%; background: #2D3277; }
h2 { font-size: 11pt; color: #2D3277; margin: 20px 0 8px; padding-bottom: 5px; border-bottom: 2px solid #FFE600;
     text-transform: uppercase; letter-spacing: .05em; page-break-after: avoid; break-after: avoid; }
h3 { font-size: 9.5pt; margin: 12px 0 6px; color: #344054; }
.summary { background: #F9FAFB; border-left: 4px solid #2D3277; padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 0; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
ul, ol { margin: 0; padding-left: 18px; } li { margin: 2px 0; }
ol.steps { counter-reset: s; list-style: none; padding: 0; }
ol.steps li { counter-increment: s; position: relative; padding-left: 26px; margin: 5px 0; }
ol.steps li::before { content: counter(s); position: absolute; left: 0; top: 0; width: 18px; height: 18px;
  border-radius: 50%; background: #2D3277; color: #FFE600; font-size: 8pt; font-weight: 700; text-align: center; line-height: 18px; }
table { width: 100%; border-collapse: collapse; font-size: 8.8pt; page-break-inside: auto; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; break-inside: avoid; }
th { text-align: left; font-size: 7.5pt; text-transform: uppercase; letter-spacing: .05em; color: #667085;
     background: #F9FAFB; padding: 6px 8px; border-bottom: 1px solid #EAECF0; }
td { padding: 6px 8px; border-bottom: 1px solid #F2F4F7; vertical-align: top; }
td.k { width: 28%; color: #475467; font-weight: 600; }
code, .mono { font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace; font-size: 8pt; word-break: break-all; }
.chip { display: inline-block; background: #EEF0FF; color: #2D3277; font-size: 7.5pt; padding: 1px 7px; border-radius: 999px; font-weight: 600; }
.tid { font-weight: 700; color: #2D3277; text-decoration: none; }
.muted { color: #98A2B3; }
.card { border: 1px solid #EAECF0; border-radius: 6px; padding: 10px 12px; break-inside: avoid; }
.sig { font-size: 14pt; font-weight: 800; color: #101828; }
.toolbar { max-width: 210mm; margin: 16px auto -8px; display: flex; justify-content: flex-end; gap: 8px; }
.btn { font: 600 9.5pt Inter, Arial, sans-serif; background: #2D3277; color: #fff; text-decoration: none;
       padding: 8px 14px; border-radius: 6px; }
.btn.alt { background: #fff; color: #2D3277; border: 1px solid #D0D5DD; }
.qblock { margin: 10px 0; break-inside: avoid; page-break-inside: avoid; }
.qhead { font-size: 8.5pt; color: #2D3277; margin-bottom: 3px; }
pre.q { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font: 7.4pt/1.45 "JetBrains Mono", "DejaVu Sans Mono", monospace;
        background: #0B1020; color: #E4E7EC; padding: 8px 10px; border-radius: 5px; }
.sign { margin-top: 18px; font-size: 8pt; color: #667085; border-top: 1px dashed #D0D5DD; padding-top: 8px; }
@media print { body { background: #fff; } .sheet { box-shadow: none; margin: 0; max-width: none; border-radius: 0; }
  .toolbar { display: none; } .runhead { display: block; } .band { margin: 0; } }
@media screen and (max-width: 720px) { .kpis { grid-template-columns: repeat(2, 1fr); } .cols { grid-template-columns: 1fr; }
  .hero { flex-direction: column; align-items: flex-start; } .content, .band { padding-left: 16px; padding-right: 16px; } }
.runhead { font-size: 7.5pt; color: #667085; border-bottom: 1px solid #EAECF0; padding-bottom: 4px; width: 100%; }
.runhead b { color: #2D3277; }
"""


def band_html(brand: Brand, doc_label: str, doc_id: str) -> str:
    """Cabeçalho amarelo (logo + TLP + id do documento), reutilizado por triagem e incidentes."""
    generated = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    return (f"<header class='band'><div class='brand'>{_logo_html(brand)}</div>"
            f"<div class='band-meta'><span class='tlp'>{escape(brand.tlp)}</span><br>{escape(doc_label)} <b>{escape(doc_id)}</b>"
            f"<br>Gerado em {generated}</div></header><div class='stripe'></div>")


def html_to_pdf(html: str) -> bytes:
    """Converte HTML em PDF (A4) com WeasyPrint (import tardio: dependência pesada)."""
    from weasyprint import HTML

    return HTML(string=html, base_url=str(STATIC_DIR)).write_pdf()


def _hunts_html(pack: dict[str, Any] | None) -> str:
    if not pack:
        return ""
    rows = "".join(
        f"<tr><td><b>{escape(h['id'])}</b></td><td><b>{escape(h['title'])}</b><br><span class='muted'>{escape(h['hypothesis'])}</span></td>"
        f"<td>{''.join(f'<span class=chip>{escape(a)}</span> ' for a in h['attack'])}</td></tr>"
        for h in pack["hunts"])
    blocks = ""
    for h in pack["hunts"]:
        for siem, q in h["queries"].items():
            notes = "".join(f"<div class='muted' style='font-size:8pt'>{escape(n)}</div>" for n in h.get("query_notes", {}).get(siem, []))
            blocks += (f"<div class='qblock'><div class='qhead'><b>{escape(h['id'])}</b> · {escape(pack['siems'].get(siem, siem))}</div>"
                       f"{notes}<pre class='q'>{escape(q)}</pre></div>")
    siem_list = ", ".join(pack["siems"].values())
    return (f"<h2 style='page-break-before:always;break-before:page'>Apêndice — Threat Hunting</h2>"
            f"<p class='muted'>Consultas geradas a partir desta triagem para: {escape(siem_list)}. "
            f"Ajuste índices/tabelas/campos ao seu ambiente.</p>"
            f"<table><thead><tr><th style='width:7%'>ID</th><th>Hunt e hipótese</th><th style='width:26%'>ATT&amp;CK</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>{blocks}")


def render_report_html(scan: dict[str, Any], brand: Brand | None = None, *, for_pdf: bool = False,
                       hunt_pack: dict[str, Any] | None = None) -> str:
    brand = brand or Brand()
    t: dict[str, Any] = scan["triage"]
    f: dict[str, Any] = scan["features"]
    meta, det = f.get("meta", {}), f.get("detection", {})
    mb: dict[str, Any] = f.get("malwarebazaar", {}) or {}
    color, verdict_label = VERDICT_STYLE.get(t.get("verdict", "unknown"), VERDICT_STYLE["unknown"])
    file_hash = scan["hash"]
    report_id = f"TRI-{str(scan['created_at'])[:10].replace('-', '')}-{scan['scan_id']:04d}"
    confidence = int(t.get("confidence", 0))
    mal, total = det.get("malicious", 0), det.get("analysed_engines", 0)
    det_pct = round(100 * mal / total) if total else 0

    attack_rows = "".join(
        f"<tr><td><a class='tid' href='https://attack.mitre.org/techniques/{escape(a['id'].replace('.', '/'))}/'>"
        f"{escape(a['id'])}</a></td><td>{escape(a.get('name') or '')}</td>"
        f"<td><span class='chip'>{escape(a.get('tactic') or '—')}</span></td></tr>"
        for a in t.get("mitre_attack", [])
    ) or "<tr><td colspan='3' class='muted'>Nenhuma técnica mapeada nesta triagem (configure um LLM para mapeamento automático).</td></tr>"

    iocs = t.get("iocs", {})
    ioc_rows = "".join(
        f"<tr><td><span class='chip'>{kind}</span></td><td class='mono'>{escape(defang(v))}</td></tr>"
        for kind, key in (("Domínio", "domains"), ("IP", "ips"), ("URL", "urls"))
        for v in iocs.get(key, [])
    ) + "".join(
        f"<tr><td><span class='chip' style='background:#FFFAEB;color:#93370D'>Serviço abusado</span></td>"
        f"<td class='mono'>{escape(defang(v))} <span class='muted' style='font-family:inherit'>— legítimo, usado como DDR: "
        f"bloquear só a URL/perfil, não o domínio</span></td></tr>"
        for v in iocs.get("abused_services", [])
    ) or "<tr><td colspan='2' class='muted'>Nenhum IoC de rede observado</td></tr>"

    det_rows = "".join(
        f"<tr><td>{escape(e)}</td><td><code>{escape(str(lbl))}</code></td></tr>"
        for e, lbl in det.get("labels_by_engine", {}).items()
    ) or "<tr><td colspan='2' class='muted'>Sem detecções</td></tr>"

    if mb.get("found"):
        vendor_rows = "".join(
            f"<tr><td class='k'>{escape(v)}</td><td>{escape(' · '.join(f'{k}: {val}' for k, val in d.items()))}</td></tr>"
            for v, d in mb.get("vendor_intel", {}).items()
        ) or "<tr><td colspan='2' class='muted'>Sem vendor intel</td></tr>"
        mb_html = f"""
 <div class="cols">
  <div class="card"><div class="eyebrow">Assinatura</div><div class="sig">{escape(str(mb.get('signature') or 'n/d'))}</div>
   <table><tbody>
    <tr><td class="k">Arquivo</td><td>{escape(str(mb.get('file_name')))} <span class="muted">({escape(str(mb.get('file_type')))})</span></td></tr>
    <tr><td class="k">1ª vez visto</td><td>{escape(str(mb.get('first_seen')))}</td></tr>
    <tr><td class="k">Entrega</td><td>{escape(str(mb.get('delivery_method') or 'n/d'))}</td></tr>
    <tr><td class="k">Tags</td><td>{''.join(f"<span class='chip'>{escape(x)}</span> " for x in mb.get('tags', [])) or '—'}</td></tr>
   </tbody></table></div>
  <div class="card"><div class="eyebrow">Vendor intel</div>
   <table><tbody>{vendor_rows}</tbody></table>
   <h3>Regras YARA</h3>{_ul(mb.get('yara_rules', []))}</div>
 </div>"""
    else:
        mb_html = "<p class='muted'>Hash não encontrado no MalwareBazaar (ou fonte desabilitada).</p>"

    sim_banner = (
        "<div class='warn'><b>Atenção:</b> dados de origem SIMULADOS (modo mock). "
        "Configure VT_API_KEY / MB_API_KEY para dados reais.</div>"
        if f.get("simulated") else ""
    )
    toolbar = "" if for_pdf else (
        f"<div class='toolbar'><a class='btn alt' href='javascript:window.print()'>Imprimir</a>"
        f"<a class='btn' href='/api/v1/report/{escape(file_hash)}/pdf?fallback=print'>Baixar PDF</a></div>"
    )

    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(report_id)} · {escape(t.get('malware_family', 'unknown'))}</title>
<style>{CSS}</style></head>
<body>
<div class="runhead"><b>{escape(brand.name)}</b> · {escape(report_id)} · {escape(t.get('malware_family', 'unknown'))} · {escape(brand.tlp)}</div>
{toolbar}
<article class="sheet">
 {band_html(brand, "Relatório", report_id)}
 <div class="content">
  <div class="eyebrow">Relatório de triagem de malware</div>
  <div class="hero">
   <h1>{escape(t.get('malware_family', 'unknown'))}</h1>
   <span class="pill" style="background:{color}">{verdict_label}</span>
  </div>
  <div class="hash">SHA-256 · {escape(file_hash)}</div>
  {sim_banner}

  <div class="kpis">
   <div class="kpi"><div class="l">Confiança</div><div class="v">{confidence}%</div><div class="bar"><span style="width:{confidence}%"></span></div></div>
   <div class="kpi"><div class="l">Detecções VT</div><div class="v">{escape(det.get('ratio', '0/0'))}</div><div class="bar"><span style="width:{det_pct}%;background:{color}"></span></div></div>
   <div class="kpi"><div class="l">MalwareBazaar</div><div class="v">{escape(str(mb.get('signature') or ('—' if not mb.get('found') else 'n/d')))}</div></div>
   <div class="kpi"><div class="l">Plataforma</div><div class="v">{escape(t.get('platform', 'unknown'))}</div></div>
   <div class="kpi"><div class="l">Categoria</div><div class="v">{escape(t.get('threat_category', 'unknown'))}</div></div>
  </div>

  <h2>Resumo</h2>
  <p class="summary">{escape(t.get('summary', ''))}</p>

  <div class="cols">
   <div><h2>Principais achados</h2>{_ul(t.get('key_findings', []))}</div>
   <div><h2>Ações recomendadas</h2>{_ol(t.get('recommended_actions', []))}</div>
  </div>

  <h2>MITRE ATT&amp;CK</h2>
  <table><thead><tr><th style="width:14%">ID</th><th>Técnica</th><th style="width:30%">Tática</th></tr></thead><tbody>{attack_rows}</tbody></table>

  <h2>Indicadores de comprometimento</h2>
  <table><thead><tr><th style="width:14%">Tipo</th><th>Indicador (defanged)</th></tr></thead><tbody>{ioc_rows}</tbody></table>

  <h2>MalwareBazaar</h2>
  {mb_html}

  <h2>Metadados do artefato</h2>
  <div class="cols">
   <table><tbody>
    <tr><td class="k">Tipo</td><td>{escape(str(meta.get('type')))}</td></tr>
    <tr><td class="k">Tamanho</td><td>{escape(str(meta.get('size')))} bytes</td></tr>
    <tr><td class="k">Nomes</td><td>{escape(', '.join(meta.get('names', [])) or '—')}</td></tr>
    <tr><td class="k">1ª submissão</td><td>{escape(str(meta.get('first_submission')))}</td></tr>
   </tbody></table>
   <table><tbody>
    <tr><td class="k">Fontes</td><td>{escape(str(scan.get('source', '')))}</td></tr>
    <tr><td class="k">Motor</td><td>{escape(str(scan.get('engine', '')))}</td></tr>
    <tr><td class="k">Score</td><td>{scan.get('heuristic_score', 0)}/100</td></tr>
    <tr><td class="k">Aliases</td><td>{escape(', '.join(t.get('family_aliases', [])) or '—')}</td></tr>
   </tbody></table>
  </div>

  <h2>Detecções por engine</h2>
  <table><thead><tr><th style="width:28%">Engine</th><th>Rótulo</th></tr></thead><tbody>{det_rows}</tbody></table>

  <h2>Notas do analista</h2>
  <p>{escape(t.get('analyst_notes') or '—')}</p>
  {_hunts_html(hunt_pack)}

  <div class="sign">Scan #{scan['scan_id']} · análise de {escape(str(scan['created_at']))} · {escape(brand.name)} ·
   Classificação {escape(brand.tlp)} — não compartilhar fora da organização.</div>
 </div>
</article>
</body></html>"""

