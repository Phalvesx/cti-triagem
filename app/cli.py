"""Linha de comando: usa a ferramenta no PC sem abrir a interface web.

Os comandos chamam a própria API em processo (FastAPI TestClient), então o comportamento é
idêntico ao da interface: mesmo banco SQLite, mesmo agente, mesmas exportações.

Exemplos:
    python -m app.cli serve --open                       # sobe a interface em http://127.0.0.1:8000
    python -m app.cli check                              # valida as chaves de API (VT / MalwareBazaar)
    python -m app.cli analyze <hash> --pdf relatorio.pdf --siem sentinel
    python -m app.cli hunt <hash> --siem splunk --out hunts.md
    python -m app.cli dfir <hash> --os windows                     # script de triagem forense do host
    python -m app.cli attack <hash> --navigator layer.json --csv tecnicas.csv
    python -m app.cli attack-import <hash> layer_editado.json --mode merge
    python -m app.cli heatmap --navigator heatmap.json
    python -m app.cli search nfs8u9aw[.]shop
    python -m app.cli hash-file ~/Downloads/arquivo_suspeito.dmg   # hash local; o arquivo não é enviado
    python -m app.cli incident open <hash> --host mbp-dev-01 --owner ana
    python -m app.cli incident export 1 --pdf incidente.pdf
"""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from typing import Any

SIEM_CHOICES = ["all", "splunk", "sentinel", "elastic", "qradar", "secops", "wazuh", "sigma"]
COLOR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def _client():
    from fastapi.testclient import TestClient

    from app.main import create_app

    return TestClient(create_app())


def _check(r: Any) -> Any:
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        if isinstance(detail, list):  # erro de validação do FastAPI (422)
            detail = "; ".join(str(d.get("msg", d)) for d in detail if isinstance(d, dict)) or str(detail)
            if "pattern" in detail:
                detail = "hash inválido — use MD5 (32), SHA-1 (40) ou SHA-256 (64) caracteres hexadecimais"
        sys.exit(_c(f"Erro {r.status_code}: {detail}", "31"))
    return r


def _save(path: str, content: bytes | str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    print(_c(f"  ✔ salvo: {p.resolve()}", "32"))


def _save_pdf_or_html(c: Any, pdf_url: str, html_url: str, out: str) -> None:
    r = c.get(pdf_url)
    if r.status_code == 501:  # WeasyPrint/Pango ausente (comum no Windows)
        html_out = str(Path(out).with_suffix(".html"))
        _save(html_out, _check(c.get(html_url)).text)
        print(_c("  ! PDF indisponível neste PC (WeasyPrint/Pango). Abra o HTML e use Imprimir > Salvar como PDF.", "33"))
        return
    _save(out, _check(r).content)


# ------------------------------------------------------------------ comandos
def _port_free(host: str, port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host if host != "0.0.0.0" else "127.0.0.1", port)) != 0  # noqa: S104


def _already_running(host: str, port: int) -> bool:
    """Outra instância do CTI Triage já está nessa porta?"""
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/health", timeout=1.5) as r:  # noqa: S104,S310
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def cmd_serve(a: argparse.Namespace) -> None:
    import threading

    import uvicorn

    from app.banner import G, box, style

    if not _port_free(a.host, a.port):
        if _already_running(a.host, a.port):
            url = f"http://127.0.0.1:{a.port}"
            print(style(f"  {G['info']} O CTI Triage já está rodando em {url} — abrindo o navegador.", "cyan"))
            if a.open:
                webbrowser.open(url)
            return
        for p in range(a.port + 1, a.port + 20):
            if _port_free(a.host, p):
                print(style(f"  {G['warn']} Porta {a.port} ocupada por outro programa; usando {p}.", "yellow"))
                a.port = p
                break
    url = f"http://{'127.0.0.1' if a.host == '0.0.0.0' else a.host}:{a.port}"  # noqa: S104
    print(box([
        f"{style('Interface ', 'gray')} {style(url, 'bold', 'cyan')}",
        f"{style('API docs  ', 'gray')} {style(url + '/docs', 'cyan')}",
        f"{style('Parar     ', 'gray')} Ctrl+C ou feche esta janela",
    ], title=style("Servidor no ar", "bold", "green"), color="green"))
    print()
    if a.open:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run("app.main:app", host=a.host, port=a.port, log_level="warning" if a.quiet else "info")


def cmd_check(a: argparse.Namespace) -> None:
    """Valida as chaves de API (VirusTotal / MalwareBazaar) e mostra o estado das integrações."""
    from app.banner import G, box, style
    from app.config import get_settings
    from app.healthcheck import run_all

    results = run_all(get_settings(), online=not a.offline)
    if a.json:
        print(json.dumps(results, ensure_ascii=False))
        return
    icon = {"ok": (G["ok"], "green"), "invalid": (G["fail"], "red"), "error": (G["warn"], "yellow"),
            "missing": (G["off"], "yellow"), "mock": (G["off"], "yellow"), "off": (G["off"], "gray")}
    lines = []
    for r in results:
        ic, col = icon.get(r["status"], (G["info"], "white"))
        lines.append(f"{style(ic, 'bold', col)} {r['service']:<14} {style(r['detail'], 'gray' if col == 'gray' else col)}")
    print(box(lines, title=style("Integrações", "bold")))
    if any(r["status"] == "invalid" for r in results):
        sys.exit(2)


def cmd_analyze(a: argparse.Namespace) -> None:
    with _client() as c:
        d = _check(c.get(f"/api/v1/analyze/{a.hash}", params={"force": a.force})).json()
        t = d["triage"]
        verdict_color = {"malicious": "31", "suspicious": "33", "benign": "32"}.get(t["verdict"], "37")
        print(f"\n{_c(t['malware_family'], '1')}  [{_c(t['verdict'].upper(), verdict_color)}]  confiança {t['confidence']}%")
        print(f"  hash    {d['hash']}")
        print(f"  fontes  {d['source']}  ·  motor {d['engine']}  ·  score {d['heuristic_score']}/100"
              + (f"  ·  {_c('dados simulados', '33')}" if d["features"].get("simulated") else ""))
        for k, v in d.get("source_errors", {}).items():
            print(_c(f"  ! {k}: {v}", "33"))
        print(f"\n  {t['summary']}\n")
        if t["mitre_attack"]:
            print("  ATT&CK: " + ", ".join(f"{x['id']}" for x in t["mitre_attack"]))
        iocs = t["iocs"]
        print("  IoCs:   " + ", ".join([*iocs["domains"], *iocs["ips"]]) if (iocs["domains"] or iocs["ips"]) else "  IoCs:   —")
        if iocs.get("abused_services"):
            print("  Serviços abusados (não bloquear inteiro): " + ", ".join(iocs["abused_services"]))
        print()
        if a.json:
            _save(a.json, json.dumps(d, ensure_ascii=False, indent=2))
        if a.html:
            _save(a.html, _check(c.get(f"/api/v1/report/{a.hash}", params={"siem": a.siem})).text)
        if a.pdf:
            _save_pdf_or_html(c, f"/api/v1/report/{a.hash}/pdf?siem={a.siem}", f"/api/v1/report/{a.hash}?siem={a.siem}", a.pdf)


def file_hashes(path: str) -> dict[str, str]:
    """MD5/SHA-1/SHA-256 lendo o arquivo em blocos, só leitura: nada é executado nem enviado."""
    import hashlib

    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}  # noqa: S324 - identificação, não criptografia
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            for h in hs.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in hs.items()}


def cmd_hash_file(a: argparse.Namespace) -> None:
    p = Path(a.file)
    if not p.is_file():
        sys.exit(_c(f"Arquivo não encontrado: {p}", "31"))
    hs = file_hashes(str(p))
    print(f"\n  {p.name}  ({p.stat().st_size} bytes)")
    for k, v in hs.items():
        print(f"  {k:<7} {v}")
    print(_c("  O arquivo foi apenas lido: não foi executado nem enviado. Só o hash é consultado.\n", "36"))
    if not a.no_lookup:
        cmd_analyze(argparse.Namespace(hash=hs["sha256"], force=False, json=None, html=None, pdf=a.pdf, siem="none"))


def cmd_dfir(a: argparse.Namespace) -> None:
    with _client() as c:
        params = {"os": a.os} if a.os else {}
        plan = _check(c.get(f"/api/v1/dfir/{a.hash}", params=params)).json()
        print(f"\n  Plano DFIR — {plan['family']} · SO: {plan['os']} (detectado: {plan['recommended_os'] or 'n/d'})")
        for t in plan["technique_checks"]:
            print(f"  [{t['technique']}] {t['check']}\n      {t['command']}")
        out = a.out or plan["script"]
        _save(out, _check(c.get(f"/api/v1/dfir/{a.hash}/script", params=params)).content)
        print(f"  Rode no host isolado: {plan['how_to_run']}\n")


def cmd_hunt(a: argparse.Namespace) -> None:
    with _client() as c:
        md = _check(c.get(f"/api/v1/hunt/{a.hash}", params={"siem": a.siem, "format": "markdown"})).text
        if a.out:
            _save(a.out, md)
        else:
            print(md)


def cmd_attack(a: argparse.Namespace) -> None:
    with _client() as c:
        data = _check(c.get(f"/api/v1/attack/{a.hash}")).json()
        for t in data["techniques"]:
            print(f"  {t['id']:<11} {t.get('tactic', ''):<22} {t.get('name', '')}")
        if a.navigator:
            _save(a.navigator, _check(c.get(f"/api/v1/attack/{a.hash}", params={"format": "navigator"})).text)
            print("  Abra em https://mitre-attack.github.io/attack-navigator/ > Open Existing Layer > Upload from local")
        if a.csv:
            _save(a.csv, _check(c.get(f"/api/v1/attack/{a.hash}", params={"format": "csv"})).text)


def cmd_attack_import(a: argparse.Namespace) -> None:
    content = Path(a.file).read_text(encoding="utf-8-sig")
    ctype = "application/json" if a.file.lower().endswith(".json") else "text/csv"
    with _client() as c:
        r = _check(c.post(f"/api/v1/attack/{a.hash}/import", params={"mode": a.mode}, content=content,
                          headers={"content-type": ctype})).json()
        print(_c(f"  ✔ {r['imported']} técnica(s) importada(s) ({a.mode}); total no scan: {r['total']}", "32"))


def cmd_heatmap(a: argparse.Namespace) -> None:
    with _client() as c:
        data = _check(c.get("/api/v1/attack/heatmap")).json()
        print(f"  {data['scans']} scan(s)")
        for t in data["techniques"][:40]:
            print(f"  {t['scans']:>3}×  {t['id']:<11} {t['name']}  ({', '.join(t['families'])})")
        if a.navigator:
            _save(a.navigator, _check(c.get("/api/v1/attack/heatmap", params={"format": "navigator"})).text)
        if a.csv:
            _save(a.csv, _check(c.get("/api/v1/attack/heatmap", params={"format": "csv"})).text)


def cmd_search(a: argparse.Namespace) -> None:
    with _client() as c:
        d = _check(c.get("/api/v1/search", params={"q": a.indicator})).json()
        s = d["reputation"].get("last_analysis_stats", {})
        print(f"\n  {d['type']}: {d['query']}  ·  maliciosos {s.get('malicious', 0)}  ·  suspeitos {s.get('suspicious', 0)}")
        for r in d["related_scans"]:
            print(f"  ↳ {r['malware_family']} [{r['verdict']}] {r['hash']}")
        print()


def cmd_history(a: argparse.Namespace) -> None:
    with _client() as c:
        for i in _check(c.get("/api/v1/history", params={"limit": a.limit})).json()["items"]:
            print(f"  {i['created_at'][:19]}  {i['verdict']:<10} {i['confidence']:>3}%  {i['malware_family']:<18} {i['hash']}")


def cmd_incident(a: argparse.Namespace) -> None:
    with _client() as c:
        if a.action == "open":
            body = {"hash": a.target, "owner": a.owner, "hosts": a.host or [], "severity": a.severity, "title": a.title}
            inc = _check(c.post("/api/v1/incidents", json={k: v for k, v in body.items() if v not in (None, [])})).json()
            print(_c(f"  ✔ Incidente #{inc['id']} aberto — severidade {inc['severity']} — {inc['tasks_total']} tarefas", "32"))
            for ph in inc["phases"]:
                if ph["total"]:
                    print(f"    {ph['phase']:<20} {ph['total']} tarefa(s)")
        elif a.action == "list":
            for i in _check(c.get("/api/v1/incidents")).json():
                print(f"  #{i['id']:<4} {i['severity']:<8} {i['status']:<11} {i['tasks_done']}/{i['tasks_total']}  {i['title']}")
        elif a.action == "show":
            inc = _check(c.get(f"/api/v1/incidents/{a.target}")).json()
            print(f"\n  #{inc['id']} {inc['title']}  [{inc['severity']} · {inc['status']} · {inc['progress']}%]")
            for t in inc["tasks"]:
                mark = "x" if t["status"] in ("concluida", "nao_aplicavel") else " "
                print(f"   [{mark}] ({t['id']:>3}) {t['phase']:<20} {t['title']}")
        elif a.action == "task":
            inc = _check(c.patch(f"/api/v1/incidents/{a.target}/tasks/{a.task_id}",
                                 json={"status": a.status, "note": a.note, "author": a.owner})).json()
            print(_c(f"  ✔ progresso: {inc['progress']}%", "32"))
        elif a.action == "status":
            _check(c.patch(f"/api/v1/incidents/{a.target}", json={"status": a.status, "author": a.owner}))
            print(_c(f"  ✔ status: {a.status}", "32"))
        elif a.action == "note":
            _check(c.post(f"/api/v1/incidents/{a.target}/events", json={"message": a.note, "author": a.owner}))
            print(_c("  ✔ anotação registrada", "32"))
        elif a.action == "export":
            base = f"/api/v1/incidents/{a.target}/export"
            if a.md:
                _save(a.md, _check(c.get(base, params={"format": "markdown"})).text)
            if a.pdf:
                _save_pdf_or_html(c, f"{base}?format=pdf", f"{base}?format=html", a.pdf)


# ------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.cli", description="CTI Triage — análise de malware, hunting e resposta a incidentes")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="sobe a interface web local")
    s.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 só se quiser expor na rede")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--open", action="store_true", help="abre o navegador")
    s.add_argument("--quiet", action="store_true", help="log do servidor só com avisos")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("check", help="valida as chaves do VirusTotal/MalwareBazaar e o estado das integrações")
    s.add_argument("--offline", action="store_true", help="não consulta as APIs, só confere o .env")
    s.add_argument("--json", action="store_true", help="saída JSON")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("analyze", help="analisa um hash (VT + MalwareBazaar + IA)")
    s.add_argument("hash")
    s.add_argument("--force", action="store_true", help="ignora o cache")
    s.add_argument("--json"), s.add_argument("--html"), s.add_argument("--pdf")
    s.add_argument("--siem", choices=[*SIEM_CHOICES, "none"], default="all", help="apêndice de hunting do relatório")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("hash-file", help="calcula o hash de um arquivo suspeito localmente e consulta só o hash")
    s.add_argument("file")
    s.add_argument("--no-lookup", action="store_true", help="só calcula o hash, sem consultar VT/MB")
    s.add_argument("--pdf", help="salvar relatório PDF da triagem")
    s.set_defaults(func=cmd_hash_file)

    s = sub.add_parser("dfir", help="gera o script de triagem forense do host (macOS/Windows/Linux)")
    s.add_argument("hash")
    s.add_argument("--os", choices=["macos", "windows", "linux"], help="padrão: SO detectado na triagem")
    s.add_argument("--out", help="arquivo de saída (padrão: triagem_<so>.sh/.ps1)")
    s.set_defaults(func=cmd_dfir)

    s = sub.add_parser("hunt", help="gera consultas de threat hunting")
    s.add_argument("hash")
    s.add_argument("--siem", choices=SIEM_CHOICES, default="all")
    s.add_argument("--out", help="arquivo .md (padrão: imprime na tela)")
    s.set_defaults(func=cmd_hunt)

    s = sub.add_parser("attack", help="lista/exporta técnicas ATT&CK de um scan")
    s.add_argument("hash")
    s.add_argument("--navigator", help="salvar layer JSON do ATT&CK Navigator")
    s.add_argument("--csv", help="salvar CSV")
    s.set_defaults(func=cmd_attack)

    s = sub.add_parser("attack-import", help="importa layer do Navigator (.json) ou CSV para um scan")
    s.add_argument("hash")
    s.add_argument("file")
    s.add_argument("--mode", choices=["merge", "replace"], default="merge")
    s.set_defaults(func=cmd_attack_import)

    s = sub.add_parser("heatmap", help="heatmap ATT&CK de todo o histórico")
    s.add_argument("--navigator"), s.add_argument("--csv")
    s.set_defaults(func=cmd_heatmap)

    s = sub.add_parser("search", help="reputação de IP/domínio/URL + scans relacionados")
    s.add_argument("indicator")
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("history", help="últimos scans")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("incident", help="resposta a incidentes")
    s.add_argument("action", choices=["open", "list", "show", "task", "status", "note", "export"])
    s.add_argument("target", nargs="?", help="hash (open) ou id do incidente")
    s.add_argument("task_id", nargs="?", type=int, help="id da tarefa (action=task)")
    s.add_argument("--host", action="append", help="host afetado (repita para vários)")
    s.add_argument("--owner"), s.add_argument("--title"), s.add_argument("--note")
    s.add_argument("--severity", choices=["baixa", "media", "alta", "critica"])
    s.add_argument("--status", help="status da tarefa (pendente|em_andamento|concluida|nao_aplicavel) ou do incidente")
    s.add_argument("--pdf"), s.add_argument("--md")
    s.set_defaults(func=cmd_incident)
    return p


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # acentos no terminal do Windows
    args = build_parser().parse_args(argv)
    if args.cmd not in ("serve", "check"):
        import logging
        import os

        os.environ.setdefault("LOG_LEVEL", "ERROR")  # saída limpa no terminal
        logging.disable(logging.WARNING)
    args.func(args)


if __name__ == "__main__":
    main()
