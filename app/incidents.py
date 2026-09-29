"""Módulo de Resposta a Incidentes.

Cria um incidente a partir de um scan e gera um playbook no ciclo do NIST SP 800-61
(Detecção e Análise → Contenção → Erradicação → Recuperação → Pós-incidente), com tarefas
derivadas da própria triagem: IoCs a bloquear, hunts a executar, persistência a remover,
credenciais a revogar etc. Tudo fica no SQLite com linha do tempo (auditoria).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import Any

from app.database import Database

PHASES: list[str] = ["Detecção e Análise", "Contenção", "Erradicação", "Recuperação", "Pós-incidente"]
INCIDENT_STATUS: list[str] = ["aberto", "em_analise", "contido", "erradicado", "recuperado", "encerrado"]
TASK_STATUS: list[str] = ["pendente", "em_andamento", "concluida", "nao_aplicavel"]
SEVERITIES: list[str] = ["baixa", "media", "alta", "critica"]


class IncidentError(ValueError):
    status_code = 400


class IncidentNotFound(IncidentError):
    status_code = 404


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def suggest_severity(scan: dict[str, Any], hosts: list[str]) -> str:
    t = scan["triage"]
    text = " ".join([t.get("threat_category", ""), *t.get("family_aliases", []),
                     *(a.get("tactic", "") for a in t.get("mitre_attack", []))]).lower()
    if t.get("verdict") == "malicious":
        if hosts:
            return "critica"
        return "alta" if any(k in text for k in ("stealer", "backdoor", "ransom", "credential", "rat")) else "media"
    return "media" if t.get("verdict") == "suspicious" else "baixa"


def build_playbook(scan: dict[str, Any], hunts: list[dict[str, Any]] | None = None) -> list[tuple[str, str, str]]:
    """Gera [(fase, título, detalhe)] a partir da triagem."""
    t, f = scan["triage"], scan["features"]
    iocs = t.get("iocs", {})
    fam = t.get("malware_family", "unknown")
    tids = {a.get("id", "") for a in t.get("mitre_attack", [])}
    text = " ".join([t.get("threat_category", ""), t.get("summary", ""), *f.get("meta", {}).get("tags", [])]).lower()
    is_mac = "mac" in (t.get("platform") or "").lower()
    plat = (t.get("platform") or "").lower()
    script = "triagem_macos.sh" if is_mac else "triagem_linux.sh" if "linux" in plat else "triagem_windows.ps1"
    stealer = any(k in text for k in ("stealer", "credential", "psw")) or any(x.startswith(("T1555", "T1539", "T1056")) for x in tids)
    persistence = any(x.startswith(("T1543", "T1547", "T1053")) for x in tids) or "persistence" in text

    pb: list[tuple[str, str, str]] = [
        ("Detecção e Análise", "Validar a triagem e o escopo",
         f"Confirmar veredito '{t.get('verdict')}' e família {fam} (confiança {t.get('confidence')}%). "
         "Registrar fonte do alerta, primeiro host e primeiro horário conhecidos."),
    ]
    for h in hunts or []:
        pb.append(("Detecção e Análise", f"Executar hunt {h['id']}: {h['title']}",
                   f"Hipótese: {h['hypothesis']} Fontes: {', '.join(h['data_sources'])}. Registrar hosts positivos no incidente."))
    pb += [
        ("Detecção e Análise", "Executar a triagem DFIR nos hosts afetados",
         f"Com o host isolado, rodar o script gerado na aba DFIR (`{script}`): somente leitura, sem rede, coleta na ordem de "
         "volatilidade (RFC 3227) e gera MANIFESTO_SHA256.txt. Anexar o pacote .zip ao incidente."),
        ("Detecção e Análise", "Preservar evidências e cadeia de custódia",
         ("macOS: `sudo log collect --last 3d`; " if is_mac else "Se possível, capturar a memória antes de qualquer limpeza; ")
         + "registrar quem coletou, quando e o SHA-256 de cada pacote. Amostras em zip com senha 'infected'."),
        ("Detecção e Análise", "Definir linha do tempo e paciente zero",
         "Correlacionar primeiro download/execução, primeiro contato com C2 e acessos com credenciais do usuário."),
        ("Contenção", "Isolar hosts afetados no EDR", "Isolamento de rede mantendo o canal do EDR. Não desligar a máquina (perde memória)."),
        ("Contenção", "Bloquear hash no EDR/antivírus", f"SHA-256 {scan['hash']}."),
    ]
    if iocs.get("domains") or iocs.get("ips"):
        pb.append(("Contenção", "Bloquear infraestrutura de C2 (DNS/proxy/firewall)",
                   "Sinkhole/bloqueio: " + ", ".join([*iocs.get("domains", []), *iocs.get("ips", [])])))
    if iocs.get("urls") and iocs.get("abused_services"):
        pb.append(("Contenção", "Bloquear URLs específicas do Dead Drop Resolver",
                   "Bloquear apenas as URLs/perfis (" + ", ".join(iocs["urls"]) + "), não o serviço inteiro ("
                   + ", ".join(iocs["abused_services"]) + "). Denunciar as contas à plataforma."))
    if stealer:
        pb += [
            ("Contenção", "Revogar sessões e tokens dos usuários afetados",
             "Revogar sessões no IdP/SSO, consoles de nuvem, GitHub/GitLab, Slack e e-mail. Cookies roubados contornam MFA."),
            ("Contenção", "Rotacionar credenciais", "Senha do sistema, senhas salvas no navegador/Keychain, chaves SSH e tokens de API do host."),
        ]
    if persistence:
        pb.append(("Erradicação", "Remover persistência",
                   ("`launchctl bootout gui/<uid> <plist>` e remover o plist e o payload em ~/Library. " if is_mac
                    else "Remover serviço/tarefa/Run key criados. ")
                   + "Verificar o parque inteiro (hunt de persistência)."))
    pb += [
        ("Erradicação", "Remover artefatos e confirmar limpeza", "Varredura completa no EDR; confirmar ausência de IoCs após a remoção."),
        ("Erradicação", "Reimagem dos hosts de alto privilégio", "Para máquinas de admins/devs/executivos, preferir reimagem a limpeza."),
        ("Recuperação", "Restaurar operação dos hosts", "Retirar isolamento após validação; restaurar dados de backup confiável se necessário."),
        ("Recuperação", "Monitoramento reforçado por 30 dias", "Regras dos hunts em modo detecção; alertar em reincidência dos IoCs/comportamentos."),
    ]
    if stealer:
        pb.append(("Recuperação", "Verificar uso indevido das credenciais",
                   "Logins anômalos (geo/ASN/dispositivo) nas contas afetadas; monitorar vazamento em feeds de stealer logs. "
                   "Se houver carteiras cripto no host, mover fundos para nova seed em dispositivo limpo."))
    pb += [
        ("Pós-incidente", "Converter hunts em detecções", "Promover as consultas validadas a regras agendadas no SIEM, com dono e SLA."),
        ("Pós-incidente", "Atualizar inteligência (TIP) e ATT&CK", "Registrar IoCs, TTPs e o layer do Navigator; compartilhar conforme TLP."),
        ("Pós-incidente", "Reunião de lições aprendidas", "O que falhou na prevenção/detecção? Ações com responsáveis e prazos."),
        ("Pós-incidente", "Relatório final do incidente", "Exportar o relatório (PDF) e anexar evidências e linha do tempo."),
    ]
    return pb


class IncidentStore:
    """CRUD de incidentes sobre o mesmo SQLite da aplicação."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ----------------------------------------------------------------- create
    def create_from_scan(self, scan: dict[str, Any], *, title: str | None = None, severity: str | None = None,
                         owner: str | None = None, hosts: list[str] | None = None,
                         hunts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        hosts = sorted({h.strip() for h in hosts or [] if h and h.strip()})
        severity = severity or suggest_severity(scan, hosts)
        if severity not in SEVERITIES:
            raise IncidentError(f"severity deve ser um de {SEVERITIES}")
        t = scan["triage"]
        verdict_pt = {"malicious": "malicioso", "suspicious": "suspeito", "benign": "benigno"}.get(t.get("verdict", ""), "indeterminado")
        title = title or f"{t.get('malware_family', 'Malware')} — {verdict_pt} ({scan['hash'][:12]})"
        now = _now()
        with self.db._conn() as conn:
            cur = conn.execute(
                """INSERT INTO incidents (title, severity, status, scan_hash, family, owner, hosts_json, summary, created_at, updated_at)
                   VALUES (?, ?, 'aberto', ?, ?, ?, ?, ?, ?, ?)""",
                (title, severity, scan["hash"], t.get("malware_family"), owner, json.dumps(hosts), t.get("summary"), now, now),
            )
            iid = int(cur.lastrowid or 0)
            conn.executemany(
                """INSERT INTO incident_tasks (incident_id, phase, position, title, detail, status, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'pendente', ?)""",
                [(iid, ph, i, ti, de, now) for i, (ph, ti, de) in enumerate(build_playbook(scan, hunts))],
            )
            conn.execute(
                "INSERT INTO incident_events (incident_id, ts, author, kind, message) VALUES (?, ?, ?, 'criacao', ?)",
                (iid, now, owner or "sistema", f"Incidente aberto a partir do scan {scan['hash']} (severidade {severity})."),
            )
        return self.get(iid)

    # ------------------------------------------------------------------- read
    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        clause, params = ("WHERE i.status = ?", [status]) if status else ("", [])
        with self.db._conn() as conn:
            rows = conn.execute(
                f"""SELECT i.*, COUNT(t.id) AS tasks_total,
                           SUM(CASE WHEN t.status IN ('concluida','nao_aplicavel') THEN 1 ELSE 0 END) AS tasks_done
                    FROM incidents i LEFT JOIN incident_tasks t ON t.incident_id = i.id
                    {clause} GROUP BY i.id ORDER BY i.id DESC""",
                params,
            ).fetchall()
        return [self._incident_row(r) for r in rows]

    def get(self, incident_id: int) -> dict[str, Any]:
        with self.db._conn() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not row:
                raise IncidentNotFound(f"Incidente {incident_id} não encontrado")
            tasks = conn.execute(
                "SELECT * FROM incident_tasks WHERE incident_id = ? ORDER BY position", (incident_id,)).fetchall()
            events = conn.execute(
                "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()
        inc = self._incident_row(row)
        inc["tasks"] = [dict(t) for t in tasks]
        inc["events"] = [dict(e) for e in events]
        done = sum(1 for t in inc["tasks"] if t["status"] in ("concluida", "nao_aplicavel"))
        inc["tasks_total"], inc["tasks_done"] = len(inc["tasks"]), done
        inc["progress"] = round(100 * done / len(inc["tasks"])) if inc["tasks"] else 0
        inc["phases"] = [
            {"phase": ph, "total": sum(1 for t in inc["tasks"] if t["phase"] == ph),
             "done": sum(1 for t in inc["tasks"] if t["phase"] == ph and t["status"] in ("concluida", "nao_aplicavel"))}
            for ph in PHASES
        ]
        return inc

    # ----------------------------------------------------------------- update
    def update(self, incident_id: int, *, author: str | None = None, **changes: Any) -> dict[str, Any]:
        current = self.get(incident_id)
        sets, params, log = [], [], []
        if (st := changes.get("status")) is not None:
            if st not in INCIDENT_STATUS:
                raise IncidentError(f"status deve ser um de {INCIDENT_STATUS}")
            sets.append("status = ?"); params.append(st); log.append(f"status: {current['status']} → {st}")
        if (sev := changes.get("severity")) is not None:
            if sev not in SEVERITIES:
                raise IncidentError(f"severity deve ser um de {SEVERITIES}")
            sets.append("severity = ?"); params.append(sev); log.append(f"severidade: {current['severity']} → {sev}")
        if (ow := changes.get("owner")) is not None:
            sets.append("owner = ?"); params.append(ow); log.append(f"responsável: {ow}")
        if (hs := changes.get("hosts")) is not None:
            hosts = sorted({h.strip() for h in hs if h and h.strip()})
            sets.append("hosts_json = ?"); params.append(json.dumps(hosts)); log.append(f"hosts afetados: {', '.join(hosts) or '—'}")
        if not sets:
            return current
        now = _now()
        with self.db._conn() as conn:
            conn.execute(f"UPDATE incidents SET {', '.join(sets)}, updated_at = ? WHERE id = ?", [*params, now, incident_id])
            conn.execute("INSERT INTO incident_events (incident_id, ts, author, kind, message) VALUES (?, ?, ?, 'alteracao', ?)",
                         (incident_id, now, author or "analista", "; ".join(log)))
        return self.get(incident_id)

    def update_task(self, incident_id: int, task_id: int, *, status: str | None = None, owner: str | None = None,
                    note: str | None = None, author: str | None = None) -> dict[str, Any]:
        if status is not None and status not in TASK_STATUS:
            raise IncidentError(f"status da tarefa deve ser um de {TASK_STATUS}")
        now = _now()
        with self.db._conn() as conn:
            task = conn.execute("SELECT * FROM incident_tasks WHERE id = ? AND incident_id = ?",
                                (task_id, incident_id)).fetchone()
            if not task:
                raise IncidentNotFound(f"Tarefa {task_id} não encontrada no incidente {incident_id}")
            conn.execute("UPDATE incident_tasks SET status = COALESCE(?, status), owner = COALESCE(?, owner), updated_at = ? WHERE id = ?",
                         (status, owner, now, task_id))
            msg = f"Tarefa '{task['title']}'" + (f": {task['status']} → {status}" if status else "") + (f" — {note}" if note else "")
            conn.execute("INSERT INTO incident_events (incident_id, ts, author, kind, message) VALUES (?, ?, ?, 'tarefa', ?)",
                         (incident_id, now, author or "analista", msg))
            conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        return self.get(incident_id)

    def add_event(self, incident_id: int, message: str, author: str | None = None) -> dict[str, Any]:
        self.get(incident_id)
        if not message.strip():
            raise IncidentError("Mensagem vazia")
        now = _now()
        with self.db._conn() as conn:
            conn.execute("INSERT INTO incident_events (incident_id, ts, author, kind, message) VALUES (?, ?, ?, 'nota', ?)",
                         (incident_id, now, author or "analista", message.strip()))
            conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        return self.get(incident_id)

    @staticmethod
    def _incident_row(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["hosts"] = json.loads(d.pop("hosts_json") or "[]")
        d["tasks_total"] = d.get("tasks_total") or 0
        d["tasks_done"] = d.get("tasks_done") or 0
        return d


# ----------------------------------------------------------------- exportação
_STATUS_LABEL = {"pendente": "☐ pendente", "em_andamento": "◐ em andamento", "concluida": "☑ concluída",
                 "nao_aplicavel": "— n/a"}


def incident_markdown(inc: dict[str, Any]) -> str:
    out = [f"# Incidente #{inc['id']} — {inc['title']}", "",
           f"- **Severidade:** {inc['severity']}  ·  **Status:** {inc['status']}  ·  **Responsável:** {inc.get('owner') or '—'}",
           f"- **Artefato:** `{inc.get('scan_hash')}` ({inc.get('family')})",
           f"- **Hosts afetados:** {', '.join(inc['hosts']) or '—'}",
           f"- **Progresso:** {inc['progress']}% ({inc['tasks_done']}/{inc['tasks_total']} tarefas)",
           f"- **Aberto em:** {inc['created_at']}  ·  **Atualizado em:** {inc['updated_at']}", "",
           "## Resumo", "", inc.get("summary") or "—", ""]
    for ph in PHASES:
        tasks = [t for t in inc["tasks"] if t["phase"] == ph]
        if not tasks:
            continue
        out += [f"## {ph}", ""]
        out += [f"- [{'x' if t['status'] in ('concluida', 'nao_aplicavel') else ' '}] **{t['title']}** "
                f"({_STATUS_LABEL.get(t['status'], t['status'])}{', ' + t['owner'] if t.get('owner') else ''}) — {t.get('detail') or ''}"
                for t in tasks]
        out.append("")
    out += ["## Linha do tempo", "", "| Quando (UTC) | Autor | Tipo | Registro |", "|---|---|---|---|"]
    out += [f"| {e['ts'][:19].replace('T', ' ')} | {e.get('author') or ''} | {e['kind']} | {e['message'].replace('|', '/')} |"
            for e in inc["events"]]
    return "\n".join(out) + "\n"


def incident_html(inc: dict[str, Any], css: str, header_html: str) -> str:
    sev_color = {"baixa": "#039855", "media": "#DC6803", "alta": "#D92D20", "critica": "#7A271A"}[inc["severity"]]
    phases = ""
    for ph in PHASES:
        tasks = [t for t in inc["tasks"] if t["phase"] == ph]
        if not tasks:
            continue
        rows = "".join(
            f"<tr><td style='width:22%'><span class='chip'>{escape(_STATUS_LABEL.get(t['status'], t['status']))}</span></td>"
            f"<td><b>{escape(t['title'])}</b><br><span class='muted'>{escape(t.get('detail') or '')}</span></td>"
            f"<td style='width:14%'>{escape(t.get('owner') or '')}</td></tr>" for t in tasks)
        phases += f"<h2>{escape(ph)}</h2><table><tbody>{rows}</tbody></table>"
    events = "".join(
        f"<tr><td class='mono' style='width:22%'>{escape(e['ts'][:19].replace('T', ' '))}</td><td style='width:14%'>{escape(e.get('author') or '')}</td>"
        f"<td style='width:12%'><span class='chip'>{escape(e['kind'])}</span></td><td>{escape(e['message'])}</td></tr>"
        for e in inc["events"])
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Incidente #{inc['id']}</title><style>{css}</style></head>
<body><article class="sheet">{header_html}
<div class="content">
 <div class="eyebrow">Relatório de incidente · #{inc['id']}</div>
 <div class="hero"><h1 style="font-size:20pt">{escape(inc['title'])}</h1>
  <span class="pill" style="background:{sev_color}">{escape(inc['severity'])}</span></div>
 <div class="hash">Artefato {escape(str(inc.get('scan_hash')))} · {escape(str(inc.get('family')))}</div>
 <div class="kpis">
  <div class="kpi"><div class="l">Status</div><div class="v">{escape(inc['status'])}</div></div>
  <div class="kpi"><div class="l">Progresso</div><div class="v">{inc['progress']}%</div><div class="bar"><span style="width:{inc['progress']}%"></span></div></div>
  <div class="kpi"><div class="l">Tarefas</div><div class="v">{inc['tasks_done']}/{inc['tasks_total']}</div></div>
  <div class="kpi"><div class="l">Hosts</div><div class="v">{len(inc['hosts'])}</div></div>
  <div class="kpi"><div class="l">Responsável</div><div class="v">{escape(inc.get('owner') or '—')}</div></div>
 </div>
 <h2>Resumo</h2><p class="summary">{escape(inc.get('summary') or '—')}</p>
 <h2>Hosts afetados</h2><p>{escape(', '.join(inc['hosts']) or '—')}</p>
 {phases}
 <h2>Linha do tempo</h2><table><thead><tr><th>Quando (UTC)</th><th>Autor</th><th>Tipo</th><th>Registro</th></tr></thead><tbody>{events}</tbody></table>
</div></article></body></html>"""
