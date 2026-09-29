"""Exportação/importação da tabela MITRE ATT&CK.

Formatos:
* **ATT&CK Navigator layer (JSON, layer 4.5)** — abre direto em https://mitre-attack.github.io/attack-navigator/
  ("Open Existing Layer" -> "Upload from local"). Também é o formato de importação.
* **CSV** — `technique_id,technique_name,tactic[,scans,families]` para planilhas/SIEM/GRC.

O heatmap agrega todos os scans do histórico: score = nº de scans em que a técnica aparece.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.security import csv_safe

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ATTACK_VERSION = "17"
NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"

# Nome da tática (como vem do LLM/relatório) -> shortname usado pelo Navigator
TACTIC_SHORTNAMES: dict[str, str] = {
    "reconnaissance": "reconnaissance", "resource development": "resource-development",
    "initial access": "initial-access", "execution": "execution", "persistence": "persistence",
    "privilege escalation": "privilege-escalation", "defense evasion": "defense-evasion",
    "credential access": "credential-access", "discovery": "discovery", "lateral movement": "lateral-movement",
    "collection": "collection", "command and control": "command-and-control", "exfiltration": "exfiltration",
    "impact": "impact",
}
_SHORT_TO_NAME = {v: k.title().replace("And", "and") for k, v in TACTIC_SHORTNAMES.items()}


class AttackImportError(ValueError):
    """Arquivo de importação inválido."""


def tactic_shortname(tactic: str | None) -> str | None:
    if not tactic:
        return None
    key = tactic.strip().lower().replace("-", " ").replace("_", " ").replace("&", "and")
    return TACTIC_SHORTNAMES.get(key) or (key.replace(" ", "-") if key.replace(" ", "-") in _SHORT_TO_NAME else None)


def _clean(techniques: list[dict[str, Any]]) -> list[dict[str, str]]:
    seen: dict[tuple[str, str], dict[str, str]] = {}
    for t in techniques:
        tid = str(t.get("id") or t.get("techniqueID") or "").strip().upper()
        if not TECHNIQUE_RE.match(tid):
            continue
        tac = t.get("tactic") or ""
        seen[(tid, tac)] = {"id": tid, "name": str(t.get("name") or "").strip(), "tactic": tac}
    return list(seen.values())


# ------------------------------------------------------------------ exportação
def _layer(name: str, description: str, techniques: list[dict[str, Any]], max_score: int,
           metadata: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows", "macOS", "Linux", "Network", "PRE", "Containers", "IaaS",
                                  "SaaS", "Office Suite", "Identity Provider"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#fff7b3", "#ffe600", "#d92d20"], "minValue": 0, "maxValue": max(1, max_score)},
        "legendItems": [{"label": "Observado no artefato", "color": "#ffe600"},
                        {"label": "Recorrente em vários scans", "color": "#d92d20"}],
        "metadata": metadata,
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2D3277",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def _nav_technique(t: dict[str, str], score: int, comment: str, meta: list[dict[str, str]]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "techniqueID": t["id"], "score": score, "color": "", "comment": comment,
        "enabled": True, "metadata": meta, "links": [], "showSubtechniques": True,
    }
    if (short := tactic_shortname(t.get("tactic"))):
        item["tactic"] = short
    return item


def scan_to_layer(scan: dict[str, Any]) -> dict[str, Any]:
    t = scan["triage"]
    techniques = _clean(t.get("mitre_attack", []))
    items = [
        _nav_technique(x, 1, x.get("name", ""), [{"name": "family", "value": t.get("malware_family", "")},
                                                 {"name": "sha256", "value": scan["hash"]}])
        for x in techniques
    ]
    return _layer(
        name=f"{t.get('malware_family', 'unknown')} — {scan['hash'][:12]}",
        description=f"Técnicas ATT&CK da triagem do artefato {scan['hash']} (veredito: {t.get('verdict')}).",
        techniques=items, max_score=1,
        metadata=[{"name": "sha256", "value": scan["hash"]}, {"name": "engine", "value": str(scan.get("engine", ""))},
                  {"name": "exported_at", "value": datetime.now(timezone.utc).isoformat()}],
    )


def aggregate(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agrupa técnicas de vários scans: [{id, name, tactic, scans, families, hashes}]."""
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for s in scans:
        for t in _clean(s["triage"].get("mitre_attack", [])):
            key = (t["id"], t["tactic"])
            row = agg.setdefault(key, {**t, "hashes": set(), "families": set()})
            row["name"] = row["name"] or t["name"]
            row["hashes"].add(s["hash"])
            row["families"].add(s["triage"].get("malware_family", "unknown"))
    out = [{**r, "scans": len(r["hashes"]), "hashes": sorted(r["hashes"]), "families": sorted(r["families"])}
           for r in agg.values()]
    return sorted(out, key=lambda r: (-r["scans"], r["id"]))


def heatmap_layer(scans: list[dict[str, Any]]) -> dict[str, Any]:
    rows = aggregate(scans)
    items = [
        _nav_technique(r, r["scans"], f"{r['name']} — {r['scans']} scan(s): {', '.join(r['families'])}",
                       [{"name": "families", "value": ", ".join(r["families"])}])
        for r in rows
    ]
    return _layer(
        name="Heatmap de técnicas — histórico de scans",
        description=f"Frequência das técnicas ATT&CK em {len(scans)} scan(s). Score = nº de scans.",
        techniques=items, max_score=max((r["scans"] for r in rows), default=1),
        metadata=[{"name": "scans", "value": str(len(scans))},
                  {"name": "exported_at", "value": datetime.now(timezone.utc).isoformat()}],
    )


def to_csv(rows: list[dict[str, Any]], *, aggregate_mode: bool = False) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    if aggregate_mode:
        w.writerow(["technique_id", "technique_name", "tactic", "scans", "families"])
        for r in rows:
            w.writerow([csv_safe(x) for x in (r["id"], r["name"], r["tactic"], r["scans"], "; ".join(r["families"]))])
    else:
        w.writerow(["technique_id", "technique_name", "tactic"])
        for r in _clean(rows):
            w.writerow([csv_safe(x) for x in (r["id"], r["name"], r["tactic"])])
    return buf.getvalue()


# ------------------------------------------------------------------ importação
def parse_import(content: str, content_type: str = "") -> list[dict[str, str]]:
    """Lê um layer do Navigator (JSON) ou CSV e devolve técnicas normalizadas."""
    text = content.strip().lstrip("﻿")
    if not text:
        raise AttackImportError("Arquivo vazio")
    if "json" in content_type or text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AttackImportError(f"JSON inválido: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("techniques"), list):
            raise AttackImportError("Não parece um layer do ATT&CK Navigator (campo 'techniques' ausente)")
        if data.get("domain") not in (None, "enterprise-attack"):
            raise AttackImportError(f"Domínio não suportado: {data.get('domain')} (use enterprise-attack)")
        items = [
            {"id": t.get("techniqueID"),
             "name": (t.get("comment") or "").split(" — ")[0],
             "tactic": _SHORT_TO_NAME.get(t.get("tactic") or "", "")}
            for t in data["techniques"]
            if isinstance(t, dict) and t.get("enabled", True) is not False
            and (t.get("score") not in (0,) or t.get("comment") or t.get("color"))
        ]
    else:
        reader = csv.DictReader(io.StringIO(text))
        fields = {f.lower().strip() for f in reader.fieldnames or []}
        id_col = next((c for c in ("technique_id", "techniqueid", "id", "technique") if c in fields), None)
        if not id_col:
            raise AttackImportError("CSV sem coluna 'technique_id'")
        items = []
        for row in reader:
            r = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}
            items.append({"id": r.get(id_col), "name": r.get("technique_name") or r.get("name", ""),
                          "tactic": r.get("tactic", "")})
    techniques = _clean(items)
    if not techniques:
        raise AttackImportError("Nenhuma técnica válida encontrada (formato esperado: T1234 ou T1234.001)")
    return techniques


def merge_techniques(current: list[dict[str, Any]], imported: list[dict[str, str]], mode: str) -> list[dict[str, str]]:
    """mode='merge' une (preservando nomes existentes); mode='replace' substitui."""
    if mode not in {"merge", "replace"}:
        raise AttackImportError("mode deve ser 'merge' ou 'replace'")
    names = {t["id"]: t["name"] for t in _clean(current) if t.get("name")}
    base = [] if mode == "replace" else _clean(current)
    merged = {(t["id"], t["tactic"]): t for t in base}
    for t in imported:
        t = {**t, "name": t["name"] or names.get(t["id"], "")}
        # se a mesma técnica já existe sem tática, substitui pela versão com tática
        merged.pop((t["id"], ""), None)
        if not t["tactic"] and any(k[0] == t["id"] for k in merged):
            continue
        merged[(t["id"], t["tactic"])] = t
    return sorted(merged.values(), key=lambda x: (x["tactic"], x["id"]))
