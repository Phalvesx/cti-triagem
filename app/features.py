"""Extração de features relevantes do JSON do VirusTotal e do MalwareBazaar + triagem heurística determinística.

Reduzir o JSON bruto (que pode ter centenas de KB) a um resumo compacto é essencial para:
  * caber no contexto do LLM com custo baixo;
  * dar ao modelo apenas sinais úteis (menos alucinação);
  * permitir um fallback heurístico quando não há LLM configurado.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

# Tokens genéricos de nomes de detecção que NÃO identificam família
GENERIC_TOKENS: frozenset[str] = frozenset(
    {
        "trojan", "malware", "generic", "gen", "agent", "heur", "heuristic", "osx", "macos", "mac",
        "win32", "win64", "w32", "w64", "linux", "script", "variant", "malicious", "high", "confidence",
        "drp", "dropper", "downloader", "pws", "psw", "stealer", "infostealer", "backdoor", "riskware",
        "unsafe", "susp", "suspicious", "ai", "ml", "score", "static", "cloud", "behavior", "application",
        "applescript", "shell", "bat", "b", "a", "c", "d", "fo", "v", "tr", "and", "multiverze", "pua",
        "trojanpsw", "trojan-psw", "trojan-dropper", "osx32", "osx64", "virus", "worm", "adware",
    }
)
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

# Serviços legítimos frequentemente abusados como Dead Drop Resolver / hospedagem de payload.
# Bloquear o domínio inteiro quebraria o negócio: o IoC útil é a URL/perfil específico.
LEGIT_SERVICES: frozenset[str] = frozenset(
    {
        "t.me", "telegram.org", "telegram.me", "steamcommunity.com", "pastebin.com", "github.com",
        "raw.githubusercontent.com", "gist.github.com", "gitlab.com", "bitbucket.org", "discord.com",
        "cdn.discordapp.com", "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
        "x.com", "twitter.com", "youtube.com", "mega.nz", "notion.so", "telegra.ph",
    }
)


def is_legit_service(domain: str) -> bool:
    d = domain.lower().strip(".")
    return any(d == s or d.endswith("." + s) for s in LEGIT_SERVICES)


def classify_iocs(iocs: dict[str, list[str]]) -> dict[str, list[str]]:
    """Separa domínios de serviços legítimos abusados dos domínios maliciosos de fato."""
    domains = sorted({d.lower() for d in iocs.get("domains", []) if d})
    return {
        "domains": [d for d in domains if not is_legit_service(d)],
        "ips": sorted(set(iocs.get("ips", []))),
        "urls": sorted(set(iocs.get("urls", []))),
        "abused_services": sorted({*iocs.get("abused_services", []), *(d for d in domains if is_legit_service(d))}),
    }


# Mapeamento ATT&CK determinístico (usado sem LLM). Cada regra: (gatilhos, técnica, nome, tática)
_ATTACK_RULES: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
    (("applescript", "osascript"), "T1059.002", "Command and Scripting Interpreter: AppleScript", "Execution"),
    (("powershell",), "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    (("clickfix",), "T1204.004", "User Execution: Malicious Copy and Paste", "Execution"),
    (("persistence", "launchagent"), "T1543.001", "Create or Modify System Process: Launch Agent", "Persistence"),
    (("stealer", "psw", "pws", "infostealer"), "T1555", "Credentials from Password Stores", "Credential Access"),
    (("stealer", "infostealer"), "T1539", "Steal Web Session Cookie", "Credential Access"),
    (("keylog",), "T1056.001", "Input Capture: Keylogging", "Credential Access"),
    (("ddr", "dead drop"), "T1102.001", "Web Service: Dead Drop Resolver", "Command and Control"),
    (("backdoor", "rat"), "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    (("dropper", "downloader", "loader"), "T1105", "Ingress Tool Transfer", "Command and Control"),
    (("ransom",), "T1486", "Data Encrypted for Impact", "Impact"),
    (("miner", "coinminer"), "T1496", "Resource Hijacking", "Impact"),
)


def infer_attack(features: dict[str, Any]) -> list[dict[str, str]]:
    """Técnicas ATT&CK inferidas de tags, rótulos de AV, sandbox e rede (sem LLM)."""
    det = features.get("detection", {})
    corpus = " ".join(
        [
            *features.get("meta", {}).get("tags", []),
            str(features.get("meta", {}).get("type") or ""),
            *map(str, det.get("labels_by_engine", {}).values()),
            *det.get("popular_threat_categories", []),
            *features.get("malwarebazaar", {}).get("tags", []),
            *(c for v in features.get("sandbox", {}).values() for c in v.get("classification", [])),
        ]
    ).lower()
    out: dict[str, dict[str, str]] = {}
    for triggers, tid, name, tactic in _ATTACK_RULES:
        if any(tr in corpus for tr in triggers):
            out[tid] = {"id": tid, "name": name, "tactic": tactic}
    net = features.get("network", {})
    if any(is_legit_service(d) for d in net.get("domains", [])) and net.get("urls"):
        out["T1102.001"] = {"id": "T1102.001", "name": "Web Service: Dead Drop Resolver", "tactic": "Command and Control"}
    if net.get("domains") or net.get("ips"):
        out.setdefault("T1071.001", {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
                                     "tactic": "Command and Control"})
    return list(out.values())


def _ts(value: int | None) -> str | None:
    if not value:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()


def family_candidates(
    labels: list[str],
    suggested: str | None = None,
    strong_names: list[str] | None = None,
) -> list[tuple[str, int]]:
    """Votação de tokens nos nomes de detecção para sugerir a família.

    `suggested` (rótulo consolidado do VT) e `strong_names` (sandbox / popular_threat_name)
    recebem peso 2, pois já são nomes de família e não rótulos genéricos de AV.
    """
    counter: Counter[str] = Counter()
    for label in labels:
        tokens = {
            t for t in _TOKEN_SPLIT.split(label.lower())
            if len(t) >= 4 and t not in GENERIC_TOKENS and not t.isdigit() and not re.fullmatch(r"[0-9a-f]{5,}", t)
        }
        counter.update(tokens)
    if suggested:
        for tok in _TOKEN_SPLIT.split(suggested.lower()):
            if len(tok) >= 4 and tok not in GENERIC_TOKENS:
                counter[tok] += 2  # label consolidado pelo VT pesa mais
    for name in strong_names or []:
        tok = name.strip().lower()
        if len(tok) >= 4 and tok not in GENERIC_TOKENS:
            counter[tok] += 2
    return counter.most_common(5)


def _summarize_vendor_intel(vendor_intel: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normaliza `vendor_intel` do MalwareBazaar (cada vendor tem formato próprio: dict ou lista)."""
    keys = ("malware_family", "threat_name", "verdict", "status", "score", "detection")
    out: dict[str, dict[str, Any]] = {}
    for vendor, value in (vendor_intel or {}).items():
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if isinstance(entry, dict):
                picked = {k: entry[k] for k in keys if entry.get(k)}
                if picked:
                    out[vendor] = picked
                    break
    return out


def extract_malwarebazaar(mb_report: dict[str, Any] | None) -> dict[str, Any]:
    """Resumo do registro `get_info` do MalwareBazaar."""
    if not mb_report or not mb_report.get("data"):
        return {"found": False}
    d: dict[str, Any] = mb_report["data"]
    intel = d.get("intelligence") or {}
    return {
        "found": True,
        "signature": d.get("signature"),
        "file_name": d.get("file_name"),
        "file_type": d.get("file_type"),
        "file_type_mime": d.get("file_type_mime"),
        "file_size": d.get("file_size"),
        "first_seen": d.get("first_seen"),
        "last_seen": d.get("last_seen"),
        "reporter": d.get("reporter"),
        "origin_country": d.get("origin_country"),
        "delivery_method": d.get("delivery_method"),
        "tags": d.get("tags") or [],
        "yara_rules": [y.get("rule_name") for y in d.get("yara_rules") or [] if y.get("rule_name")],
        "vendor_intel": _summarize_vendor_intel(d.get("vendor_intel") or {}),
        "clamav": intel.get("clamav"),
        "downloads": intel.get("downloads"),
        "comments": [c.get("comment") for c in (d.get("comments") or [])[:5] if c.get("comment")],
        "hashes": {"md5": d.get("md5_hash"), "sha1": d.get("sha1_hash"), "ssdeep": d.get("ssdeep"),
                   "tlsh": d.get("tlsh"), "imphash": d.get("imphash")},
    }


def extract_features(
    vt_report: dict[str, Any] | None,
    mb_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Converte as respostas do VirusTotal e do MalwareBazaar em um dicionário compacto e estável.

    Qualquer uma das fontes pode ser None (ex.: hash ausente no VT mas presente no MB).
    """
    vt_report = vt_report or {}
    data = vt_report.get("data", {}) or {}
    attrs: dict[str, Any] = data.get("attributes", {}) or {}
    stats: dict[str, int] = attrs.get("last_analysis_stats", {}) or {}
    results: dict[str, dict[str, Any]] = attrs.get("last_analysis_results", {}) or {}
    ptc: dict[str, Any] = attrs.get("popular_threat_classification", {}) or {}
    rels: dict[str, list[dict[str, Any]]] = vt_report.get("relationships", {}) or {}
    mb = extract_malwarebazaar(mb_report)

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    analysed = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))

    detections = {
        engine: r.get("result")
        for engine, r in results.items()
        if r.get("category") in {"malicious", "suspicious"} and r.get("result")
    }
    labels = [str(v) for v in detections.values()]
    suggested = ptc.get("suggested_threat_label")

    # Nomes "fortes" (já são nomes de família): VT popular_threat_name, sandboxes, MB signature/vendors
    strong_names = [x.get("value", "") for x in ptc.get("popular_threat_name", [])] + [
        n for v in (attrs.get("sandbox_verdicts", {}) or {}).values() for n in v.get("malware_names", [])
    ]
    if mb["found"]:
        if mb.get("signature"):
            strong_names += [mb["signature"]] * 2  # assinatura curada do MB pesa mais
        strong_names += [v["malware_family"] for v in mb["vendor_intel"].values() if v.get("malware_family")]
        labels += [v["threat_name"] for v in mb["vendor_intel"].values() if v.get("threat_name")]

    urls = [
        (u.get("context_attributes") or {}).get("url") or u.get("id")
        for u in rels.get("contacted_urls", [])
    ]

    sandbox = {
        name: {
            "category": v.get("category"),
            "classification": v.get("malware_classification", []),
            "names": v.get("malware_names", []),
        }
        for name, v in (attrs.get("sandbox_verdicts", {}) or {}).items()
    }

    mb_hashes = mb.get("hashes", {}) if mb["found"] else {}
    yara = [y.get("rule_name") for y in attrs.get("crowdsourced_yara_results", []) or []]
    yara += [r for r in mb.get("yara_rules", []) if r not in yara]

    return {
        "simulated": bool(vt_report.get("_simulated", False)) or bool((mb_report or {}).get("_simulated", False)),
        "sources": {"virustotal": bool(data), "malwarebazaar": mb["found"]},
        "meta": {
            "sha256": attrs.get("sha256", data.get("id")) or (mb_report or {}).get("data", {}).get("sha256_hash"),
            "md5": attrs.get("md5") or mb_hashes.get("md5"),
            "sha1": attrs.get("sha1") or mb_hashes.get("sha1"),
            "type": attrs.get("type_description") or mb.get("file_type"),
            "type_tag": attrs.get("type_tag"),
            "size": attrs.get("size") or mb.get("file_size"),
            "names": (attrs.get("names") or ([mb["file_name"]] if mb.get("file_name") else []))[:10],
            "meaningful_name": attrs.get("meaningful_name"),
            "first_submission": _ts(attrs.get("first_submission_date")) or mb.get("first_seen"),
            "last_analysis": _ts(attrs.get("last_analysis_date")),
            "times_submitted": attrs.get("times_submitted"),
            "reputation": attrs.get("reputation"),
            "tags": sorted({*attrs.get("tags", []), *(t.lower() for t in mb.get("tags", []))}),
        },
        "detection": {
            "malicious": malicious,
            "suspicious": suspicious,
            "analysed_engines": analysed,
            "ratio": f"{malicious}/{analysed}" if analysed else "0/0",
            "labels_by_engine": dict(list(detections.items())[:30]),
            "suggested_threat_label": suggested,
            "popular_threat_names": [x.get("value") for x in ptc.get("popular_threat_name", [])],
            "popular_threat_categories": [x.get("value") for x in ptc.get("popular_threat_category", [])],
            "family_candidates": family_candidates(labels, suggested, strong_names),
        },
        "malwarebazaar": mb,
        "rules": {
            "yara": yara,
            "sigma": [
                {"title": s.get("rule_title"), "level": s.get("rule_level")}
                for s in attrs.get("sigma_analysis_results", []) or []
            ],
        },
        "sandbox": sandbox,
        "network": {
            "domains": sorted({d.get("id") for d in rels.get("contacted_domains", []) if d.get("id")}),
            "ips": sorted({i.get("id") for i in rels.get("contacted_ips", []) if i.get("id")}),
            "urls": sorted({u for u in urls if u}),
        },
    }


def _recommended_actions(verdict: str, features: dict[str, Any]) -> list[str]:
    """Playbook determinístico mínimo, ajustado ao veredito e ao tipo de ameaça."""
    if verdict in {"benign", "unknown"}:
        return ["Sem ação de contenção; reavaliar se surgirem novas detecções ou contexto de incidente."]
    actions = [
        "Bloquear o hash no EDR e executar varredura retroativa no parque de endpoints.",
        "Aplicar sinkhole/bloqueio dos domínios e URLs de C2 no DNS corporativo e no proxy.",
        "Isolar hosts com execução ou contato de rede confirmado e preservar evidências.",
    ]
    text = " ".join(
        [*features["meta"].get("tags", []), *features["detection"].get("popular_threat_categories", []),
         *map(str, features["detection"].get("labels_by_engine", {}).values())]
    ).lower()
    if any(k in text for k in ("stealer", "psw", "pws", "keychain", "infostealer")):
        actions.append("Revogar sessões (SSO/cloud/SaaS) e rotacionar credenciais dos usuários afetados — "
                       "cookies e senhas podem ter sido exfiltrados.")
    if any(k in text for k in ("backdoor", "persistence", "rat")):
        actions.append("Caçar mecanismos de persistência (LaunchAgents, serviços, tarefas agendadas) em todo o parque.")
    if verdict == "suspicious":
        actions.append("Detonar a amostra em sandbox para confirmar comportamento antes de ampliar o bloqueio.")
    return actions


# grafia oficial das famílias mais comuns (o VT devolve tudo em minúsculas)
_FAMILY_NAMES = {n.lower(): n for n in (
    "AgentTesla", "QakBot", "RedLine", "RedLineStealer", "LummaStealer", "AsyncRAT", "NjRAT", "DarkGate", "IcedID",
    "BazarLoader", "CobaltStrike", "Remcos", "FormBook", "XLoader", "SnakeKeylogger", "GuLoader", "SmokeLoader",
    "AMOS", "AtomicStealer", "Emotet", "TrickBot", "Mirai", "Gafgyt", "LockBit", "BlackCat", "WannaCry", "Raccoon",
    "Vidar", "StealC", "NanoCore", "QuasarRAT", "DCRat", "PlugX", "SocGholish", "Phexia", "Heodo", "Qbot",
)}


def _pretty_family(name: str, mb_signature: str | None = None) -> str:
    if mb_signature and mb_signature.lower() == name.lower():
        return mb_signature  # MalwareBazaar já usa a grafia oficial
    return _FAMILY_NAMES.get(name.lower(), name[:1].upper() + name[1:])


def _platform(features: dict[str, Any]) -> str:
    det, meta = features["detection"], features["meta"]
    tags = [t.lower() for t in meta.get("tags", [])]
    labels = " ".join(map(str, det["labels_by_engine"].values())).lower()
    ftype = f"{meta.get('type') or ''} {meta.get('type_tag') or ''}".lower()
    if any(t in labels for t in ("osx", "macos", "mac.")) or "macos" in tags or any(
            k in ftype for k in ("mach-o", "macho", "applescript", "dmg")):
        return "macOS"
    if any(k in ftype for k in ("win32", "win64", "peexe", "pedll", "msi", "exe", "dll", "lnk", "powershell")) or any(
            t in ("peexe", "pedll", "msi") for t in tags):
        return "Windows"
    if any(k in ftype for k in ("elf", "linux")) or "elf" in tags:
        return "Linux"
    if any(k in ftype for k in ("apk", "android")):
        return "Android"
    return "unknown"


def heuristic_triage(features: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Triagem determinística. Retorna (score 0-100, TriageReport como dict)."""
    det = features["detection"]
    mb = features.get("malwarebazaar", {"found": False})
    mal, susp, total = det["malicious"], det["suspicious"], det["analysed_engines"]
    sandbox_mal = any(v.get("category") == "malicious" for v in features["sandbox"].values())
    yara_hits = bool(features["rules"]["yara"])
    in_bazaar = bool(mb.get("found"))  # o MalwareBazaar só cataloga amostras maliciosas

    score = round(100 * (mal + 0.5 * susp) / total) if total else 0
    score += 15 if sandbox_mal else 0
    score += 10 if yara_hits else 0
    score += 20 if in_bazaar else 0
    score = max(0, min(100, score))

    if mal >= 5 or score >= 40 or sandbox_mal or in_bazaar:
        verdict = "malicious"
    elif mal >= 1 or susp >= 1 or yara_hits:
        verdict = "suspicious"
    elif total > 0:
        verdict = "benign"
    else:
        verdict = "unknown"

    candidates = det["family_candidates"]
    family = (_pretty_family(candidates[0][0], mb.get("signature"))
              if candidates and verdict != "benign" else "unknown")
    if verdict == "benign":  # confiança cresce com o número de engines que analisaram e nada viram
        confidence = 70 if total >= 50 else 50 if total >= 20 else 30
    elif family != "unknown":
        confidence = min(85, 30 + 5 * (candidates[0][1] if candidates else 0))
    else:
        confidence = 20

    platform = _platform(features)

    categories = det.get("popular_threat_categories") or []
    findings = [
        f"Taxa de detecção VT: {det['ratio']} (suspeitos: {susp})",
        f"Rótulo sugerido pelo VT: {det.get('suggested_threat_label') or 'n/d'}",
        f"Sandbox marcou como malicioso: {'sim' if sandbox_mal else 'não'}",
        f"Regras YARA: {', '.join(features['rules']['yara']) or 'nenhuma'}",
    ]
    if in_bazaar:
        findings.append(
            f"MalwareBazaar: assinatura '{mb.get('signature') or 'n/d'}', 1ª vez visto {mb.get('first_seen') or 'n/d'}, "
            f"entrega '{mb.get('delivery_method') or 'n/d'}'"
        )
    else:
        findings.append("MalwareBazaar: hash não encontrado (ou fonte desabilitada)")

    report = {
        "verdict": verdict,
        "confidence": confidence,
        "malware_family": family,
        "family_aliases": [c for c, _ in candidates[1:3]],
        "platform": platform,
        "threat_category": categories[0] if categories else "unknown",
        "summary": (
            (f"Triagem heurística: {det['ratio']} engines do VT marcaram o artefato como malicioso"
             if total else "Triagem heurística: sem análise do VirusTotal para este hash")
            + ("; presente no MalwareBazaar" if in_bazaar else "")
            + (f"; família mais votada: {family}." if family != "unknown" else
               "; nenhuma família atribuída." if verdict != "benign" else "; nenhum indício de malware.")
        ),
        "key_findings": findings,
        "mitre_attack": infer_attack(features) if verdict in {"malicious", "suspicious"} else [],
        "iocs": classify_iocs(features["network"]),
        "recommended_actions": _recommended_actions(verdict, features),
        "analyst_notes": "Resultado gerado sem LLM (fallback determinístico).",
    }
    return score, report
