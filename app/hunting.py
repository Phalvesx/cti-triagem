"""Gerador de Threat Hunts por SIEM a partir de um scan.

Cada hunt segue o modelo *hypothesis-driven* (PEAK / TaHiTI):
    hipótese -> fontes de dados -> consulta -> como triar os resultados -> virar detecção.

SIEMs/linguagens suportados:
    splunk   Splunk SPL (modelos CIM: Endpoint, Network_Resolution, Web)
    sentinel Microsoft Sentinel / Defender XDR (KQL, tabelas Device*)
    elastic  Elastic Security (KQL / EQL, campos ECS)
    qradar   IBM QRadar (AQL)
    secops   Google SecOps / Chronicle (YARA-L 2.0, campos UDM)
    wazuh    Wazuh (regras XML + listas CDB + configuração FIM)
    sigma    Sigma (neutro; converta com `sigma convert -t <backend>`)

Os hunts comportamentais (credencial via AppleScript, LaunchAgent, cadeia ClickFix) são
incluídos quando a plataforma é macOS. Hunts de IoC (hash, rede, DDR) valem para qualquer
plataforma. A biblioteca é extensível: adicione um `_hunt_*` e registre em `build_hunt_pack`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.features import is_legit_service

SIEMS: dict[str, str] = {
    "splunk": "Splunk (SPL)",
    "sentinel": "Microsoft Sentinel / Defender XDR (KQL)",
    "elastic": "Elastic Security (KQL/EQL)",
    "qradar": "IBM QRadar (AQL)",
    "secops": "Google SecOps / Chronicle (YARA-L 2.0)",
    "wazuh": "Wazuh (regras XML)",
    "sigma": "Sigma (neutro)",
}

BROWSERS = ["Google Chrome", "Google Chrome Helper", "Safari", "firefox", "Microsoft Edge", "Brave Browser",
            "Arc", "Opera", "chrome.exe", "msedge.exe", "firefox.exe"]

METHODOLOGY: list[dict[str, str]] = [
    {"step": "1. Hipótese", "detail": "Formule uma hipótese testável a partir da inteligência (ex.: 'hosts macOS executaram "
     "osascript pedindo senha nas últimas 4 semanas'). Amarre a uma técnica ATT&CK."},
    {"step": "2. Escopo e dados", "detail": "Defina período (ex.: 30-90 dias), população (macOS, VIPs, devs) e fontes "
     "necessárias (EDR/processos, arquivos, DNS, proxy). Verifique se os dados existem e estão parseados."},
    {"step": "3. Execução", "detail": "Rode primeiro a busca por IoCs (rápida, precisa) e depois a comportamental "
     "(mais durável). Use stacking/contagem: o raro é o interessante."},
    {"step": "4. Triagem", "detail": "Para cada resultado: processo pai, usuário, linha de comando completa, conexões "
     "próximas no tempo. Classifique em malicioso / benigno conhecido / precisa de mais dados."},
    {"step": "5. Resposta", "detail": "Achou? Abra incidente (aba Incidentes), isole o host e siga o playbook NIST."},
    {"step": "6. Automatizar", "detail": "Converta a consulta em regra de detecção agendada, documente falsos positivos, "
     "defina severidade e dono. Registre o hunt (hipótese, dados, resultado) mesmo sem achados."},
]


@dataclass
class HuntContext:
    family: str
    hashes: list[str]
    domains: list[str]
    ips: list[str]
    ddr_urls: list[str]
    ddr_needles: list[str]
    abused_services: list[str]
    file_names: list[str]
    platform: str

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "_", self.family.lower()).strip("_") or "unknown"

    @property
    def is_macos(self) -> bool:
        return "mac" in self.platform.lower() or "osx" in self.platform.lower()


# ------------------------------------------------------------------ helpers de escape
def _q(v: str) -> str:
    """String entre aspas duplas (SPL/KQL/YARA-L/EQL)."""
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _qs(v: str) -> str:
    """String entre aspas simples (AQL)."""
    return "'" + v.replace("'", "''") + "'"


def _join(values: list[str], quote=_q, sep: str = ", ") -> str:
    return sep.join(quote(v) for v in values)


def _like_any(values: list[str]) -> str:
    """AQL: UTF8(payload) ILIKE '%v1%' OR UTF8(payload) ILIKE '%v2%' ..."""
    return " OR ".join("UTF8(payload) ILIKE " + _qs("%" + v + "%") for v in values)


def _re_alt(values: list[str]) -> str:
    return "|".join(re.escape(v) for v in values)


# ------------------------------------------------------------------ contexto
_HEX = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_SAFE_NAME = re.compile(r"^[\w.\-]{4,80}$")


def build_context(scan: dict[str, Any]) -> HuntContext:
    t, f = scan["triage"], scan["features"]
    meta = f.get("meta", {})
    iocs = t.get("iocs", {})
    hashes = [h.lower() for h in (scan["hash"], meta.get("sha256"), meta.get("sha1"), meta.get("md5"))
              if h and _HEX.match(str(h).lower())]

    ddr_urls, needles = [], []
    for u in iocs.get("urls", []):
        host = urlparse(u if "://" in u else f"https://{u}").hostname or ""
        if is_legit_service(host):
            ddr_urls.append(u)
            seg = [s for s in urlparse(u if "://" in u else f"https://{u}").path.split("/") if s]
            if seg:
                needles.append(seg[-1])

    names = [*meta.get("names", []), (f.get("malwarebazaar") or {}).get("file_name")]
    file_names = sorted({n for n in names if n and _SAFE_NAME.match(n) and not _HEX.match(n.lower())})

    return HuntContext(
        family=t.get("malware_family") or "unknown",
        hashes=sorted(set(hashes)),
        domains=list(iocs.get("domains", [])),
        ips=list(iocs.get("ips", [])),
        ddr_urls=ddr_urls,
        ddr_needles=sorted(set(needles)),
        abused_services=list(iocs.get("abused_services", [])),
        file_names=file_names,
        platform=t.get("platform") or "unknown",
    )


# ------------------------------------------------------------------ hunts
def _hunt_hashes(c: HuntContext) -> dict[str, Any]:
    h = c.hashes
    hl = _join(h)
    return {
        "id": "H1", "title": "Varredura de hashes do artefato", "type": "IoC",
        "hypothesis": f"O artefato {c.family} (ou suas variantes conhecidas) foi gravado ou executado em algum endpoint.",
        "attack": ["T1204.002"], "data_sources": ["EDR: criação de arquivo", "EDR: criação de processo"],
        "triage": "Qualquer resultado é incidente confirmado: isole o host e abra incidente. Verifique usuário, caminho e processo pai.",
        "queries": {
            "splunk": (
                f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Filesystem.file_path) AS evidence\n"
                f"  from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ({hl}) by Filesystem.dest Filesystem.user\n"
                f"| rename Filesystem.* AS *\n"
                f"| append [| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Processes.process) AS evidence\n"
                f"  from datamodel=Endpoint.Processes where Processes.process_hash IN ({hl}) by Processes.dest Processes.user\n"
                f"  | rename Processes.* AS *]\n"
                f"| convert ctime(first_seen) ctime(last_seen)"
            ),
            "sentinel": (
                f"let iocHashes = dynamic([{hl}]);\n"
                f"union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents\n"
                f"| where Timestamp > ago(90d)\n"
                f"| where SHA256 in~ (iocHashes) or SHA1 in~ (iocHashes) or MD5 in~ (iocHashes)\n"
                f"| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Events=count(),\n"
                f"            Paths=make_set(FolderPath, 20), Users=make_set(AccountName, 20) by DeviceName, SHA256"
            ),
            "elastic": (
                "// KQL (Discover / Timeline)\n"
                + "\nor ".join(
                    f"{fld}.hash.{alg} : ({_join(vals, sep=' or ')})"
                    for alg, vals in (("sha256", [x for x in h if len(x) == 64]), ("sha1", [x for x in h if len(x) == 40]),
                                      ("md5", [x for x in h if len(x) == 32]))
                    if vals for fld in ("file", "process"))
            ),
            "qradar": (
                "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, LOGSOURCENAME(logsourceid) AS log_source,\n"
                "       sourceip, username, QIDNAME(qid) AS event_name\n"
                "FROM events\n"
                "WHERE " + _like_any(h) + "\n"
                "ORDER BY starttime DESC\n"
                "LAST 30 DAYS\n"
                "-- Performance: se houver propriedade customizada de hash (ex.: \"SHA256 Hash\"), troque o payload por ela."
            ),
            "secops": (
                f"rule hunt_{c.slug}_hashes {{\n"
                f"  meta:\n    author = \"CTI\"\n    description = \"Arquivo/processo com hash de {c.family}\"\n"
                f"    severity = \"CRITICAL\"\n    mitre_attack = \"T1204.002\"\n"
                f"  events:\n"
                f"    ($e.metadata.event_type = \"PROCESS_LAUNCH\" or $e.metadata.event_type = \"FILE_CREATION\")\n"
                f"    (\n      " + "\n      or ".join(
                    f"$e.target.file.sha256 = {_q(x)} nocase or $e.target.process.file.sha256 = {_q(x)} nocase"
                    if len(x) == 64 else
                    (f"$e.target.file.md5 = {_q(x)} nocase" if len(x) == 32 else f"$e.target.file.sha1 = {_q(x)} nocase")
                    for x in h) + "\n    )\n"
                "  condition:\n    $e\n}"
            ),
            "wazuh": (
                "<!-- 1) Lista CDB: /var/ossec/etc/lists/cti-hashes (uma linha por hash, formato chave:valor) -->\n"
                + "\n".join(f"<!-- {x}:{c.family} -->" for x in h) + "\n"
                "<!-- 2) ossec.conf (manager) dentro de <ruleset>: <list>etc/lists/cti-hashes</list> -->\n"
                "<!-- 3) Regra (local_rules.xml). 554 = arquivo adicionado, 550 = arquivo modificado (FIM/syscheck) -->\n"
                f"<group name=\"cti,{c.slug},\">\n"
                f"  <rule id=\"100500\" level=\"14\">\n"
                f"    <if_sid>554, 550</if_sid>\n"
                f"    <list field=\"sha256_after\" lookup=\"match_key\">etc/lists/cti-hashes</list>\n"
                f"    <description>CTI: arquivo com hash de {c.family} detectado: $(file)</description>\n"
                f"    <mitre><id>T1204.002</id></mitre>\n"
                f"  </rule>\n</group>"
            ),
            "sigma": (
                f"title: {c.family} - Known File Hash\n"
                "status: experimental\n"
                "logsource:\n  category: process_creation\n"
                "detection:\n  selection:\n    Hashes|contains:\n"
                + "".join(f"      - '{x}'\n" for x in h)
                + "  condition: selection\nlevel: critical\n"
                "tags:\n  - attack.execution\n  - attack.t1204.002"
            ),
        },
    }


def _hunt_network(c: HuntContext) -> dict[str, Any] | None:
    if not (c.domains or c.ips):
        return None
    d, ips = c.domains, c.ips
    dl = _join(d)
    wild = _join([*d, *(f"*.{x}" for x in d)])
    ipl = _join(ips)
    spl_parts = []
    if d:
        spl_parts += [
            "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(DNS.src) AS src\n"
            f"  from datamodel=Network_Resolution.DNS where DNS.query IN ({wild}) by DNS.query\n"
            "  | rename DNS.query AS indicator",
            "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Web.src) AS src\n"
            f"  from datamodel=Web where Web.dest IN ({wild}) by Web.dest | rename Web.dest AS indicator",
        ]
    if ips:
        spl_parts.append(
            "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(All_Traffic.src) AS src\n"
            f"  from datamodel=Network_Traffic where All_Traffic.dest IN ({ipl}) by All_Traffic.dest | rename All_Traffic.dest AS indicator"
        )
    spl = spl_parts[0] + "".join(f"\n| append [{x}]" for x in spl_parts[1:]) + "\n| convert ctime(first_seen) ctime(last_seen)"
    dom_re = rf"(^|\.)({_re_alt(d)})$" if d else "a^"
    return {
        "id": "H2", "title": "Contato com infraestrutura de C2 (domínios/IPs)", "type": "IoC",
        "hypothesis": f"Algum host resolveu ou se conectou à infraestrutura de C2 de {c.family}.",
        "attack": ["T1071.001", "T1041"], "data_sources": ["DNS", "Proxy/SWG", "Firewall", "EDR: conexões de rede"],
        "triage": "Identifique o processo que originou a conexão (EDR). Resolução DNS sem conexão pode ser bloqueio efetivo; "
                  "conexão HTTP concluída = host comprometido. Domínios de TLD barato expiram rápido: priorize o período em que estavam ativos.",
        "queries": {
            "splunk": spl,
            "sentinel": (
                f"let iocDomains = dynamic([{dl}]);\n"
                f"let iocIPs = dynamic([{ipl}]);\n"
                f"union\n"
                f"  (DeviceNetworkEvents\n"
                f"   | where Timestamp > ago(90d)\n"
                f"   | where RemoteUrl has_any (iocDomains) or RemoteIP in (iocIPs)\n"
                f"   | project Timestamp, DeviceName, Indicator=coalesce(RemoteUrl, RemoteIP), InitiatingProcessFileName, InitiatingProcessCommandLine),\n"
                f"  (DeviceEvents\n"
                f"   | where Timestamp > ago(90d) and ActionType == \"DnsQueryResponse\"\n"
                f"   | extend Query = tostring(parse_json(AdditionalFields).DnsQueryString)\n"
                f"   | where Query has_any (iocDomains)\n"
                f"   | project Timestamp, DeviceName, Indicator=Query, InitiatingProcessFileName, InitiatingProcessCommandLine),\n"
                f"  (CommonSecurityLog  // proxy/firewall via CEF\n"
                f"   | where TimeGenerated > ago(90d)\n"
                f"   | where DestinationHostName has_any (iocDomains) or RequestURL has_any (iocDomains) or DestinationIP in (iocIPs)\n"
                f"   | project Timestamp=TimeGenerated, DeviceName=SourceIP, Indicator=coalesce(DestinationHostName, DestinationIP), InitiatingProcessFileName=\"(proxy)\", InitiatingProcessCommandLine=RequestURL)\n"
                f"| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Procs=make_set(InitiatingProcessFileName, 10) by DeviceName, Indicator"
            ),
            "elastic": (
                "// KQL\n"
                + " or ".join(
                    [*(f"dns.question.name : ({_join(d, sep=' or ')})" for _ in [0] if d),
                     *(f"dns.question.name : *.{x}" for x in d),
                     *(f"url.domain : ({_join(d, sep=' or ')})" for _ in [0] if d),
                     *(f"destination.domain : ({_join(d, sep=' or ')})" for _ in [0] if d),
                     *(f"destination.ip : ({_join(ips, sep=' or ')})" for _ in [0] if ips)])
            ),
            "qradar": (
                "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, destinationip,\n"
                "       LOGSOURCENAME(logsourceid) AS log_source, QIDNAME(qid) AS event_name\n"
                "FROM events\n"
                "WHERE " + " OR ".join(
                    [*([_like_any(d)] if d else []), *(f"destinationip = {_qs(x)}" for x in ips)])
                + "\nORDER BY starttime DESC\nLAST 30 DAYS\n"
                "-- Para fluxos (QFlow/NetFlow): SELECT ... FROM flows WHERE destinationip IN (...) LAST 30 DAYS"
            ),
            "secops": (
                f"rule hunt_{c.slug}_c2_infra {{\n"
                f"  meta:\n    author = \"CTI\"\n    description = \"Contato com C2 de {c.family}\"\n    severity = \"HIGH\"\n"
                f"  events:\n    (\n"
                + (f"      re.regex($e.network.dns.questions.name, `{dom_re}`) nocase\n"
                   f"      or re.regex($e.target.hostname, `{dom_re}`) nocase\n" if d else "")
                + ("      " + ("or " if d else "") + " or ".join(f"$e.target.ip = {_q(x)}" for x in ips) + "\n" if ips else "")
                + "    )\n    $e.principal.hostname = $host\n"
                "  match:\n    $host over 1h\n  condition:\n    $e\n}"
            ),
            "wazuh": (
                "<!-- Lista CDB /var/ossec/etc/lists/cti-domains (chave:valor) -->\n"
                + "\n".join(f"<!-- {x}:{c.family} -->" for x in d) + "\n"
                "<!-- Regra para DNS do Suricata (eve.json). 86600 = regra base do Suricata no ruleset padrão.\n"
                "     Para proxy (Squid etc.), troque if_sid/field pelo decoder do seu proxy (ex.: field=\"url\"). -->\n"
                f"<group name=\"cti,{c.slug},\">\n"
                f"  <rule id=\"100510\" level=\"12\">\n"
                f"    <if_sid>86600</if_sid>\n"
                f"    <field name=\"event_type\">^dns$</field>\n"
                f"    <list field=\"dns.rrname\" lookup=\"match_key\">etc/lists/cti-domains</list>\n"
                f"    <description>CTI: consulta DNS a C2 de {c.family}: $(dns.rrname)</description>\n"
                f"    <mitre><id>T1071.001</id></mitre>\n"
                f"  </rule>\n</group>"
            ),
            "sigma": (
                f"title: {c.family} - C2 Domain Resolution\n"
                "status: experimental\n"
                "logsource:\n  category: dns_query\n"
                "detection:\n  selection:\n    QueryName|endswith:\n"
                + "".join(f"      - '{x}'\n" for x in d)
                + "  condition: selection\nlevel: high\n"
                "tags:\n  - attack.command_and_control\n  - attack.t1071.001"
            ) if d else (
                f"title: {c.family} - C2 IP Connection\n"
                "status: experimental\n"
                "logsource:\n  category: network_connection\n"
                "detection:\n  selection:\n    DestinationIp:\n"
                + "".join(f"      - '{x}'\n" for x in ips)
                + "  condition: selection\nlevel: high\n"
                "tags:\n  - attack.command_and_control\n  - attack.t1071.001"
            ),
        },
    }


def _hunt_ddr(c: HuntContext) -> dict[str, Any] | None:
    if not c.ddr_needles:
        return None
    n = c.ddr_needles
    rx = _re_alt(n)
    svc = c.abused_services or ["t.me", "steamcommunity.com"]
    spl_urls = " OR ".join('Web.url="*' + x + '*"' for x in n)
    return {
        "id": "H3", "title": "Consulta ao Dead Drop Resolver (Telegram/Steam/etc.)", "type": "IoC + comportamento",
        "hypothesis": "Um processo que não é navegador acessou o perfil/canal usado como Dead Drop Resolver para descobrir o C2.",
        "attack": ["T1102.001"], "data_sources": ["Proxy/SWG com URL completa", "EDR: conexões de rede por processo"],
        "triage": "Acesso ao perfil DDR por navegador pode ser pesquisa de analista; por curl/osascript/binário desconhecido é "
                  "fortíssimo indicador. NÃO bloqueie o serviço inteiro: bloqueie a URL/perfil específico.",
        "queries": {
            "splunk": (
                "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen\n"
                "  from datamodel=Web where (" + spl_urls + ")\n"
                "  by Web.src Web.user Web.url Web.http_user_agent\n"
                "| rename Web.* AS *\n"
                "| eval suspicious_client=if(match(http_user_agent, \"(?i)(curl|wget|python|go-http|osascript|CFNetwork)\") OR isnull(http_user_agent), \"yes\", \"no\")\n"
                "| sort - suspicious_client"
            ),
            "sentinel": (
                f"let ddrNeedles = dynamic([{_join(n)}]);\n"
                f"let ddrServices = dynamic([{_join(svc)}]);\n"
                f"let browsers = dynamic([{_join(BROWSERS)}]);\n"
                f"DeviceNetworkEvents\n"
                f"| where Timestamp > ago(90d)\n"
                f"| where RemoteUrl has_any (ddrNeedles)\n"
                f"   or (RemoteUrl has_any (ddrServices) and not(InitiatingProcessFileName in~ (browsers)))\n"
                f"| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine,\n"
                f"          InitiatingProcessParentFileName, InitiatingProcessAccountName\n"
                f"| order by Timestamp desc"
            ),
            "elastic": (
                "// KQL\n"
                f"url.original : ({' or '.join(f'*{x}*' for x in n)}) or url.full : ({' or '.join(f'*{x}*' for x in n)})\n"
                "// EQL (EDR): processo não-navegador falando com o serviço abusado\n"
                f"// network where destination.domain in ({_join(svc)}) and not process.name in ({_join(BROWSERS)})"
            ),
            "qradar": (
                "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,\n"
                "       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw\n"
                "FROM events\n"
                "WHERE " + _like_any(n) + "\n"
                "ORDER BY starttime DESC\nLAST 90 DAYS"
            ),
            "secops": (
                f"rule hunt_{c.slug}_ddr_lookup {{\n"
                f"  meta:\n    author = \"CTI\"\n    description = \"Acesso ao Dead Drop Resolver de {c.family}\"\n"
                f"    severity = \"HIGH\"\n    mitre_attack = \"T1102.001\"\n"
                f"  events:\n    re.regex($e.target.url, `{rx}`) nocase\n"
                f"    $e.principal.hostname = $host\n"
                f"  match:\n    $host over 1h\n  condition:\n    $e\n}}"
            ),
            "wazuh": (
                f"<group name=\"cti,{c.slug},\">\n"
                f"  <!-- Regra genérica (casa em qualquer log com URL completa: proxy, EDR, firewall L7) -->\n"
                f"  <rule id=\"100520\" level=\"12\">\n"
                f"    <match type=\"pcre2\">(?i)({rx})</match>\n"
                f"    <description>CTI: acesso ao Dead Drop Resolver de {c.family}</description>\n"
                f"    <mitre><id>T1102.001</id></mitre>\n"
                f"  </rule>\n</group>"
            ),
            "sigma": (
                f"title: {c.family} - Dead Drop Resolver Lookup\n"
                "status: experimental\n"
                "logsource:\n  category: proxy\n"
                "detection:\n  selection:\n    c-uri|contains:\n"
                + "".join(f"      - '{x}'\n" for x in n)
                + "  condition: selection\nlevel: high\n"
                "tags:\n  - attack.command_and_control\n  - attack.t1102.001"
            ),
        },
    }


def _hunt_mac_credential_prompt(c: HuntContext) -> dict[str, Any]:
    return {
        "id": "H4", "title": "Phishing de senha via AppleScript (diálogo falso)", "type": "Comportamento",
        "hypothesis": "Um script exibiu um diálogo falso pedindo a senha do macOS e validou a senha com dscl.",
        "attack": ["T1056.002", "T1059.002", "T1555.001"], "data_sources": ["EDR macOS: criação de processo com linha de comando"],
        "triage": "Ferramentas legítimas quase nunca usam 'hidden answer' + dscl authonly em sequência. Verifique o processo pai "
                  "(Terminal? script em /tmp? app baixado?) e se houve acesso ao login.keychain-db logo depois.",
        "queries": {
            "splunk": (
                "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen\n"
                "  from datamodel=Endpoint.Processes\n"
                "  where (Processes.process_name=\"osascript\" Processes.process=\"*hidden answer*\")\n"
                "     OR (Processes.process_name=\"dscl\" Processes.process=\"*authonly*\")\n"
                "  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process\n"
                "| rename Processes.* AS *\n"
                "| convert ctime(first_seen) ctime(last_seen)"
            ),
            "sentinel": (
                "DeviceProcessEvents\n"
                "| where Timestamp > ago(30d)\n"
                "| where (FileName =~ \"osascript\" and ProcessCommandLine has \"hidden answer\")\n"
                "     or (FileName =~ \"dscl\" and ProcessCommandLine has \"authonly\")\n"
                "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,\n"
                "          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName\n"
                "| order by Timestamp desc"
            ),
            "elastic": (
                "// EQL\n"
                "process where host.os.type == \"macos\" and event.type == \"start\" and\n"
                "  ((process.name == \"osascript\" and process.command_line : \"*hidden answer*\") or\n"
                "   (process.name == \"dscl\" and process.args == \"authonly\"))"
            ),
            "qradar": (
                "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,\n"
                "       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw\n"
                "FROM events\n"
                "WHERE (UTF8(payload) ILIKE '%osascript%' AND UTF8(payload) ILIKE '%hidden answer%')\n"
                "   OR (UTF8(payload) ILIKE '%dscl%' AND UTF8(payload) ILIKE '%authonly%')\n"
                "ORDER BY starttime DESC\nLAST 30 DAYS"
            ),
            "secops": (
                f"rule hunt_macos_applescript_password_prompt {{\n"
                f"  meta:\n    author = \"CTI\"\n    description = \"Diálogo AppleScript pedindo senha / validação com dscl ({c.family})\"\n"
                f"    severity = \"HIGH\"\n    mitre_attack = \"T1056.002\"\n"
                f"  events:\n    $e.metadata.event_type = \"PROCESS_LAUNCH\"\n    (\n"
                f"      (re.regex($e.target.process.file.full_path, `/osascript$`) and re.regex($e.target.process.command_line, `hidden answer`) nocase)\n"
                f"      or (re.regex($e.target.process.file.full_path, `/dscl$`) and re.regex($e.target.process.command_line, `authonly`) nocase)\n"
                f"    )\n  condition:\n    $e\n}}"
            ),
            "wazuh": (
                "<!-- Requer telemetria de processos do macOS no Wazuh (ex.: EDR encaminhado via syslog/JSON\n"
                "     ou osquery integrado). O Unified Log não traz a linha de comando por padrão. -->\n"
                f"<group name=\"cti,macos,{c.slug},\">\n"
                "  <rule id=\"100530\" level=\"12\">\n"
                "    <match type=\"pcre2\">(?i)(osascript.*hidden answer|dscl\\s+\\.\\s+-?authonly)</match>\n"
                "    <description>CTI: AppleScript pedindo senha / validação com dscl (roubo de credencial)</description>\n"
                "    <mitre><id>T1056.002</id></mitre>\n"
                "  </rule>\n</group>"
            ),
            "sigma": (
                "title: macOS AppleScript Password Prompt\n"
                "status: experimental\n"
                "logsource:\n  product: macos\n  category: process_creation\n"
                "detection:\n  osascript:\n    Image|endswith: '/osascript'\n    CommandLine|contains: 'hidden answer'\n"
                "  dscl:\n    Image|endswith: '/dscl'\n    CommandLine|contains: 'authonly'\n"
                "  condition: osascript or dscl\nlevel: high\n"
                "tags:\n  - attack.credential_access\n  - attack.t1056.002"
            ),
        },
    }


def _hunt_mac_launchagent(c: HuntContext) -> dict[str, Any]:
    names = [re.sub(r"\.(plist|scpt)$", "", n) for n in c.file_names]
    name_rx = _re_alt(names) if names else "a^"
    rand_rx = r"com\.[^./]+\.[a-z]{12,20}\.plist$"
    return {
        "id": "H5", "title": "Persistência por LaunchAgent com nome aleatório", "type": "Comportamento",
        "hypothesis": "Um LaunchAgent novo, com nome aleatório (padrão com.<user>.<12-20 letras>.plist), foi criado no perfil do usuário.",
        "attack": ["T1543.001"], "data_sources": ["EDR macOS: eventos de arquivo", "FIM", "osquery (tabela launchd)"],
        "triage": "Faça stacking por nome de arquivo no parque: legítimos se repetem (com.google.keystone...), maliciosos são únicos. "
                  "Abra o plist: ProgramArguments apontando para ~/Library/<nome aleatório> ou osascript é sinal forte.",
        "queries": {
            "splunk": (
                "| tstats summariesonly=false count min(_time) AS first_seen values(Filesystem.action) AS action\n"
                "  from datamodel=Endpoint.Filesystem\n"
                "  where Filesystem.file_path=\"*/Library/LaunchAgents/*\" Filesystem.file_name=\"*.plist\"\n"
                "  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path\n"
                "| rename Filesystem.* AS *\n"
                f"| where match(file_name, \"{rand_rx}\") OR match(file_path, \"(?i)({name_rx})\")\n"
                "| eventstats dc(dest) AS hosts_with_same_name by file_name\n"
                "| where hosts_with_same_name < 3\n"
                "| convert ctime(first_seen)"
            ),
            "sentinel": (
                "DeviceFileEvents\n"
                "| where Timestamp > ago(30d)\n"
                "| where FolderPath has \"/Library/LaunchAgents/\" and FileName endswith \".plist\"\n"
                "| where ActionType in (\"FileCreated\", \"FileModified\", \"FileRenamed\")\n"
                f"| where FileName matches regex @\"^{rand_rx}\"" + (f" or FolderPath matches regex @\"(?i)({name_rx})\"" if names else "") + "\n"
                "| summarize Hosts=dcount(DeviceName), Devices=make_set(DeviceName, 20), FirstSeen=min(Timestamp),\n"
                "            Writers=make_set(InitiatingProcessFileName, 10) by FileName\n"
                "| where Hosts < 3"
            ),
            "elastic": (
                "// EQL\n"
                "file where host.os.type == \"macos\" and event.type in (\"creation\", \"change\") and\n"
                "  file.path : \"/Users/*/Library/LaunchAgents/*.plist\" and\n"
                f"  (file.name regex~ \"\"\"{rand_rx.rstrip('$')}\"\"\"" + (f" or file.path regex~ \"\"\".*({name_rx}).*\"\"\"" if names else "") + ")"
            ),
            "qradar": (
                "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,\n"
                "       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw\n"
                "FROM events\n"
                "WHERE UTF8(payload) ILIKE '%/Library/LaunchAgents/%'\n"
                f"  AND (UTF8(payload) IMATCHES '.*{rand_rx.rstrip('$')}.*'"
                + ("".join(" OR " + _like_any([x]) for x in names)) + ")\n"
                "ORDER BY starttime DESC\nLAST 30 DAYS"
            ),
            "secops": (
                f"rule hunt_macos_random_launchagent {{\n"
                f"  meta:\n    author = \"CTI\"\n    description = \"LaunchAgent com nome aleatório (persistência estilo {c.family})\"\n"
                f"    severity = \"MEDIUM\"\n    mitre_attack = \"T1543.001\"\n"
                f"  events:\n    ($e.metadata.event_type = \"FILE_CREATION\" or $e.metadata.event_type = \"FILE_MODIFICATION\")\n"
                f"    re.regex($e.target.file.full_path, `/Library/LaunchAgents/{rand_rx}`)\n"
                f"  condition:\n    $e\n}}"
            ),
            "wazuh": (
                "<!-- ossec.conf (agente macOS): monitorar LaunchAgents em tempo real -->\n"
                "<!-- <syscheck><directories realtime=\"yes\" check_all=\"yes\">/Users/*/Library/LaunchAgents,/Library/LaunchAgents</directories></syscheck> -->\n"
                f"<group name=\"cti,macos,{c.slug},\">\n"
                "  <rule id=\"100540\" level=\"12\">\n"
                "    <if_sid>554</if_sid>\n"
                f"    <field name=\"file\" type=\"pcre2\">/Library/LaunchAgents/{rand_rx}</field>\n"
                "    <description>CTI: LaunchAgent com nome aleatório criado: $(file)</description>\n"
                "    <mitre><id>T1543.001</id></mitre>\n"
                "  </rule>\n</group>"
            ),
            "sigma": (
                "title: macOS LaunchAgent With Random Name\n"
                "status: experimental\n"
                "logsource:\n  product: macos\n  category: file_event\n"
                "detection:\n  selection:\n    TargetFilename|contains: '/Library/LaunchAgents/'\n"
                f"    TargetFilename|re: '{rand_rx}'\n"
                "  condition: selection\nlevel: medium\n"
                "falsepositives:\n  - Instaladores legítimos com IDs gerados (validar por stacking)\n"
                "tags:\n  - attack.persistence\n  - attack.t1543.001"
            ),
        },
    }


def _hunt_mac_clickfix(c: HuntContext) -> dict[str, Any]:
    return {
        "id": "H6", "title": "Cadeia ClickFix: Terminal → curl → osascript", "type": "Comportamento",
        "hypothesis": "Um usuário colou no Terminal um comando que baixou (curl) e executou AppleScript em menos de 1 minuto.",
        "attack": ["T1204.004", "T1059.004", "T1105", "T1553.001"], "data_sources": ["EDR macOS: criação de processo com pai/avô"],
        "triage": "Desenvolvedores usam curl no Terminal o tempo todo; o sinal é curl seguido de osascript (ou curl | bash de domínio "
                  "desconhecido). Veja a URL no comando do curl e a navegação do usuário no minuto anterior.",
        "queries": {
            "splunk": (
                "| tstats summariesonly=false count from datamodel=Endpoint.Processes\n"
                "  where Processes.process_name IN (\"curl\", \"wget\", \"osascript\")\n"
                "  by _time span=1s Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name\n"
                "| rename Processes.* AS *\n"
                "| sort 0 _time\n"
                "| streamstats time_window=60s values(process_name) AS chain values(process) AS commands by dest\n"
                "| where process_name=\"osascript\" AND mvcount(chain)>=2\n"
                "| table _time dest user chain commands"
            ),
            "sentinel": (
                "let downloads = DeviceProcessEvents\n"
                "| where Timestamp > ago(30d)\n"
                "| where FileName in~ (\"curl\", \"wget\")\n"
                "| where InitiatingProcessFileName in~ (\"bash\", \"zsh\", \"sh\") and InitiatingProcessParentFileName in~ (\"Terminal\", \"iTerm2\")\n"
                "| project DeviceId, DeviceName, DlTime=Timestamp, DlCmd=ProcessCommandLine, AccountName;\n"
                "DeviceProcessEvents\n"
                "| where Timestamp > ago(30d) and FileName =~ \"osascript\"\n"
                "| project DeviceId, OsaTime=Timestamp, OsaCmd=ProcessCommandLine\n"
                "| join kind=inner downloads on DeviceId\n"
                "| where OsaTime between (DlTime .. (DlTime + 1m))\n"
                "| project DlTime, DeviceName, AccountName, DlCmd, OsaCmd"
            ),
            "elastic": (
                "// EQL (sequência)\n"
                "sequence by host.id with maxspan=1m\n"
                "  [process where host.os.type == \"macos\" and event.type == \"start\" and\n"
                "     process.name in (\"curl\", \"wget\") and process.parent.name in (\"bash\", \"zsh\", \"sh\")]\n"
                "  [process where host.os.type == \"macos\" and event.type == \"start\" and process.name == \"osascript\"]"
            ),
            "qradar": (
                "-- AQL lista os candidatos; para correlação em tempo real crie uma regra de SEQUÊNCIA no Rule Wizard:\n"
                "-- 'when these events are detected in this order... within 1 minutes... with the same source IP/host'.\n"
                "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,\n"
                "       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw\n"
                "FROM events\n"
                "WHERE (UTF8(payload) ILIKE '%curl%' OR UTF8(payload) ILIKE '%osascript%')\n"
                "  AND LOGSOURCETYPENAME(devicetype) ILIKE '%mac%'\n"
                "ORDER BY sourceip, starttime\nLAST 7 DAYS"
            ),
            "secops": (
                "rule hunt_macos_clickfix_curl_osascript {\n"
                "  meta:\n    author = \"CTI\"\n    description = \"curl/wget seguido de osascript no mesmo host em 1 min (ClickFix)\"\n"
                "    severity = \"HIGH\"\n    mitre_attack = \"T1204.004\"\n"
                "  events:\n"
                "    $dl.metadata.event_type = \"PROCESS_LAUNCH\"\n"
                "    re.regex($dl.target.process.file.full_path, `/(curl|wget)$`)\n"
                "    $dl.principal.hostname = $host\n"
                "    $osa.metadata.event_type = \"PROCESS_LAUNCH\"\n"
                "    re.regex($osa.target.process.file.full_path, `/osascript$`)\n"
                "    $osa.principal.hostname = $host\n"
                "    $dl.metadata.event_timestamp.seconds <= $osa.metadata.event_timestamp.seconds\n"
                "  match:\n    $host over 1m\n"
                "  condition:\n    $dl and $osa\n}"
            ),
            "wazuh": (
                "<!-- Correlação em duas regras: a 2ª só dispara se a 1ª casou no mesmo agente nos últimos 60s -->\n"
                f"<group name=\"cti,macos,{c.slug},\">\n"
                "  <rule id=\"100550\" level=\"3\">\n"
                "    <match type=\"pcre2\">(?i)\\b(curl|wget)\\b.*https?://</match>\n"
                "    <description>macOS: download via curl/wget</description>\n"
                "  </rule>\n"
                "  <rule id=\"100551\" level=\"12\" timeframe=\"60\">\n"
                "    <if_matched_sid>100550</if_matched_sid>\n"
                "    <same_location />\n"
                "    <match type=\"pcre2\">(?i)\\bosascript\\b</match>\n"
                "    <description>CTI: curl seguido de osascript em 60s (possível ClickFix)</description>\n"
                "    <mitre><id>T1204.004</id></mitre>\n"
                "  </rule>\n</group>"
            ),
            "sigma": (
                "title: macOS Curl Download\n"
                "name: macos_curl_download\n"
                "status: experimental\n"
                "logsource:\n  product: macos\n  category: process_creation\n"
                "detection:\n  selection:\n    Image|endswith:\n      - '/curl'\n      - '/wget'\n  condition: selection\n"
                "---\n"
                "title: macOS Osascript Execution\n"
                "name: macos_osascript_exec\n"
                "status: experimental\n"
                "logsource:\n  product: macos\n  category: process_creation\n"
                "detection:\n  selection:\n    Image|endswith: '/osascript'\n  condition: selection\n"
                "---\n"
                "title: ClickFix Chain - Curl and Osascript Within 1 Minute\n"
                "description: Use type temporal_ordered se o seu backend suportar (garante a ordem curl -> osascript)\n"
                "status: experimental\n"
                "correlation:\n  type: temporal\n  rules:\n    - macos_curl_download\n    - macos_osascript_exec\n"
                "  group-by:\n    - Computer\n  timespan: 1m\n"
                "level: high\n"
                "tags:\n  - attack.execution\n  - attack.t1204.004"
            ),
        },
    }


_NO_COMMENT_LANGS = {"qradar": "--", "elastic": "//"}  # AQL e KQL não aceitam comentários na consulta


def _split_comments(queries: dict[str, str]) -> dict[str, list[str]]:
    """Remove linhas de comentário das linguagens que não os suportam e devolve-as como notas."""
    notes: dict[str, list[str]] = {}
    for siem, prefix in _NO_COMMENT_LANGS.items():
        if siem not in queries:
            continue
        lines = queries[siem].split("\n")
        notes[siem] = [ln.lstrip(prefix + " ").strip() for ln in lines if ln.lstrip().startswith(prefix)]
        queries[siem] = "\n".join(ln for ln in lines if not ln.lstrip().startswith(prefix)).strip()
    return {k: v for k, v in notes.items() if v}


# ------------------------------------------------------------------ API pública
def build_hunt_pack(scan: dict[str, Any], siem: str = "all") -> dict[str, Any]:
    """Monta o pacote de hunts para um scan. `siem` filtra as consultas ('all' = todas)."""
    if siem != "all" and siem not in SIEMS:
        raise ValueError(f"SIEM inválido: {siem}. Opções: all, {', '.join(SIEMS)}")
    c = build_context(scan)
    hunts = [_hunt_hashes(c), _hunt_network(c), _hunt_ddr(c)]
    if c.is_macos and scan["triage"].get("verdict") in {"malicious", "suspicious"}:
        hunts += [_hunt_mac_credential_prompt(c), _hunt_mac_launchagent(c), _hunt_mac_clickfix(c)]
    hunts = [h for h in hunts if h]
    for h in hunts:
        h["query_notes"] = _split_comments(h["queries"])
    if siem != "all":
        for h in hunts:
            h["queries"] = {siem: h["queries"][siem]}
            h["query_notes"] = {k: v for k, v in h["query_notes"].items() if k == siem}
    return {
        "hash": scan["hash"],
        "family": c.family,
        "platform": c.platform,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "siems": SIEMS if siem == "all" else {siem: SIEMS[siem]},
        "methodology": METHODOLOGY,
        "notes": [
            "Ajuste nomes de índice/tabela/campo ao seu ambiente (parsers e data models variam).",
            "Serviços legítimos abusados (t.me, Steam...) aparecem só como URL/perfil específico — não bloqueie o domínio inteiro.",
            "Sigma: converta com `sigma convert -t splunk|kusto|lucene|esql|qradar-aql|... regra.yml` (pySigma).",
        ],
        "hunts": hunts,
    }


def hunt_pack_markdown(pack: dict[str, Any]) -> str:
    """Versão Markdown (para colar em wiki/ticket)."""
    fence_lang = {"splunk": "spl", "sentinel": "kql", "elastic": "sql", "qradar": "sql", "secops": "yaral",
                  "wazuh": "xml", "sigma": "yaml"}
    out = [f"# Threat Hunting — {pack['family']} ({pack['hash']})", "", "## Como executar um hunt", ""]
    out += [f"- **{m['step']}** — {m['detail']}" for m in pack["methodology"]]
    out += ["", "> " + "\n> ".join(pack["notes"]), ""]
    for h in pack["hunts"]:
        out += [f"## {h['id']} · {h['title']}", "",
                f"- **Tipo:** {h['type']}",
                f"- **Hipótese:** {h['hypothesis']}",
                f"- **ATT&CK:** {', '.join(h['attack'])}",
                f"- **Fontes de dados:** {', '.join(h['data_sources'])}",
                f"- **Como triar:** {h['triage']}", ""]
        for siem, q in h["queries"].items():
            out += [f"### {pack['siems'].get(siem, siem)}", ""]
            notes = h.get("query_notes", {}).get(siem, [])
            if notes:
                out += [*(f"> {n}" for n in notes), ""]
            out += [f"```{fence_lang.get(siem, '')}", q, "```", ""]
    return "\n".join(out)
