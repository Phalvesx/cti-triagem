"""DFIR: do CTI para a coleta forense no host.

A partir de um scan, gera:
* um **plano de coleta** por sistema operacional, na ordem de volatilidade (RFC 3227), com as
  verificações específicas das técnicas ATT&CK observadas (o que procurar, onde e com qual comando);
* um **script de triagem** pronto (macOS/Linux em bash, Windows em PowerShell) com os IoCs do
  artefato embutidos.

Garantias dos scripts (guardrails): somente leitura, sem nenhuma conexão de rede, manifesto SHA-256
das evidências (cadeia de custódia) e pacote .zip/.tar.gz para o time de IR.
Referências: NIST SP 800-86 (forense integrada à resposta), RFC 3227 (coleta e ordem de volatilidade),
NIST SP 800-61 (tratamento de incidentes).
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Literal

from app.hunting import build_context

OS = Literal["macos", "windows", "linux"]
OSES: tuple[str, ...] = ("macos", "windows", "linux")
OS_LABEL = {"macos": "macOS", "windows": "Windows", "linux": "Linux"}
TEMPLATES = Path(__file__).parent / "dfir_templates"
SCRIPT_NAME = {"macos": "triagem_macos.sh", "windows": "triagem_windows.ps1", "linux": "triagem_linux.sh"}

ORDER_OF_VOLATILITY = [
    "1. Memória e processos em execução",
    "2. Conexões de rede e cache DNS",
    "3. Persistência e configurações do sistema",
    "4. Arquivos (temporários, downloads, perfil do usuário)",
    "5. Históricos e logs locais",
    "6. Logs centralizados (EDR/SIEM) e backups",
]

SAFE_RULES = [
    "Isole o host antes (contenção do EDR); não desligue: a memória se perde.",
    "O script é somente leitura e não usa a rede: pode rodar com o host isolado.",
    "Consulte só hashes; não faça upload da amostra ao VirusTotal (vira pública).",
    "Mova as evidências por mídia dedicada; nada de pastas de rede, AirDrop ou e-mail.",
    "Guarde amostras em zip com senha 'infected'; análise dinâmica só em VM sem rede.",
    "Registre quem coletou, quando e o hash do pacote (cadeia de custódia).",
]

# Verificações por técnica ATT&CK (prefixo) e por SO: (o que verificar, comando somente leitura)
TECH_CHECKS: dict[str, dict[str, list[tuple[str, str]]]] = {
    "T1543": {
        "macos": [("LaunchAgents/Daemons", "ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons")],
        "windows": [("Serviços com binário fora de Program Files/Windows",
                     "Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch '(?i)\\\\(Windows|Program Files)' } | Select-Object Name,State,PathName")],
        "linux": [("Units systemd alteradas em 30 dias", "find /etc/systemd/system /home/*/.config/systemd -name '*.service' -mtime -30 -ls")],
    },
    "T1547": {
        "macos": [("Itens de login (BTM)", "sfltool dumpbtm 2>/dev/null | head -200")],
        "windows": [("Chaves Run/RunOnce", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")],
        "linux": [("Autostart e perfis de shell", "ls -la /etc/xdg/autostart /home/*/.config/autostart /etc/profile.d")],
    },
    "T1053": {
        "macos": [("Crontab do usuário", "crontab -l")],
        "windows": [("Tarefas agendadas criadas em 30 dias",
                     "Get-ScheduledTask | Where-Object { $_.Date -and [datetime]$_.Date -gt (Get-Date).AddDays(-30) } | Select-Object TaskPath,TaskName,Date")],
        "linux": [("Cron de todos os usuários", "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u \"$u\" 2>/dev/null; done; ls -la /etc/cron.*")],
    },
    "T1059": {
        "macos": [("Execuções de osascript (24h)", "log show --last 24h --style compact --predicate 'process == \"osascript\"' | tail -200")],
        "windows": [("Script blocks do PowerShell (4104, 24h)",
                     "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200 | Select-Object TimeCreated,Message")],
        "linux": [("Interpretadores em execução", "ps -eo pid,ppid,user,cmd | grep -E 'python|perl|bash -c|sh -c' | grep -v grep")],
    },
    "T1204": {
        "macos": [("Comandos colados no Terminal", "grep -aE 'curl|osascript|base64' ~/.zsh_history | tail -50")],
        "windows": [("Comandos colados no Win+R (ClickFix)", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")],
        "linux": [("Comandos colados no terminal", "grep -aE 'curl|wget|base64' ~/.bash_history | tail -50")],
    },
    "T1555": {
        "macos": [("Arquivos de credenciais alterados (Keychain/Chrome)",
                   "ls -la ~/Library/Keychains/ \"$HOME/Library/Application Support/Google/Chrome/Default/Login Data\"")],
        "windows": [("Bancos de senhas do navegador",
                     "Get-Item \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\", \"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data\" | Select-Object FullName,LastAccessTime,LastWriteTime")],
        "linux": [("Chaveiros e bancos de senha", "ls -la ~/.local/share/keyrings ~/.config/google-chrome/Default/'Login Data' 2>/dev/null")],
    },
    "T1539": {
        "macos": [("Cookies do navegador (último acesso)", "ls -la \"$HOME/Library/Application Support/Google/Chrome/Default/Cookies\"")],
        "windows": [("Cookies do navegador (último acesso)",
                     "Get-Item \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Network\\Cookies\" | Select-Object FullName,LastAccessTime,LastWriteTime")],
        "linux": [("Cookies do navegador (último acesso)", "ls -la ~/.config/google-chrome/Default/Cookies 2>/dev/null")],
    },
    "T1071": {
        "macos": [("Conexões por processo", "lsof -nP -i")],
        "windows": [("Conexões por processo", "Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort,OwningProcess")],
        "linux": [("Conexões por processo", "ss -tunap")],
    },
    "T1102": {
        "macos": [("Processos não-navegador falando com serviços web", "lsof -nP -i | grep -vE 'Chrome|Safari|firefox|Brave|Edge'")],
        "windows": [("Cache DNS de serviços usados como DDR", "Get-DnsClientCache | Where-Object Entry -match 't\\.me|telegram|steamcommunity|pastebin|github'")],
        "linux": [("Processos não-navegador com conexões HTTPS", "ss -tnp state established '( dport = :443 )'")],
    },
    "T1105": {
        "macos": [("Downloads recentes (quarentena)",
                   "sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* \"SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'),LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY 1 DESC LIMIT 30\"")],
        "windows": [("Origem dos downloads (Zone.Identifier)",
                     "Get-ChildItem $env:USERPROFILE\\Downloads -File | ForEach-Object { Get-Content $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue }")],
        "linux": [("Arquivos novos em Downloads/tmp (7 dias)", "find ~/Downloads /tmp /dev/shm -type f -mtime -7 -ls 2>/dev/null")],
    },
    "T1486": {
        "macos": [("Arquivos modificados em massa (1h)", "find ~ -type f -mmin -60 2>/dev/null | head -200")],
        "windows": [("Cópias de sombra (apagadas por ransomware)", "vssadmin list shadows"),
                    ("Notas de resgate recentes", "Get-ChildItem C:\\Users -Recurse -Include *readme*.txt,*decrypt*,*recover* -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-3) | Select-Object -First 50 FullName")],
        "linux": [("Arquivos modificados em massa (1h)", "find /home /srv /var/www -type f -mmin -60 2>/dev/null | head -200")],
    },
}


def normalize_os(platform: str | None) -> str | None:
    p = (platform or "").lower()
    if "mac" in p or "osx" in p or "darwin" in p:
        return "macos"
    if "win" in p:
        return "windows"
    if "linux" in p or "elf" in p or "android" in p:
        return "linux"
    return None


def _safe_tokens(values: list[str], pattern: str) -> list[str]:
    """Só valores que casam com o padrão entram no script (evita injeção de shell/PowerShell)."""
    rx = re.compile(pattern)
    return [v for v in values if rx.fullmatch(v)]


def _iocs(scan: dict[str, Any]) -> dict[str, list[str]]:
    c = build_context(scan)
    ips = [ip for ip in c.ips if _is_ip(ip)]
    return {
        "hashes": _safe_tokens(c.hashes, r"[a-f0-9]{32,64}"),
        "domains": _safe_tokens(c.domains, r"[a-z0-9.-]{3,253}"),
        "needles": _safe_tokens([*c.ddr_needles, *ips], r"[A-Za-z0-9._:-]{3,80}"),
        "names": _safe_tokens(c.file_names, r"[\w.-]{3,80}"),
    }


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def technique_checks(scan: dict[str, Any], os_name: str) -> list[dict[str, str]]:
    tids = [a.get("id", "") for a in scan["triage"].get("mitre_attack", [])]
    names = {a.get("id", ""): a.get("name", "") for a in scan["triage"].get("mitre_attack", [])}
    out, seen = [], set()
    for prefix, per_os in TECH_CHECKS.items():
        matched = [t for t in tids if t == prefix or t.startswith(prefix + ".")]
        if not matched:
            continue
        for title, cmd in per_os.get(os_name, []):
            if (prefix, title) in seen:
                continue
            seen.add((prefix, title))
            out.append({"technique": matched[0], "technique_name": names.get(matched[0], ""), "check": title, "command": cmd})
    return out


def build_plan(scan: dict[str, Any], os_name: str | None = None) -> dict[str, Any]:
    recommended = normalize_os(scan["triage"].get("platform"))
    chosen = os_name or recommended or "windows"
    if chosen not in OSES:
        raise ValueError(f"SO inválido: {chosen}. Use: {', '.join(OSES)}")
    iocs = _iocs(scan)
    return {
        "hash": scan["hash"],
        "family": scan["triage"].get("malware_family", "unknown"),
        "os": chosen,
        "recommended_os": recommended,
        "script": SCRIPT_NAME[chosen],
        "how_to_run": {
            "macos": "bash triagem_macos.sh   (ou sudo bash triagem_macos.sh)",
            "linux": "sudo bash triagem_linux.sh",
            "windows": "powershell -ExecutionPolicy Bypass -File .\\triagem_windows.ps1   (como administrador)",
        }[chosen],
        "standards": ["NIST SP 800-86", "RFC 3227 (ordem de volatilidade)", "NIST SP 800-61"],
        "safe_rules": SAFE_RULES,
        "order_of_volatility": ORDER_OF_VOLATILITY,
        "iocs_embedded": iocs,
        "technique_checks": technique_checks(scan, chosen),
    }


def render_script(scan: dict[str, Any], os_name: str) -> str:
    if os_name not in OSES:
        raise ValueError(f"SO inválido: {os_name}")
    iocs = _iocs(scan)
    family = re.sub(r"[^A-Za-z0-9 ._()-]", "", scan["triage"].get("malware_family") or "unknown")[:60] or "unknown"
    slug = re.sub(r"[^a-z0-9]+", "_", family.lower()).strip("_") or "ameaca"
    checks = technique_checks(scan, os_name)
    tpl = (TEMPLATES / {"macos": "macos.sh", "linux": "linux.sh", "windows": "windows.ps1"}[os_name]).read_text(encoding="utf-8")

    if os_name == "windows":
        arr = lambda xs: "@(" + ", ".join("'" + x + "'" for x in xs) + ")"  # noqa: E731
        block = "\n".join([
            f"$Family = '{family}'", f"$FamilySlug = '{slug}'",
            f"$Hashes = {arr(iocs['hashes'])}", f"$Domains = {arr(iocs['domains'])}",
            f"$Needles = {arr(iocs['needles'])}", f"$Names = {arr(iocs['names'])}",
        ])
        tech = "\n".join(
            f"Say '  [{c['technique']}] {c['check']}'\n"
            f"try {{ {c['command']} | Out-File -Encoding UTF8 (Join-Path $Out 'tecnica_{c['technique']}_{i}.txt') }} catch {{ }}"
            for i, c in enumerate(checks, 1)
        ) or "Say '  (nenhuma técnica mapeada com verificação específica)'"
    else:
        block = "\n".join([
            f'FAMILY="{family}"', f'FAMILY_SLUG="{slug}"',
            f'HASHES="{" ".join(iocs["hashes"])}"', f'DOMAINS="{" ".join(iocs["domains"])}"',
            f'NEEDLES="{" ".join(iocs["needles"])}"', f'NAMES="{" ".join(iocs["names"])}"',
        ])
        tech = "\n".join(
            f"say \"  [{c['technique']}] {c['check']}\"\n"
            f"{{ {c['command']} ; }} > \"$OUT/tecnica_{c['technique']}_{i}.txt\" 2>&1"
            for i, c in enumerate(checks, 1)
        ) or 'say "  (nenhuma técnica mapeada com verificação específica)"'

    title = f"{family} ({scan['hash'][:12]})"
    bom = "\ufeff" if os_name == "windows" else ""  # PowerShell 5.1 precisa de BOM para ler UTF-8
    return bom + (tpl.replace("@@TITLE@@", title).replace("@@HASH@@", scan["hash"])
               .replace("# @@IOCS@@", block).replace("# @@TECH_CHECKS@@", tech))
