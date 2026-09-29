"""Instalador com progresso (0–100%) — CTI Triage.

Uso:  python instalar.py              (instala ou confirma que já está instalado)
      python instalar.py --reinstalar  (recria o .venv do zero)
      python instalar.py --chaves      (pede de novo as chaves do VirusTotal / MalwareBazaar)

Só usa a biblioteca padrão. Cria o ambiente .venv, instala as dependências uma a uma mostrando a
porcentagem, cria o .env (perguntando as chaves de API), valida as chaves e verifica se a aplicação
importa. Todo o detalhe vai para install.log. Sintaxe compatível com Pythons antigos só para
conseguir mostrar a mensagem de versão.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(ROOT, ".venv")
LOG = os.path.join(ROOT, "install.log")
REQ = os.path.join(ROOT, "requirements.txt")
ENV = os.path.join(ROOT, ".env")
ENV_EXAMPLE = os.path.join(ROOT, ".env.example")
MARKER = os.path.join(VENV, ".instalado")
MIN_PY = (3, 11)

sys.path.insert(0, ROOT)
try:
    from app.banner import G, box, print_banner, style
except Exception:  # noqa: BLE001 - Python muito antigo ou arquivo faltando: modo texto simples
    G = {"ok": "OK", "fail": "X", "warn": "!", "info": "*", "off": "-", "arrow": ">", "spin": "|/-\\",
         "full": "#", "empty": "-"}

    def style(text, *_):
        return text

    def box(lines, title="", **_):
        return "\n".join(["  -- %s --" % title] + ["    " + ln for ln in lines])

    def print_banner(subtitle=None):
        print("\n  CTI Triage — Desenvolvido por Phillipe Alves · Desafio Mercado Livre · 2026\n")

def vlen(text):
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


INTERACTIVE = sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("CI")
T0 = time.time()


def log(text):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def fmt_secs(s):
    return "%ds" % s if s < 60 else "%dm%02ds" % (s // 60, s % 60)


# ------------------------------------------------------------------ progresso
class Live:
    """Linha viva: spinner + barra global 0–100% + passo atual + cronômetro.

    Passos concluídos são impressos acima como linhas fixas (✔ nome ........ 3s).
    """

    WIDTH = 28

    def __init__(self):
        self.pct = 0
        self.msg = ""
        self._spin = False
        self._t = None
        self._frame = 0
        self._lock = threading.Lock()

    def _render(self):
        filled = int(self.WIDTH * self.pct / 100)
        bar = style(G["full"] * filled, "yellow") + style(G["empty"] * (self.WIDTH - filled), "gray")
        spin = G["spin"][self._frame % len(G["spin"])] if self._spin else " "
        line = "  %s %s %s  %s  %s" % (
            style(spin, "bold", "cyan"), bar, style("%3d%%" % self.pct, "bold"),
            self.msg, style(fmt_secs(time.time() - T0), "gray"))
        sys.stdout.write("\r\033[2K" + line if style("x", "bold") != "x" else "\r" + line.ljust(100))
        sys.stdout.flush()

    def update(self, pct=None, msg=None):
        with self._lock:
            if pct is not None:
                self.pct = max(self.pct, min(100, int(pct)))
            if msg is not None:
                self.msg = msg
            self._render()

    def clear(self):
        sys.stdout.write("\r\033[2K" if style("x", "bold") != "x" else "\r" + " " * 110 + "\r")
        sys.stdout.flush()

    def done(self, label, secs=None, note=""):
        """Fixa uma linha de passo concluído e redesenha a barra embaixo."""
        with self._lock:
            self.clear()
            right = "" if secs is None else (fmt_secs(secs) if secs >= 1 else "<1s")
            extra = ("  " + style(note, "gray")) if note else ""
            dots = " " + "." * max(46 - vlen(label + extra) - len(right), 1) + " " if right else ""
            print("  %s %s%s%s%s" % (style(G["ok"], "bold", "green"), label, extra, style(dots, "gray"), style(right, "gray")))
            self._render()

    def _spinner(self):
        while self._spin:
            with self._lock:
                self._frame += 1
                self._render()
            time.sleep(0.1)

    def start(self):
        self._spin = True
        self._t = threading.Thread(target=self._spinner, daemon=True)
        self._t.start()

    def stop(self):
        self._spin = False
        if self._t:
            self._t.join()


L = Live()


def run(cmd, pct, msg, label=None, note=""):
    """Executa um comando com spinner; saída completa vai para install.log."""
    L.update(pct, msg)
    log("\n$ " + " ".join(cmd))
    t = time.time()
    L.start()
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            rc = subprocess.call(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=ROOT)
    finally:
        L.stop()
    if rc != 0:
        fail(label or msg)
    if label:
        L.done(label, time.time() - t, note)


def fail(step, hint=None):
    L.clear()
    print("  %s %s\n" % (style(G["fail"], "bold", "red"), style("Falhou em: " + step, "bold", "red")))
    tail = []
    try:
        with open(LOG, encoding="utf-8", errors="replace") as fh:
            tail = [ln for ln in fh.read().splitlines() if ln.strip()][-10:]
    except OSError:
        pass
    if tail:
        print(style("  Últimas linhas do install.log:", "gray"))
        for ln in tail:
            print(style("    " + ln[:120], "gray"))
        print()
    text = " ".join(tail)
    tips = [hint] if hint else []
    net_markers = ("ConnectTimeout", "ConnectionError", "NewConnectionError", "Temporary failure", "ProxyError",
                   "SSLError", "Max retries", "from versions: none", "getaddrinfo failed")
    if any(k in text for k in net_markers):
        tips.append("Não foi possível baixar os pacotes do PyPI: verifique a internet. Em rede corporativa, "
                    "defina o proxy antes (set HTTPS_PROXY=http://proxy:porta).")
    if "requires a different Python" in text or ("No matching distribution" in text and "from versions: none" not in text):
        tips.append("Versão do Python incompatível. Instale o Python 3.12 em https://www.python.org/downloads/")
    if "Permission denied" in text or "Acesso negado" in text or "WinError 5" in text:
        tips.append("Arquivo em uso: feche outras janelas do CTI Triage (ou o antivírus pode estar bloqueando o .venv).")
    if not hint:
        tips.append("Tente de novo com:  python instalar.py --reinstalar")
    for t in tips:
        print(style("  %s %s" % (G["arrow"], t), "yellow"))
    print()
    sys.exit(1)


def venv_python():
    return os.path.join(VENV, "Scripts", "python.exe") if os.name == "nt" else os.path.join(VENV, "bin", "python")


def requirements():
    with open(REQ, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith(("#", "-"))]


def fingerprint():
    with open(REQ, "rb") as fh:
        return hashlib.sha256(fh.read() + sys.version.encode()).hexdigest()


# ------------------------------------------------------------------ .env / chaves
def read_env():
    values = {}
    if os.path.isfile(ENV):
        with open(ENV, encoding="utf-8") as fh:
            for ln in fh:
                if "=" in ln and not ln.lstrip().startswith("#"):
                    k, v = ln.split("=", 1)
                    values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def set_env(key, value):
    """Grava/atualiza KEY=valor no .env preservando comentários e a ordem."""
    lines = []
    if os.path.isfile(ENV):
        with open(ENV, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    pat = re.compile(r"^\s*%s\s*=" % re.escape(key))
    for i, ln in enumerate(lines):
        if pat.match(ln):
            lines[i] = "%s=%s" % (key, value)
            break
    else:
        lines.append("%s=%s" % (key, value))
    with open(ENV, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


KEYS = [
    ("VT_API_KEY", "VirusTotal", "https://www.virustotal.com/gui/my-apikey", r"^[0-9a-fA-F]{64}$"),
    ("MB_API_KEY", "MalwareBazaar", "https://auth.abuse.ch/", r"^[0-9a-fA-F]{48}$"),
]


def ask_keys(force=False):
    """Pergunta as chaves que estiverem vazias (só em terminal interativo)."""
    env = read_env()
    missing = [k for k in KEYS if force or not env.get(k[0])]
    if not missing or not INTERACTIVE:
        return False
    saved = False
    L.clear()
    print()
    print(box([
        "Cole as chaves de API para análises reais (Enter pula e usa o modo simulado).",
        style("Elas ficam só no arquivo .env deste PC — nunca vão para o GitHub.", "gray"),
    ], title=style("Chaves de API", "bold")))
    for var, name, url, pattern in missing:
        print(style("  %s %s  %s" % (G["arrow"], name, url), "gray"))
        while True:
            try:
                val = input("    %s: " % var).strip().strip('"').strip("'")
            except EOFError:
                val = ""
            if not val:
                break
            if re.match(pattern, val):
                set_env(var, val)
                saved = True
                print("    %s %s" % (style(G["ok"], "green"), style("salva no .env", "gray")))
                break
            print(style("    %s formato inesperado para %s; confira e cole de novo (ou Enter para pular)." % (G["warn"], name), "yellow"))
    print()
    return saved


def show_integrations(py, online):
    """Roda `app.cli check` no .venv e imprime a caixa de integrações."""
    args = [py, "-m", "app.cli", "check"] + ([] if online else ["--offline"])
    L.update(msg="Validando as chaves de API..." if online else "Lendo configuração...")
    L.start()
    try:
        out = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=40)
        text, rc = out.stdout, out.returncode
    except Exception as exc:  # noqa: BLE001
        text, rc = "", 1
        log("check falhou: %r" % exc)
    finally:
        L.stop()
        L.clear()
    if text.strip():
        print(text.rstrip("\n"))
    return rc


# ------------------------------------------------------------------ main
def main():
    reinstall = "--reinstalar" in sys.argv
    rekeys = "--chaves" in sys.argv
    print_banner()
    pyver = "%d.%d.%d" % sys.version_info[:3]
    print("  %s  %s" % (style("Instalação", "bold"), style("Python %s · detalhes em install.log" % pyver, "gray")))
    print()
    with open(LOG, "w", encoding="utf-8") as fh:
        fh.write("install.log — %s\nPython: %s\n%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), sys.version, sys.executable))

    # 1. Python
    L.update(2, "Verificando o Python...")
    if sys.version_info < MIN_PY:
        fail("Python %d.%d encontrado; é preciso 3.11 ou superior" % sys.version_info[:2],
             "Instale o Python 3.12 em https://www.python.org/downloads/ (marque 'Add python.exe to PATH')")
    L.done("Python %s compatível" % pyver)

    # 2. arquivos do projeto
    L.update(4, "Verificando os arquivos do projeto...")
    if not os.path.isfile(REQ) or not os.path.isdir(os.path.join(ROOT, "app")):
        fail("arquivos do projeto não encontrados", "Extraia o .zip inteiro para uma pasta antes de executar.")
    L.done("Arquivos do projeto")

    # .env sempre existe (mesmo no caminho rápido)
    if not os.path.isfile(ENV) and os.path.isfile(ENV_EXAMPLE):
        shutil.copyfile(ENV_EXAMPLE, ENV)

    # já instalado?
    if not reinstall and os.path.isfile(MARKER) and os.path.isfile(venv_python()):
        with open(MARKER, encoding="utf-8") as fh:
            if fh.read().strip() == fingerprint():
                L.update(100, "")
                L.done("Dependências já instaladas")
                L.clear()
                saved = ask_keys(force=rekeys)
                show_integrations(venv_python(), online=rekeys or saved)
                print()
                return

    # 3. venv
    if reinstall and os.path.isdir(VENV):
        L.update(6, "Removendo o ambiente antigo...")
        shutil.rmtree(VENV, ignore_errors=True)
        L.done("Ambiente antigo removido")
    if not os.path.isfile(venv_python()):
        run([sys.executable, "-m", "venv", VENV], 8, "Criando o ambiente virtual (.venv)...", "Ambiente virtual (.venv)")
    py = venv_python()
    pip = [py, "-m", "pip", "--disable-pip-version-check", "--no-input"]

    # 4. pip
    run(pip + ["install", "--upgrade", "pip"], 12, "Atualizando o pip...", "pip atualizado")

    # 5. pacotes (15% → 88%)
    reqs = requirements()
    for i, req in enumerate(reqs):
        name = re.split(r"[=<>\[~!]", req)[0]
        ver = req.split("==")[1] if "==" in req else ""
        start = 15 + 73 * i / len(reqs)
        run(pip + ["install", req], start,
            "Instalando %s  %s" % (style(name, "bold"), style("(%d/%d)" % (i + 1, len(reqs)), "gray")),
            "%s %s" % (name, style(ver, "gray")))
    L.update(88, "Pacotes instalados")

    # 6. verificação
    run([py, "-c", "import app.main"], 92, "Verificando a aplicação...", "Aplicação importa sem erros")
    with open(MARKER, "w", encoding="utf-8") as fh:
        fh.write(fingerprint())
    L.update(100, style("Concluído!", "bold", "green"))
    L.clear()
    print()
    print("  %s %s" % (style(G["ok"], "bold", "green"),
                       style("Instalação concluída em %s" % fmt_secs(time.time() - T0), "bold", "green")))

    # 7. chaves + validação online
    ask_keys(force=rekeys)
    show_integrations(py, online=True)
    print(style("  Dica: rode  python instalar.py --chaves  para trocar as chaves depois.", "gray"))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        L.stop()
        L.clear()
        print("\n  Instalação interrompida.")
        sys.exit(130)
