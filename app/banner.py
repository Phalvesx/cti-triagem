"""Banner e utilitários visuais de terminal (instalador, CLI).

Só biblioteca padrão e sintaxe compatível com Pythons antigos: o instalador importa este módulo
com o Python do sistema, antes de o .venv existir.
"""
import os
import shutil
import sys

try:
    from app import __version__ as VERSION
except Exception:  # noqa: BLE001
    VERSION = ""

AUTHOR = "Phillipe Alves"
EVENT = "Desafio Mercado Livre"
YEAR = "2026"
TAGLINE = "Análise de Malware · Threat Hunting · DFIR · Resposta a Incidentes"

LOGO = [
    " ██████╗████████╗██╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗",
    "██╔════╝╚══██╔══╝██║    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝",
    "██║        ██║   ██║       ██║   ██████╔╝██║███████║██║  ███╗█████╗  ",
    "██║        ██║   ██║       ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝  ",
    "╚██████╗   ██║   ██║       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗",
    " ╚═════╝   ╚═╝   ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
]
LOGO_SMALL = [  # para janelas estreitas (< 74 colunas)
    "  ___ _____ ___   _____    _               ",
    " / __|_   _|_ _| |_   _| _(_)__ _ __ _ ___ ",
    "| (__  | |  | |    | || '_| / _` / _` / -_)",
    " \\___| |_| |___|   |_||_| |_\\__,_\\__, \\___|",
    "                                 |___/     ",
]

# ------------------------------------------------------------------ capacidades do terminal
if os.name == "nt":
    os.system("")  # ativa sequências ANSI no console do Windows 10+  # noqa: S605,S607
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
# Windows Terminal, VS Code e terminais Unix têm fontes com todos os glifos; o conhost clássico não.
MODERN = os.name != "nt" or bool(os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"))
TRUECOLOR = COLOR and (MODERN or os.environ.get("COLORTERM") in ("truecolor", "24bit"))


def _can_encode(s):
    try:
        s.encode(sys.stdout.encoding or "utf-8")
        return True
    except Exception:  # noqa: BLE001
        return False


UNICODE = _can_encode("█░═╗✔")
if UNICODE and MODERN:
    G = {"ok": "✔", "fail": "✖", "warn": "▲", "info": "●", "off": "○", "arrow": "›",
         "spin": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "full": "█", "empty": "░",
         "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│"}
elif UNICODE:  # conhost clássico (Consolas/Lucida): só glifos garantidos
    G = {"ok": "√", "fail": "×", "warn": "!", "info": "■", "off": "·", "arrow": "»",
         "spin": "|/-\\", "full": "█", "empty": "░",
         "tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│"}
else:
    G = {"ok": "OK", "fail": "X", "warn": "!", "info": "*", "off": "-", "arrow": ">",
         "spin": "|/-\\", "full": "#", "empty": "-",
         "tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"}

# paleta (amarelo Mercado Livre → âmbar)
YELLOW = (255, 230, 0)
AMBER = (255, 159, 28)
CYAN = (86, 204, 242)
_ANSI = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34",
         "magenta": "35", "cyan": "36", "white": "37", "gray": "90"}


def style(text, *names):
    """style('x', 'bold', 'green') — ignora cores se o terminal não suportar."""
    if not COLOR or not names:
        return text
    codes = ";".join(_ANSI[n] for n in names if n in _ANSI)
    return "\033[%sm%s\033[0m" % (codes, text)


def rgb(text, color, bold=False):
    if not COLOR:
        return text
    if not TRUECOLOR:
        return style(text, "bold", "yellow") if bold else style(text, "yellow")
    return "\033[%s38;2;%d;%d;%dm%s\033[0m" % ("1;" if bold else "", color[0], color[1], color[2], text)


def gradient(line, start=YELLOW, end=AMBER):
    """Degradê horizontal caractere a caractere (fallback: amarelo sólido)."""
    if not COLOR:
        return line
    if not TRUECOLOR:
        return style(line, "bold", "yellow")
    n = max(len(line) - 1, 1)
    out = []
    for i, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        t = i / n
        r, g, b = (int(start[k] + (end[k] - start[k]) * t) for k in range(3))
        out.append("\033[1;38;2;%d;%d;%dm%s" % (r, g, b, ch))
    return "".join(out) + "\033[0m"


def visible_len(text):
    import re

    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def term_width(default=100):
    try:
        return shutil.get_terminal_size((default, 30)).columns
    except Exception:  # noqa: BLE001
        return default


def box(lines, title="", color="gray", pad=2, width=None):
    """Caixa com bordas; `lines` pode conter códigos ANSI."""
    inner = max([visible_len(ln) + pad * 2 for ln in lines] + [visible_len(title) + 6, width or 0])
    top_label = (" %s " % title) if title else ""
    top = G["tl"] + G["h"] * 2 + top_label + G["h"] * max(inner - 2 - visible_len(top_label), 0) + G["tr"]
    out = ["  " + style(top, color)]
    for ln in lines:
        fill = inner - pad - visible_len(ln)
        out.append("  " + style(G["v"], color) + " " * pad + ln + " " * max(fill, 0) + style(G["v"], color))
    out.append("  " + style(G["bl"] + G["h"] * inner + G["br"], color))
    return "\n".join(out)


def print_banner(subtitle=None):
    wide = term_width() >= 74 and UNICODE
    art = LOGO if wide else LOGO_SMALL
    print()
    for ln in art:
        print("  " + gradient(ln))
    print()
    print("  " + style(TAGLINE, "white"))
    credit = "Desenvolvido por %s %s %s %s %s" % (
        rgb(AUTHOR, YELLOW, bold=True), style("·", "gray"), EVENT, style("·", "gray"), YEAR)
    title = ("v" + VERSION) if VERSION else ""
    print(box([credit], title=title, width=(len(art[0]) - 2) if wide else None, pad=2))
    if subtitle:
        print("  " + subtitle)
    print()


if __name__ == "__main__":
    print_banner()
