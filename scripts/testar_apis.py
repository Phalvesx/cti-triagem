"""Teste de fumaça das integrações REAIS (VirusTotal + MalwareBazaar) com hashes conhecidos.

Uso (na pasta do projeto, depois de instalar):
    Windows:  TESTAR_APIS.bat
    Linux/mac: .venv/bin/python scripts/testar_apis.py [--rapido]

A API pública do VT permite 4 requisições/min e cada análise usa até 4 (arquivo + 3 relacionamentos),
então o script espera ~60s entre um hash e outro (use --rapido para testar só 2 hashes).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ.setdefault("LOG_LEVEL", "ERROR")

from fastapi.testclient import TestClient  # noqa: E402

from app.banner import G, box, print_banner, style  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.healthcheck import run_all  # noqa: E402
from app.main import create_app  # noqa: E402

HASHES = [
    ("7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e", "Hash do desafio (Phexia, macOS)", None),
    ("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "WannaCry (ransomware, Windows)", "malicious"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR (arquivo de teste antivírus)", "malicious"),
    ("84c82835a5d21bbcf75a61706d8ab549", "WannaCry em MD5 (testa entrada MD5)", "malicious"),
    ("0" * 64, "Hash inexistente (deve dar 404)", "404"),
]


def main() -> int:
    rapido = "--rapido" in sys.argv
    print_banner()
    s = get_settings()
    checks = run_all(s)
    icons = {"ok": (G["ok"], "green"), "off": (G["off"], "gray"), "invalid": (G["fail"], "red")}
    lines = []
    for r in checks:
        ic, col = icons.get(r["status"], (G["warn"], "yellow"))
        lines.append(f"{style(ic, 'bold', col)} {r['service']:<14} {r['detail']}")
    print(box(lines, title=style("1. Chaves de API", "bold")))
    if checks[0]["status"] != "ok":
        print(style(f"\n  {G['fail']} VirusTotal indisponível — corrija a VT_API_KEY no .env (python instalar.py --chaves).\n", "red"))
        return 1

    items = HASHES[:2] + HASHES[-1:] if rapido else HASHES
    print(f"\n  {style('2. Análises reais', 'bold')}  {style('(%d hashes, ~1 min cada por causa do limite do VT)' % len(items), 'gray')}\n")
    with TestClient(create_app()) as client:
        return _run(client, items)


def _run(client: TestClient, items: list) -> int:
    ok_count = 0
    for i, (h, desc, expected) in enumerate(items):
        if i:
            for left in range(62, 0, -1):
                sys.stdout.write(f"\r  {style('aguardando limite do VT… %2ds' % left, 'gray')}")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\r" + " " * 50 + "\r")
        t = time.time()
        r = client.get(f"/api/v1/analyze/{h}", params={"force": True})
        secs = time.time() - t
        if r.status_code == 200:
            d = r.json()
            tri = d["triage"]
            passed = expected in (None, tri["verdict"])
            info = (f"{tri['verdict']:<10} {tri['malware_family']:<14} {d['features']['detection']['ratio']:<7} "
                    f"fontes={d['source']}")
            if d.get("source_errors"):
                info += style("  (" + "; ".join(f"{k}: {v}" for k, v in d["source_errors"].items()) + ")", "gray")
        else:
            passed = expected == str(r.status_code)
            info = f"HTTP {r.status_code}: {str(r.json().get('detail'))[:70]}"
        ok_count += passed
        mark = style(G["ok"], "bold", "green") if passed else style(G["fail"], "bold", "red")
        print(f"  {mark} {desc}\n      {info}  {style('%.1fs' % secs, 'gray')}")

    total = len(items)
    color = "green" if ok_count == total else "yellow"
    print("\n" + box([style(f"{ok_count}/{total} testes OK", "bold", color)], title="Resultado", color=color) + "\n")
    return 0 if ok_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
