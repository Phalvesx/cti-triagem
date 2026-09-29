#!/usr/bin/env bash
# CTI Triage — Phillipe Alves · Desafio Mercado Livre · 2026
# Instala (1a vez, com progresso 0–100%) e abre a ferramenta. Uso: ./iniciar.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1
PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -z "$PY" ] && { echo "Instale o Python 3.11+ (https://www.python.org/downloads/)"; exit 1; }
"$PY" instalar.py "$@" || { echo "  A instalação não terminou. Veja as dicas acima e o install.log."; exit 1; }

exec .venv/bin/python -m app.cli serve --open --quiet
