#!/usr/bin/env bash
# Linha de comando da ferramenta. Ex.: ./cti.sh analyze <hash> --pdf relatorio.pdf
cd "$(dirname "$0")" && exec .venv/bin/python -m app.cli "$@"
