@echo off
REM Linha de comando da ferramenta (sem interface). Ex.: cti analyze <hash> --pdf relatorio.pdf
chcp 65001 >nul
"%~dp0.venv\Scripts\python.exe" -m app.cli %*
