@echo off
REM Testa as chaves e as APIs reais (VirusTotal + MalwareBazaar) com hashes conhecidos.
chcp 65001 >nul
title CTI Triage - Teste das APIs
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (echo   Rode o INICIAR_WINDOWS.bat primeiro. & pause & exit /b 1)
".venv\Scripts\python.exe" scripts\testar_apis.py %*
pause
