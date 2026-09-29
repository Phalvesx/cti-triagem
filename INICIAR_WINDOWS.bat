@echo off
REM ============================================================
REM  CTI Triage - Phillipe Alves - Desafio Mercado Livre - 2026
REM  Duplo clique para instalar (1a vez) e abrir a ferramenta.
REM  Opcoes:  INICIAR_WINDOWS.bat --reinstalar | --chaves
REM ============================================================
setlocal EnableExtensions
chcp 65001 >nul
title CTI Triage  ^|  Phillipe Alves  ^|  Desafio Mercado Livre 2026
cd /d "%~dp0"

REM Codigo ESC para cores ANSI (Windows 10+)
for /f %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"
set "R=%ESC%[0m" & set "Y=%ESC%[1;33m" & set "RED=%ESC%[1;31m" & set "C=%ESC%[36m" & set "GR=%ESC%[90m"

REM Aberto de dentro do .zip? (o Windows extrai so o .bat para a pasta Temp)
echo "%~dp0" | find /i "\AppData\Local\Temp\" >nul && goto :naoextraido
if not exist "requirements.txt" goto :naoextraido
if not exist "app\main.py" goto :naoextraido

REM Escolhe o Python mais novo disponivel (3.13, 3.12, 3.11) e cai para "python"
set "PY="
for %%V in (3.13 3.12 3.11) do (
  if not defined PY (
    py -%%V --version >nul 2>nul
    if not errorlevel 1 set "PY=py -%%V"
  )
)
if not defined PY (
  python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
  if not errorlevel 1 set "PY=python"
)
if not defined PY goto :nopython

cls
%PY% instalar.py %*
if errorlevel 1 goto :falhou

".venv\Scripts\python.exe" -m app.cli serve --open --quiet
echo.
echo   %GR%Servidor encerrado. Rode o INICIAR_WINDOWS.bat de novo quando quiser.%R%
pause >nul
exit /b 0

:naoextraido
echo.
echo   %Y%[!] Parece que o arquivo foi aberto de dentro do .zip.%R%
echo.
echo   1. Clique com o botao direito no .zip ^> "Extrair tudo..."
echo   2. Abra a pasta extraida e rode o %C%INICIAR_WINDOWS.bat%R% de la.
echo.
pause
exit /b 1

:nopython
echo.
echo   %RED%[x] Python 3.11 ou superior nao encontrado.%R%
echo.
echo   1. Instale em %C%https://www.python.org/downloads/%R%
echo   2. Na instalacao, marque %Y%"Add python.exe to PATH"%R%
echo   3. Feche esta janela e rode o INICIAR_WINDOWS.bat de novo.
echo.
choice /c SN /n /m "  Abrir a pagina de download do Python agora? [S/N] "
if not errorlevel 2 start "" "https://www.python.org/downloads/"
exit /b 1

:falhou
echo.
echo   %RED%A instalacao nao terminou.%R% Veja as dicas acima e o arquivo %C%install.log%R%.
echo   %GR%Para recomecar do zero:  INICIAR_WINDOWS.bat --reinstalar%R%
echo.
pause
exit /b 1
