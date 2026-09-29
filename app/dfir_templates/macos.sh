#!/bin/bash
# =============================================================================
#  Triagem DFIR — macOS · @@TITLE@@
#  Gerado por CTI Triage a partir da triagem do artefato @@HASH@@
#
#  * SOMENTE LEITURA: não apaga, não mata processos e não altera nada.
#  * SEM REDE: não faz nenhuma conexão (não consulta IoCs, não envia nada).
#    Rode com o Mac ISOLADO da rede (contenção do EDR ou Wi-Fi desligado).
#  * Coleta na ORDEM DE VOLATILIDADE (RFC 3227): processos e rede primeiro,
#    depois persistência, arquivos, históricos e logs.
#  * Gera MANIFESTO_SHA256.txt (cadeia de custódia) e um .zip para o time de IR.
#  * Só ferramentas nativas do macOS; compatível com o bash 3.2 do sistema.
#
#  Uso:  bash triagem_macos.sh   |   sudo bash triagem_macos.sh   |   SKIP_LOGS=1 bash ...
#  Dica: dê "Acesso Total ao Disco" ao Terminal para ler Safari e bancos protegidos.
# =============================================================================
set -u

# ---------------------------------------------------------------- IoCs (gerados a partir da triagem)
# @@IOCS@@
# IoCs extras: EXTRA_IOCS="dominio1.com dominio2.xyz" bash triagem_macos.sh
EXTRA="${EXTRA_IOCS:-}"
IOC_REGEX="$(echo "$DOMAINS $NEEDLES $NAMES $EXTRA" | xargs | sed 's/\./\\./g; s/ /|/g')"
[ -z "$IOC_REGEX" ] && IOC_REGEX="__nenhum_ioc_definido__"
RANDOM_AGENT_REGEX='^com\.[^./]+\.[a-z]{12,20}\.plist$'

# ---------------------------------------------------------------- saída
TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME="$(eval echo "~$TARGET_USER")"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$TARGET_HOME/Desktop/triagem_${FAMILY_SLUG}_$(hostname -s)_$STAMP"
mkdir -p "$OUT"
SUMMARY="$OUT/RESUMO.txt"
HITS=0
TMPCOPY="$(mktemp -d)"
trap 'rm -rf "$TMPCOPY"' EXIT

say()   { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
alert() { HITS=$((HITS + 1)); say "  [ALERTA] $*"; }
ok()    { say "  [ok] $*"; }
section() { say ""; say "== $* =="; }

say "Triagem DFIR ($FAMILY) — $(date '+%Y-%m-%d %H:%M:%S %Z')"
say "Host: $(hostname) · Usuário analisado: $TARGET_USER · Executado como: $(id -un)"
say "macOS: $(sw_vers -productVersion 2>/dev/null || echo '?') ($(uname -m))"
say "Evidências em: $OUT"

# ---------------------------------------------------------------- 0. processos e rede agora (mais voláteis)
section "0. Processos e conexões ativas (voláteis — RFC 3227)"
ps -axo pid,ppid,user,etime,command > "$OUT/processos.txt" 2>&1
grep -E "osascript|curl .*\| *(ba|z)?sh" "$OUT/processos.txt" | grep -v -e grep -e mac_triage > "$OUT/processos_suspeitos.txt"
if [ -s "$OUT/processos_suspeitos.txt" ]; then alert "Processo osascript/curl|sh em execução — ver processos_suspeitos.txt"
else ok "Nenhum osascript/curl|sh em execução agora"; fi
lsof -nP -i > "$OUT/conexoes.txt" 2>&1
grep -E "^(osascript|curl|bash|zsh|sh) " "$OUT/conexoes.txt" > "$OUT/conexoes_suspeitas.txt"
if [ -s "$OUT/conexoes_suspeitas.txt" ]; then alert "Script/shell com conexão de rede aberta — ver conexoes_suspeitas.txt"
else ok "Nenhuma conexão de rede aberta por osascript/curl/shell"; fi
grep -Eiq "$IOC_REGEX" /etc/hosts && alert "/etc/hosts cita IoC"
grep -Ei "$IOC_REGEX" "$OUT/conexoes.txt" > "$OUT/conexoes_iocs.txt" 2>/dev/null
[ -s "$OUT/conexoes_iocs.txt" ] && alert "Conexão ativa com IoC — ver conexoes_iocs.txt"

# ---------------------------------------------------------------- 1. persistência
section "1. Persistência (LaunchAgents / LaunchDaemons / Login Items)"
for dir in "$TARGET_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
  [ -d "$dir" ] || continue
  ls -la "$dir" >> "$OUT/persistencia_ls.txt" 2>&1
  for plist in "$dir"/*.plist; do
    [ -e "$plist" ] || continue
    name="$(basename "$plist")"
    content="$(plutil -p "$plist" 2>/dev/null)"
    { echo "### $plist"; echo "$content"; echo; } >> "$OUT/persistencia_plists.txt"
    if echo "$name" | grep -Eq "$RANDOM_AGENT_REGEX"; then
      alert "LaunchAgent com nome aleatório: $plist"
    fi
    if echo "$name $content" | grep -Eiq "$IOC_REGEX"; then
      alert "LaunchAgent cita IoC conhecido: $plist"
    fi
    if echo "$content" | grep -Eiq 'osascript|/Library/[a-z]{12,20}"|curl .*\| *(ba|z)?sh'; then
      alert "LaunchAgent executa osascript/script suspeito: $plist"
    fi
  done
done
launchctl list > "$OUT/launchctl_list.txt" 2>&1
if [ "$(id -u)" -eq 0 ]; then
  sfltool dumpbtm > "$OUT/btm_dump.txt" 2>&1 && ok "Background Task Management exportado (btm_dump.txt)"
  grep -Eiq "$IOC_REGEX" "$OUT/btm_dump.txt" 2>/dev/null && alert "Item de login/BTM cita IoC (btm_dump.txt)"
else
  say "  (rode com sudo para incluir 'sfltool dumpbtm' — lista todos os itens de inicialização)"
fi

# ---------------------------------------------------------------- 2. arquivos
section "2. Arquivos do malware e hash do artefato"
SEARCH_DIRS="$TARGET_HOME/Library $TARGET_HOME/Downloads $TARGET_HOME/Desktop $TARGET_HOME/Documents /Users/Shared /tmp /private/tmp /private/var/folders"
for n in $NAMES; do
  # shellcheck disable=SC2086
  while read -r f; do
    alert "Arquivo com nome ligado à ameaça: $f"
    shasum -a 256 "$f" >> "$OUT/arquivos_suspeitos_sha256.txt" 2>/dev/null
  done < <(find $SEARCH_DIRS -name "$n" -print 2>/dev/null)
done
# payload persistido: arquivo sem extensão, nome de 12-20 letras, direto em ~/Library
while read -r f; do
  alert "Arquivo com nome aleatório em ~/Library (padrão do loader): $f"
  head -c 400 "$f" > "$OUT/amostra_$(basename "$f").txt" 2>/dev/null
done < <(find -E "$TARGET_HOME/Library" -maxdepth 1 -type f -regex '.*/[a-z]{12,20}' -print 2>/dev/null)
say "  Calculando SHA-256 de arquivos pequenos recentes (Downloads, ~/Library, temporários)..."
# shellcheck disable=SC2086
find "$TARGET_HOME/Downloads" "$TARGET_HOME/Library" /tmp /private/tmp /Users/Shared -maxdepth 2 -type f \
     -size -5M -mtime -120 -print0 2>/dev/null | xargs -0 shasum -a 256 2>/dev/null > "$OUT/hashes_recentes.txt"
for h in $HASHES; do
  if grep -qi "$h" "$OUT/hashes_recentes.txt"; then alert "Hash do artefato encontrado: $(grep -i "$h" "$OUT/hashes_recentes.txt")"
  else ok "Hash $h não encontrado nos diretórios verificados"; fi
done

# ---------------------------------------------------------------- 3. histórico do shell (ClickFix)
section "3. Histórico do Terminal (comandos colados — ClickFix)"
: > "$OUT/historico_shell_suspeito.txt"
for hf in "$TARGET_HOME/.zsh_history" "$TARGET_HOME/.bash_history" "$TARGET_HOME"/.zsh_sessions/*.history; do
  [ -f "$hf" ] || continue
  grep -aEn "curl[^|]*\| *(ba|z)?sh|osascript|base64 (-d|--decode)|echo [A-Za-z0-9+/=]{40,}|$IOC_REGEX" "$hf" \
    | sed "s|^|$hf:|" >> "$OUT/historico_shell_suspeito.txt"
done
if [ -s "$OUT/historico_shell_suspeito.txt" ]; then
  alert "Comandos suspeitos no histórico do shell ($(wc -l < "$OUT/historico_shell_suspeito.txt" | xargs) linha(s)) — revise historico_shell_suspeito.txt"
else ok "Nenhum comando suspeito no histórico do shell"; fi

# ---------------------------------------------------------------- 4. downloads (Quarantine Events)
section "4. Downloads registrados pelo macOS (Quarantine Events)"
QDB="$(find "$TARGET_HOME/Library/Preferences" -maxdepth 1 -name 'com.apple.LaunchServices.QuarantineEventsV*' 2>/dev/null | head -1)"
if [ -n "$QDB" ]; then
  sqlite3 -separator ' | ' "$QDB" "SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch'), LSQuarantineAgentName,
      LSQuarantineDataURLString, LSQuarantineOriginURLString FROM LSQuarantineEvent
      ORDER BY LSQuarantineTimeStamp DESC LIMIT 300;" > "$OUT/downloads_quarentena.txt" 2>&1
  if grep -Eiq "$IOC_REGEX" "$OUT/downloads_quarentena.txt"; then alert "Download a partir de IoC (downloads_quarentena.txt)"
  else ok "Nenhum download a partir dos IoCs (últimos 300 registros)"; fi
else say "  Banco de quarentena não encontrado"; fi

# ---------------------------------------------------------------- 5. navegadores
section "5. Histórico dos navegadores (acesso ao C2 / Dead Drop Resolver)"
for hist in "$TARGET_HOME/Library/Application Support/Google/Chrome/"*/History \
            "$TARGET_HOME/Library/Application Support/BraveSoftware/Brave-Browser/"*/History \
            "$TARGET_HOME/Library/Application Support/Microsoft Edge/"*/History; do
  [ -f "$hist" ] || continue
  cp "$hist" "$TMPCOPY/h.db" 2>/dev/null || continue   # copia: o navegador trava o arquivo
  label="${hist#"$TARGET_HOME/Library/Application Support/"}"
  sqlite3 -separator ' | ' "$TMPCOPY/h.db" "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url
      FROM urls ORDER BY last_visit_time DESC LIMIT 5000;" 2>/dev/null | grep -Ei "$IOC_REGEX" \
      | sed "s|^|$label: |" >> "$OUT/navegador_iocs.txt"
  sqlite3 -separator ' | ' "$TMPCOPY/h.db" "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url
      FROM downloads ORDER BY start_time DESC LIMIT 50;" 2>/dev/null | sed "s|^|$label: |" >> "$OUT/navegador_downloads.txt"
done
SAFARI="$TARGET_HOME/Library/Safari/History.db"
if [ -r "$SAFARI" ] && cp "$SAFARI" "$TMPCOPY/s.db" 2>/dev/null; then
  sqlite3 -separator ' | ' "$TMPCOPY/s.db" "SELECT datetime(v.visit_time + 978307200,'unixepoch'), i.url FROM history_visits v
      JOIN history_items i ON i.id = v.history_item ORDER BY v.visit_time DESC LIMIT 5000;" 2>/dev/null \
      | grep -Ei "$IOC_REGEX" | sed 's|^|Safari: |' >> "$OUT/navegador_iocs.txt"
else say "  Safari: sem permissão (dê Acesso Total ao Disco ao Terminal) ou sem histórico"; fi
if [ -s "$OUT/navegador_iocs.txt" ]; then alert "Navegador acessou IoC — ver navegador_iocs.txt"
else ok "Nenhum acesso a IoC no histórico dos navegadores"; fi

# ---------------------------------------------------------------- 6. Unified Log
section "6. Unified Log (últimas 72h)"
if [ "${SKIP_LOGS:-0}" = "1" ]; then say "  Pulado (SKIP_LOGS=1)"
else
  say "  Coletando (pode levar alguns minutos)..."
  log show --last 72h --style compact --predicate 'process == "osascript"' > "$OUT/log_osascript.txt" 2>&1
  log show --last 72h --style compact --predicate 'subsystem == "com.apple.backgroundtaskmanagement"' > "$OUT/log_btm.txt" 2>&1
  n="$(grep -c "osascript" "$OUT/log_osascript.txt" 2>/dev/null || echo 0)"
  say "  osascript no log: $n linha(s) (log_osascript.txt) — o log não traz a linha de comando; cruze com o EDR"
  grep -Ei "LaunchAgents|$IOC_REGEX" "$OUT/log_btm.txt" > "$OUT/log_btm_itens.txt" 2>/dev/null
  [ -s "$OUT/log_btm_itens.txt" ] && say "  Itens de inicialização registrados no período: log_btm_itens.txt (revise nomes aleatórios)"
fi

# ---------------------------------------------------------------- 7. técnicas observadas (ATT&CK)
section "7. Verificações específicas das técnicas observadas"
# @@TECH_CHECKS@@

# ---------------------------------------------------------------- cadeia de custódia
( cd "$OUT" && find . -type f ! -name MANIFESTO_SHA256.txt -exec shasum -a 256 {} + ) > "$OUT/MANIFESTO_SHA256.txt" 2>/dev/null
say "  Manifesto de integridade (SHA-256) das evidências: MANIFESTO_SHA256.txt"

# ---------------------------------------------------------------- resumo
section "Resultado"
if [ "$HITS" -gt 0 ]; then
  say "  $HITS ALERTA(S). Trate como possível comprometimento:"
  say "   1) NÃO desligue a máquina; isole da rede (ou pelo EDR)."
  say "   2) Preserve esta pasta e rode: sudo log collect --last 3d --output ~/Desktop/"
  say "   3) Siga o playbook (playbook do incidente): revogar sessões e trocar senhas a partir de OUTRO dispositivo."
else
  say "  Nenhum indicador da ameaça encontrado nas verificações locais."
  say "  Isso não prova que o host está limpo: confirme com a telemetria do EDR/SIEM (hunts H1–H6)."
fi
say ""
ditto -c -k --keepParent "$OUT" "$OUT.zip" 2>/dev/null && say "Pacote para o time de IR: $OUT.zip"
[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT" "$OUT.zip" 2>/dev/null
exit 0
