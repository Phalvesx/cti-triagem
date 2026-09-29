#!/bin/bash
# =============================================================================
#  Triagem DFIR — Linux · @@TITLE@@
#  Gerado por CTI Triage a partir da triagem do artefato @@HASH@@
#
#  * SOMENTE LEITURA: não apaga, não mata processos e não altera nada.
#  * SEM REDE: não faz nenhuma conexão. Rode com o host ISOLADO da rede.
#  * Coleta na ORDEM DE VOLATILIDADE (RFC 3227): processos e rede primeiro.
#  * Gera MANIFESTO_SHA256.txt (cadeia de custódia) e um .tar.gz para o time de IR.
#  * Só ferramentas padrão (ps, ss, find, sha256sum, crontab, systemctl, journalctl).
#
#  Uso:  sudo bash triagem_linux.sh     (sem sudo, vê só o usuário atual)
#        SKIP_LOGS=1 sudo bash triagem_linux.sh
# =============================================================================
set -u

# ---------------------------------------------------------------- IoCs (gerados a partir da triagem)
# @@IOCS@@
EXTRA="${EXTRA_IOCS:-}"
IOC_REGEX="$(echo "$DOMAINS $NEEDLES $NAMES $EXTRA" | xargs | sed 's/\./\\./g; s/ /|/g')"
[ -z "$IOC_REGEX" ] && IOC_REGEX="__nenhum_ioc_definido__"
SUSP_CMD='curl[^|]*\| *(ba|z)?sh|wget[^|]*\| *(ba|z)?sh|base64 (-d|--decode)|/dev/tcp/|nc(at)? .* -e |python[0-9.]* -c .*socket'

# ---------------------------------------------------------------- saída
STAMP="$(date +%Y%m%d_%H%M%S)"
BASE="${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}"
OUT="${BASE:-$HOME}/triagem_${FAMILY_SLUG}_$(hostname -s)_$STAMP"
mkdir -p "$OUT"
SUMMARY="$OUT/RESUMO.txt"
HITS=0
say()     { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
alert()   { HITS=$((HITS + 1)); say "  [ALERTA] $*"; }
ok()      { say "  [ok] $*"; }
section() { say ""; say "== $* =="; }
check()   { # check "descrição" arquivo  -> alerta se o arquivo tiver conteúdo
  if [ -s "$2" ]; then alert "$1 — ver $(basename "$2")"; else ok "Nada encontrado: $1"; fi; }

say "Triagem DFIR ($FAMILY) — $(date '+%Y-%m-%d %H:%M:%S %Z')"
say "Host: $(hostname) · Kernel: $(uname -r) · Executado como: $(id -un)"
say "Evidências em: $OUT"

# ---------------------------------------------------------------- 0. voláteis
section "0. Processos e conexões (voláteis — RFC 3227)"
ps -eo pid,ppid,user,lstart,cmd > "$OUT/processos.txt" 2>&1
grep -Ei "$SUSP_CMD|$IOC_REGEX" "$OUT/processos.txt" | grep -v -e grep -e triagem_linux > "$OUT/processos_suspeitos.txt"
check "Processo com linha de comando suspeita ou IoC" "$OUT/processos_suspeitos.txt"
# binário apagado do disco mas ainda em execução (técnica comum de malware)
find /proc/[0-9]*/exe -maxdepth 0 -printf '%p -> %l\n' 2>/dev/null | grep '(deleted)' > "$OUT/processos_binario_apagado.txt"
check "Processo rodando a partir de binário apagado" "$OUT/processos_binario_apagado.txt"
(ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null) > "$OUT/conexoes.txt"
grep -Ei "$IOC_REGEX" "$OUT/conexoes.txt" > "$OUT/conexoes_iocs.txt"
check "Conexão ativa com IoC" "$OUT/conexoes_iocs.txt"
grep -Ei "$IOC_REGEX" /etc/hosts > "$OUT/hosts_iocs.txt" 2>/dev/null
check "/etc/hosts cita IoC" "$OUT/hosts_iocs.txt"

# ---------------------------------------------------------------- 1. persistência
section "1. Persistência (cron, systemd, autostart, ld.so.preload, chaves SSH)"
{ cut -d: -f1 /etc/passwd | while read -r u; do c="$(crontab -l -u "$u" 2>/dev/null)"; [ -n "$c" ] && printf '### %s\n%s\n' "$u" "$c"; done
  cat /etc/crontab /etc/cron.d/* 2>/dev/null; } > "$OUT/cron.txt"
grep -Ei "$SUSP_CMD|$IOC_REGEX|/tmp/|/dev/shm/" "$OUT/cron.txt" > "$OUT/cron_suspeito.txt"
check "Cron suspeito" "$OUT/cron_suspeito.txt"
find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /home/*/.config/systemd /root/.config/systemd \
     -name '*.service' -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort > "$OUT/systemd_recentes.txt"
[ -s "$OUT/systemd_recentes.txt" ] && say "  Units systemd alteradas nos últimos 30 dias: systemd_recentes.txt (revise)"
grep -ls -Ei "$SUSP_CMD|$IOC_REGEX|/tmp/|/dev/shm/" /etc/systemd/system/*.service /home/*/.config/systemd/user/*.service \
     > "$OUT/systemd_suspeito.txt" 2>/dev/null
check "Serviço systemd suspeito" "$OUT/systemd_suspeito.txt"
ls -la /etc/xdg/autostart /home/*/.config/autostart > "$OUT/autostart.txt" 2>/dev/null
[ -s /etc/ld.so.preload ] && { cp /etc/ld.so.preload "$OUT/ld.so.preload"; alert "/etc/ld.so.preload existe (injeção de biblioteca) — revise"; }
find /root/.ssh /home/*/.ssh -name authorized_keys -mtime -30 -print > "$OUT/ssh_keys_recentes.txt" 2>/dev/null
check "authorized_keys alterado nos últimos 30 dias" "$OUT/ssh_keys_recentes.txt"

# ---------------------------------------------------------------- 2. arquivos
section "2. Arquivos da ameaça e hash do artefato"
: > "$OUT/arquivos_por_nome.txt"
for n in $NAMES; do find / -xdev -name "$n" -print 2>/dev/null >> "$OUT/arquivos_por_nome.txt"; done
check "Arquivo com nome ligado à ameaça" "$OUT/arquivos_por_nome.txt"
find /tmp /var/tmp /dev/shm -type f -perm -u+x -print 2>/dev/null > "$OUT/executaveis_temporarios.txt"
check "Executável em /tmp, /var/tmp ou /dev/shm" "$OUT/executaveis_temporarios.txt"
find /tmp /var/tmp /dev/shm /root /home -maxdepth 3 -type f -size -20M -mtime -120 -print0 2>/dev/null \
  | xargs -0 sha256sum 2>/dev/null > "$OUT/hashes_recentes.txt"
: > "$OUT/hash_match.txt"
for h in $HASHES; do grep -i "$h" "$OUT/hashes_recentes.txt" >> "$OUT/hash_match.txt"; done
check "Hash do artefato encontrado no disco" "$OUT/hash_match.txt"

# ---------------------------------------------------------------- 3. históricos
section "3. Históricos de shell"
grep -aEn "$SUSP_CMD|$IOC_REGEX" /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history \
  > "$OUT/historico_suspeito.txt" 2>/dev/null
check "Comando suspeito no histórico do shell" "$OUT/historico_suspeito.txt"

# ---------------------------------------------------------------- 4. logs
section "4. Logs (últimos 3 dias)"
if [ "${SKIP_LOGS:-0}" = "1" ]; then say "  Pulado (SKIP_LOGS=1)"
else
  last -F -n 50 > "$OUT/logins.txt" 2>/dev/null
  journalctl --since "-3d" --no-pager -o short-iso 2>/dev/null | grep -Ei "$IOC_REGEX|$SUSP_CMD" > "$OUT/journal_iocs.txt"
  check "Journal cita IoC ou comando suspeito" "$OUT/journal_iocs.txt"
  journalctl --since "-3d" --no-pager -o short-iso _COMM=systemd 2>/dev/null | grep -Ei "Started|Created" | tail -300 > "$OUT/journal_servicos.txt"
fi

# ---------------------------------------------------------------- 5. técnicas observadas (ATT&CK)
section "5. Verificações específicas das técnicas observadas"
# @@TECH_CHECKS@@

# ---------------------------------------------------------------- cadeia de custódia e resumo
( cd "$OUT" && find . -type f ! -name MANIFESTO_SHA256.txt -exec sha256sum {} + ) > "$OUT/MANIFESTO_SHA256.txt" 2>/dev/null
section "Resultado"
if [ "$HITS" -gt 0 ]; then
  say "  $HITS ALERTA(S). Trate como possível comprometimento:"
  say "   1) NÃO desligue o host; mantenha-o isolado da rede."
  say "   2) Preserve esta pasta; se possível, capture a memória (ex.: AVML/LiME) antes de qualquer limpeza."
  say "   3) Siga o playbook do incidente: revogar credenciais/chaves a partir de OUTRA máquina."
else
  say "  Nenhum indicador da ameaça encontrado nas verificações locais."
  say "  Isso não prova que o host está limpo: confirme com EDR/SIEM (hunts)."
fi
tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null && say "Pacote para o time de IR: $OUT.tar.gz"
[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT" "$OUT.tar.gz" 2>/dev/null
exit 0
