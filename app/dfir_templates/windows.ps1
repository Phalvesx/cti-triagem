<#
=============================================================================
 Triagem DFIR — Windows · @@TITLE@@
 Gerado por CTI Triage a partir da triagem do artefato @@HASH@@

 * SOMENTE LEITURA: não apaga, não mata processos e não altera nada.
 * SEM REDE: não faz nenhuma conexão. Rode com o host ISOLADO (contenção do EDR).
 * Coleta na ORDEM DE VOLATILIDADE (RFC 3227): processos e rede primeiro.
 * Gera MANIFESTO_SHA256.txt (cadeia de custódia) e um .zip para o time de IR.
 * Só cmdlets nativos (PowerShell 5.1+). Como administrador vê mais (eventos de segurança).

 Uso (PowerShell como administrador):
   powershell -ExecutionPolicy Bypass -File .\triagem_windows.ps1
   powershell -ExecutionPolicy Bypass -File .\triagem_windows.ps1 -SkipEventLogs
=============================================================================
#>
param([switch]$SkipEventLogs)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- IoCs (gerados a partir da triagem)
# @@IOCS@@
$IocList = @($Domains + $Needles + $Names) | Where-Object { $_ }
$IocRegex = if ($IocList.Count) { ($IocList | ForEach-Object { [regex]::Escape($_) }) -join '|' } else { '__nenhum_ioc_definido__' }
$SuspRegex = '(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-expression|iex\s*\(|mshta(\.exe)?\s+http|rundll32(\.exe)?\s+\S+,|regsvr32(\.exe)?\s+/s\s+/i:http|certutil(\.exe)?\s+-urlcache|bitsadmin\s+/transfer|curl(\.exe)?\s+.*\|\s*(powershell|cmd))'

# ---------------------------------------------------------------- saída
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Out = Join-Path ([Environment]::GetFolderPath('Desktop')) ("triagem_{0}_{1}_{2}" -f $FamilySlug, $env:COMPUTERNAME, $Stamp)
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$Summary = Join-Path $Out 'RESUMO.txt'
$script:Hits = 0
function Say([string]$m) { $m | Tee-Object -FilePath $Summary -Append }
function Alert([string]$m) { $script:Hits++; Say "  [ALERTA] $m" }
function Ok([string]$m) { Say "  [ok] $m" }
function Section([string]$m) { Say ''; Say "== $m ==" }
function Check([string]$desc, $items, [string]$file) {
    $items = @($items | Where-Object { $null -ne $_ })   # @($null) teria Count 1: evita falso alerta
    if ($items.Count -gt 0) { $items | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out $file); Alert "$desc ($($items.Count)) — ver $file" }
    else { Ok "Nada encontrado: $desc" }
}
function Test-Ioc([string]$text) { $text -and ($text -match $IocRegex -or $text -match $SuspRegex) }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ("Triagem DFIR ({0}) — {1}" -f $Family, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
Say ("Host: {0} · Usuário: {1} · Admin: {2} · Windows {3}" -f $env:COMPUTERNAME, $env:USERNAME, $IsAdmin, [Environment]::OSVersion.Version)
Say "Evidências em: $Out"

# ---------------------------------------------------------------- 0. voláteis
Section '0. Processos, conexões e cache DNS (voláteis — RFC 3227)'
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate
$procs | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'processos.csv')
Check 'Processo com linha de comando suspeita ou IoC' ($procs | Where-Object { Test-Ioc $_.CommandLine }) 'processos_suspeitos.csv'
# atenção: variáveis do PowerShell ignoram maiúsculas ($procNames ≠ $Names dos IoCs)
$procNames = @{}; $procs | ForEach-Object { $procNames[[int]$_.ProcessId] = $_.Name }
$conns = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
    @{ n = 'Processo'; e = { $procNames[[int]$_.OwningProcess] } }
$conns | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'conexoes.csv')
Check 'Conexão ativa com IP de IoC' ($conns | Where-Object { $Needles -contains $_.RemoteAddress }) 'conexoes_iocs.csv'
$dns = Get-DnsClientCache | Select-Object Entry, Data, TimeToLive
$dns | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'dns_cache.csv')
Check 'Cache DNS resolveu domínio de IoC' ($dns | Where-Object { $_.Entry -match $IocRegex }) 'dns_cache_iocs.csv'
$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -match $IocRegex }
if ($hosts) { Alert 'Arquivo hosts cita IoC' }

# ---------------------------------------------------------------- 1. persistência
Section '1. Persistência (Run keys, tarefas, serviços, Startup, WMI)'
$runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
$run = foreach ($k in $runKeys) {
    $p = Get-ItemProperty $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { [pscustomobject]@{ Chave = $k; Nome = $_.Name; Valor = "$($_.Value)" } } }
}
$run | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'run_keys.csv')
Check 'Run key suspeita' ($run | Where-Object { (Test-Ioc $_.Valor) -or $_.Valor -match '(?i)\\(AppData|Temp|Public)\\' }) 'run_keys_suspeitas.csv'
$tasks = Get-ScheduledTask | ForEach-Object { $t = $_; $t.Actions | ForEach-Object {
    [pscustomobject]@{ Tarefa = $t.TaskPath + $t.TaskName; Estado = $t.State; Executa = "$($_.Execute) $($_.Arguments)" } } }
$tasks | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'tarefas.csv')
Check 'Tarefa agendada suspeita' ($tasks | Where-Object { (Test-Ioc $_.Executa) -or $_.Executa -match '(?i)\\(AppData|Temp|Public)\\' }) 'tarefas_suspeitas.csv'
$svcs = Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName
$svcs | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'servicos.csv')
Check 'Serviço suspeito' ($svcs | Where-Object { (Test-Ioc $_.PathName) -or $_.PathName -match '(?i)\\(AppData|Temp|Public)\\' }) 'servicos_suspeitos.csv'
$startup = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force |
    Select-Object FullName, LastWriteTime
$startup | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'startup.csv')
$wmi = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
Check 'Assinatura WMI com execução de comando (persistência rara em uso legítimo)' $wmi 'wmi_consumers.csv'

# ---------------------------------------------------------------- 2. arquivos
Section '2. Arquivos da ameaça e hash do artefato'
$dirs = @()
if ($env:USERPROFILE) { $dirs += (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Desktop') }
if ($env:SystemRoot) { $dirs += (Join-Path $env:SystemRoot 'Temp') }
$dirs = @($dirs + $env:TEMP + $env:APPDATA + $env:LOCALAPPDATA + $env:PUBLIC | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
$cut = (Get-Date).AddDays(-120)
$files = if ($dirs.Count) { Get-ChildItem $dirs -File -Recurse -Depth 2 -Force | Where-Object { $_.Length -lt 20MB -and $_.LastWriteTime -gt $cut } }
Check 'Arquivo com nome ligado à ameaça' ($files | Where-Object { $Names -contains $_.Name } | Select-Object FullName, LastWriteTime) 'arquivos_por_nome.csv'
$fileHashes = $files | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path
$fileHashes | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'hashes_recentes.csv')
Check 'Hash do artefato encontrado no disco' ($fileHashes | Where-Object { $Hashes -contains $_.Hash.ToLower() }) 'hash_match.csv'
$zone = @()
if ($env:USERPROFILE) {
    $zone = Get-ChildItem (Join-Path $env:USERPROFILE 'Downloads') -File -Force | ForEach-Object {
        $z = Get-Content -Path $_.FullName -Stream Zone.Identifier
        if ($z) { [pscustomobject]@{ Arquivo = $_.FullName; Origem = ($z -join ' ') } } }
}
Check 'Download cuja origem (Zone.Identifier) cita IoC' ($zone | Where-Object { $_.Origem -match $IocRegex }) 'downloads_iocs.csv'

# ---------------------------------------------------------------- 3. históricos (execução pelo usuário / ClickFix)
Section '3. Históricos: PowerShell e caixa Executar (Win+R — usada no ClickFix)'
$psHist = Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force |
    ForEach-Object { Select-String -Path $_.FullName -Pattern $SuspRegex, $IocRegex } | Select-Object Path, LineNumber, Line
Check 'Comando suspeito no histórico do PowerShell' $psHist 'historico_powershell_suspeito.csv'
$mru = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
$mruItems = if ($mru) { $mru.PSObject.Properties | Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object { [pscustomobject]@{ Item = $_.Name; Comando = "$($_.Value)" } } }
Check 'Comando suspeito colado no Win+R (RunMRU)' ($mruItems | Where-Object { (Test-Ioc $_.Comando) -or ($_.Comando -match '(?i)powershell|mshta|curl') }) 'runmru_suspeito.csv'

# ---------------------------------------------------------------- 4. antivírus e logs
Section '4. Microsoft Defender e logs de eventos (últimos 7 dias)'
$det = Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, ProcessName, @{ n = 'Recursos'; e = { $_.Resources -join '; ' } }
Check 'Detecções do Microsoft Defender' $det 'defender_deteccoes.csv'
if (-not $SkipEventLogs) {
    $since = (Get-Date).AddDays(-7)
    $ev = @()
    $ev += Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since }            # serviço instalado
    if ($IsAdmin) { $ev += Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698; StartTime = $since } }  # tarefa criada
    $ev += Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since } -MaxEvents 3000 |
        Where-Object { $_.Message -match $SuspRegex -or $_.Message -match $IocRegex }                   # script block
    $ev += Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3, 22; StartTime = $since } -MaxEvents 20000 |
        Where-Object { $_.Message -match $IocRegex }                                                    # Sysmon (se instalado)
    $evOut = $ev | Select-Object TimeCreated, LogName, Id, @{ n = 'Mensagem'; e = { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(500, $_.Message.Length)) } }
    $evOut | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out 'eventos_relevantes.csv')
    Say ("  Eventos relevantes exportados: {0} (serviço criado 7045, tarefa criada 4698, script block 4104, Sysmon)" -f @($evOut).Count)
} else { Say '  Logs pulados (-SkipEventLogs)' }

# ---------------------------------------------------------------- 5. técnicas observadas (ATT&CK)
Section '5. Verificações específicas das técnicas observadas'
# @@TECH_CHECKS@@

# ---------------------------------------------------------------- cadeia de custódia e resumo
Get-ChildItem $Out -File -Recurse | Where-Object Name -ne 'MANIFESTO_SHA256.txt' | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLower(), $_.Path.Substring($Out.Length + 1) } | Set-Content (Join-Path $Out 'MANIFESTO_SHA256.txt') -Encoding UTF8
Section 'Resultado'
if ($script:Hits -gt 0) {
    Say "  $($script:Hits) ALERTA(S). Trate como possível comprometimento:"
    Say '   1) NÃO desligue o host; mantenha-o isolado (contenção do EDR).'
    Say '   2) Preserve esta pasta; se possível, capture a memória (ex.: WinPmem/Magnet RAM Capture) antes de limpar.'
    Say '   3) Siga o playbook do incidente: revogar sessões e trocar senhas a partir de OUTRA máquina.'
} else {
    Say '  Nenhum indicador da ameaça encontrado nas verificações locais.'
    Say '  Isso não prova que o host está limpo: confirme com EDR/SIEM (hunts).'
}
Compress-Archive -Path $Out -DestinationPath "$Out.zip" -Force
Say "Pacote para o time de IR: $Out.zip"
