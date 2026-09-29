# Threat Hunting — Phexia (7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e)

## Como executar um hunt

- **1. Hipótese** — Formule uma hipótese testável a partir da inteligência (ex.: 'hosts macOS executaram osascript pedindo senha nas últimas 4 semanas'). Amarre a uma técnica ATT&CK.
- **2. Escopo e dados** — Defina período (ex.: 30-90 dias), população (macOS, VIPs, devs) e fontes necessárias (EDR/processos, arquivos, DNS, proxy). Verifique se os dados existem e estão parseados.
- **3. Execução** — Rode primeiro a busca por IoCs (rápida, precisa) e depois a comportamental (mais durável). Use stacking/contagem: o raro é o interessante.
- **4. Triagem** — Para cada resultado: processo pai, usuário, linha de comando completa, conexões próximas no tempo. Classifique em malicioso / benigno conhecido / precisa de mais dados.
- **5. Resposta** — Achou? Abra incidente (aba Incidentes), isole o host e siga o playbook NIST.
- **6. Automatizar** — Converta a consulta em regra de detecção agendada, documente falsos positivos, defina severidade e dono. Registre o hunt (hipótese, dados, resultado) mesmo sem achados.

> Ajuste nomes de índice/tabela/campo ao seu ambiente (parsers e data models variam).
> Serviços legítimos abusados (t.me, Steam...) aparecem só como URL/perfil específico — não bloqueie o domínio inteiro.
> Sigma: converta com `sigma convert -t splunk|kusto|lucene|esql|qradar-aql|... regra.yml` (pySigma).

## H1 · Varredura de hashes do artefato

- **Tipo:** IoC
- **Hipótese:** O artefato Phexia (ou suas variantes conhecidas) foi gravado ou executado em algum endpoint.
- **ATT&CK:** T1204.002
- **Fontes de dados:** EDR: criação de arquivo, EDR: criação de processo
- **Como triar:** Qualquer resultado é incidente confirmado: isole o host e abra incidente. Verifique usuário, caminho e processo pai.

### Splunk (SPL)

```spl
| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Filesystem.file_path) AS evidence
  from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e") by Filesystem.dest Filesystem.user
| rename Filesystem.* AS *
| append [| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Processes.process) AS evidence
  from datamodel=Endpoint.Processes where Processes.process_hash IN ("7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e") by Processes.dest Processes.user
  | rename Processes.* AS *]
| convert ctime(first_seen) ctime(last_seen)
```

### Microsoft Sentinel / Defender XDR (KQL)

```kql
let iocHashes = dynamic(["7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"]);
union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where Timestamp > ago(90d)
| where SHA256 in~ (iocHashes) or SHA1 in~ (iocHashes) or MD5 in~ (iocHashes)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Events=count(),
            Paths=make_set(FolderPath, 20), Users=make_set(AccountName, 20) by DeviceName, SHA256
```

### Elastic Security (KQL/EQL)

> KQL (Discover / Timeline)

```sql
file.hash.sha256 : ("7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e")
or process.hash.sha256 : ("7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e")
```

### IBM QRadar (AQL)

> Performance: se houver propriedade customizada de hash (ex.: "SHA256 Hash"), troque o payload por ela.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, LOGSOURCENAME(logsourceid) AS log_source,
       sourceip, username, QIDNAME(qid) AS event_name
FROM events
WHERE UTF8(payload) ILIKE '%7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e%'
ORDER BY starttime DESC
LAST 30 DAYS
```

### Google SecOps / Chronicle (YARA-L 2.0)

```yaral
rule hunt_phexia_hashes {
  meta:
    author = "CTI"
    description = "Arquivo/processo com hash de Phexia"
    severity = "CRITICAL"
    mitre_attack = "T1204.002"
  events:
    ($e.metadata.event_type = "PROCESS_LAUNCH" or $e.metadata.event_type = "FILE_CREATION")
    (
      $e.target.file.sha256 = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e" nocase or $e.target.process.file.sha256 = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e" nocase
    )
  condition:
    $e
}
```

### Wazuh (regras XML)

```xml
<!-- 1) Lista CDB: /var/ossec/etc/lists/cti-hashes (uma linha por hash, formato chave:valor) -->
<!-- 7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e:Phexia -->
<!-- 2) ossec.conf (manager) dentro de <ruleset>: <list>etc/lists/cti-hashes</list> -->
<!-- 3) Regra (local_rules.xml). 554 = arquivo adicionado, 550 = arquivo modificado (FIM/syscheck) -->
<group name="cti,phexia,">
  <rule id="100500" level="14">
    <if_sid>554, 550</if_sid>
    <list field="sha256_after" lookup="match_key">etc/lists/cti-hashes</list>
    <description>CTI: arquivo com hash de Phexia detectado: $(file)</description>
    <mitre><id>T1204.002</id></mitre>
  </rule>
</group>
```

### Sigma (neutro)

```yaml
title: Phexia - Known File Hash
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Hashes|contains:
      - '7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e'
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.t1204.002
```

## H2 · Contato com infraestrutura de C2 (domínios/IPs)

- **Tipo:** IoC
- **Hipótese:** Algum host resolveu ou se conectou à infraestrutura de C2 de Phexia.
- **ATT&CK:** T1071.001, T1041
- **Fontes de dados:** DNS, Proxy/SWG, Firewall, EDR: conexões de rede
- **Como triar:** Identifique o processo que originou a conexão (EDR). Resolução DNS sem conexão pode ser bloqueio efetivo; conexão HTTP concluída = host comprometido. Domínios de TLD barato expiram rápido: priorize o período em que estavam ativos.

### Splunk (SPL)

```spl
| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(DNS.src) AS src
  from datamodel=Network_Resolution.DNS where DNS.query IN ("ad4rchr39w8f.fun", "kys.li", "nfs8u9aw.shop", "*.ad4rchr39w8f.fun", "*.kys.li", "*.nfs8u9aw.shop") by DNS.query
  | rename DNS.query AS indicator
| append [| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Web.src) AS src
  from datamodel=Web where Web.dest IN ("ad4rchr39w8f.fun", "kys.li", "nfs8u9aw.shop", "*.ad4rchr39w8f.fun", "*.kys.li", "*.nfs8u9aw.shop") by Web.dest | rename Web.dest AS indicator]
| convert ctime(first_seen) ctime(last_seen)
```

### Microsoft Sentinel / Defender XDR (KQL)

```kql
let iocDomains = dynamic(["ad4rchr39w8f.fun", "kys.li", "nfs8u9aw.shop"]);
let iocIPs = dynamic([]);
union
  (DeviceNetworkEvents
   | where Timestamp > ago(90d)
   | where RemoteUrl has_any (iocDomains) or RemoteIP in (iocIPs)
   | project Timestamp, DeviceName, Indicator=coalesce(RemoteUrl, RemoteIP), InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceEvents
   | where Timestamp > ago(90d) and ActionType == "DnsQueryResponse"
   | extend Query = tostring(parse_json(AdditionalFields).DnsQueryString)
   | where Query has_any (iocDomains)
   | project Timestamp, DeviceName, Indicator=Query, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (CommonSecurityLog  // proxy/firewall via CEF
   | where TimeGenerated > ago(90d)
   | where DestinationHostName has_any (iocDomains) or RequestURL has_any (iocDomains) or DestinationIP in (iocIPs)
   | project Timestamp=TimeGenerated, DeviceName=SourceIP, Indicator=coalesce(DestinationHostName, DestinationIP), InitiatingProcessFileName="(proxy)", InitiatingProcessCommandLine=RequestURL)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Procs=make_set(InitiatingProcessFileName, 10) by DeviceName, Indicator
```

### Elastic Security (KQL/EQL)

> KQL

```sql
dns.question.name : ("ad4rchr39w8f.fun" or "kys.li" or "nfs8u9aw.shop") or dns.question.name : *.ad4rchr39w8f.fun or dns.question.name : *.kys.li or dns.question.name : *.nfs8u9aw.shop or url.domain : ("ad4rchr39w8f.fun" or "kys.li" or "nfs8u9aw.shop") or destination.domain : ("ad4rchr39w8f.fun" or "kys.li" or "nfs8u9aw.shop")
```

### IBM QRadar (AQL)

> Para fluxos (QFlow/NetFlow): SELECT ... FROM flows WHERE destinationip IN (...) LAST 30 DAYS

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, destinationip,
       LOGSOURCENAME(logsourceid) AS log_source, QIDNAME(qid) AS event_name
FROM events
WHERE UTF8(payload) ILIKE '%ad4rchr39w8f.fun%' OR UTF8(payload) ILIKE '%kys.li%' OR UTF8(payload) ILIKE '%nfs8u9aw.shop%'
ORDER BY starttime DESC
LAST 30 DAYS
```

### Google SecOps / Chronicle (YARA-L 2.0)

```yaral
rule hunt_phexia_c2_infra {
  meta:
    author = "CTI"
    description = "Contato com C2 de Phexia"
    severity = "HIGH"
  events:
    (
      re.regex($e.network.dns.questions.name, `(^|\.)(ad4rchr39w8f\.fun|kys\.li|nfs8u9aw\.shop)$`) nocase
      or re.regex($e.target.hostname, `(^|\.)(ad4rchr39w8f\.fun|kys\.li|nfs8u9aw\.shop)$`) nocase
    )
    $e.principal.hostname = $host
  match:
    $host over 1h
  condition:
    $e
}
```

### Wazuh (regras XML)

```xml
<!-- Lista CDB /var/ossec/etc/lists/cti-domains (chave:valor) -->
<!-- ad4rchr39w8f.fun:Phexia -->
<!-- kys.li:Phexia -->
<!-- nfs8u9aw.shop:Phexia -->
<!-- Regra para DNS do Suricata (eve.json). 86600 = regra base do Suricata no ruleset padrão.
     Para proxy (Squid etc.), troque if_sid/field pelo decoder do seu proxy (ex.: field="url"). -->
<group name="cti,phexia,">
  <rule id="100510" level="12">
    <if_sid>86600</if_sid>
    <field name="event_type">^dns$</field>
    <list field="dns.rrname" lookup="match_key">etc/lists/cti-domains</list>
    <description>CTI: consulta DNS a C2 de Phexia: $(dns.rrname)</description>
    <mitre><id>T1071.001</id></mitre>
  </rule>
</group>
```

### Sigma (neutro)

```yaml
title: Phexia - C2 Domain Resolution
status: experimental
logsource:
  category: dns_query
detection:
  selection:
    QueryName|endswith:
      - 'ad4rchr39w8f.fun'
      - 'kys.li'
      - 'nfs8u9aw.shop'
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
```

## H3 · Consulta ao Dead Drop Resolver (Telegram/Steam/etc.)

- **Tipo:** IoC + comportamento
- **Hipótese:** Um processo que não é navegador acessou o perfil/canal usado como Dead Drop Resolver para descobrir o C2.
- **ATT&CK:** T1102.001
- **Fontes de dados:** Proxy/SWG com URL completa, EDR: conexões de rede por processo
- **Como triar:** Acesso ao perfil DDR por navegador pode ser pesquisa de analista; por curl/osascript/binário desconhecido é fortíssimo indicador. NÃO bloqueie o serviço inteiro: bloqueie a URL/perfil específico.

### Splunk (SPL)

```spl
| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen
  from datamodel=Web where (Web.url="*phefuckxia*" OR Web.url="*phefuckxiabot*")
  by Web.src Web.user Web.url Web.http_user_agent
| rename Web.* AS *
| eval suspicious_client=if(match(http_user_agent, "(?i)(curl|wget|python|go-http|osascript|CFNetwork)") OR isnull(http_user_agent), "yes", "no")
| sort - suspicious_client
```

### Microsoft Sentinel / Defender XDR (KQL)

```kql
let ddrNeedles = dynamic(["phefuckxia", "phefuckxiabot"]);
let ddrServices = dynamic(["steamcommunity.com", "t.me"]);
let browsers = dynamic(["Google Chrome", "Google Chrome Helper", "Safari", "firefox", "Microsoft Edge", "Brave Browser", "Arc", "Opera", "chrome.exe", "msedge.exe", "firefox.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (ddrNeedles)
   or (RemoteUrl has_any (ddrServices) and not(InitiatingProcessFileName in~ (browsers)))
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Elastic Security (KQL/EQL)

> KQL
> EQL (EDR): processo não-navegador falando com o serviço abusado
> network where destination.domain in ("steamcommunity.com", "t.me") and not process.name in ("Google Chrome", "Google Chrome Helper", "Safari", "firefox", "Microsoft Edge", "Brave Browser", "Arc", "Opera", "chrome.exe", "msedge.exe", "firefox.exe")

```sql
url.original : (*phefuckxia* or *phefuckxiabot*) or url.full : (*phefuckxia* or *phefuckxiabot*)
```

### IBM QRadar (AQL)

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,
       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw
FROM events
WHERE UTF8(payload) ILIKE '%phefuckxia%' OR UTF8(payload) ILIKE '%phefuckxiabot%'
ORDER BY starttime DESC
LAST 90 DAYS
```

### Google SecOps / Chronicle (YARA-L 2.0)

```yaral
rule hunt_phexia_ddr_lookup {
  meta:
    author = "CTI"
    description = "Acesso ao Dead Drop Resolver de Phexia"
    severity = "HIGH"
    mitre_attack = "T1102.001"
  events:
    re.regex($e.target.url, `phefuckxia|phefuckxiabot`) nocase
    $e.principal.hostname = $host
  match:
    $host over 1h
  condition:
    $e
}
```

### Wazuh (regras XML)

```xml
<group name="cti,phexia,">
  <!-- Regra genérica (casa em qualquer log com URL completa: proxy, EDR, firewall L7) -->
  <rule id="100520" level="12">
    <match type="pcre2">(?i)(phefuckxia|phefuckxiabot)</match>
    <description>CTI: acesso ao Dead Drop Resolver de Phexia</description>
    <mitre><id>T1102.001</id></mitre>
  </rule>
</group>
```

### Sigma (neutro)

```yaml
title: Phexia - Dead Drop Resolver Lookup
status: experimental
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains:
      - 'phefuckxia'
      - 'phefuckxiabot'
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1102.001
```

## H4 · Phishing de senha via AppleScript (diálogo falso)

- **Tipo:** Comportamento
- **Hipótese:** Um script exibiu um diálogo falso pedindo a senha do macOS e validou a senha com dscl.
- **ATT&CK:** T1056.002, T1059.002, T1555.001
- **Fontes de dados:** EDR macOS: criação de processo com linha de comando
- **Como triar:** Ferramentas legítimas quase nunca usam 'hidden answer' + dscl authonly em sequência. Verifique o processo pai (Terminal? script em /tmp? app baixado?) e se houve acesso ao login.keychain-db logo depois.

### Splunk (SPL)

```spl
| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen
  from datamodel=Endpoint.Processes
  where (Processes.process_name="osascript" Processes.process="*hidden answer*")
     OR (Processes.process_name="dscl" Processes.process="*authonly*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| rename Processes.* AS *
| convert ctime(first_seen) ctime(last_seen)
```

### Microsoft Sentinel / Defender XDR (KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "osascript" and ProcessCommandLine has "hidden answer")
     or (FileName =~ "dscl" and ProcessCommandLine has "authonly")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Elastic Security (KQL/EQL)

> EQL

```sql
process where host.os.type == "macos" and event.type == "start" and
  ((process.name == "osascript" and process.command_line : "*hidden answer*") or
   (process.name == "dscl" and process.args == "authonly"))
```

### IBM QRadar (AQL)

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,
       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw
FROM events
WHERE (UTF8(payload) ILIKE '%osascript%' AND UTF8(payload) ILIKE '%hidden answer%')
   OR (UTF8(payload) ILIKE '%dscl%' AND UTF8(payload) ILIKE '%authonly%')
ORDER BY starttime DESC
LAST 30 DAYS
```

### Google SecOps / Chronicle (YARA-L 2.0)

```yaral
rule hunt_macos_applescript_password_prompt {
  meta:
    author = "CTI"
    description = "Diálogo AppleScript pedindo senha / validação com dscl (Phexia)"
    severity = "HIGH"
    mitre_attack = "T1056.002"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    (
      (re.regex($e.target.process.file.full_path, `/osascript$`) and re.regex($e.target.process.command_line, `hidden answer`) nocase)
      or (re.regex($e.target.process.file.full_path, `/dscl$`) and re.regex($e.target.process.command_line, `authonly`) nocase)
    )
  condition:
    $e
}
```

### Wazuh (regras XML)

```xml
<!-- Requer telemetria de processos do macOS no Wazuh (ex.: EDR encaminhado via syslog/JSON
     ou osquery integrado). O Unified Log não traz a linha de comando por padrão. -->
<group name="cti,macos,phexia,">
  <rule id="100530" level="12">
    <match type="pcre2">(?i)(osascript.*hidden answer|dscl\s+\.\s+-?authonly)</match>
    <description>CTI: AppleScript pedindo senha / validação com dscl (roubo de credencial)</description>
    <mitre><id>T1056.002</id></mitre>
  </rule>
</group>
```

### Sigma (neutro)

```yaml
title: macOS AppleScript Password Prompt
status: experimental
logsource:
  product: macos
  category: process_creation
detection:
  osascript:
    Image|endswith: '/osascript'
    CommandLine|contains: 'hidden answer'
  dscl:
    Image|endswith: '/dscl'
    CommandLine|contains: 'authonly'
  condition: osascript or dscl
level: high
tags:
  - attack.credential_access
  - attack.t1056.002
```

## H5 · Persistência por LaunchAgent com nome aleatório

- **Tipo:** Comportamento
- **Hipótese:** Um LaunchAgent novo, com nome aleatório (padrão com.<user>.<12-20 letras>.plist), foi criado no perfil do usuário.
- **ATT&CK:** T1543.001
- **Fontes de dados:** EDR macOS: eventos de arquivo, FIM, osquery (tabela launchd)
- **Como triar:** Faça stacking por nome de arquivo no parque: legítimos se repetem (com.google.keystone...), maliciosos são únicos. Abra o plist: ProgramArguments apontando para ~/Library/<nome aleatório> ou osascript é sinal forte.

### Splunk (SPL)

```spl
| tstats summariesonly=false count min(_time) AS first_seen values(Filesystem.action) AS action
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/Library/LaunchAgents/*" Filesystem.file_name="*.plist"
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| rename Filesystem.* AS *
| where match(file_name, "com\.[^./]+\.[a-z]{12,20}\.plist$") OR match(file_path, "(?i)(UserInformation\.txt|gfskjsnghdjsvuxj)")
| eventstats dc(dest) AS hosts_with_same_name by file_name
| where hosts_with_same_name < 3
| convert ctime(first_seen)
```

### Microsoft Sentinel / Defender XDR (KQL)

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/Library/LaunchAgents/" and FileName endswith ".plist"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName matches regex @"^com\.[^./]+\.[a-z]{12,20}\.plist$" or FolderPath matches regex @"(?i)(UserInformation\.txt|gfskjsnghdjsvuxj)"
| summarize Hosts=dcount(DeviceName), Devices=make_set(DeviceName, 20), FirstSeen=min(Timestamp),
            Writers=make_set(InitiatingProcessFileName, 10) by FileName
| where Hosts < 3
```

### Elastic Security (KQL/EQL)

> EQL

```sql
file where host.os.type == "macos" and event.type in ("creation", "change") and
  file.path : "/Users/*/Library/LaunchAgents/*.plist" and
  (file.name regex~ """com\.[^./]+\.[a-z]{12,20}\.plist""" or file.path regex~ """.*(UserInformation\.txt|gfskjsnghdjsvuxj).*""")
```

### IBM QRadar (AQL)

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,
       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw
FROM events
WHERE UTF8(payload) ILIKE '%/Library/LaunchAgents/%'
  AND (UTF8(payload) IMATCHES '.*com\.[^./]+\.[a-z]{12,20}\.plist.*' OR UTF8(payload) ILIKE '%UserInformation.txt%' OR UTF8(payload) ILIKE '%gfskjsnghdjsvuxj%')
ORDER BY starttime DESC
LAST 30 DAYS
```

### Google SecOps / Chronicle (YARA-L 2.0)

```yaral
rule hunt_macos_random_launchagent {
  meta:
    author = "CTI"
    description = "LaunchAgent com nome aleatório (persistência estilo Phexia)"
    severity = "MEDIUM"
    mitre_attack = "T1543.001"
  events:
    ($e.metadata.event_type = "FILE_CREATION" or $e.metadata.event_type = "FILE_MODIFICATION")
    re.regex($e.target.file.full_path, `/Library/LaunchAgents/com\.[^./]+\.[a-z]{12,20}\.plist$`)
  condition:
    $e
}
```

### Wazuh (regras XML)

```xml
<!-- ossec.conf (agente macOS): monitorar LaunchAgents em tempo real -->
<!-- <syscheck><directories realtime="yes" check_all="yes">/Users/*/Library/LaunchAgents,/Library/LaunchAgents</directories></syscheck> -->
<group name="cti,macos,phexia,">
  <rule id="100540" level="12">
    <if_sid>554</if_sid>
    <field name="file" type="pcre2">/Library/LaunchAgents/com\.[^./]+\.[a-z]{12,20}\.plist$</field>
    <description>CTI: LaunchAgent com nome aleatório criado: $(file)</description>
    <mitre><id>T1543.001</id></mitre>
  </rule>
</group>
```

### Sigma (neutro)

```yaml
title: macOS LaunchAgent With Random Name
status: experimental
logsource:
  product: macos
  category: file_event
detection:
  selection:
    TargetFilename|contains: '/Library/LaunchAgents/'
    TargetFilename|re: 'com\.[^./]+\.[a-z]{12,20}\.plist$'
  condition: selection
level: medium
falsepositives:
  - Instaladores legítimos com IDs gerados (validar por stacking)
tags:
  - attack.persistence
  - attack.t1543.001
```

## H6 · Cadeia ClickFix: Terminal → curl → osascript

- **Tipo:** Comportamento
- **Hipótese:** Um usuário colou no Terminal um comando que baixou (curl) e executou AppleScript em menos de 1 minuto.
- **ATT&CK:** T1204.004, T1059.004, T1105, T1553.001
- **Fontes de dados:** EDR macOS: criação de processo com pai/avô
- **Como triar:** Desenvolvedores usam curl no Terminal o tempo todo; o sinal é curl seguido de osascript (ou curl | bash de domínio desconhecido). Veja a URL no comando do curl e a navegação do usuário no minuto anterior.

### Splunk (SPL)

```spl
| tstats summariesonly=false count from datamodel=Endpoint.Processes
  where Processes.process_name IN ("curl", "wget", "osascript")
  by _time span=1s Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| rename Processes.* AS *
| sort 0 _time
| streamstats time_window=60s values(process_name) AS chain values(process) AS commands by dest
| where process_name="osascript" AND mvcount(chain)>=2
| table _time dest user chain commands
```

### Microsoft Sentinel / Defender XDR (KQL)

```kql
let downloads = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl", "wget")
| where InitiatingProcessFileName in~ ("bash", "zsh", "sh") and InitiatingProcessParentFileName in~ ("Terminal", "iTerm2")
| project DeviceId, DeviceName, DlTime=Timestamp, DlCmd=ProcessCommandLine, AccountName;
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName =~ "osascript"
| project DeviceId, OsaTime=Timestamp, OsaCmd=ProcessCommandLine
| join kind=inner downloads on DeviceId
| where OsaTime between (DlTime .. (DlTime + 1m))
| project DlTime, DeviceName, AccountName, DlCmd, OsaCmd
```

### Elastic Security (KQL/EQL)

> EQL (sequência)

```sql
sequence by host.id with maxspan=1m
  [process where host.os.type == "macos" and event.type == "start" and
     process.name in ("curl", "wget") and process.parent.name in ("bash", "zsh", "sh")]
  [process where host.os.type == "macos" and event.type == "start" and process.name == "osascript"]
```

### IBM QRadar (AQL)

> AQL lista os candidatos; para correlação em tempo real crie uma regra de SEQUÊNCIA no Rule Wizard:
> 'when these events are detected in this order... within 1 minutes... with the same source IP/host'.

```sql
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS event_time, sourceip, username,
       LOGSOURCENAME(logsourceid) AS log_source, UTF8(payload) AS raw
FROM events
WHERE (UTF8(payload) ILIKE '%curl%' OR UTF8(payload) ILIKE '%osascript%')
  AND LOGSOURCETYPENAME(devicetype) ILIKE '%mac%'
ORDER BY sourceip, starttime
LAST 7 DAYS
```

### Google SecOps / Chronicle (YARA-L 2.0)

```yaral
rule hunt_macos_clickfix_curl_osascript {
  meta:
    author = "CTI"
    description = "curl/wget seguido de osascript no mesmo host em 1 min (ClickFix)"
    severity = "HIGH"
    mitre_attack = "T1204.004"
  events:
    $dl.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($dl.target.process.file.full_path, `/(curl|wget)$`)
    $dl.principal.hostname = $host
    $osa.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($osa.target.process.file.full_path, `/osascript$`)
    $osa.principal.hostname = $host
    $dl.metadata.event_timestamp.seconds <= $osa.metadata.event_timestamp.seconds
  match:
    $host over 1m
  condition:
    $dl and $osa
}
```

### Wazuh (regras XML)

```xml
<!-- Correlação em duas regras: a 2ª só dispara se a 1ª casou no mesmo agente nos últimos 60s -->
<group name="cti,macos,phexia,">
  <rule id="100550" level="3">
    <match type="pcre2">(?i)\b(curl|wget)\b.*https?://</match>
    <description>macOS: download via curl/wget</description>
  </rule>
  <rule id="100551" level="12" timeframe="60">
    <if_matched_sid>100550</if_matched_sid>
    <same_location />
    <match type="pcre2">(?i)\bosascript\b</match>
    <description>CTI: curl seguido de osascript em 60s (possível ClickFix)</description>
    <mitre><id>T1204.004</id></mitre>
  </rule>
</group>
```

### Sigma (neutro)

```yaml
title: macOS Curl Download
name: macos_curl_download
status: experimental
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '/curl'
      - '/wget'
  condition: selection
---
title: macOS Osascript Execution
name: macos_osascript_exec
status: experimental
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: '/osascript'
  condition: selection
---
title: ClickFix Chain - Curl and Osascript Within 1 Minute
description: Use type temporal_ordered se o seu backend suportar (garante a ordem curl -> osascript)
status: experimental
correlation:
  type: temporal
  rules:
    - macos_curl_download
    - macos_osascript_exec
  group-by:
    - Computer
  timespan: 1m
level: high
tags:
  - attack.execution
  - attack.t1204.004
```
