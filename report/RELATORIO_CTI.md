# Relatório de Inteligência Cibernética — Phexia macOS Stealer / Backdoor

| Campo | Valor |
|---|---|
| **ID do relatório** | CTI-2026-0924-PHEXIA |
| **Classificação (TLP)** | TLP:AMBER — uso interno (Segurança Cibernética / IR / SOC) |
| **Data** | 24/09/2026 |
| **Artefato de referência** | SHA-256 `7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e` |
| **Família atribuída** | **Phexia** (macOS Stealer + backdoor AppleScript residente) |
| **Confiança na atribuição** | **Moderada-Alta** (ver §2.3 — ACH) |
| **Plataforma alvo** | macOS (Intel e Apple Silicon) |
| **Público** | Threat Hunting, Resposta a Incidentes, Engenharia de Detecção, Endpoint/MDM, IAM |

> **Nota metodológica sobre as fontes.** Este relatório combina (a) fontes abertas verificáveis citadas no Anexo C, (b) inferências analíticas, sinalizadas com linguagem estimativa (*provável*, *quase certo*, etc.) e (c) recomendações. Onde um dado não pôde ser confirmado para **este hash especificamente** (ex.: tamanho, tipo exato do arquivo, IPs de resolução), isso é dito explicitamente — esses campos devem ser preenchidos com a coleta automatizada da API (Parte 2) antes da disseminação final. Domínios estão *defanged* (`[.]`).

---

## 1. Resumo Executivo (BLUF)

- O hash `7a8fc48c…25ed8e` foi publicado em **28/10/2025** pelo pesquisador **@L0Psec** como IoC de um **backdoor macOS então não atribuído**, com apenas **2 detecções no VirusTotal** no momento da publicação. O artefato resolve seu C2 por meio da técnica **Dead Drop Resolver (DDR)**, lendo o endereço do servidor a partir de um bot do **Telegram (`phefuckxiabot`)** e de um perfil da **Steam (`phefuckxia`)**. Os C2 associados eram `nfs8u9aw[.]shop` e `ad4rchr39w8f[.]fun`.
- Em **novembro/2025** a **Moonlock Lab (MacPaw)** conectou o mesmo identificador DDR a um payload que exibe a string **"Phexia macOS Stealer"**. A Objective-See, no relatório *"The Mac Malware of 2025"*, descreve o Phexia como **stealer persistente com reverse shell**, distribuído via **malvertising e engenharia social**, com persistência via **LaunchAgent** e backdoor em **AppleScript** que consulta Telegram/Steam para obter o C2.
- Em **dez/2025** o C2 publicado no DDR foi trocado para `kys[.]li` — evidenciando **rotação ativa de infraestrutura** mesmo após denúncia das contas. Em **2026** o Phexia passou a ser observado em campanhas **ClickFix** (vítima cola um comando no Terminal) e com lures de falsas atualizações.
- **Impacto para o Mercado Livre:** estações macOS de engenharia, produto e executivos são alvo de alto valor. O stealer coleta **senha de login do macOS (via diálogo falso), Keychain, cookies/sessões de navegadores Chromium, extensões e carteiras de criptomoedas, Notes e sessões de Telegram**. Cookies de sessão roubados permitem **sequestro de sessão (bypass de MFA)** em SSO, consoles de nuvem, GitHub e ferramentas internas; carteiras cripto afetam diretamente colaboradores ligados ao **Mercado Pago / cripto**.
- **Ações imediatas (P1):** (1) bloquear os IoCs de rede e **as consultas a `t.me/phefuckxiabot` e `steamcommunity.com/id/phefuckxia`** a partir de endpoints corporativos; (2) caçar o LaunchAgent `com.*.gfskjsnghdjsvuxj.plist` e cadeias `Terminal → curl → osascript` no parque macOS; (3) em qualquer host positivo, **revogar sessões e rotacionar credenciais** — reimagem não basta, pois os tokens já foram exfiltrados.

**Avaliação-chave:** É **provável (55–80%)** que o artefato seja um componente da família Phexia (stage de backdoor/loader AppleScript ou dropper). É **quase certo (>95%)** que ele seja malicioso e opere com DDR via Telegram/Steam. A ameaça é **oportunista (MaaS/privado, ~20 afiliados)**, não direcionada especificamente ao MELI, mas o **risco é Alto** dado o perfil de alvos e a facilidade de monetização de sessões roubadas.

---

## 2. Identificação da Ameaça e Atribuição

### 2.1 Ficha do artefato

| Atributo | Valor | Fonte / Status |
|---|---|---|
| SHA-256 | `7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e` | Desafio / @L0Psec |
| MD5 / SHA-1 / tamanho / magic | *Preencher via VT + MalwareBazaar (`/api/v1/analyze`)* | Coleta automatizada |
| MalwareBazaar | Assinatura, tags, YARA e vendor intel (Triage, ANY.RUN, ReversingLabs) — *coletados por `/api/v1/analyze/{hash}` (seção `features.malwarebazaar`)* | Coleta automatizada |
| Plataforma | macOS | @L0Psec, Moonlock |
| Primeira aparição pública | 28/10/2025 | @L0Psec (X) |
| Detecções iniciais | 2 engines (VT, 28/10/2025) | @L0Psec |
| Nomes de detecção conhecidos p/ família | `OSX/PSW.Agent.FO` (ESET), `OSX/Phebot-A` (Sophos), `HEUR:Trojan-Dropper.OSX.Agent.v` (Kaspersky), `MacOS:Agent-BAT [Drp]` (Avast) | PCrisk (família, não necessariamente este hash) |
| Linguagem/execução | AppleScript via `osascript` + shell (`curl`) | Objective-See, CyStack |

### 2.2 Perfil da família Phexia

| Dimensão | Detalhe |
|---|---|
| Tipo | Infostealer + backdoor residente (reverse shell, tasking remoto) |
| Modelo de negócio | Privado por assinatura (~20 usuários em 2025), com plano de migrar para MaaS com vagas limitadas |
| Linhagem | ~85% de similaridade de código no módulo stealer com **mac.c** (linhagem AMOS/MacSync); desenvolvedor era próximo dos autores do mac.c |
| Atividade | Desde **abril/2024** (segundo o próprio desenvolvedor); pico de visibilidade em out–dez/2025 e 2026 |
| Geografia | Declara não operar em países da CIS (padrão de atores de língua russa) |
| Infecção | Malvertising, falsos instaladores/atualizações, software pirata, **ClickFix** (2026) |
| C2 | DDR em Telegram/Steam (e blockchain, segundo o dev) → HTTP para `/api.php?check=1` e `/task.php`; failover automático de domínios |
| Artefato de coleta | `UserInformation.txt` com banner "Phexia macOS Stealer" e campos `Build:`, `Username:`, `Password:`, `Hardware`, `IP Address`… |

### 2.3 Atribuição — Análise de Hipóteses Concorrentes (ACH)

| Evidência | H1: Phexia | H2: AMOS/Atomic | H3: MacSync / mac.c | H4: Stealer Windows (Vidar/ACR) com DDR Steam |
|---|---|---|---|---|
| E1. DDR Telegram **e** Steam com o mesmo handle `phefuckxia*` | **C** | I | I | C (técnica), I (plataforma) |
| E2. Moonlock liga o handle a payload com string "Phexia macOS Stealer" | **CC** | I | I | I |
| E3. Alvo macOS, AppleScript, LaunchAgent | C | C | C | **II** |
| E4. Endpoints `/api.php?check=1`, `/task.php` e polling 30 s | C | N | N | N |
| E5. Baixa detecção inicial (2 engines no VT) | N | N | N | N |
| **Inconsistências** | 0 | 3 | 2 | 3+ |

*C = consistente, CC = fortemente consistente, I = inconsistente, II = fortemente inconsistente, N = neutro.*

**Conclusão:** H1 (Phexia) é a hipótese com menos inconsistências. O principal fator limitante de confiança é que o elo entre **este hash** e a string "Phexia" é **indireto** (via identificador DDR compartilhado), e a similaridade de 85% com mac.c gera risco de *misattribution* entre famílias irmãs. **Lacuna de coleta:** obter o arquivo (MalwareBazaar/VT Intelligence) e confirmar strings/estrutura.

### 2.4 Modelo Diamante

```
                 ADVERSÁRIO
     Dev "Phexia" + ~20 afiliados (Build tag por cliente)
     Língua russa provável; exclusão CIS
                     |
  INFRAESTRUTURA ----+---- CAPACIDADE
  DDR: t.me/phefuckxiabot, steamcommunity.com/id/phefuckxia
  C2: nfs8u9aw[.]shop, ad4rchr39w8f[.]fun, kys[.]li
  Rotação rápida de domínios (TLDs baratos .shop/.fun/.li)
                     |      AppleScript stealer + backdoor LaunchAgent,
                     |      phishing de senha por diálogo, reverse shell
                  VÍTIMA
  Usuários macOS com cripto/sessões valiosas; oportunista
  (malvertising, ClickFix) → colaboradores e executivos MELI
```

### 2.5 Cadeia de ataque (Kill Chain)

1. **Entrega** — anúncio malicioso / página falsa (ex.: "atualização", "verificação humana") instrui o usuário a colar um comando no **Terminal** (ClickFix) ou baixar um DMG falso.
2. **Execução** — `curl … | bash` ou `osascript` baixa o stager; como o conteúdo vem via `curl`, **não recebe o atributo `com.apple.quarantine`**, contornando Gatekeeper.
3. **Credenciais** — diálogo AppleScript falso ("macOS precisa da sua senha…") captura a senha do usuário, que é validada localmente (`dscl . authonly`) e usada para desbloquear o Keychain.
4. **Coleta** — Keychain, perfis Chromium (Login Data, Cookies, Web Data, extensões), carteiras (desktop e extensões), Notes, sessão Telegram, `system_profiler` → `UserInformation.txt`.
5. **Exfiltração** — arquivo compactado enviado por HTTP ao C2 obtido via DDR.
6. **Persistência** — `~/Library/LaunchAgents/com.<user>.gfskjsnghdjsvuxj.plist` (`RunAtLoad`) executa `~/Library/gfskjsnghdjsvuxj` (loader AppleScript).
7. **Ação no objetivo** — backdoor faz *polling* a cada ~30 s (`/api.php?check=1`, `/task.php`), coleta UUID do hardware e executa comandos/2º estágio arbitrários.

---

## 3. Indicadores de Comprometimento (IoCs)

### 3.1 IoCs atômicos

| Tipo | Indicador | Contexto | Confiança | Validade estimada |
|---|---|---|---|---|
| SHA-256 | `7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e` | Artefato de referência | Alta | Longa |
| Domínio | `nfs8u9aw[.]shop` | C2 (out/2025) | Alta | Curta — provavelmente rotacionado |
| Domínio | `ad4rchr39w8f[.]fun` | C2 (out/2025) | Alta | Curta |
| Domínio | `kys[.]li` | C2 publicado no DDR (dez/2025) | Média-Alta | Curta |
| URL (DDR) | `hxxps://t[.]me/phefuckxiabot` | Dead Drop Resolver — Telegram | Alta | Média (conta pode ser banida) |
| URL (DDR) | `hxxps://steamcommunity[.]com/id/phefuckxia` | Dead Drop Resolver — Steam | Alta | Média |
| URI | `/api.php?check=1` | Check-in do backdoor | Média | Longa (comportamental) |
| URI | `/task.php` | Busca de tarefas | Média | Longa |
| Arquivo | `~/Library/gfskjsnghdjsvuxj` | Loader AppleScript persistido | Alta | Pode variar por build |
| Arquivo | `~/Library/LaunchAgents/com.<user>.gfskjsnghdjsvuxj.plist` | Persistência | Alta | Pode variar por build |
| Arquivo | `UserInformation.txt` (temporário/staging) | Saída do stealer | Média | Longa |
| String | `Phexia macOS Stealer` | Banner do payload | Alta | Longa |

> **IPs:** nenhum IP foi publicado em fonte aberta verificável para estes domínios. **Não** foram incluídos IPs especulativos. A API (endpoint `/api/v1/search`) enriquece domínios com as resoluções do VirusTotal (`last_dns_records`) — use-a para gerar a lista de IPs no momento da resposta, lembrando que TLDs baratos costumam estar atrás de proxies/CDN (risco de falso positivo ao bloquear IP).

### 3.2 Indicadores comportamentais (mais duráveis que os atômicos — topo da *Pyramid of Pain*)

- `Terminal`/`bash`/`zsh` → `curl` → `osascript` em janela curta de tempo (padrão ClickFix).
- `osascript` exibindo `display dialog … with hidden answer` seguido de `dscl . authonly <user>`.
- Processo não-navegador lendo `~/Library/Application Support/Google/Chrome/*/Cookies`, `Login Data`, `Local Extension Settings/*`, ou `~/Library/Keychains/login.keychain-db`.
- Criação de `.plist` em `~/Library/LaunchAgents` com nome aleatório de 12–20 letras minúsculas.
- Requisições HTTP de processos não-navegador a `t.me/*` ou `steamcommunity.com/id/*`, seguidas de conexão a domínio recém-registrado.
- *Beacon* HTTP periódico (~30 s) para `*.php` em domínio de baixa reputação.

### 3.3 Threat Hunting — como criar e executar os hunts

Os IoCs atômicos da §3.1 expiram rápido (o ator troca domínios em dias). Por isso o hunting aqui é **orientado a hipóteses** (modelo **PEAK** — *Prepare, Execute, Act with Knowledge* — e **TaHiTI**), combinando varredura de IoCs com comportamento, que dura mais.

**Passo a passo para criar um hunt**

1. **Hipótese** — uma frase testável, ligada a uma técnica ATT&CK. Ex.: *"Hosts macOS executaram `osascript` com `hidden answer` nas últimas 4 semanas"* (T1056.002).
2. **Escopo e dados** — período (30–90 dias), população (macOS, devs, VIPs, times do Mercado Pago) e fontes necessárias. Antes de rodar, confirme se os dados existem e estão parseados (tabela abaixo).
3. **Execução** — primeiro a varredura de IoCs (H1–H3: rápida e precisa), depois a comportamental (H4–H6). Use *stacking*: conte ocorrências por valor e olhe para o que é raro.
4. **Triagem** — para cada resultado: processo pai, usuário, linha de comando completa e conexões próximas no tempo. Classifique em malicioso / benigno conhecido / precisa de mais dados.
5. **Resposta** — positivo confirmado vira incidente (playbook da §5.4 e módulo de incidentes da ferramenta).
6. **Automatizar e documentar** — a consulta validada vira regra agendada no SIEM, com dono, severidade e falsos positivos conhecidos. Registre o hunt mesmo sem achados (ausência de evidência também é inteligência).

**Hunts priorizados para Phexia**

| ID | Hunt | Hipótese | ATT&CK | Fontes de dados |
|---|---|---|---|---|
| **H1** | Varredura de hashes do artefato | O artefato Phexia (ou suas variantes conhecidas) foi gravado ou executado em algum endpoint. | T1204.002 | EDR: criação de arquivo, EDR: criação de processo |
| **H2** | Contato com infraestrutura de C2 (domínios/IPs) | Algum host resolveu ou se conectou à infraestrutura de C2 de Phexia. | T1071.001, T1041 | DNS, Proxy/SWG, Firewall, EDR: conexões de rede |
| **H3** | Consulta ao Dead Drop Resolver (Telegram/Steam/etc.) | Um processo que não é navegador acessou o perfil/canal usado como Dead Drop Resolver para descobrir o C2. | T1102.001 | Proxy/SWG com URL completa, EDR: conexões de rede por processo |
| **H4** | Phishing de senha via AppleScript (diálogo falso) | Um script exibiu um diálogo falso pedindo a senha do macOS e validou a senha com dscl. | T1056.002, T1059.002, T1555.001 | EDR macOS: criação de processo com linha de comando |
| **H5** | Persistência por LaunchAgent com nome aleatório | Um LaunchAgent novo, com nome aleatório (padrão com.<user>.<12-20 letras>.plist), foi criado no perfil do usuário. | T1543.001 | EDR macOS: eventos de arquivo, FIM, osquery (tabela launchd) |
| **H6** | Cadeia ClickFix: Terminal → curl → osascript | Um usuário colou no Terminal um comando que baixou (curl) e executou AppleScript em menos de 1 minuto. | T1204.004, T1059.004, T1105, T1553.001 | EDR macOS: criação de processo com pai/avô |

**Prontidão de dados por SIEM** (o que precisa estar chegando para cada hunt funcionar)

| SIEM | Processos / arquivos macOS | DNS / proxy | Observação |
|---|---|---|---|
| Splunk | CIM `Endpoint.Processes` / `Endpoint.Filesystem` (EDR com TA compatível) | CIM `Network_Resolution`, `Web` | Consultas usam `tstats`; com data models não acelerados, `summariesonly=false` |
| Microsoft Sentinel / Defender XDR | `DeviceProcessEvents`, `DeviceFileEvents` (Defender for Endpoint no Mac) | `DeviceNetworkEvents`, `CommonSecurityLog` (proxy CEF) | Mesmas consultas rodam no Advanced Hunting do Defender |
| Elastic Security | Elastic Defend / Endpoint (ECS `process.*`, `file.*`) | `dns.question.name`, `url.*` | Comportamentais em **EQL** (inclui `sequence` para ClickFix) |
| IBM QRadar | Logs do EDR via DSM; sem propriedade customizada, a busca usa `payload` | Proxy/DNS/QFlow | Para correlação em tempo real use regra de **sequência** no Rule Wizard |
| Google SecOps (Chronicle) | UDM `PROCESS_LAUNCH`, `FILE_CREATION` | UDM `network.dns`, `target.url` | Regras **YARA-L 2.0** prontas para *Detection Engine* ou *retrohunt* |
| Wazuh | FIM (`syscheck`) em `~/Library/LaunchAgents` + telemetria de EDR/osquery | Suricata (`eve.json`) ou proxy | Regras XML + listas CDB; correlação com `if_matched_sid` + `timeframe` |
| Sigma | `process_creation`, `file_event` (macOS) | `dns_query`, `proxy` | Formato neutro: `sigma convert -t <backend>` gera a consulta de qualquer SIEM acima |

As consultas completas de cada hunt, para cada SIEM, estão em **`report/HUNTING_PLAYBOOK.md`** (separadas do relatório para mantê-lo legível). A ferramenta gera o mesmo pacote para qualquer hash analisado (aba *Hunting*, `GET /api/v1/hunt/{hash}` ou `cti hunt <hash>`).

### 3.4 Varredura direta nos endpoints (osquery e YARA)

**osquery — persistência e arquivos:**
```sql
SELECT path, label, program, program_arguments, run_at_load
FROM launchd
WHERE path LIKE '/Users/%/Library/LaunchAgents/%'
  AND (label LIKE '%gfskjsnghdjsvuxj%' OR label REGEXP '^com\.[a-z0-9._-]+\.[a-z]{12,20}$');

SELECT path, size, mtime FROM file
WHERE path LIKE '/Users/%/Library/gfskjsnghdjsvuxj'
   OR path LIKE '/Users/%/%UserInformation.txt'
   OR path LIKE '/tmp/%UserInformation.txt';
```

**YARA (artefatos em disco / memória de osascript):**
```yara
rule MAL_macOS_Phexia_Stealer_Backdoor
{
  meta:
    author = "CTI MELI (candidato)"
    date = "2026-09-24"
    reference = "7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e"
  strings:
    $s1 = "Phexia macOS Stealer" ascii wide
    $s2 = "gfskjsnghdjsvuxj" ascii
    $s3 = "phefuckxia" ascii nocase
    $s4 = "api.php?check=1" ascii
    $s5 = "task.php" ascii
    $s6 = "UserInformation.txt" ascii
    $s7 = "hidden answer" ascii
    $s8 = "login.keychain-db" ascii
  condition:
    filesize < 5MB and ( $s1 or $s2 or $s3 or ( $s4 and $s5 ) or ( $s6 and $s7 and $s8 ) )
}
```

### 3.5 Como buscar essas evidências num Mac (passo a passo)

Esta seção é para quem está **na frente do Mac suspeito** (ou com acesso remoto a ele). Tudo aqui é **somente leitura**: não apague nada antes de coletar as evidências.

**Forense segura — regras para investigar sem espalhar a ameaça**

1. **Isole primeiro:** contenção de rede pelo EDR (ou desligue o Wi-Fi e o cabo). O Mac para de falar com o C2 e com os outros Macs, e as verificações abaixo funcionam offline.
2. **Consulte só o hash, nunca envie o arquivo:** calcule com `shasum -a 256 <arquivo>` (ou pelo botão "Calcular hash de um arquivo" da ferramenta, que calcula no navegador) e pesquise o hash. Fazer upload ao VirusTotal torna a amostra pública, pode vazar dados da empresa e avisa o atacante.
3. **Não abra nem execute a amostra** em máquina de trabalho. Se precisar de análise dinâmica, use uma VM macOS **sem placa de rede** (UTM/Parallels) com snapshot.
4. **Guarde a amostra "desarmada":** `zip -P infected amostra.zip <arquivo>` (senha padrão da indústria). Assim ela não roda por clique acidental e o antivírus não a apaga.
5. **Não use AirDrop, pastas de rede ou pendrive compartilhado** para mover evidências. Use uma mídia dedicada.
6. **Se fosse ransomware:** desmonte compartilhamentos de rede e **nunca** conecte o disco de backup no host infectado.

**Opção rápida — script automático.** O projeto traz `scripts/mac_triage.sh`, gerado a partir deste relatório, que faz todas as verificações abaixo com ferramentas nativas do macOS (somente leitura, sem rede, na ordem de volatilidade da RFC 3227, com manifesto SHA-256 para cadeia de custódia). Para outro artefato ou outro sistema, a aba **DFIR** da ferramenta gera o script equivalente para **macOS, Windows ou Linux** com os IoCs e as técnicas daquele artefato. Ele cria uma pasta na Mesa com as evidências, um `RESUMO.txt` com os alertas e um `.zip` para o time de resposta:

```bash
bash mac_triage.sh            # como o usuário afetado
sudo bash mac_triage.sh       # inclui itens de inicialização do sistema (sfltool dumpbtm)
```

> Antes, dê **Acesso Total ao Disco** ao Terminal (Ajustes do Sistema → Privacidade e Segurança). Sem isso, o macOS esconde o histórico do Safari e alguns bancos de dados.

**Opção manual — o que procurar, onde e com qual comando**

| # | O que procurar | Onde fica no Mac | Comando |
|---|---|---|---|
| 1 | **Persistência** (LaunchAgent com nome aleatório) | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` | `ls -la ~/Library/LaunchAgents` e `plutil -p ~/Library/LaunchAgents/<arquivo>.plist` (veja `ProgramArguments`: `osascript` ou `~/Library/<nome aleatório>` é suspeito) |
| 2 | Itens de inicialização registrados pelo sistema | Background Task Management (macOS 13+) | `sudo sfltool dumpbtm` |
| 3 | Agentes carregados agora | launchd | `launchctl list \| grep -v com.apple` |
| 4 | **Payload** do backdoor | `~/Library/gfskjsnghdjsvuxj` (arquivo sem extensão, 12–20 letras) | `ls -la ~/Library \| grep -E ' [a-z]{12,20}$'` e `head -c 400 ~/Library/<nome>` |
| 5 | Arquivo de coleta do stealer | `UserInformation.txt` em pastas temporárias | `find ~ /tmp /private/var/folders -name UserInformation.txt 2>/dev/null` |
| 6 | **Hash** do artefato | Downloads, `~/Library`, temporários | `find ~/Downloads ~/Library /tmp -type f -size -5M -exec shasum -a 256 {} + 2>/dev/null \| grep 7a8fc48c` |
| 7 | **Comando colado no Terminal** (ClickFix) | `~/.zsh_history`, `~/.bash_history`, `~/.zsh_sessions/` | `grep -aE 'curl[^\|]*\| *(ba\|z)?sh\|osascript\|base64 (-d\|--decode)' ~/.zsh_history ~/.bash_history` |
| 8 | **Downloads** (instalador falso, DMG) | Banco de quarentena do macOS | `sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY 1 DESC LIMIT 50;"` |
| 9 | Acesso ao C2 ou ao DDR pelo navegador | Chrome: `~/Library/Application Support/Google/Chrome/Default/History` (copie antes; o arquivo fica travado) | `sqlite3 /tmp/History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url FROM urls WHERE url LIKE '%phefuckxia%' OR url LIKE '%nfs8u9aw%' OR url LIKE '%ad4rchr39w8f%' OR url LIKE '%kys.li%';"` |
| 10 | Mesmo acesso no Safari | `~/Library/Safari/History.db` (exige Acesso Total ao Disco) | `sqlite3 /tmp/History.db "SELECT datetime(v.visit_time+978307200,'unixepoch'), i.url FROM history_visits v JOIN history_items i ON i.id=v.history_item WHERE i.url LIKE '%phefuckxia%';"` |
| 11 | Processos e conexões **agora** | Memória / rede | `ps -axo pid,ppid,user,etime,command \| grep -E 'osascript\|curl'` e `lsof -nP -i \| grep -E '^(osascript\|curl\|bash\|zsh)'` |
| 12 | Execuções de AppleScript e itens de login recentes | Unified Log | `log show --last 72h --style compact --predicate 'process == "osascript"'` e `log show --last 72h --predicate 'subsystem == "com.apple.backgroundtaskmanagement"'` |
| 13 | Redirecionamento de DNS local | `/etc/hosts` | `grep -Ei 'nfs8u9aw\|ad4rchr39w8f\|kys\.li' /etc/hosts` |

**Como ler os resultados**

- **Achou algo nos itens 1, 4, 5 ou 6?** Considere o Mac **comprometido**.
- **Achou algo só nos itens 7 a 10?** Houve **exposição**: o usuário colou o comando ou visitou a página. Confirme a execução pelos itens 1–6 e pelo EDR.
- **O Unified Log não guarda a linha de comando completa.** Para ver *o que* o `osascript` executou, use a telemetria do EDR (hunts H4–H6).
- **Nada encontrado não prova que o Mac está limpo.** O malware pode ter apagado rastros. Confirme com o EDR e o SIEM.

**Se confirmar a infecção — preservar antes de limpar**

1. **Não desligue o Mac.** Isole-o da rede (pelo EDR, ou desligando o Wi-Fi).
2. **Colete os logs:** `sudo log collect --last 3d --output ~/Desktop/`.
3. **Copie as evidências:** o plist, o payload de `~/Library`, os históricos e a pasta gerada pelo script. Calcule o `shasum -a 256` de cada arquivo (cadeia de custódia).
4. **Para uma coleta completa,** use ferramentas abertas de resposta a incidente para macOS: **Aftermath** (Jamf) e **KnockKnock** (Objective-See, lista toda a persistência).
5. **Só então remova a persistência:** `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/<arquivo>.plist` e apague o plist e o payload.
6. **Troque as senhas e revogue as sessões a partir de outro dispositivo** (§5.4). O stealer levou senha do Mac, Keychain e cookies do navegador.

---

## 4. TTPs — MITRE ATT&CK (Enterprise, macOS)

| Tática | Técnica | ID | Evidência / Observação | Confiança |
|---|---|---|---|---|
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | Domínios descartáveis `.shop`/`.fun`/`.li`, rotação | Alta |
| Resource Development | Acquire Infrastructure: Malvertising | T1583.008 | Distribuição via anúncios maliciosos | Média-Alta |
| Initial Access | Drive-by Compromise | T1189 | Páginas de malvertising / falsa atualização | Média |
| Execution | User Execution: Malicious Copy and Paste | T1204.004 | Campanhas ClickFix (2026) | Média-Alta |
| Execution | User Execution: Malicious File | T1204.002 | DMG/instaladores falsos, software pirata | Média |
| Execution | Command and Scripting Interpreter: AppleScript | T1059.002 | Stealer e backdoor em AppleScript (`osascript`) | Alta |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `curl`/`bash` no stager; execução de tarefas | Alta |
| Persistence | Create or Modify System Process: Launch Agent | T1543.001 | `com.<user>.gfskjsnghdjsvuxj.plist`, `RunAtLoad` | Alta |
| Defense Evasion | Subvert Trust Controls: Gatekeeper Bypass | T1553.001 | Payload via `curl` não recebe quarentena | Média |
| Defense Evasion | Obfuscated Files or Information | T1027 | Nome aleatório, strings ofuscadas; baixa detecção inicial | Média |
| Credential Access | Input Capture: GUI Input Capture | T1056.002 | Diálogo falso pedindo senha do macOS | Alta |
| Credential Access | Credentials from Password Stores: Keychain | T1555.001 | `login.keychain-db` | Alta |
| Credential Access | Credentials from Web Browsers | T1555.003 | Login Data de navegadores Chromium | Alta |
| Credential Access | Steal Web Session Cookie | T1539 | Cookies de navegador → sequestro de sessão | Alta |
| Discovery | System Information Discovery | T1082 | `system_profiler`, UUID de hardware | Alta |
| Discovery | Software Discovery | T1518 | Campo `Software` no relatório | Média |
| Collection | Data from Local System | T1005 | Notes, carteiras, sessão Telegram | Alta |
| Collection | Clipboard Data | T1115 | Reportado por fonte secundária | Baixa |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | `ditto`/`zip` — padrão da linhagem AMOS/mac.c | Média (inferência) |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | Telegram `phefuckxiabot`, Steam `phefuckxia` | Alta |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP `/api.php?check=1`, `/task.php` | Alta |
| Command and Control | Ingress Tool Transfer | T1105 | Download de 2º estágio pelo loader | Alta |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Upload do arquivo coletado ao C2 | Alta |
| Impact | Financial Theft | T1657 | Drenagem de carteiras cripto; venda de logs | Média |

---

> **ATT&CK Navigator:** esta tabela está em `report/attack_layer_phexia.json` (layer 4.5). Abra em https://mitre-attack.github.io/attack-navigator/ → *Open Existing Layer* → *Upload from local*. A ferramenta importa e exporta os dois formatos.

---

## 5. Recomendações — MITRE D3FEND

Priorização: **P1** = imediato (24–72 h), **P2** = curto prazo (≤30 dias), **P3** = estrutural.

### 5.1 Harden (reduzir superfície)

| Prio | D3FEND | Ação concreta no MELI | ATT&CK mitigado |
|---|---|---|---|
| P2 | **D3-EAL** Executable Allowlisting | Santa (modo lockdown para perfis de alto risco) / Jamf Protect; bloquear binários não assinados/notarizados | T1204.002, T1105 |
| P2 | **D3-SCP** System Configuration Permissions | Perfil MDM: bloquear gravação em `~/Library/LaunchAgents` por processos não gerenciados; *Managed Login Items* (macOS 13+) com notificação | T1543.001 |
| P2 | **D3-ACH** Application Configuration Hardening | Restringir `osascript`/Terminal para não-desenvolvedores via TCC/PPPC; desabilitar Script Editor onde não há necessidade | T1059.002, T1204.004 |
| P1 | **D3-MFA** Multi-factor Authentication + **D3-TB** Token Binding | MFA resistente a phishing (FIDO2/Passkeys) e sessões ligadas ao dispositivo (Device Bound Session Credentials / Conditional Access com *device compliance*) para reduzir o valor de cookies roubados | T1539 |
| P3 | **D3-CH** Credential Hardening | Proibir armazenamento de senhas corporativas em navegador; usar gerenciador corporativo | T1555.003 |
| P2 | **D3-SU** Software Update | macOS atualizado (XProtect/XProtect Remediator recebem assinaturas de stealers) | Geral |

### 5.2 Detect (visibilidade)

| Prio | D3FEND | Ação concreta | ATT&CK |
|---|---|---|---|
| P1 | **D3-PLA** Process Lineage Analysis | Regra para `Terminal → sh/zsh → curl → osascript` (ClickFix) | T1204.004, T1059 |
| P1 | **D3-SEA** Script Execution Analysis | Alertar `osascript` com `display dialog … hidden answer` e `dscl . authonly` (Sigma §3.3) | T1056.002 |
| P1 | **D3-SJA** Scheduled Job Analysis / **D3-SICA** System Init Config Analysis | Monitorar criação de LaunchAgents com nomes aleatórios (osquery §3.3; ESF `NOTIFY_BTM_LAUNCH_ITEM_ADD`) | T1543.001 |
| P1 | **D3-FAPA** File Access Pattern Analysis | Processo não-navegador acessando Cookies/Login Data/Keychain/carteiras | T1555, T1539, T1005 |
| P1 | **D3-FHRA** File Hash Reputation Analysis + **D3-FCR** File Content Rules | Hash no EDR + YARA §3.3 em varredura retroativa | — |
| P2 | **D3-DNSTA** DNS Traffic Analysis + **D3-DNRA** Domain Name Reputation Analysis | Alertar domínios recém-registrados em TLDs baratos acessados por processos não-navegador | T1071.001 |
| P2 | **D3-CSPP** Client-server Payload Profiling + **D3-NTA** Network Traffic Analysis | Detectar *beaconing* ~30 s para `*.php` e sequências `t.me`/`steamcommunity` → domínio novo (DDR) | T1102.001 |
| P2 | **D3-WSAA** Web Session Activity Analysis / **D3-UGLPA** | Detectar sessão reutilizada de outro ASN/geo/device (indicador de cookie roubado) no IdP e apps críticos | T1539 |
| P3 | **D3-DUC** Decoy User Credential / **D3-DST** Decoy Session Token | *Canary tokens* em perfis de navegador de VIPs para detectar uso de logs roubados | T1539, T1555 |

### 5.3 Isolate / Deny

| Prio | D3FEND | Ação concreta |
|---|---|---|
| P1 | **D3-DNSDL** DNS Denylisting / **D3-FRDDL** | Sinkhole dos domínios §3.1 em DNS corporativo e *secure web gateway* |
| P1 | **D3-OTF** Outbound Traffic Filtering | Bloquear `t.me/phefuckxiabot` e `steamcommunity.com/id/phefuckxia`; avaliar bloquear Steam em endpoints corporativos |
| P2 | **D3-URA** URL Reputation Analysis / **D3-CF** Content Filtering | Filtrar categorias de malvertising, sites de *crack* e páginas ClickFix conhecidas |

### 5.4 Evict / Restore (playbook de resposta)

1. **Conter:** isolar o host via EDR (**D3-NI**); preservar evidências — plist, `~/Library/gfskjsnghdjsvuxj`, unified logs (`log collect`), histórico do shell, histórico de navegador.
2. **Erradicar:** `launchctl bootout gui/<uid> ~/Library/LaunchAgents/com.<user>.gfskjsnghdjsvuxj.plist`; encerrar processos (**D3-PT**); remover arquivos (**D3-FEV**). Reimagem recomendada em host de alto privilégio.
3. **Credenciais (crítico):** **D3-CR** Credential Revocation — revogar **todas** as sessões no IdP/SSO, GitHub, AWS/GCP, Slack etc.; **D3-CRO/D3-PR** rotacionar senha do macOS, senhas salvas no navegador e itens do Keychain; **D3-RIC** reemitir tokens/chaves SSH/API encontrados no host.
4. **Cripto:** se houver carteiras no host, mover fundos imediatamente para nova seed gerada em dispositivo limpo.
5. **Escopo:** **D3-CCSA** Credential Compromise Scope Analysis — mapear todos os serviços acessados com as credenciais/cookies do usuário nos últimos 30 dias e caçar logins anômalos.
6. **Lições aprendidas:** alimentar a TIP (MISP/OpenCTI) com os IoCs e as regras; atualizar awareness sobre ClickFix ("nunca cole comandos do navegador no Terminal").

> Na ferramenta, **Abrir incidente** a partir do scan gera este playbook como checklist (fases NIST SP 800-61, tarefas dos hunts H1–H6, responsável, hosts e linha do tempo), exportável em PDF/Markdown/JSON.

### 5.5 Recomendações além do D3FEND

- **Monitoramento de logs de stealers:** assinar feeds de *stealer logs* (ex.: Hudson Rock, SpyCloud, Flare) para detectar domínios `@mercadolivre`/`@mercadopago` e cookies corporativos à venda — permite agir **antes** do uso.
- **Takedown/denúncia:** reportar as contas DDR ao Telegram e à Valve; domínios aos registrars (**D3-DRT** Domain Registration Takedown) — com a ressalva de que o ator já demonstrou rotação rápida.
- **Detecção de marca:** monitorar anúncios que usem a marca MELI/Mercado Pago como isca de malvertising.

---

## 6. Avaliação de Risco para o Mercado Livre

| Fator | Avaliação |
|---|---|
| Probabilidade de exposição | **Média** — ameaça oportunista; ampla base macOS em engenharia/produto; ClickFix tem alta taxa de sucesso |
| Impacto | **Alto** — sessões SSO/cloud/GitHub, dados de clientes indiretamente, fraude financeira com cripto |
| Risco residual pós-P1 | **Médio** — IoCs atômicos expiram rápido; a defesa durável é comportamental (§3.2) + MFA com binding de sessão |

## 7. Lacunas de Inteligência e Próximos Passos (PIRs)

1. **PIR-1:** Confirmar tipo, tamanho e strings do artefato (download via MalwareBazaar / VT Intelligence) e detonar em sandbox macOS (ANY.RUN macOS, Triage).
2. **PIR-2:** Quais domínios estão *atualmente* publicados nos DDRs? (monitoramento automatizado das páginas do Telegram/Steam com alerta de mudança).
3. **PIR-3:** Há telemetria interna (EDR/proxy) de contato com qualquer IoC desde 10/2025? (retro-hunt de 12 meses).
4. **PIR-4:** Existem *Build tags* de afiliados que indiquem campanha focada em LATAM/Brasil?

---

## Anexo A — Escala de linguagem estimativa (ICD 203)

Quase certo (>95%) · Muito provável (80–95%) · **Provável (55–80%)** · Chance equilibrada (45–55%) · Improvável (20–45%) · Muito improvável (5–20%).

## Anexo B — Avaliação de fontes (Admiralty Code)

| Fonte | Confiabilidade | Credibilidade da informação |
|---|---|---|
| @L0Psec (X) — IoCs originais | B (normalmente confiável) | 2 (provavelmente verdadeira) |
| Moonlock Lab (MacPaw) — ligação com Phexia | A/B | 2 |
| Objective-See — "The Mac Malware of 2025" | A (confiável) | 2 |
| CyStack stealer-fingerprints | B | 2 |
| g0njxa — entrevista com o desenvolvedor | C (declarações do próprio ator) | 3 (possivelmente verdadeira) |
| PCrisk / Mallory (agregadores) | C | 3 |

## Anexo C — Referências

- L0Psec, IoCs do hash: https://x.com/L0Psec/status/1982917091956236737 · correção de usernames: https://x.com/L0Psec/status/1982931475604611442 · mudança de C2 para kys.li: https://x.com/L0Psec/status/2002103795279675647
- Moonlock Lab, atribuição a Phexia: https://x.com/moonlock_lab/status/1991619589382246673 · https://x.com/moonlock_lab/status/1991619828335993264
- Objective-See, *The Mac Malware of 2025*: https://objective-see.org/blog/blog_0x84.html
- CyStack, fingerprints Phexia: https://github.com/cystack/stealer-fingerprints/blob/main/families/phexia/README.md
- g0njxa, entrevista com o dev: https://g0njxa.medium.com/approaching-stealers-devs-a-brief-interview-with-phexia-38ad3772dbcd
- PCrisk, Phexia Stealer (Mac): https://www.pcrisk.com/removal-guides/34957-phexia-stealer-mac
- Mallory, Phexia Stealer (ClickFix): https://www.mallory.ai/malware/019ed1e7-daac-7136-bc77-66821834ffda
- MITRE ATT&CK: https://attack.mitre.org · MITRE D3FEND: https://d3fend.mitre.org
- Splunk PEAK Threat Hunting Framework: https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html · TaHiTI (whitepaper): https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf
- NIST SP 800-61 (Incident Handling): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86 (forense integrada à resposta a incidentes): https://csrc.nist.gov/pubs/sp/800/86/final · RFC 3227 (coleta de evidências e ordem de volatilidade): https://www.rfc-editor.org/rfc/rfc3227
- Aftermath (Jamf, IR para macOS): https://github.com/jamf/aftermath · KnockKnock (Objective-See): https://objective-see.org/products/knockknock.html
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/ · Sigma / pySigma: https://sigmahq.io
- VirusTotal: https://www.virustotal.com/gui/file/7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e
- MalwareBazaar: https://bazaar.abuse.ch/sample/7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e/ · API: https://bazaar.abuse.ch/api/
