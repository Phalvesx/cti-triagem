# Como esta solução atende ao desafio

> Desenvolvido por **Phillipe Alves** · Desafio Mercado Livre · 2026

Este documento explica, item por item, o que o desafio pede, o que o projeto entrega e onde encontrar cada parte. Para instalar e rodar, veja o [README](README.md).

**Resumo:** o hash do desafio corresponde a um componente do **Phexia**, um infostealer com backdoor para macOS (atribuição com confiança moderada-alta). O projeto tem três peças:

- **Relatório de inteligência** — `report/RELATORIO_CTI.md`
- **Ferramenta em Python** — API FastAPI + agente LangGraph + SQLite + interface web
- **Material de apoio** — playbook de hunting para 7 SIEMs e camada do ATT&CK Navigator

## Visão geral: pedido × entregue

| Item do desafio | O que foi pedido | O que o projeto entrega | Onde está |
|---|---|---|---|
| **1. Buscar o hash** | Pesquisar no VirusTotal / MalwareBazaar | Pesquisa em OSINT (fontes citadas) e consulta automática às duas plataformas, ao mesmo tempo | Relatório §1–2 · `app/vt_client.py`, `app/mb_client.py` |
| **2. Relatório CTI** | TTPs, C2, mitigação (D3FEND), metodologia, criatividade | Relatório com ACH, Modelo Diamante, Kill Chain, IoCs, 24 técnicas ATT&CK, 36 técnicas D3FEND, hunting e playbook de resposta | `report/RELATORIO_CTI.md` |
| **3. API + GenAI** | Python, VT/MB, LangGraph/LangChain para triagem e família, JSON, SQLite/CSV | FastAPI + agente LangGraph com saída estruturada e validada, retorno em JSON e persistência em SQLite | `app/main.py`, `app/agent.py`, `app/database.py` |
| **4. Extra: Docker** | Rodar em container | `Dockerfile` multi-stage (usuário não-root, healthcheck) + `docker-compose.yml` | raiz do projeto |
| **4. Extra: funcionalidades** | Histórico, busca de IP/domínio, criatividade | Histórico, busca de IP/domínio, log de requisições, hunting por SIEM, ATT&CK Navigator (exportar/importar), resposta a incidentes, PDF | `app/` |
| **4. Extra: documentação** | Documentar | README (uso), este documento (explicação) e docs automáticas em `/docs` | raiz |
| **4. Extra: testes** | Testes unitários | 95 testes com pytest, sem precisar de chave nem internet | `tests/` |
| **DFIR** | Item 2: "buscar evidências numa máquina infectada" | Plano de coleta e script de triagem forense por SO (macOS, Windows, Linux) gerados da triagem | `app/dfir.py` · aba DFIR |
| **Segurança** | (não pedido) | Guardrails: não executa nem recebe arquivos, nunca acessa o IoC, anti *prompt injection*, CSP, limite de taxa, token opcional | `app/security.py` |
| **4. Extra: frontend** | Interface + relatório de triagem em HTML | Interface web com análise, hunting, ATT&CK, incidentes e relatório HTML/PDF | `app/static/index.html`, `/api/v1/report/{hash}` |

---

## Item 1 — Busca do hash

**O que foi encontrado.** O hash foi divulgado em 28/10/2025 pelo pesquisador @L0Psec como um backdoor para macOS, com só 2 detecções no VirusTotal na época. O malware descobre o endereço do servidor de comando lendo um bot do Telegram (`phefuckxiabot`) e um perfil da Steam (`phefuckxia`), técnica chamada *Dead Drop Resolver*. Os servidores associados eram `nfs8u9aw[.]shop` e `ad4rchr39w8f[.]fun`, e depois `kys[.]li`. Em seguida, a Moonlock Lab ligou esse mesmo nome de usuário a uma amostra com a string "Phexia macOS Stealer".

**Como a ferramenta faz a busca.** `GET /api/v1/analyze/{hash}` consulta o VirusTotal (arquivo e conexões de rede) e o MalwareBazaar (assinatura, tags, YARA e análises de parceiros) em paralelo. Se uma fonte falhar, a análise segue com a outra e registra a falha em `source_errors`.

**Limitação.** Sem chaves de API, a ferramenta usa dados **simulados** no formato real das APIs, montados a partir da OSINT, e marca isso na resposta e no relatório. Para a entrega final, rode com `VT_API_KEY` e `MB_API_KEY` para preencher tipo, tamanho e detecções atuais do arquivo.

---

## Item 2 — Relatório de inteligência

O desafio pede um relatório que sirva a duas tarefas: **achar evidências numa máquina infectada** e **melhorar os controles**. O relatório foi organizado assim:

| Necessidade do leitor | Seção do relatório |
|---|---|
| Entender a ameaça em 1 minuto | §1 Resumo executivo (BLUF), com avaliação de confiança |
| Saber de onde vem a atribuição | §2 Ficha do artefato, perfil da família, **ACH** (hipóteses concorrentes), **Modelo Diamante**, **Kill Chain** |
| Procurar evidências na máquina | §3.1 IoCs (com validade estimada), §3.2 comportamentos, §3.3 **hunts**, §3.4 osquery e YARA, §3.5 **passo a passo no Mac** + script `scripts/mac_triage.sh` |
| Mapear o comportamento | §4 **24 técnicas MITRE ATT&CK** com evidência e confiança; camada pronta para o Navigator |
| Melhorar controles | §5 **D3FEND** por fase (Harden, Detect, Isolate, Evict/Restore), com prioridade P1/P2/P3 |
| Responder ao incidente | §5.4 playbook de resposta (contenção, erradicação, revogação de credenciais) |
| Decidir prioridade | §6 risco para o Mercado Livre · §7 lacunas e PIRs |

**Metodologias usadas:**

- **ACH** (*Analysis of Competing Hypotheses*) para a atribuição.
- **Modelo Diamante** e **Cyber Kill Chain**.
- Linguagem estimativa **ICD 203** ("provável", "quase certo").
- **Admiralty Code** para avaliar cada fonte.
- **Pyramid of Pain** para separar IoCs que expiram de comportamentos duráveis.
- **PEAK/TaHiTI** para os hunts.
- **PIRs** (*Priority Intelligence Requirements*) para as lacunas.

**Partes criativas (além do pedido):**

- **Serviços legítimos separados de C2:** o relatório trata Telegram e Steam como serviços abusados, e não como C2. Bloquear o domínio inteiro quebraria o negócio.
- **Hunts prontos:** para Splunk, Sentinel/Defender, Elastic, QRadar, Google SecOps, Wazuh e Sigma, em `report/HUNTING_PLAYBOOK.md`. As regras Sigma foram validadas com `sigma convert`.
- **Recomendações específicas ao contexto:** monitorar logs de stealers à venda e proteger sessões contra o roubo de cookies.

**Honestidade analítica.** O vínculo entre este hash e o nome Phexia é indireto, via o nome de usuário usado no Telegram e na Steam. O relatório diz isso explicitamente e não inventa IPs que nenhuma fonte publicou.

---

## Item 3 — API e agente de GenAI

### Fluxo

```
GET /api/v1/analyze/{hash}
   │
   ├─► VirusTotal ─┐   (em paralelo; uma fonte pode falhar)
   ├─► MalwareBazaar ─┘
   │
   ▼
Agente LangGraph
   extract_features ─► heuristic_triage ─┬─► llm_triage ─► finalize
                                         └─────────────────► finalize (sem LLM)
   │
   ├─► SQLite (scans, iocs, request_log)
   └─► JSON de resposta
```

### Por que foi feito assim

| Decisão | Motivo |
|---|---|
| **Reduzir o JSON antes do LLM** (`features.py`) | A resposta do VT tem centenas de KB. O modelo recebe só sinais úteis: rótulos, sandbox, YARA, assinatura do MB e rede. É mais barato e alucina menos. |
| **Baseline por regras antes do LLM** | Votação de rótulos de antivírus (ignorando nomes genéricos como "Trojan.Generic") mais a assinatura curada do MB. Serve de referência para o modelo e de **resposta de reserva** se a IA falhar ou não estiver configurada. |
| **Saída estruturada com Pydantic** | O LLM precisa devolver um `TriageReport` (veredito, confiança, família, técnicas ATT&CK, IoCs e ações). Se o JSON vier inválido, a API não quebra: cai na baseline e registra o motivo. |
| **IoCs observados nunca são descartados** | O passo `finalize` junta os IoCs do VT aos do LLM e separa serviços legítimos abusados. |
| **Modelo escolhido** | `gpt-4o-mini` (OpenAI) ou Claude (Anthropic), trocando só uma variável. Os dois suportam bem saída estruturada, e o custo por triagem é baixo. |
| **SQLite** | O desafio aceita SQLite ou CSV. SQLite permite consultar histórico e buscar IoCs com SQL e não exige servidor. |

### Onde fica cada dado

| Tabela | Conteúdo |
|---|---|
| `scans` | Hash, veredito, família, confiança, features, triagem e JSON bruto do VT e do MB |
| `iocs` | Domínios, IPs e URLs de cada scan (usada pela busca de IP/domínio) |
| `request_log` | Histórico de todas as requisições à API |
| `incidents`, `incident_tasks`, `incident_events` | Módulo de resposta a incidentes |

---

## Item 4 — Extras

**Docker:** `docker compose up -d --build`. A imagem é multi-stage, roda com usuário não-root, sistema de arquivos somente leitura e healthcheck. O compose também tem um serviço que roda os testes.

**Funcionalidades adicionais:**

| Funcionalidade | Para quê | Onde |
|---|---|---|
| Histórico de scans | Consultar análises anteriores com filtro por veredito e família | `/api/v1/history` |
| Busca de IP/domínio/URL | Reputação no VT e quais scans locais citam o indicador (aceita `evil[.]com` e `hxxps://`) | `/api/v1/search` |
| Hash local de arquivo | Calcula o SHA-256 no navegador ou no terminal; o arquivo não é enviado nem executado | botão na interface · `cti hash-file` |
| Log de requisições | Auditoria de uso da API | `/api/v1/requests` |
| Hunting por SIEM | Hipóteses e consultas para 7 plataformas, geradas a partir de qualquer hash | `/api/v1/hunt/{hash}` · aba Hunting |
| MITRE ATT&CK | Exportar/importar camada do Navigator e CSV, e mapa de calor do histórico | `/api/v1/attack/...` · aba ATT&CK |
| Resposta a incidentes | Playbook NIST SP 800-61 com checklist, hosts, responsável e linha do tempo | `/api/v1/incidents` · aba Incidentes |
| Relatórios HTML e PDF | Triagem e incidente, com apêndice de hunting | `/api/v1/report/{hash}` · `/pdf` |
| Linha de comando | Usar tudo sem abrir a interface | `python -m app.cli` |
| Triagem de Mac | Script somente leitura que procura as evidências do Phexia num Mac e empacota para o time de resposta | `scripts/mac_triage.sh` |

**Frontend:** a interface web tem campo único que reconhece hash, IP ou domínio, resultado em JSON, **relatório de triagem em HTML** (pedido explícito do desafio), exportação em PDF e as abas Hunting, ATT&CK e Incidentes.

**Testes:** 95 testes com pytest, cobrindo:

- endpoints e tratamento de erros (404, 422, 429, 501)
- clientes do VT e do MB com HTTP simulado
- agente LangGraph com LLM falso: saída válida, JSON dentro de markdown e resposta inválida
- hunting (YAML Sigma e XML Wazuh válidos), importação/exportação ATT&CK, incidentes, CLI, PDF, cache e migração do banco
- guardrails: prompt injection, saída do LLM saneada, CSV injection, CSP, sem CORS, limite de taxa e de tamanho, token
- DFIR: sintaxe dos scripts (bash -n, shellcheck, parser do PowerShell), somente leitura, sem rede e bloqueio de injeção

---

## Serve para outros indicadores?

Sim. Nada é fixo no hash do desafio:

- **Qualquer hash** (MD5, SHA-1, SHA-256) passa pela mesma triagem: VT + MB + IA, família, ATT&CK, IoCs, hunts, relatório e incidente.
- **IP, domínio e URL** passam pela busca: reputação no VT e correlação com os scans já feitos.
- **Pré-requisito:** as chaves de API. Sem elas, só o hash do desafio tem dados de exemplo, e a ferramenta avisa isso com clareza.
- **Hunts comportamentais:** os de macOS (H4–H6) aparecem quando a plataforma é macOS. Para outras plataformas, a ferramenta gera os hunts de IoC (H1–H3).

## DFIR: do CTI para a máquina infectada

**É pertinente?** Sim. O item 2 do desafio diz que o relatório será usado "para buscar evidências de exploração numa máquina infectada", e isso é DFIR. O papel do CTI aqui é **dizer ao DFIR o que procurar e onde**, não substituir uma perícia completa (imagem de disco, laboratório). Por isso a entrega foi mantida mínima:

| Etapa | O que o projeto entrega | Padrão seguido |
|---|---|---|
| Preparar | Regras de forense segura: isolar antes, não desligar, só hash e nunca upload, mídia dedicada | NIST SP 800-61 |
| Coletar | Script por SO, somente leitura e sem rede, na **ordem de volatilidade** (processos e rede → persistência → arquivos → históricos e logs) | RFC 3227 |
| Direcionar | Verificações **específicas das técnicas ATT&CK** do artefato (ex.: LaunchAgent no macOS, Run keys e tarefas no Windows, cron e systemd no Linux) | ATT&CK |
| Preservar | `MANIFESTO_SHA256.txt` e pacote `.zip`/`.tar.gz` para a cadeia de custódia | NIST SP 800-86 |
| Registrar | Tarefas no incidente: executar a triagem DFIR e preservar as evidências | NIST SP 800-61 |

**O que muda conforme o artefato e o SO.** O script leva os IoCs daquele hash (hashes, domínios, IPs, perfis de DDR, nomes de arquivo) e as verificações das técnicas mapeadas na triagem. O SO vem da triagem (ex.: Phexia → macOS) e pode ser trocado na aba DFIR.

| Sistema | O que o script verifica |
|---|---|
| **macOS** | LaunchAgents, itens de login, histórico do Terminal, quarentena de downloads, navegadores e Unified Log |
| **Windows** | Processos com linha de comando, conexões, cache DNS, Run keys, tarefas, serviços, WMI, histórico do PowerShell, Win+R (ClickFix), Zone.Identifier, Defender e eventos 7045/4698/4104/Sysmon |
| **Linux** | Processos (inclusive binário apagado), conexões, cron, systemd, `ld.so.preload`, `authorized_keys`, executáveis em `/tmp`, históricos e journal |

## Guardrails e forense segura

| Risco | Como o projeto evita |
|---|---|
| A ferramenta executar ou espalhar malware | Não aceita upload nem executa nada; recebe só texto (hash, IP, domínio, URL) |
| A ferramenta contatar o C2 | Nunca acessa o indicador: só pergunta ao VirusTotal/MalwareBazaar sobre ele |
| Vazar a amostra ao investigar | Hash calculado localmente (navegador ou `cti hash-file`); orientação de **não** fazer upload ao VT |
| Atacante manipular a IA (*prompt injection*) | Dados de ameaça limpos, truncados e marcados como não confiáveis; saída do LLM validada e saneada |
| XSS / fórmulas em CSV | HTML escapado, IoCs *defanged*, células CSV neutralizadas |
| Outro site chamar a API local | Sem CORS, CSP e cabeçalhos de segurança; escuta só em `127.0.0.1` |
| Abuso da API | Limite de taxa, limite de tamanho e token opcional (`API_TOKEN`) |
| Espalhar a infecção durante a coleta no Mac | `mac_triage.sh` é somente leitura e **não usa a rede**; o relatório (§3.5) manda isolar o host antes, guardar a amostra em zip com senha `infected` e não usar AirDrop ou pastas compartilhadas |

## O que foi removido para enxugar

| Removido | Motivo |
|---|---|
| Endpoint `/api/v1/malwarebazaar/{hash}` | Repetia dados que o `/analyze` já devolve |
| Endpoint `/api/v1/family/{nome}` (pivô por família) | Fora do escopo do desafio e pouco usado |
| Anexo D do relatório (≈700 linhas de consultas) | Deixava o relatório ilegível; as consultas ficaram em `report/HUNTING_PLAYBOOK.md` |
| CSV duplicado do ATT&CK e o arquivo `SOLUCAO_COMPLETA.md` | Duplicavam o layer do Navigator e o próprio código |
| Código morto (funções e imports sem uso) | Limpeza com `ruff` e `vulture` |

---

## Limitações e próximos passos

- **Dados reais:** sem chaves de API, os dados do VT/MB são simulados (marcados como tal). Com as chaves, a ferramenta usa os dados reais sem nenhuma mudança de código.
- **Amostra não analisada:** o arquivo em si não foi baixado nem detonado. As próximas etapas estão no relatório (PIR-1): obter a amostra e analisá-la em sandbox macOS.
- **Consultas de SIEM:** foram escritas com os campos padrão de cada plataforma (CIM, ECS, UDM, tabelas do Defender). Só as regras Sigma foram validadas automaticamente; as demais precisam de ajuste fino no ambiente real.
- **Monitoramento contínuo:** um próximo passo natural é vigiar os perfis do Telegram e da Steam para saber quando o C2 publicado mudar.

## Roteiro de demonstração (5 minutos)

1. **Abrir a ferramenta:** `INICIAR_WINDOWS.bat` (ou `./iniciar.sh`).
2. **Analisar o hash:** mostrar família, veredito, confiança, fontes e o JSON.
3. **Relatório HTML:** abrir a aba e exportar o PDF.
4. **Hunting:** escolher o SIEM da empresa e copiar uma consulta.
5. **ATT&CK:** exportar a camada, abrir no Navigator e importar de volta.
6. **Incidente:** abrir um incidente, marcar uma tarefa e mostrar a linha do tempo.
7. **Busca:** procurar `kys[.]li` e ver a correlação com o scan.
8. **Fechar:** mostrar os testes (`pytest -q`) e o relatório CTI.
