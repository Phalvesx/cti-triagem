# CTI Triage — Análise de Malware, Threat Hunting e Resposta a Incidentes

> **Desenvolvido por Phillipe Alves · Desafio Mercado Livre · 2026**

Ferramenta local (roda no seu PC) que:

1. **Analisa** um hash no **VirusTotal** e no **MalwareBazaar** e faz a triagem com **GenAI** (LangGraph/LangChain), atribuindo família, veredito, técnicas ATT&CK e IoCs.
2. **Gera hunts** prontos para **Splunk, Microsoft Sentinel/Defender, Elastic, IBM QRadar, Google SecOps, Wazuh e Sigma**.
3. **Exporta e importa a tabela MITRE ATT&CK** (layer do **ATT&CK Navigator** e CSV), com heatmap de todo o histórico.
4. **Conduz a resposta a incidentes**: playbook NIST SP 800-61 com checklist, responsável, hosts e linha do tempo.
5. **Guia o DFIR no host**: gera o script de triagem forense para **macOS, Windows ou Linux** com os IoCs e as técnicas do artefato (somente leitura, sem rede, ordem de volatilidade, manifesto SHA-256).
6. **Gera relatórios** em HTML e **PDF** (triagem e incidente), com logo configurável.

Tudo fica num banco **SQLite** local.

- **Como a solução atende a cada item do desafio:** [`SOLUCAO.md`](SOLUCAO.md)
- **Relatório de inteligência:** [`report/RELATORIO_CTI.md`](report/RELATORIO_CTI.md)
- **Consultas de hunting por SIEM:** [`report/HUNTING_PLAYBOOK.md`](report/HUNTING_PLAYBOOK.md)

---

## Rodar no PC (sem Docker)

Requisito: **Python 3.11 ou superior** ([python.org](https://www.python.org/downloads/) — no Windows, marque *Add python.exe to PATH*).

| Sistema | Como iniciar |
|---|---|
| **Windows** | Duplo clique em **`INICIAR_WINDOWS.bat`** |
| **macOS / Linux** | `./iniciar.sh` |

Na primeira vez o instalador mostra o banner e uma **barra de progresso de 0% a 100%**: verifica o Python, cria o ambiente `.venv`, instala os pacotes um a um (ex.: `Instalando langgraph (6/9)`), testa a aplicação, **pede as chaves de API** (é só colar; Enter pula) e mostra um painel **Integrações** validando cada chave online (VirusTotal mostra até a cota diária usada). A primeira instalação baixa cerca de 150 MB e leva de 1 a 5 minutos, conforme a internet. Nas próximas vezes ele detecta que já está instalado e abre direto o navegador em **http://127.0.0.1:8000**. A ferramenta escuta só no seu PC (127.0.0.1).

**Se a instalação não andar:**

| Sintoma | Solução |
|---|---|
| "Parece que o arquivo foi aberto de dentro do .zip" | Clique com o botão direito no .zip → **Extrair tudo**, e rode o `INICIAR_WINDOWS.bat` da pasta extraída |
| "Python 3.11 ou superior não encontrado" | Instale o Python 3.12 em [python.org](https://www.python.org/downloads/) marcando **Add python.exe to PATH**, feche e abra de novo |
| Falha em "Instalando ..." com aviso de internet | Rede corporativa: rode `set HTTPS_PROXY=http://proxy:porta` no mesmo terminal e depois `python instalar.py` |
| Chave recusada (✖ no painel Integrações) | `INICIAR_WINDOWS.bat --chaves` (ou `python instalar.py --chaves`) e cole de novo |
| Porta 8000 ocupada | Automático: se já for o CTI Triage, só abre o navegador; senão usa a próxima porta livre |
| Qualquer outro erro | `INICIAR_WINDOWS.bat --reinstalar` e veja o arquivo `install.log` |

**Conferir as APIs:** `cti check` valida as chaves; `TESTAR_APIS.bat` (ou `.venv/bin/python scripts/testar_apis.py`) roda análises reais com hashes conhecidos (hash do desafio, WannaCry, EICAR, entrada MD5 e um hash inexistente) e mostra ✔/✖ para cada um.

Sem nenhuma chave configurada, tudo funciona em **modo simulado** (dados de exemplo do hash do desafio), útil para conhecer a ferramenta.

### Chaves (arquivo `.env`)

| Variável | Para quê |
|---|---|
| `VT_API_KEY` | VirusTotal (a conta gratuita serve; limite de 4 req/min — a ferramenta espera e tenta de novo) |
| `MB_API_KEY` | MalwareBazaar — Auth-Key grátis em https://auth.abuse.ch/ |
| `LLM_PROVIDER` + `OPENAI_API_KEY` ou `ANTHROPIC_API_KEY` | IA da triagem (`openai`, `anthropic` ou `none`). Com `none`, a triagem é feita por regras |
| `LLM_MODEL` | ex.: `gpt-4o-mini`, `claude-sonnet-4-5` |
| `BRAND_NAME`, `BRAND_LOGO_PATH`, `REPORT_TLP` | Identidade visual e classificação TLP dos relatórios |
| `CACHE_TTL_HOURS` | Por quanto tempo um scan vale antes de reconsultar as fontes (padrão 24h) |
| `API_TOKEN` | Opcional. Se definido, a API exige o header `X-API-Key` (a interface pede o token uma vez) |
| `RATE_LIMIT_PER_MIN`, `MAX_BODY_KB` | Limite por IP nas consultas externas (padrão 30/min) e tamanho máximo de requisição |

**Logo:** salve o arquivo como `app/static/logo.svg` ou `app/static/logo.png`. Ele aparece na interface, no HTML e no PDF.

---

## Usar pela linha de comando (sem abrir a interface)

Windows: `cti <comando>` · macOS/Linux: `./cti.sh <comando>`

```bash
cti analyze <hash> --pdf relatorio.pdf --siem sentinel   # triagem + PDF com apêndice de hunting
cti hunt <hash> --siem splunk --out hunts.md             # all|splunk|sentinel|elastic|qradar|secops|wazuh|sigma
cti dfir <hash> --os windows                              # script de triagem forense do host (macos|windows|linux)
cti attack <hash> --navigator layer.json --csv tecnicas.csv
cti attack-import <hash> layer_editado.json --mode merge  # importa layer do Navigator ou CSV
cti heatmap --navigator heatmap.json                      # técnicas de todo o histórico
cti search nfs8u9aw[.]shop                                # reputação + scans que citam o indicador (IP, domínio ou URL)
cti hash-file ~/Downloads/suspeito.dmg                    # hash calculado localmente; o arquivo não é enviado
cti incident open <hash> --host mbp-dev-01 --owner ana    # abre incidente com playbook
cti incident show 1                                       # checklist
cti incident task 1 5 --status concluida --note "host isolado"
cti incident export 1 --pdf incidente.pdf --md incidente.md
cti history
```

---

## Funcionalidades

### Análise e triagem
VirusTotal e MalwareBazaar são consultados ao mesmo tempo. Se uma fonte falhar, a análise segue com a outra (a falha aparece em `source_errors`). O agente LangGraph monta primeiro uma baseline por regras (votação de rótulos de AV, sandbox, YARA, assinatura do MalwareBazaar). Com IA configurada, o modelo devolve um relatório estruturado e validado; se a IA falhar, a baseline é usada. Sem IA, as técnicas ATT&CK também são inferidas por regras.

Domínios de **serviços legítimos abusados** (t.me, Steam, GitHub, Pastebin…) são separados dos domínios de C2: aparecem como "serviço abusado", e o que se bloqueia é a URL/perfil específico, não o serviço inteiro.

### Threat Hunting
A aba **Hunting** gera, para cada hash, hunts orientados a hipótese: H1 hashes, H2 infraestrutura de C2, H3 Dead Drop Resolver e, para macOS, H4 phishing de senha por AppleScript, H5 LaunchAgent aleatório e H6 cadeia ClickFix. Cada hunt traz hipótese, fontes de dados, como triar os resultados e a consulta para cada SIEM. As regras Sigma são validadas com `sigma convert`. A metodologia está no relatório CTI, §3.3.

### MITRE ATT&CK
- **Exportar:** layer do ATT&CK Navigator (JSON 4.5) ou CSV, por scan ou do histórico inteiro (heatmap).
- **Importar:** envie um layer editado no Navigator ou um CSV (`technique_id`, `technique_name`, `tactic`) para somar ou substituir as técnicas de um scan.
- Abrir no Navigator: https://mitre-attack.github.io/attack-navigator/ → *Open Existing Layer* → *Upload from local*.

### DFIR (forense no host)
A aba **DFIR** transforma a inteligência em coleta no host. Para o sistema escolhido (detectado na triagem ou selecionado), mostra:

- as regras de forense segura;
- a ordem de coleta (RFC 3227);
- as verificações das técnicas ATT&CK observadas, com o comando de cada uma.

O botão baixa um script pronto: `triagem_macos.sh`, `triagem_linux.sh` ou `triagem_windows.ps1`. O script tem os IoCs embutidos, **só lê** (não apaga nem mata processos), **não usa a rede** (rode com o host isolado) e gera um pacote com `MANIFESTO_SHA256.txt` para cadeia de custódia. Os IoCs passam por validação antes de entrar no script, o que impede injeção de comandos.

### Resposta a incidentes
O botão **Abrir incidente** cria um playbook nas fases do NIST SP 800-61 (Detecção e Análise, Contenção, Erradicação, Recuperação, Pós-incidente), com tarefas tiradas da triagem: executar os hunts, bloquear IoCs, revogar sessões (stealer), remover persistência etc. Cada mudança de status e cada nota vai para a linha do tempo. Exporta em PDF, Markdown e JSON.

---

## API (http://127.0.0.1:8000/docs)

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/v1/analyze/{hash}?force=` | Triagem (VT + MB + IA) |
| GET | `/api/v1/report/{hash}` · `/pdf` | Relatório HTML/PDF (`?siem=` define o apêndice de hunting; `?fallback=print` para PC sem PDF nativo) |
| GET | `/api/v1/hunt/{hash}?siem=&format=json\|markdown` | Pacote de hunting |
| GET | `/api/v1/dfir/{hash}?os=` · `/dfir/{hash}/script?os=` | Plano de coleta forense e script de triagem por SO |
| GET | `/api/v1/attack/{hash}?format=json\|navigator\|csv` | Técnicas ATT&CK do scan |
| POST | `/api/v1/attack/{hash}/import?mode=merge\|replace` | Importa layer JSON ou CSV (corpo da requisição) |
| GET | `/api/v1/attack/heatmap?format=json\|navigator\|csv` | Heatmap do histórico |
| POST/GET/PATCH | `/api/v1/incidents` · `/{id}` · `/{id}/tasks/{task}` · `/{id}/events` | Incidentes |
| GET | `/api/v1/incidents/{id}/export?format=pdf\|markdown\|json\|html` | Exporta o incidente |
| GET | `/api/v1/search?q=` · `/history` · `/history/{hash}` · `/requests` | Busca de IP/domínio/URL, histórico de scans e log de requisições |

---

## Segurança (guardrails)

A ferramenta foi feita para **não virar vetor de ataque**:

| Risco | Proteção |
|---|---|
| Executar ou espalhar malware | Não aceita upload de arquivo nem executa nada. Aceita só **texto** (hash, IP, domínio, URL) e **nunca acessa o indicador**: só consulta VirusTotal/MalwareBazaar |
| Precisar do hash de um arquivo suspeito | O botão **"Calcular hash de um arquivo"** calcula o SHA-256 **no navegador** (e `cti hash-file` no terminal). O arquivo não sai do PC e não é aberto |
| *Prompt injection* (nome de arquivo ou comentário do atacante mandando a IA "dizer que é benigno") | Dados de ameaça são limpos e truncados antes da IA, marcados como `<dados_nao_confiaveis>` no prompt; a saída do modelo é validada e saneada |
| XSS / CSV injection nos relatórios | HTML sempre escapado, IoCs *defanged* (`evil[.]com`), células CSV neutralizadas (`=`, `+`, `-`, `@`) |
| Outro site no navegador chamar a API local | Sem CORS e com cabeçalhos de segurança (CSP, nosniff, frame-options); escuta só em `127.0.0.1` |
| Abuso / estouro de cota das APIs | Limite de requisições por IP (`RATE_LIMIT_PER_MIN`), limite de tamanho (`MAX_BODY_KB`) e token opcional (`API_TOKEN`) |

## Investigar um Mac suspeito

`scripts/mac_triage.sh` faz, só com ferramentas nativas do macOS, **sem alterar nada e sem usar a rede** (pode rodar com o Mac isolado), as verificações do relatório (§3.5): persistência, payload, hash, histórico do Terminal, downloads, navegadores, processos, rede e Unified Log. Gera uma pasta na Mesa com as evidências, um `RESUMO.txt` com os alertas e um `.zip` para o time de resposta.

```bash
bash scripts/mac_triage.sh        # ou: sudo bash scripts/mac_triage.sh
```

## PDF no Windows

O PDF é gerado pelo **WeasyPrint**, que no Windows precisa do GTK/Pango instalado ([instruções](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows)). Sem ele nada quebra: os botões de PDF abrem o relatório já com a janela **Imprimir → Salvar como PDF** do navegador, e o `cti ... --pdf` salva o HTML equivalente.

## Docker (opcional)

```bash
cp .env.example .env
docker compose up -d --build        # http://localhost:8000
docker compose run --rm tests       # testes dentro do container
```

## Testes

```bash
.venv/bin/python -m pip install -r requirements-dev.txt   # Windows: .venv\Scripts\python -m pip ...
.venv/bin/python -m pytest -q
```

95 testes cobrem API, clientes VT/MalwareBazaar (HTTP mockado), agente LangGraph com LLM falso, hunting (inclui validação de YAML Sigma e XML Wazuh), exportação/importação ATT&CK, incidentes, CLI, PDF, cache, migração do banco os guardrails (prompt injection, CSV/XSS, CSP, limite de taxa, token) e os scripts DFIR (sintaxe bash/PowerShell, somente leitura, sem rede, bloqueio de injeção). Nenhum teste precisa de chave ou de internet.

## Estrutura

```
app/
  main.py        API FastAPI (rotas)          cli.py       linha de comando
  agent.py       agente LangGraph              features.py  extração + triagem por regras + ATT&CK
  vt_client.py   VirusTotal                    mb_client.py MalwareBazaar
  hunting.py     gerador de hunts por SIEM     attack.py    Navigator/CSV import/export
  incidents.py   resposta a incidentes         report.py    relatórios HTML/PDF
  dfir.py        plano e scripts forenses      dfir_templates/  macOS · Windows · Linux
  database.py    SQLite                        security.py  guardrails
  static/        interface web
report/          relatório CTI, playbook de hunting, layer ATT&CK
instalar.py      instalador com progresso (0–100%), pede e valida as chaves de API
app/banner.py    banner e componentes visuais do terminal
app/healthcheck.py  validação das chaves VT/MalwareBazaar (cti check)
scripts/testar_apis.py  teste de fumaça das APIs reais (TESTAR_APIS.bat)
scripts/         mac_triage.sh (script DFIR de macOS já gerado para o Phexia)
                 regen_report.py (regenera o playbook de hunting e o layer ATT&CK)
tests/
```
