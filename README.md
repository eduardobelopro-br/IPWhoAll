# IPWhoAll

**Designed for p1r1l4mp0**

Automação de reconhecimento inicial (recon) para pentests autorizados. A partir de um IP ou endereço web, a ferramenta identifica o tipo de entrada, verifica disponibilidade do host (com evasão de bloqueio de ICMP), resolve DNS, consulta WHOIS/RDAP e — quando o alvo é brasileiro — extrai e consulta o CNPJ automaticamente.

---

## ⚠️ Aviso legal e ético

Esta ferramenta deve ser usada **exclusivamente em ativos para os quais você possua autorização explícita de teste** (contrato de pentest, escopo assinado, programa de bug bounty, ambiente de laboratório próprio, etc.).

Reconhecimento e varredura de sistemas sem autorização podem configurar crime, dependendo da jurisdição (no Brasil, por exemplo, à luz da Lei nº 12.737/2012 — "Lei Carolina Dieckmann" — e do Marco Civil da Internet). O uso desta ferramenta é de inteira responsabilidade de quem a executa.

---

## Funcionalidades

- **Detecção automática de entrada**: identifica se o valor informado é um IP ou um domínio/URL.
- **Fluxo adaptativo**:
  - Domínio → `nslookup` (resolve IPs) → checagem de disponibilidade → WHOIS/RDAP → CNPJ.
  - IP → checagem de disponibilidade → `nslookup` reverso (PTR) → WHOIS/RDAP → CNPJ.
- **Checagem de disponibilidade com evasão de bloqueio de ICMP**: se o `ping` não obtiver resposta (comum em ambientes cloud/corporativos que bloqueiam ICMP), faz fallback automático testando conexão TCP em portas comuns (443, 80, 22, 3389, 21, 25, 8080).
- **Saída completa e bruta**: exibe a saída real do `ping` e do `nslookup` do sistema, não versões resumidas.
- **WHOIS**: consulta via `python-whois`, exibindo o retorno completo do servidor.
- **RDAP oficial do Registro.br**: para domínios `.br`, consulta a API estruturada (`rdap.registro.br`), muito mais confiável que o WHOIS tradicional para extrair o CNPJ do titular do domínio.
- **Extração automática de CNPJ**: tenta extrair via RDAP primeiro; se não encontrar, tenta via regex no texto do WHOIS; só pede input manual como último recurso.
- **Consulta de CNPJ na BrasilAPI**: retorna razão social, situação cadastral, CNAE, sócios (QSA), endereço, regime tributário, etc., formatado de forma legível.
- **Geração de relatório**: ao final, pergunta se deseja salvar tudo o que foi exibido em um arquivo `.txt`, deixando você escolher o diretório (pasta atual ou `~/Documents`) e o nome do arquivo, organizado na pasta `IPWhoAll/`.

---

## Requisitos

- Python 3.10+
- Sistema com os comandos `ping` e `nslookup` disponíveis no PATH (a ferramenta tem fallback via Python puro caso não estejam instalados, mas a saída detalhada só aparece com os comandos do sistema).
- Bibliotecas Python:
  - [`python-whois`](https://pypi.org/project/python-whois/)
  - [`requests`](https://pypi.org/project/requests/)

---

## Instalação

Ambientes como o Kali Linux usam Python "externally managed" (PEP 668), então é recomendado isolar as dependências em um ambiente virtual (venv).

```bash
git clone https://github.com/<seu-usuario>/IPWhoAll.git
cd IPWhoAll

python3 -m venv ~/venvs/pentest
source ~/venvs/pentest/bin/activate
pip install python-whois requests
```

### Opção alternativa: script wrapper automático

O repositório inclui `run.sh`, que cria o venv (se não existir), instala as dependências, ativa o ambiente, executa a ferramenta e desativa o venv automaticamente ao sair (inclusive com `Ctrl+C`):

```bash
chmod +x run.sh
./run.sh
```

---

## Uso

```bash
source ~/venvs/pentest/bin/activate   # se não estiver usando o run.sh
python3 recon.py
```

Ao rodar, a ferramenta vai pedir:

```
Informe o IP ou endereço web (domínio/URL) do alvo:
```

Basta digitar um IP (`192.0.2.10`) ou um domínio/URL (`exemplo.com.br`, `https://exemplo.com.br`).

Ao final da execução, ela pergunta:

```
Deseja salvar os dados encontrados em um arquivo? (s/n):
```

Se a resposta for `s`, você escolhe onde salvar:

```
Onde deseja salvar o relatório?
  1) Pasta atual (/home/kali/pentest-tools)
  2) Documents (/home/kali/Documents)
Escolha uma opção (1/2) [padrão: 1]:
```

E em seguida o nome do arquivo:

```
Nome do arquivo (Enter para usar o padrão '<alvo>_<data>_<hora>.txt'):
```

- Digite um nome personalizado (a extensão `.txt` é adicionada automaticamente, se necessário), ou
- Pressione Enter para usar o nome padrão sugerido.

O relatório completo da sessão é salvo em:

```
<diretório escolhido>/IPWhoAll/<nome do arquivo>.txt
```

A pasta `IPWhoAll/` é criada automaticamente na primeira execução em cada diretório escolhido; nas seguintes, apenas o arquivo é adicionado.

---

## Estrutura do projeto

```
IPWhoAll/
├── recon.py        # Script principal
├── run.sh           # Wrapper opcional: cria/ativa venv, roda o script, desativa ao sair
├── README.md        # Este arquivo
├── LICENSE           # Licença MIT
├── .gitignore        # Ignora relatórios gerados, venv e arquivos de ambiente
└── IPWhoAll/         # Criada em tempo de execução, com os relatórios salvos (não versionada)
```

---

## Fontes de dados utilizadas

| Etapa               | Fonte                                                        |
|----------------------|---------------------------------------------------------------|
| Resolução de DNS     | Comando `nslookup` do sistema (fallback: `socket` do Python) |
| Disponibilidade      | `ping` ICMP do sistema + fallback TCP connect                |
| WHOIS                 | Biblioteca `python-whois`                                     |
| RDAP (domínios .br)  | [rdap.registro.br](https://rdap.registro.br) (API oficial do Registro.br/NIC.br) |
| Dados de CNPJ         | [BrasilAPI](https://brasilapi.com.br) (dados públicos da Receita Federal) |

---

## Roadmap / possíveis melhorias futuras

- [ ] Enriquecimento de IP (ASN, organização, geolocalização, detecção de CDN/WAF).
- [ ] Exportação do relatório também em formato JSON/CSV.
- [ ] Paralelização das checagens quando o domínio resolve para múltiplos IPs.
- [ ] Modo não-interativo (argumentos de linha de comando) para uso em pipelines.

---

## Licença

Distribuído sob a [Licença MIT](LICENSE) — uso livre (incluindo comercial), com atribuição ao criador original.

Copyright (c) 2026 **p1r1l4mp0**

---

## Autor

**IPWhoAll** — Designed for **p1r1l4mp0**
