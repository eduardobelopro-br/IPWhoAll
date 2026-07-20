#!/usr/bin/env python3
"""
IPWhoAll - Designed for p1r1l4mp0
Automação de reconhecimento inicial para pentest (uso autorizado apenas).

Fluxo:
  - Solicita IP ou endereço web (domínio/URL).
  - Se for domínio: nslookup (resolve IPs) -> ping/checagem de disponibilidade -> whois -> (se BR) CNPJ.
  - Se for IP: ping/checagem de disponibilidade -> nslookup reverso -> whois -> (se BR) CNPJ.
  - Ao final, oferece salvar o relatório completo em IPWhoAll/<alvo>_<timestamp>.txt

IMPORTANTE: use apenas em alvos para os quais você possua autorização
explícita de teste (contrato de pentest, escopo assinado, etc.).
"""

import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    import whois  # python-whois
except ImportError:
    whois = None

try:
    import requests
except ImportError:
    requests = None


def avisar_dependencias_faltando():
    """Alerta cedo se whois/requests não estão disponíveis (ex: venv não ativado)."""
    faltando = []
    if whois is None:
        faltando.append("python-whois")
    if requests is None:
        faltando.append("requests")
    if faltando:
        print("[!] Aviso: dependência(s) não encontrada(s): " + ", ".join(faltando))
        print("    Se você criou um venv, lembre-se de ativá-lo antes de rodar o script:")
        print("      source ~/venvs/pentest/bin/activate")
        print("    Depois instale o que faltar: pip install " + " ".join(faltando))
        print("    (Whois e CNPJ ficarão indisponíveis até isso ser resolvido.)\n")


# ----------------------------------------------------------------------
# Utilidades de entrada
# ----------------------------------------------------------------------

def normalizar_entrada(valor: str) -> str:
    """Remove protocolo, caminho e porta se o usuário colar uma URL completa."""
    valor = valor.strip()
    if "://" in valor:
        valor = urlparse(valor).netloc or valor
    # remove path/porta residual (ex: dominio.com/algo ou dominio.com:8080)
    valor = valor.split("/")[0].split(":")[0]
    return valor


def eh_ip(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def _executar_comando(cmd: list[str], timeout: int = 15):
    """
    Roda um comando do sistema e retorna (codigo_retorno, saida_completa).
    Retorna (None, None) se o comando não existir no sistema (ex: nslookup
    não instalado), para permitir fallback via biblioteca padrão do Python.
    """
    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        saida = (resultado.stdout or "") + (resultado.stderr or "")
        return resultado.returncode, saida
    except FileNotFoundError:
        return None, None
    except subprocess.TimeoutExpired:
        return None, "[!] Tempo limite excedido ao executar o comando."


def _imprimir_saida_bruta(saida: str):
    print("-" * 60)
    print(saida.strip())
    print("-" * 60)


# ----------------------------------------------------------------------
# NSLOOKUP
# ----------------------------------------------------------------------

def nslookup_dominio(dominio: str) -> list[str]:
    """Resolve um domínio para uma lista de IPs (A/AAAA), mostrando a saída
    completa e original do comando nslookup do sistema."""
    print(f"\n[*] Executando nslookup para {dominio} ...")
    codigo, saida = _executar_comando(["nslookup", dominio])

    if codigo is None and saida is None:
        print("    [!] Comando 'nslookup' não encontrado no sistema. "
              "Usando resolução via Python (socket) como alternativa.")
        try:
            infos = socket.getaddrinfo(dominio, None)
            ips = sorted({info[4][0] for info in infos})
            for ip in ips:
                print(f"    -> {ip}")
            return ips
        except socket.gaierror as e:
            print(f"    [!] Falha ao resolver {dominio}: {e}")
            return []

    _imprimir_saida_bruta(saida)

    # Extrai os IPs da seção de resposta, ignorando a linha do servidor DNS
    # (que vem no formato "Address: x.x.x.x#53")
    ips = []
    for linha in saida.splitlines():
        if "#" in linha:
            continue
        m = re.search(r"Address:\s*([0-9a-fA-F.:]+)", linha)
        if m:
            ips.append(m.group(1))
    return sorted(set(ips))


def nslookup_reverso(ip: str) -> str | None:
    """Tenta resolver o PTR (nome) de um IP, mostrando a saída completa
    do comando nslookup do sistema."""
    print(f"\n[*] Executando nslookup reverso para {ip} ...")
    codigo, saida = _executar_comando(["nslookup", ip])

    if codigo is None and saida is None:
        print("    [!] Comando 'nslookup' não encontrado no sistema. "
              "Usando resolução via Python (socket) como alternativa.")
        try:
            nome, _, _ = socket.gethostbyaddr(ip)
            print(f"    -> {nome}")
            return nome
        except socket.herror:
            print("    [!] Nenhum registro PTR encontrado.")
            return None

    _imprimir_saida_bruta(saida)

    m = re.search(r"name\s*=\s*([^\s]+?)\.?\s*$", saida, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else None


# ----------------------------------------------------------------------
# DISPONIBILIDADE (ping com fallback TCP para evadir bloqueio de ICMP)
# ----------------------------------------------------------------------

def ping_icmp(ip: str, tentativas: int = 2, timeout_s: int = 2) -> bool:
    """Ping ICMP nativo do SO (Windows/Linux), mostrando a saída completa."""
    flag_count = "-n" if sys.platform.startswith("win") else "-c"
    flag_timeout = "-w" if sys.platform.startswith("win") else "-W"
    timeout_val = str(timeout_s * 1000) if sys.platform.startswith("win") else str(timeout_s)

    cmd = ["ping", flag_count, str(tentativas), flag_timeout, timeout_val, ip]
    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        saida = (resultado.stdout or "") + (resultado.stderr or "")
        if saida.strip():
            _imprimir_saida_bruta(saida)
        return resultado.returncode == 0
    except FileNotFoundError:
        print("    [!] Comando 'ping' não encontrado no sistema.")
        return False
    except subprocess.TimeoutExpired:
        print("    [!] Tempo limite excedido ao executar o ping.")
        return False


def checar_tcp(ip: str, portas: list[int] = None, timeout_s: float = 2.0) -> int | None:
    """Fallback: tenta conectar via TCP em portas comuns (evade bloqueio de ICMP).
    Mostra o resultado de cada tentativa de porta."""
    if portas is None:
        portas = [443, 80, 22, 3389, 21, 25, 8080]
    for porta in portas:
        try:
            with socket.create_connection((ip, porta), timeout=timeout_s):
                print(f"    -> Porta TCP {porta}: ABERTA (host responde)")
                return porta
        except socket.timeout:
            print(f"    -> Porta TCP {porta}: sem resposta (timeout)")
        except ConnectionRefusedError:
            print(f"    -> Porta TCP {porta}: fechada (conexão recusada)")
        except OSError as e:
            print(f"    -> Porta TCP {porta}: erro ({e})")
    return None


def verificar_disponibilidade(ip: str) -> bool:
    print(f"\n[*] Verificando disponibilidade de {ip} ...")
    if ping_icmp(ip):
        print("    -> Host respondeu ao ping ICMP (online).")
        return True

    print("    [!] Sem resposta ICMP (possível bloqueio de firewall).")
    print("    [*] Tentando fallback via TCP connect em portas comuns...")
    porta_aberta = checar_tcp(ip)
    if porta_aberta:
        print(f"    -> Host respondeu na porta TCP {porta_aberta} (online, ICMP bloqueado).")
        return True

    print("    [!] Nenhuma resposta via ICMP ou TCP nas portas testadas.")
    return False


# ----------------------------------------------------------------------
# WHOIS
# ----------------------------------------------------------------------

def executar_whois(alvo: str):
    print(f"\n[*] Executando whois para {alvo} ...")
    if whois is None:
        print("    [!] Biblioteca 'python-whois' não instalada. Rode: pip install python-whois")
        return None
    try:
        dados = whois.whois(alvo)

        # Preferimos o texto bruto (retorno completo e original do servidor WHOIS)
        texto_bruto = getattr(dados, "text", None)
        print("-" * 60)
        if texto_bruto:
            print(texto_bruto.strip())
        else:
            # Fallback: alguns parsers não expõem .text; despeja todos os campos disponíveis
            campos = dados.keys() if hasattr(dados, "keys") else vars(dados).keys()
            for campo in campos:
                valor = dados.get(campo) if hasattr(dados, "get") else getattr(dados, campo, None)
                if valor:
                    print(f"{campo}: {valor}")
        print("-" * 60)

        return dados
    except Exception as e:
        print(f"    [!] Falha ao consultar whois: {e}")
        return None


def parece_empresa_brasileira(alvo: str, dados_whois) -> bool:
    if alvo.endswith(".br"):
        return True
    if dados_whois is None:
        return False
    texto = str(dados_whois).lower()
    return "brazil" in texto or " br\n" in texto or "country: br" in texto or ".br" in texto


def formatar_cnpj(digitos: str) -> str:
    return f"{digitos[0:2]}.{digitos[2:5]}.{digitos[5:8]}/{digitos[8:12]}-{digitos[12:14]}"


def _vcard_get(vcard_array, campo: str) -> str | None:
    """Extrai um campo (ex: 'fn', 'email') de um vcardArray no formato RDAP."""
    if not vcard_array or len(vcard_array) < 2:
        return None
    for item in vcard_array[1]:
        if len(item) >= 4 and item[0] == campo:
            valor = item[3]
            if isinstance(valor, list):
                valor = " ".join(v for v in valor if v)
            return valor or None
    return None


def _formatar_data(data_iso: str) -> str:
    """Converte '2007-06-28T11:20:03Z' em '28/06/2007 11:20:03'."""
    if not data_iso:
        return data_iso
    try:
        limpo = data_iso.replace("Z", "")
        data, hora = limpo.split("T")
        ano, mes, dia = data.split("-")
        return f"{dia}/{mes}/{ano} {hora}"
    except (ValueError, AttributeError):
        return data_iso


def imprimir_rdap_formatado(dados: dict):
    """Exibe o retorno do RDAP do Registro.br em formato legível,
    preservando todas as informações (sem resumir)."""
    print("-" * 60)
    print(f"Domínio: {dados.get('ldhName', '-')}")
    print(f"Status: {', '.join(dados.get('status', [])) or '-'}")

    eventos = dados.get("events", [])
    if eventos:
        print("\nEventos do domínio:")
        for ev in eventos:
            print(f"  - {ev.get('eventAction', '-')}: {_formatar_data(ev.get('eventDate', '-'))}")

    nameservers = dados.get("nameservers", [])
    if nameservers:
        print("\nServidores DNS (nameservers):")
        for ns in nameservers:
            print(f"  - {ns.get('ldhName', '-')}")

    secure_dns = dados.get("secureDNS", {})
    if secure_dns:
        print(f"\nDNSSEC habilitado: {'Sim' if secure_dns.get('delegationSigned') else 'Não'}")

    entidades = dados.get("entities", [])
    if entidades:
        print("\nEntidades relacionadas ao domínio:")
        for ent in entidades:
            nome = _vcard_get(ent.get("vcardArray"), "fn") or "-"
            papel = ", ".join(ent.get("roles", [])) or "-"
            print(f"\n  [{papel.upper()}] {nome}")
            print(f"    Handle: {ent.get('handle', '-')}")

            for pid in ent.get("publicIds", []):
                print(f"    {pid.get('type', '-').upper()}: {pid.get('identifier', '-')}")

            email = _vcard_get(ent.get("vcardArray"), "email")
            if email:
                print(f"    E-mail: {email}")

            for ev in ent.get("events", []):
                print(f"    Evento ({ev.get('eventAction', '-')}): {_formatar_data(ev.get('eventDate', '-'))}")

            # Sub-entidades (ex: contato administrativo/técnico dentro do registrante)
            for sub in ent.get("entities", []):
                sub_nome = _vcard_get(sub.get("vcardArray"), "fn") or "-"
                sub_papel = ", ".join(sub.get("roles", [])) or "-"
                sub_email = _vcard_get(sub.get("vcardArray"), "email")
                print(f"      -> [{sub_papel.upper()}] {sub_nome}" + (f" ({sub_email})" if sub_email else ""))

    print("-" * 60)


def rdap_registro_br(dominio: str) -> str | None:
    """
    Consulta o RDAP oficial do Registro.br (substituto moderno e estruturado
    do WHOIS para domínios .br). Retorna dados em JSON, incluindo o CNPJ/CPF
    do titular do domínio no campo 'publicIds' — muito mais confiável do
    que extrair via regex de texto livre.
    Doc: https://rdap.registro.br
    """
    if requests is None or not dominio.endswith(".br"):
        return None

    url = f"https://rdap.registro.br/domain/{dominio}"
    print(f"\n[*] Consultando RDAP oficial do Registro.br para {dominio} ...")
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            print(f"    [!] RDAP não retornou dados (status {resp.status_code}).")
            return None
        dados = resp.json()

        imprimir_rdap_formatado(dados)

        for entidade in dados.get("entities", []):
            for pid in entidade.get("publicIds", []):
                if pid.get("type", "").lower() == "cnpj":
                    digitos = re.sub(r"\D", "", pid.get("identifier", ""))
                    if len(digitos) == 14:
                        return formatar_cnpj(digitos)
        print("    [!] Nenhum CNPJ foi encontrado nas entidades retornadas pelo RDAP.")
        return None
    except (requests.RequestException, ValueError) as e:
        print(f"    [!] Falha ao consultar RDAP: {e}")
        return None


def extrair_cnpj(dados_whois) -> str | None:
    """
    Fallback: tenta extrair um CNPJ do retorno bruto do WHOIS via regex,
    usado apenas quando o RDAP do Registro.br não está disponível ou
    não retornou resultado (ex: domínio não é .br).
    """
    if dados_whois is None:
        return None

    texto = getattr(dados_whois, "text", None) or str(dados_whois)

    # 1) Padrão formatado explícito em qualquer lugar do texto (mais confiável)
    m = re.search(r"\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}", texto)
    if m:
        return m.group(0)

    # 2) Linhas com rótulos que costumam conter CNPJ (registro.br: ownerid)
    for linha in texto.splitlines():
        if re.search(r"ownerid|owner-id|owner id|cnpj", linha, re.IGNORECASE):
            digitos = re.sub(r"\D", "", linha)
            if len(digitos) == 14:
                return formatar_cnpj(digitos)

    return None


def imprimir_cnpj_formatado(dados: dict):
    """Exibe o retorno da BrasilAPI (CNPJ) em formato legível,
    preservando todas as informações (sem resumir)."""
    print("-" * 60)
    print(f"Razão Social: {dados.get('razao_social', '-')}")
    if dados.get("nome_fantasia"):
        print(f"Nome Fantasia: {dados.get('nome_fantasia')}")
    print(f"CNPJ: {formatar_cnpj(str(dados.get('cnpj', '')))}")
    print(f"Situação Cadastral: {dados.get('descricao_situacao_cadastral', '-')} "
          f"(desde {dados.get('data_situacao_cadastral', '-')}, "
          f"motivo: {dados.get('descricao_motivo_situacao_cadastral', '-')})")
    print(f"Matriz/Filial: {dados.get('descricao_identificador_matriz_filial', '-')}")
    print(f"Data de Início de Atividade: {dados.get('data_inicio_atividade', '-')}")
    print(f"Natureza Jurídica: {dados.get('natureza_juridica', '-')}")
    print(f"Porte: {dados.get('porte', '-')}")
    print(f"Capital Social: R$ {dados.get('capital_social', 0):,}".replace(",", "."))
    print(f"Opção pelo Simples: {'Sim' if dados.get('opcao_pelo_simples') else 'Não'}"
          + (f" (desde {dados.get('data_opcao_pelo_simples')})" if dados.get('data_opcao_pelo_simples') else ""))
    print(f"Opção pelo MEI: {'Sim' if dados.get('opcao_pelo_mei') else 'Não'}")

    print(f"\nAtividade Principal (CNAE {dados.get('cnae_fiscal', '-')}): "
          f"{dados.get('cnae_fiscal_descricao', '-')}")

    secundarios = dados.get("cnaes_secundarios", [])
    if secundarios:
        print(f"\nAtividades Secundárias ({len(secundarios)}):")
        for cnae in secundarios:
            print(f"  - [{cnae.get('codigo')}] {cnae.get('descricao')}")

    print(f"\nEndereço: {dados.get('descricao_tipo_de_logradouro', '')} "
          f"{dados.get('logradouro', '-')}, {dados.get('numero', '-')} "
          f"{dados.get('complemento', '')}".rstrip())
    print(f"Bairro: {dados.get('bairro', '-')}")
    print(f"Município/UF: {dados.get('municipio', '-')}/{dados.get('uf', '-')}")
    print(f"CEP: {dados.get('cep', '-')}")

    telefones = [t for t in [dados.get('ddd_telefone_1'), dados.get('ddd_telefone_2')] if t]
    print(f"Telefone(s): {', '.join(telefones) if telefones else '-'}")
    print(f"E-mail: {dados.get('email') or '-'}")

    regimes = dados.get("regime_tributario", [])
    if regimes:
        print(f"\nRegime Tributário:")
        for r in regimes:
            print(f"  - {r.get('ano')}: {r.get('forma_de_tributacao')} "
                  f"({r.get('quantidade_de_escrituracoes')} escrituração(ões))")

    qsa = dados.get("qsa", [])
    if qsa:
        print(f"\nQuadro de Sócios e Administradores (QSA) ({len(qsa)}):")
        for socio in qsa:
            print(f"  - {socio.get('nome_socio', '-')} | {socio.get('qualificacao_socio', '-')} "
                  f"| entrada: {socio.get('data_entrada_sociedade', '-')} "
                  f"| faixa etária: {socio.get('faixa_etaria', '-')}")

    print("-" * 60)


def buscar_cnpj(cnpj: str):
    print(f"\n[*] Consultando CNPJ {cnpj} na BrasilAPI ...")
    if requests is None:
        print("    [!] Biblioteca 'requests' não instalada. Rode: pip install requests")
        return
    cnpj_limpo = re.sub(r"\D", "", cnpj)
    url = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj_limpo}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            dados = resp.json()
            imprimir_cnpj_formatado(dados)
        else:
            print(f"    [!] CNPJ não encontrado ou inválido (status {resp.status_code}).")
    except requests.RequestException as e:
        print(f"    [!] Erro ao consultar BrasilAPI: {e}")


# ----------------------------------------------------------------------
# CAPTURA DE SAÍDA E SALVAMENTO DE RELATÓRIO
# ----------------------------------------------------------------------

class Tee:
    """Espelha tudo que é impresso simultaneamente para o terminal e
    para um buffer em memória, permitindo salvar o relatório completo
    da sessão em arquivo ao final, sem alterar nenhum print() existente."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)

    def flush(self):
        for s in self.streams:
            s.flush()


def escolher_diretorio_base() -> str:
    """Pergunta ao usuário onde a pasta IPWhoAll deve ser criada.
    Detecta se ~/Documents existe para oferecê-lo como opção."""
    diretorio_atual = os.getcwd()
    documents = os.path.expanduser("~/Documents")
    documents_existe = os.path.isdir(documents)

    print("\nOnde deseja salvar o relatório?")
    print(f"  1) Pasta atual ({diretorio_atual})")
    if documents_existe:
        print(f"  2) Documents ({documents})")
    else:
        print(f"  2) Documents ({documents}) [não encontrado, será criado se escolhido]")

    escolha = input("Escolha uma opção (1/2) [padrão: 1]: ").strip()
    return documents if escolha == "2" else diretorio_atual


def escolher_nome_arquivo(alvo: str) -> str:
    """Pergunta ao usuário o nome do arquivo de relatório.
    Se deixado em branco, usa um nome padrão baseado no alvo + timestamp."""
    alvo_sanitizado = re.sub(r'[<>:"/\\|?*]', "_", alvo)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_padrao = f"{alvo_sanitizado}_{timestamp}"

    nome_digitado = input(
        f"\nNome do arquivo (Enter para usar o padrão '{nome_padrao}.txt'): "
    ).strip()

    if not nome_digitado:
        nome_final = nome_padrao
    else:
        nome_final = re.sub(r'[<>:"/\\|?*]', "_", nome_digitado)

    if not nome_final.lower().endswith(".txt"):
        nome_final += ".txt"

    return nome_final


def salvar_relatorio(conteudo: str, nome_arquivo: str, diretorio_base: str = None) -> str:
    """Cria (se necessário) a pasta IPWhoAll dentro do diretório base
    escolhido e salva o relatório da pesquisa com o nome de arquivo informado."""
    if diretorio_base is None:
        diretorio_base = os.getcwd()

    pasta = os.path.join(diretorio_base, "IPWhoAll")
    if not os.path.isdir(pasta):
        os.makedirs(pasta)
        print(f"[+] Pasta '{pasta}' criada.")
    else:
        print(f"[i] Pasta '{pasta}' já existe. Criando apenas o arquivo.")

    caminho = os.path.join(pasta, nome_arquivo)

    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)

    caminho_absoluto = os.path.abspath(caminho)
    print(f"[+] Relatório salvo em: {caminho_absoluto}")
    return caminho_absoluto


# ----------------------------------------------------------------------
# FLUXO PRINCIPAL
# ----------------------------------------------------------------------

def main():
    saida_original = sys.stdout
    buffer = io.StringIO()
    sys.stdout = Tee(saida_original, buffer)

    try:
        print("=" * 60)
        print(" IPWhoAll")
        print(" Designed for p1r1l4mp0")
        print(" Automação de Reconhecimento Inicial - Pentest")
        print(" (uso restrito a alvos com autorização formal de teste)")
        print("=" * 60)

        avisar_dependencias_faltando()

        entrada_bruta = input("\nInforme o IP ou endereço web (domínio/URL) do alvo: ").strip()
        if not entrada_bruta:
            print("Entrada vazia. Encerrando.")
            return

        alvo = normalizar_entrada(entrada_bruta)
        dados_whois = None
        dominio_disponivel = None  # usado para consulta RDAP (registro.br)

        if eh_ip(alvo):
            print(f"\n[+] Entrada identificada como IP: {alvo}")
            online = verificar_disponibilidade(alvo)
            dominio_disponivel = nslookup_reverso(alvo)  # PTR, se existir
            alvo_whois = alvo
        else:
            print(f"\n[+] Entrada identificada como endereço web (domínio): {alvo}")
            ips = nslookup_dominio(alvo)
            if ips:
                for ip in ips:
                    verificar_disponibilidade(ip)
            else:
                print("    [!] Não foi possível resolver IPs; pulando checagem de disponibilidade.")
            alvo_whois = alvo  # whois de domínio costuma ser mais informativo que de IP
            dominio_disponivel = alvo

        # A partir daqui o fluxo é unificado para IP e domínio
        dados_whois = executar_whois(alvo_whois)

        if parece_empresa_brasileira(alvo_whois, dados_whois):
            print("\n[+] Indícios de empresa/domínio brasileiro (.br) detectados.")

            cnpj_extraido = None
            if dominio_disponivel and dominio_disponivel.endswith(".br"):
                cnpj_extraido = rdap_registro_br(dominio_disponivel)

            if not cnpj_extraido:
                cnpj_extraido = extrair_cnpj(dados_whois)
                if cnpj_extraido:
                    print(f"[+] CNPJ extraído do texto do WHOIS: {cnpj_extraido}")

            if cnpj_extraido:
                buscar_cnpj(cnpj_extraido)
            else:
                print("[i] Não foi possível extrair um CNPJ automaticamente (nem via RDAP, nem via WHOIS).")
                resposta = input("Informe o CNPJ manualmente (ou Enter para pular): ").strip()
                if resposta:
                    buscar_cnpj(resposta)
        else:
            print("\n[i] Não foram encontrados indícios claros de empresa brasileira via whois/domínio.")

        print("\n[✓] Reconhecimento concluído.")

        resposta_salvar = input(
            "\nDeseja salvar os dados encontrados em um arquivo? (s/n): "
        ).strip().lower()
        if resposta_salvar.startswith("s"):
            diretorio_escolhido = escolher_diretorio_base()
            nome_arquivo_escolhido = escolher_nome_arquivo(alvo)
            salvar_relatorio(buffer.getvalue(), nome_arquivo_escolhido, diretorio_escolhido)
        else:
            print("[i] Relatório não salvo.")

    finally:
        sys.stdout = saida_original


if __name__ == "__main__":
    main()
