#!/usr/bin/env python3
"""
IPWhoAll - Designed for p1r1l4mp0
Initial reconnaissance automation for pentesting (authorized use only).

Flow:
  - Prompts for an IP address or web address (domain/URL).
  - If domain: nslookup (resolves IPs) -> ping/availability check -> whois -> (if BR) CNPJ lookup.
  - If IP: ping/availability check -> reverse nslookup -> whois -> (if BR) CNPJ lookup.
  - At the end, offers to save the full report to IPWhoAll/<target>_<timestamp>.txt

IMPORTANT: use only against targets for which you have explicit
testing authorization (signed pentest contract, agreed scope, etc.).
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


def warn_missing_dependencies():
    """Warns early if whois/requests are unavailable (e.g. venv not activated)."""
    missing = []
    if whois is None:
        missing.append("python-whois")
    if requests is None:
        missing.append("requests")
    if missing:
        print("[!] Warning: missing dependenc(y/ies): " + ", ".join(missing))
        print("    If you created a venv, remember to activate it before running the script:")
        print("      source ~/venvs/pentest/bin/activate")
        print("    Then install what's missing: pip install " + " ".join(missing))
        print("    (WHOIS and CNPJ lookups will be unavailable until this is fixed.)\n")


# ----------------------------------------------------------------------
# Input utilities
# ----------------------------------------------------------------------

def normalize_input(value: str) -> str:
    """Strips protocol, path, and port if the user pastes a full URL."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc or value
    # remove residual path/port (e.g. domain.com/something or domain.com:8080)
    value = value.split("/")[0].split(":")[0]
    return value


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _run_command(cmd: list[str], timeout: int = 15):
    """
    Runs a system command and returns (return_code, full_output).
    Returns (None, None) if the command isn't found on the system (e.g.
    nslookup not installed), to allow falling back to Python's standard library.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output
    except FileNotFoundError:
        return None, None
    except subprocess.TimeoutExpired:
        return None, "[!] Timeout exceeded while running the command."


def _print_raw_output(output: str):
    print("-" * 60)
    print(output.strip())
    print("-" * 60)


# ----------------------------------------------------------------------
# NSLOOKUP
# ----------------------------------------------------------------------

def nslookup_domain(domain: str) -> list[str]:
    """Resolves a domain to a list of IPs (A/AAAA), showing the full,
    original output of the system's nslookup command."""
    print(f"\n[*] Running nslookup for {domain} ...")
    code, output = _run_command(["nslookup", domain])

    if code is None and output is None:
        print("    [!] 'nslookup' command not found on this system. "
              "Falling back to Python (socket) resolution.")
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = sorted({info[4][0] for info in infos})
            for ip in ips:
                print(f"    -> {ip}")
            return ips
        except socket.gaierror as e:
            print(f"    [!] Failed to resolve {domain}: {e}")
            return []

    _print_raw_output(output)

    # Extract IPs from the answer section, ignoring the DNS server line
    # (which comes in the format "Address: x.x.x.x#53")
    ips = []
    for line in output.splitlines():
        if "#" in line:
            continue
        m = re.search(r"Address:\s*([0-9a-fA-F.:]+)", line)
        if m:
            ips.append(m.group(1))
    return sorted(set(ips))


def reverse_nslookup(ip: str) -> str | None:
    """Attempts to resolve the PTR (hostname) of an IP, showing the full
    output of the system's nslookup command."""
    print(f"\n[*] Running reverse nslookup for {ip} ...")
    code, output = _run_command(["nslookup", ip])

    if code is None and output is None:
        print("    [!] 'nslookup' command not found on this system. "
              "Falling back to Python (socket) resolution.")
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            print(f"    -> {name}")
            return name
        except socket.herror:
            print("    [!] No PTR record found.")
            return None

    _print_raw_output(output)

    m = re.search(r"name\s*=\s*([^\s]+?)\.?\s*$", output, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else None


# ----------------------------------------------------------------------
# AVAILABILITY (ping with TCP fallback to evade firewall/ICMP blocking)
# ----------------------------------------------------------------------

def icmp_ping(ip: str, attempts: int = 2, timeout_s: int = 2) -> bool:
    """Native OS ICMP ping (Windows/Linux), showing the full output."""
    flag_count = "-n" if sys.platform.startswith("win") else "-c"
    flag_timeout = "-w" if sys.platform.startswith("win") else "-W"
    timeout_val = str(timeout_s * 1000) if sys.platform.startswith("win") else str(timeout_s)

    cmd = ["ping", flag_count, str(attempts), flag_timeout, timeout_val, ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            _print_raw_output(output)
        return result.returncode == 0
    except FileNotFoundError:
        print("    [!] 'ping' command not found on this system.")
        return False
    except subprocess.TimeoutExpired:
        print("    [!] Timeout exceeded while running ping.")
        return False


def check_tcp(ip: str, ports: list[int] = None, timeout_s: float = 2.0) -> int | None:
    """Fallback: attempts to connect via TCP on common ports (evades ICMP
    blocking). Shows the result of each port attempt."""
    if ports is None:
        ports = [443, 80, 22, 3389, 21, 25, 8080]
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                print(f"    -> TCP port {port}: OPEN (host responds)")
                return port
        except socket.timeout:
            print(f"    -> TCP port {port}: no response (timeout)")
        except ConnectionRefusedError:
            print(f"    -> TCP port {port}: closed (connection refused)")
        except OSError as e:
            print(f"    -> TCP port {port}: error ({e})")
    return None


def check_availability(ip: str) -> bool:
    print(f"\n[*] Checking availability of {ip} ...")
    if icmp_ping(ip):
        print("    -> Host responded to ICMP ping (online).")
        return True

    print("    [!] No ICMP response (possible firewall blocking).")
    print("    [*] Trying TCP connect fallback on common ports...")
    open_port = check_tcp(ip)
    if open_port:
        print(f"    -> Host responded on TCP port {open_port} (online, ICMP blocked).")
        return True

    print("    [!] No response via ICMP or TCP on the tested ports.")
    return False


# ----------------------------------------------------------------------
# WHOIS
# ----------------------------------------------------------------------

def run_whois(target: str):
    print(f"\n[*] Running whois for {target} ...")
    if whois is None:
        print("    [!] 'python-whois' library not installed. Run: pip install python-whois")
        return None
    try:
        data = whois.whois(target)

        # Prefer the raw text (full, original response from the WHOIS server)
        raw_text = getattr(data, "text", None)
        print("-" * 60)
        if raw_text:
            print(raw_text.strip())
        else:
            # Fallback: some parsers don't expose .text; dump all available fields
            fields = data.keys() if hasattr(data, "keys") else vars(data).keys()
            for field in fields:
                value = data.get(field) if hasattr(data, "get") else getattr(data, field, None)
                if value:
                    print(f"{field}: {value}")
        print("-" * 60)

        return data
    except Exception as e:
        print(f"    [!] Failed to query whois: {e}")
        return None


def looks_like_brazilian_company(target: str, whois_data) -> bool:
    if target.endswith(".br"):
        return True
    if whois_data is None:
        return False
    text = str(whois_data).lower()
    return "brazil" in text or " br\n" in text or "country: br" in text or ".br" in text


def format_cnpj(digits: str) -> str:
    return f"{digits[0:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:14]}"


def _vcard_get(vcard_array, field: str) -> str | None:
    """Extracts a field (e.g. 'fn', 'email') from an RDAP-format vcardArray."""
    if not vcard_array or len(vcard_array) < 2:
        return None
    for item in vcard_array[1]:
        if len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(v for v in value if v)
            return value or None
    return None


def _format_date(iso_date: str) -> str:
    """Converts '2007-06-28T11:20:03Z' into '06/28/2007 11:20:03'."""
    if not iso_date:
        return iso_date
    try:
        cleaned = iso_date.replace("Z", "")
        date, time = cleaned.split("T")
        year, month, day = date.split("-")
        return f"{month}/{day}/{year} {time}"
    except (ValueError, AttributeError):
        return iso_date


def print_formatted_rdap(data: dict):
    """Displays the Registro.br RDAP response in a readable format,
    preserving all information (no summarizing)."""
    print("-" * 60)
    print(f"Domain: {data.get('ldhName', '-')}")
    print(f"Status: {', '.join(data.get('status', [])) or '-'}")

    events = data.get("events", [])
    if events:
        print("\nDomain events:")
        for ev in events:
            print(f"  - {ev.get('eventAction', '-')}: {_format_date(ev.get('eventDate', '-'))}")

    nameservers = data.get("nameservers", [])
    if nameservers:
        print("\nName servers:")
        for ns in nameservers:
            print(f"  - {ns.get('ldhName', '-')}")

    secure_dns = data.get("secureDNS", {})
    if secure_dns:
        print(f"\nDNSSEC enabled: {'Yes' if secure_dns.get('delegationSigned') else 'No'}")

    entities = data.get("entities", [])
    if entities:
        print("\nEntities related to the domain:")
        for ent in entities:
            name = _vcard_get(ent.get("vcardArray"), "fn") or "-"
            role = ", ".join(ent.get("roles", [])) or "-"
            print(f"\n  [{role.upper()}] {name}")
            print(f"    Handle: {ent.get('handle', '-')}")

            for pid in ent.get("publicIds", []):
                print(f"    {pid.get('type', '-').upper()}: {pid.get('identifier', '-')}")

            email = _vcard_get(ent.get("vcardArray"), "email")
            if email:
                print(f"    Email: {email}")

            for ev in ent.get("events", []):
                print(f"    Event ({ev.get('eventAction', '-')}): {_format_date(ev.get('eventDate', '-'))}")

            # Sub-entities (e.g. administrative/technical contact within the registrant)
            for sub in ent.get("entities", []):
                sub_name = _vcard_get(sub.get("vcardArray"), "fn") or "-"
                sub_role = ", ".join(sub.get("roles", [])) or "-"
                sub_email = _vcard_get(sub.get("vcardArray"), "email")
                print(f"      -> [{sub_role.upper()}] {sub_name}" + (f" ({sub_email})" if sub_email else ""))

    print("-" * 60)


def rdap_registro_br(domain: str) -> str | None:
    """
    Queries the official Registro.br RDAP service (a modern, structured
    replacement for WHOIS on .br domains). Returns JSON data, including the
    CNPJ/CPF of the domain holder in the 'publicIds' field — far more
    reliable than extracting it via regex from free-form text.
    Docs: https://rdap.registro.br
    """
    if requests is None or not domain.endswith(".br"):
        return None

    url = f"https://rdap.registro.br/domain/{domain}"
    print(f"\n[*] Querying the official Registro.br RDAP for {domain} ...")
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            print(f"    [!] RDAP did not return data (status {resp.status_code}).")
            return None
        data = resp.json()

        print_formatted_rdap(data)

        for entity in data.get("entities", []):
            for pid in entity.get("publicIds", []):
                if pid.get("type", "").lower() == "cnpj":
                    digits = re.sub(r"\D", "", pid.get("identifier", ""))
                    if len(digits) == 14:
                        return format_cnpj(digits)
        print("    [!] No CNPJ was found among the entities returned by RDAP.")
        return None
    except (requests.RequestException, ValueError) as e:
        print(f"    [!] Failed to query RDAP: {e}")
        return None


def extract_cnpj(whois_data) -> str | None:
    """
    Fallback: attempts to extract a CNPJ from the raw WHOIS response via
    regex, used only when Registro.br RDAP is unavailable or returned
    nothing (e.g. the domain isn't .br).
    """
    if whois_data is None:
        return None

    text = getattr(whois_data, "text", None) or str(whois_data)

    # 1) Explicit formatted pattern anywhere in the text (most reliable)
    m = re.search(r"\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}", text)
    if m:
        return m.group(0)

    # 2) Lines with labels that usually contain a CNPJ (registro.br: ownerid)
    for line in text.splitlines():
        if re.search(r"ownerid|owner-id|owner id|cnpj", line, re.IGNORECASE):
            digits = re.sub(r"\D", "", line)
            if len(digits) == 14:
                return format_cnpj(digits)

    return None


def print_formatted_cnpj(data: dict):
    """Displays the BrasilAPI (CNPJ) response in a readable format,
    preserving all information (no summarizing)."""
    print("-" * 60)
    print(f"Legal Name: {data.get('razao_social', '-')}")
    if data.get("nome_fantasia"):
        print(f"Trade Name: {data.get('nome_fantasia')}")
    print(f"CNPJ: {format_cnpj(str(data.get('cnpj', '')))}")
    print(f"Registration Status: {data.get('descricao_situacao_cadastral', '-')} "
          f"(since {data.get('data_situacao_cadastral', '-')}, "
          f"reason: {data.get('descricao_motivo_situacao_cadastral', '-')})")
    print(f"Headquarters/Branch: {data.get('descricao_identificador_matriz_filial', '-')}")
    print(f"Business Start Date: {data.get('data_inicio_atividade', '-')}")
    print(f"Legal Nature: {data.get('natureza_juridica', '-')}")
    print(f"Size: {data.get('porte', '-')}")
    print(f"Share Capital: R$ {data.get('capital_social', 0):,}".replace(",", "."))
    print(f"Simples Nacional Opt-in: {'Yes' if data.get('opcao_pelo_simples') else 'No'}"
          + (f" (since {data.get('data_opcao_pelo_simples')})" if data.get('data_opcao_pelo_simples') else ""))
    print(f"MEI Opt-in: {'Yes' if data.get('opcao_pelo_mei') else 'No'}")

    print(f"\nPrimary Activity (CNAE {data.get('cnae_fiscal', '-')}): "
          f"{data.get('cnae_fiscal_descricao', '-')}")

    secondary = data.get("cnaes_secundarios", [])
    if secondary:
        print(f"\nSecondary Activities ({len(secondary)}):")
        for cnae in secondary:
            print(f"  - [{cnae.get('codigo')}] {cnae.get('descricao')}")

    print(f"\nAddress: {data.get('descricao_tipo_de_logradouro', '')} "
          f"{data.get('logradouro', '-')}, {data.get('numero', '-')} "
          f"{data.get('complemento', '')}".rstrip())
    print(f"Neighborhood: {data.get('bairro', '-')}")
    print(f"City/State: {data.get('municipio', '-')}/{data.get('uf', '-')}")
    print(f"ZIP Code: {data.get('cep', '-')}")

    phones = [t for t in [data.get('ddd_telefone_1'), data.get('ddd_telefone_2')] if t]
    print(f"Phone(s): {', '.join(phones) if phones else '-'}")
    print(f"Email: {data.get('email') or '-'}")

    tax_regimes = data.get("regime_tributario", [])
    if tax_regimes:
        print(f"\nTax Regime:")
        for r in tax_regimes:
            print(f"  - {r.get('ano')}: {r.get('forma_de_tributacao')} "
                  f"({r.get('quantidade_de_escrituracoes')} filing(s))")

    partners = data.get("qsa", [])
    if partners:
        print(f"\nPartners/Officers (QSA) ({len(partners)}):")
        for partner in partners:
            print(f"  - {partner.get('nome_socio', '-')} | {partner.get('qualificacao_socio', '-')} "
                  f"| joined: {partner.get('data_entrada_sociedade', '-')} "
                  f"| age range: {partner.get('faixa_etaria', '-')}")

    print("-" * 60)


def lookup_cnpj(cnpj: str):
    print(f"\n[*] Looking up CNPJ {cnpj} on BrasilAPI ...")
    if requests is None:
        print("    [!] 'requests' library not installed. Run: pip install requests")
        return
    clean_cnpj = re.sub(r"\D", "", cnpj)
    url = f"https://brasilapi.com.br/api/cnpj/v1/{clean_cnpj}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            print_formatted_cnpj(data)
        else:
            print(f"    [!] CNPJ not found or invalid (status {resp.status_code}).")
    except requests.RequestException as e:
        print(f"    [!] Error querying BrasilAPI: {e}")


# ----------------------------------------------------------------------
# OUTPUT CAPTURE AND REPORT SAVING
# ----------------------------------------------------------------------

class Tee:
    """Mirrors everything printed simultaneously to the terminal and to
    an in-memory buffer, allowing the full session report to be saved to
    a file at the end without altering any existing print() calls."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)

    def flush(self):
        for s in self.streams:
            s.flush()


def choose_base_directory() -> str:
    """Asks the user where the IPWhoAll folder should be created.
    Detects whether ~/Documents exists to offer it as an option."""
    current_dir = os.getcwd()
    documents = os.path.expanduser("~/Documents")
    documents_exists = os.path.isdir(documents)

    print("\nWhere would you like to save the report?")
    print(f"  1) Current folder ({current_dir})")
    if documents_exists:
        print(f"  2) Documents ({documents})")
    else:
        print(f"  2) Documents ({documents}) [not found, will be created if chosen]")

    choice = input("Choose an option (1/2) [default: 1]: ").strip()
    return documents if choice == "2" else current_dir


def choose_file_name(target: str) -> str:
    """Asks the user for the report file name.
    If left blank, uses a default name based on the target + timestamp."""
    sanitized_target = re.sub(r'[<>:"/\\|?*]', "_", target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"{sanitized_target}_{timestamp}"

    typed_name = input(
        f"\nFile name (press Enter to use the default '{default_name}.txt'): "
    ).strip()

    if not typed_name:
        final_name = default_name
    else:
        final_name = re.sub(r'[<>:"/\\|?*]', "_", typed_name)

    if not final_name.lower().endswith(".txt"):
        final_name += ".txt"

    return final_name


def save_report(content: str, file_name: str, base_directory: str = None) -> str:
    """Creates (if needed) the IPWhoAll folder inside the chosen base
    directory and saves the recon report under the given file name."""
    if base_directory is None:
        base_directory = os.getcwd()

    folder = os.path.join(base_directory, "IPWhoAll")
    if not os.path.isdir(folder):
        os.makedirs(folder)
        print(f"[+] Folder '{folder}' created.")
    else:
        print(f"[i] Folder '{folder}' already exists. Creating the file only.")

    path = os.path.join(folder, file_name)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    absolute_path = os.path.abspath(path)
    print(f"[+] Report saved to: {absolute_path}")
    return absolute_path


# ----------------------------------------------------------------------
# MAIN FLOW
# ----------------------------------------------------------------------

def main():
    original_stdout = sys.stdout
    buffer = io.StringIO()
    sys.stdout = Tee(original_stdout, buffer)

    try:
        print("=" * 60)
        print(" IPWhoAll")
        print(" Designed for p1r1l4mp0")
        print(" Initial Reconnaissance Automation - Pentest")
        print(" (restricted to targets with formal testing authorization)")
        print("=" * 60)

        warn_missing_dependencies()

        raw_input_value = input("\nEnter the target's IP or web address (domain/URL): ").strip()
        if not raw_input_value:
            print("Empty input. Exiting.")
            return

        target = normalize_input(raw_input_value)
        whois_data = None
        resolved_domain = None  # used for RDAP lookup (registro.br)

        if is_ip(target):
            print(f"\n[+] Input identified as an IP: {target}")
            online = check_availability(target)
            resolved_domain = reverse_nslookup(target)  # PTR, if it exists
            whois_target = target
        else:
            print(f"\n[+] Input identified as a web address (domain): {target}")
            ips = nslookup_domain(target)
            if ips:
                for ip in ips:
                    check_availability(ip)
            else:
                print("    [!] Could not resolve any IPs; skipping availability check.")
            whois_target = target  # domain whois tends to be more informative than IP whois
            resolved_domain = target

        # From here on, the flow is unified for IP and domain
        whois_data = run_whois(whois_target)

        if looks_like_brazilian_company(whois_target, whois_data):
            print("\n[+] Signs of a Brazilian company/domain (.br) detected.")

            extracted_cnpj = None
            if resolved_domain and resolved_domain.endswith(".br"):
                extracted_cnpj = rdap_registro_br(resolved_domain)

            if not extracted_cnpj:
                extracted_cnpj = extract_cnpj(whois_data)
                if extracted_cnpj:
                    print(f"[+] CNPJ extracted from WHOIS text: {extracted_cnpj}")

            if extracted_cnpj:
                lookup_cnpj(extracted_cnpj)
            else:
                print("[i] Could not automatically extract a CNPJ (neither via RDAP nor WHOIS).")
                answer = input("Enter the CNPJ manually (or press Enter to skip): ").strip()
                if answer:
                    lookup_cnpj(answer)
        else:
            print("\n[i] No clear signs of a Brazilian company found via whois/domain.")

        print("\n[\u2713] Reconnaissance complete.")

        save_answer = input(
            "\nWould you like to save the findings to a file? (y/n): "
        ).strip().lower()
        if save_answer.startswith("y"):
            chosen_directory = choose_base_directory()
            chosen_file_name = choose_file_name(target)
            save_report(buffer.getvalue(), chosen_file_name, chosen_directory)
        else:
            print("[i] Report not saved.")

    finally:
        sys.stdout = original_stdout


if __name__ == "__main__":
    main()
