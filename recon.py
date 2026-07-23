#!/usr/bin/env python3
"""
IPWhoAll - Designed for p1r1l4mp0
Initial reconnaissance automation for pentesting (authorized use only).

Flow:
  - Prompts for an IP address or web address (domain/URL).
  - If domain: nslookup (resolves IPs) -> parallel availability checks -> IP
    enrichment -> CDN/WAF detection -> whois -> (if BR) CNPJ lookup.
  - If IP: availability check -> IP enrichment -> reverse nslookup ->
    CDN/WAF detection -> whois -> (if BR) CNPJ lookup.
  - At the end, offers to save the full report as .txt (raw session log),
    .json (structured data), and/or .csv (tabular per-IP summary), under
    IPWhoAll/<name>.<ext>.

IMPORTANT: use only against targets for which you have explicit
testing authorization (signed pentest contract, agreed scope, etc.).
"""

import concurrent.futures
import csv
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
#
# These functions deliberately avoid calling print() directly and instead
# return their findings as data (or as pre-formatted log lines). That's
# what makes it safe to run them concurrently for multiple IPs: each
# thread builds its own isolated block of output, which the main thread
# prints afterward, in order, so the report never gets garbled by
# interleaved output from different threads.
# ----------------------------------------------------------------------

def icmp_ping(ip: str, attempts: int = 2, timeout_s: int = 2) -> tuple[bool, str]:
    """Native OS ICMP ping (Windows/Linux). Returns (success, raw_output)."""
    flag_count = "-n" if sys.platform.startswith("win") else "-c"
    flag_timeout = "-w" if sys.platform.startswith("win") else "-W"
    timeout_val = str(timeout_s * 1000) if sys.platform.startswith("win") else str(timeout_s)

    cmd = ["ping", flag_count, str(attempts), flag_timeout, timeout_val, ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output
    except FileNotFoundError:
        return False, "[!] 'ping' command not found on this system."
    except subprocess.TimeoutExpired:
        return False, "[!] Timeout exceeded while running ping."


def check_tcp(ip: str, ports: list[int] = None, timeout_s: float = 2.0) -> tuple[int | None, list[str]]:
    """Fallback: attempts to connect via TCP on common ports (evades ICMP
    blocking). Returns (open_port_or_None, log_lines) for each port tried."""
    if ports is None:
        ports = [443, 80, 22, 3389, 21, 25, 8080]
    lines = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout_s):
                lines.append(f"    -> TCP port {port}: OPEN (host responds)")
                return port, lines
        except socket.timeout:
            lines.append(f"    -> TCP port {port}: no response (timeout)")
        except ConnectionRefusedError:
            lines.append(f"    -> TCP port {port}: closed (connection refused)")
        except OSError as e:
            lines.append(f"    -> TCP port {port}: error ({e})")
    return None, lines


def check_availability(ip: str) -> tuple[bool, str | None, list[str]]:
    """Checks whether a host is online: tries ICMP ping first, then falls
    back to a TCP connect scan on common ports if ICMP gets no response.
    Returns (available, method, log_lines) — method is "icmp", "tcp:<port>",
    or None. Safe to call from multiple threads at once."""
    log = [f"\n[*] Checking availability of {ip} ..."]

    success, ping_output = icmp_ping(ip)
    if ping_output.strip():
        log.append("-" * 60)
        log.append(ping_output.strip())
        log.append("-" * 60)

    if success:
        log.append("    -> Host responded to ICMP ping (online).")
        return True, "icmp", log

    log.append("    [!] No ICMP response (possible firewall blocking).")
    log.append("    [*] Trying TCP connect fallback on common ports...")
    open_port, tcp_lines = check_tcp(ip)
    log.extend(tcp_lines)

    if open_port:
        log.append(f"    -> Host responded on TCP port {open_port} (online, ICMP blocked).")
        return True, f"tcp:{open_port}", log

    log.append("    [!] No response via ICMP or TCP on the tested ports.")
    return False, None, log


def check_availability_parallel(ips: list[str], max_workers: int = 8) -> dict[str, tuple[bool, str | None, list[str]]]:
    """Runs check_availability() for multiple IPs concurrently using a
    thread pool (availability checks are I/O-bound: waiting on ping/TCP
    timeouts, not CPU), which is much faster than checking IPs one by one
    when a domain resolves to several addresses. Returns a dict keyed by
    IP; the caller is responsible for printing the log_lines in a
    consistent order once every check has finished."""
    results = {}
    if not ips:
        return results

    workers = max(1, min(max_workers, len(ips)))
    print(f"\n[*] Checking availability of {len(ips)} IP(s) in parallel ({workers} workers) ...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(check_availability, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                results[ip] = (False, None, [f"\n[*] Checking availability of {ip} ...",
                                              f"    [!] Unexpected error during check: {e}"])
    return results


# ----------------------------------------------------------------------
# IP ENRICHMENT (ASN, organization, geolocation, CDN/WAF detection)
# ----------------------------------------------------------------------

# Keywords found in org/ISP/ASN names that indicate a known CDN or WAF
# provider is fronting the target.
KNOWN_CDN_WAF_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "cloudfront": "Amazon CloudFront",
    "amazon.com": "Amazon (AWS)",
    "amazon technologies": "Amazon (AWS)",
    "imperva": "Imperva Incapsula",
    "incapsula": "Imperva Incapsula",
    "sucuri": "Sucuri",
    "stackpath": "StackPath",
    "highwinds": "StackPath (Highwinds)",
    "google cloud": "Google Cloud CDN",
    "googleusercontent": "Google Cloud CDN",
    "microsoft azure": "Azure CDN/Front Door",
    "azure": "Azure CDN/Front Door",
    "edgecast": "Edgecast (Verizon Media)",
    "limelight": "Limelight Networks",
    "keycdn": "KeyCDN",
    "cachefly": "CacheFly",
    "cdn77": "CDN77",
    "quic.cloud": "QUIC.cloud",
}

# HTTP response headers that reveal a specific CDN/WAF provider.
CDN_WAF_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-amz-cf-pop": "Amazon CloudFront",
    "x-akamai-transformed": "Akamai",
    "akamai-origin-hop": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-iinfo": "Imperva Incapsula",
    "x-cdn": "Generic CDN",
    "x-served-by": "Fastly",
    "x-fastly-request-id": "Fastly",
    "x-azure-ref": "Azure Front Door/CDN",
    "x-msedge-ref": "Azure Front Door",
}

# Substrings looked for in the "Server" header.
CDN_WAF_SERVER_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "cloudfront": "Amazon CloudFront",
    "akamaighost": "Akamai",
    "sucuri/cloudproxy": "Sucuri",
    "awselb": "AWS Elastic Load Balancer",
    "awss3": "Amazon S3",
}


def detect_cdn_waf_from_org(*texts: str) -> list[str]:
    """Matches org/ISP/ASN name text against a list of known CDN/WAF
    provider keywords."""
    combined = " ".join(t for t in texts if t).lower()
    found = []
    for keyword, provider in KNOWN_CDN_WAF_PROVIDERS.items():
        if keyword in combined and provider not in found:
            found.append(provider)
    return found


def enrich_ip(ip: str) -> dict | None:
    """Queries ip-api.com (free, no API key required) for ASN, organization,
    ISP, and geolocation data about an IP, and flags likely CDN/WAF providers
    based on the organization name."""
    print(f"\n[*] Running IP enrichment (ASN/org/geolocation) for {ip} ...")
    if requests is None:
        print("    [!] 'requests' library not installed. Run: pip install requests")
        return None

    fields = ("status,message,continent,country,countryCode,region,regionName,"
              "city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,"
              "mobile,proxy,hosting,query")
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if data.get("status") != "success":
            print(f"    [!] IP enrichment failed: {data.get('message', 'unknown error')}")
            return None
        print_ip_enrichment(data)
        return data
    except (requests.RequestException, ValueError) as e:
        print(f"    [!] Failed to query IP enrichment: {e}")
        return None


def print_ip_enrichment(data: dict):
    """Displays IP enrichment data (ASN, org, geolocation, hosting type)
    in a readable format."""
    print("-" * 60)
    print(f"IP: {data.get('query', '-')}")
    asn = data.get("as", "-")
    asname = data.get("asname")
    print(f"ASN: {asn}" + (f" ({asname})" if asname else ""))
    print(f"Organization: {data.get('org', '-') or '-'}")
    print(f"ISP: {data.get('isp', '-')}")

    location_parts = [p for p in [data.get("city"), data.get("regionName"), data.get("country")] if p]
    print(f"Location: {', '.join(location_parts) if location_parts else '-'}")
    if data.get("zip"):
        print(f"ZIP/Postal Code: {data.get('zip')}")
    if data.get("lat") is not None and data.get("lon") is not None:
        print(f"Coordinates: {data.get('lat')}, {data.get('lon')}")
    print(f"Timezone: {data.get('timezone', '-')}")

    print(f"Hosting/Datacenter IP: {'Yes' if data.get('hosting') else 'No'}")
    print(f"Mobile Network: {'Yes' if data.get('mobile') else 'No'}")
    print(f"Known Proxy/VPN: {'Yes' if data.get('proxy') else 'No'}")

    cdn_waf = detect_cdn_waf_from_org(data.get("org", ""), data.get("asname", ""), data.get("isp", ""))
    if cdn_waf:
        print(f"CDN/WAF (by organization): {', '.join(cdn_waf)}")
    print("-" * 60)


def detect_cdn_waf_from_headers(hostname: str) -> list[str]:
    """Sends an HTTP(S) request to the given hostname and inspects the
    response headers for known CDN/WAF fingerprints (Cloudflare, Akamai,
    CloudFront, Incapsula, Sucuri, Fastly, Azure Front Door, etc.)."""
    if requests is None:
        return []

    print(f"\n[*] Checking HTTP headers of {hostname} for CDN/WAF fingerprints ...")
    found = []
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{hostname}", timeout=6, allow_redirects=True)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header_name, provider in CDN_WAF_HEADER_SIGNATURES.items():
                if header_name in headers_lower and provider not in found:
                    found.append(provider)

            server = headers_lower.get("server", "").lower()
            for signature, provider in CDN_WAF_SERVER_SIGNATURES.items():
                if signature in server and provider not in found:
                    found.append(provider)

            if found:
                print(f"    -> CDN/WAF fingerprint(s) found via {scheme.upper()}: {', '.join(found)}")
            else:
                print(f"    -> No known CDN/WAF fingerprints found in {scheme.upper()} headers.")
            break  # one successful request is enough
        except requests.RequestException as e:
            print(f"    [!] Could not connect via {scheme.upper()}: {e}")
            continue

    return found


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


def get_whois_raw_text(whois_data) -> str | None:
    """Returns the raw WHOIS response text, if available, for use in exports."""
    if whois_data is None:
        return None
    return getattr(whois_data, "text", None) or str(whois_data)


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


def _find_cnpj_in_entity(entity: dict) -> str | None:
    """Looks for a CNPJ (14-digit taxpayer ID) inside a single RDAP entity.

    Registro.br exposes the registrant's CNPJ/CPF in two possible places
    depending on the domain: the 'publicIds' array (type == 'cnpj'), or
    directly as the entity's 'handle' (a bare 14-digit string for CNPJ,
    or 11 digits for an individual's CPF). Both are checked here."""
    for pid in entity.get("publicIds", []):
        if pid.get("type", "").lower() == "cnpj":
            digits = re.sub(r"\D", "", pid.get("identifier", ""))
            if len(digits) == 14:
                return format_cnpj(digits)

    handle_digits = re.sub(r"\D", "", entity.get("handle", "") or "")
    if len(handle_digits) == 14:
        return format_cnpj(handle_digits)

    return None


def rdap_registro_br(domain: str) -> tuple[str | None, dict | None]:
    """
    Queries the official Registro.br RDAP service (a modern, structured
    replacement for WHOIS on .br domains). Returns a tuple of
    (cnpj_or_None, raw_rdap_json_or_None). The CNPJ/CPF of the domain
    holder can come either from the 'publicIds' field or from the
    registrant entity's 'handle' — far more reliable than extracting it
    via regex from free-form text.
    Docs: https://rdap.registro.br
    """
    if requests is None or not domain.endswith(".br"):
        return None, None

    url = f"https://rdap.registro.br/domain/{domain}"
    print(f"\n[*] Querying the official Registro.br RDAP for {domain} ...")
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            print(f"    [!] RDAP did not return data (status {resp.status_code}).")
            return None, None
        data = resp.json()

        print_formatted_rdap(data)

        entities = data.get("entities", [])
        cnpj_found = None

        # First pass: prioritize the entity with the "registrant" role.
        for entity in entities:
            if "registrant" in [r.lower() for r in entity.get("roles", [])]:
                cnpj_found = _find_cnpj_in_entity(entity)
                if cnpj_found:
                    break

        # Second pass: fall back to any entity (including nested sub-entities).
        if not cnpj_found:
            for entity in entities:
                cnpj_found = _find_cnpj_in_entity(entity)
                if cnpj_found:
                    break
                for sub_entity in entity.get("entities", []):
                    cnpj_found = _find_cnpj_in_entity(sub_entity)
                    if cnpj_found:
                        break
                if cnpj_found:
                    break

        if not cnpj_found:
            print("    [!] No CNPJ was found among the entities returned by RDAP.")

        return cnpj_found, data
    except (requests.RequestException, ValueError) as e:
        print(f"    [!] Failed to query RDAP: {e}")
        return None, None


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


def lookup_cnpj(cnpj: str) -> dict | None:
    """Looks up a CNPJ on BrasilAPI and returns the parsed JSON data
    (or None on failure), so it can also be included in JSON exports."""
    print(f"\n[*] Looking up CNPJ {cnpj} on BrasilAPI ...")
    if requests is None:
        print("    [!] 'requests' library not installed. Run: pip install requests")
        return None
    clean_cnpj = re.sub(r"\D", "", cnpj)
    url = f"https://brasilapi.com.br/api/cnpj/v1/{clean_cnpj}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            print_formatted_cnpj(data)
            return data
        else:
            print(f"    [!] CNPJ not found or invalid (status {resp.status_code}).")
            return None
    except requests.RequestException as e:
        print(f"    [!] Error querying BrasilAPI: {e}")
        return None


# ----------------------------------------------------------------------
# OUTPUT CAPTURE AND REPORT EXPORT (TXT / JSON / CSV)
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


def choose_file_base_name(target: str) -> str:
    """Asks the user for the report's base file name (without extension —
    the correct extension is added automatically per exported format).
    If left blank, uses a default name based on the target + timestamp."""
    sanitized_target = re.sub(r'[<>:"/\\|?*]', "_", target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"{sanitized_target}_{timestamp}"

    typed_name = input(
        f"\nFile name, without extension (press Enter to use the default '{default_name}'): "
    ).strip()

    if not typed_name:
        return default_name

    base_name = re.sub(r'[<>:"/\\|?*]', "_", typed_name)
    # Strip a known extension if the user typed one anyway.
    for ext in (".txt", ".json", ".csv"):
        if base_name.lower().endswith(ext):
            base_name = base_name[: -len(ext)]
            break
    return base_name


def choose_export_formats() -> list[str]:
    """Asks which format(s) the report should be saved in."""
    print("\nWhich format(s) would you like to save the report in?")
    print("  1) Text (.txt)  - full raw session log, exactly as shown on screen")
    print("  2) JSON (.json) - structured data (all findings, machine-readable)")
    print("  3) CSV (.csv)   - tabular summary, one row per resolved IP")
    print("  4) All of the above")

    choice = input("Choose one or more, comma-separated (e.g. 1,3) [default: 1]: ").strip()
    if not choice:
        return ["txt"]
    if choice == "4":
        return ["txt", "json", "csv"]

    mapping = {"1": "txt", "2": "json", "3": "csv"}
    selected = []
    for part in choice.split(","):
        fmt = mapping.get(part.strip())
        if fmt and fmt not in selected:
            selected.append(fmt)
    return selected or ["txt"]


def build_json_content(session: dict) -> str:
    """Serializes the structured session data collected during the run
    into an indented, human- and machine-readable JSON document."""
    return json.dumps(session, indent=2, ensure_ascii=False, default=str)


def build_csv_content(session: dict) -> str:
    """Builds a tabular CSV summary of the session: one row per resolved
    IP, combining its availability/enrichment data with the target-level
    findings (WHOIS-derived Brazilian-company flag, CNPJ, etc.)."""
    fieldnames = [
        "target", "input_type", "ip", "available", "availability_method",
        "asn", "organization", "isp", "city", "region", "country", "zip",
        "latitude", "longitude", "timezone", "hosting", "mobile", "proxy",
        "cdn_waf_by_org", "reverse_dns", "cdn_waf_by_headers",
        "is_brazilian_company", "cnpj",
    ]

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()

    resolved_ips = session.get("resolved_ips") or [{}]
    for entry in resolved_ips:
        enrichment = entry.get("enrichment") or {}
        cdn_by_org = detect_cdn_waf_from_org(
            enrichment.get("org", ""), enrichment.get("asname", ""), enrichment.get("isp", "")
        ) if enrichment else []

        writer.writerow({
            "target": session.get("target"),
            "input_type": session.get("input_type"),
            "ip": entry.get("ip"),
            "available": entry.get("available"),
            "availability_method": entry.get("availability_method"),
            "asn": enrichment.get("as"),
            "organization": enrichment.get("org"),
            "isp": enrichment.get("isp"),
            "city": enrichment.get("city"),
            "region": enrichment.get("regionName"),
            "country": enrichment.get("country"),
            "zip": enrichment.get("zip"),
            "latitude": enrichment.get("lat"),
            "longitude": enrichment.get("lon"),
            "timezone": enrichment.get("timezone"),
            "hosting": enrichment.get("hosting"),
            "mobile": enrichment.get("mobile"),
            "proxy": enrichment.get("proxy"),
            "cdn_waf_by_org": ", ".join(cdn_by_org),
            "reverse_dns": session.get("reverse_dns"),
            "cdn_waf_by_headers": ", ".join(session.get("cdn_waf_headers") or []),
            "is_brazilian_company": session.get("is_brazilian_company"),
            "cnpj": session.get("cnpj"),
        })

    return buffer.getvalue()


def save_report(content: str, file_name: str, base_directory: str = None) -> str:
    """Creates (if needed) the IPWhoAll folder inside the chosen base
    directory and saves the given content under the given file name.
    Works for any text-based format (.txt, .json, .csv)."""
    if base_directory is None:
        base_directory = os.getcwd()

    folder = os.path.join(base_directory, "IPWhoAll")
    if not os.path.isdir(folder):
        os.makedirs(folder)
        print(f"[+] Folder '{folder}' created.")
    else:
        print(f"[i] Folder '{folder}' already exists. Creating the file only.")

    path = os.path.join(folder, file_name)

    with open(path, "w", encoding="utf-8", newline="") as f:
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

        # Structured data collected throughout the run, used for the
        # JSON/CSV exports at the end.
        session = {
            "target": target,
            "input_type": None,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "resolved_ips": [],
            "reverse_dns": None,
            "cdn_waf_headers": [],
            "whois_raw_text": None,
            "is_brazilian_company": False,
            "rdap": None,
            "cnpj": None,
            "cnpj_data": None,
        }

        if is_ip(target):
            print(f"\n[+] Input identified as an IP: {target}")
            session["input_type"] = "ip"

            available, method, log_lines = check_availability(target)
            for line in log_lines:
                print(line)

            enrichment = enrich_ip(target)
            session["resolved_ips"].append({
                "ip": target, "available": available,
                "availability_method": method, "enrichment": enrichment,
            })

            resolved_domain = reverse_nslookup(target)  # PTR, if it exists
            session["reverse_dns"] = resolved_domain
            if resolved_domain:
                session["cdn_waf_headers"] = detect_cdn_waf_from_headers(resolved_domain)
            whois_target = target
        else:
            print(f"\n[+] Input identified as a web address (domain): {target}")
            session["input_type"] = "domain"

            ips = nslookup_domain(target)
            if ips:
                # Availability checks run in parallel (I/O-bound: ping/TCP
                # timeouts), then results are printed sequentially in the
                # original resolution order so the report stays readable.
                availability_results = check_availability_parallel(ips)
                for ip in ips:
                    available, method, log_lines = availability_results.get(
                        ip, (False, None, [f"\n[*] Checking availability of {ip} ...",
                                            "    [!] No result returned for this IP."])
                    )
                    for line in log_lines:
                        print(line)

                    enrichment = enrich_ip(ip)
                    session["resolved_ips"].append({
                        "ip": ip, "available": available,
                        "availability_method": method, "enrichment": enrichment,
                    })
            else:
                print("    [!] Could not resolve any IPs; skipping availability check.")

            session["cdn_waf_headers"] = detect_cdn_waf_from_headers(target)
            whois_target = target  # domain whois tends to be more informative than IP whois
            resolved_domain = target

        # From here on, the flow is unified for IP and domain
        whois_data = run_whois(whois_target)
        session["whois_raw_text"] = get_whois_raw_text(whois_data)

        is_brazilian = looks_like_brazilian_company(whois_target, whois_data)
        session["is_brazilian_company"] = is_brazilian

        if is_brazilian:
            print("\n[+] Signs of a Brazilian company/domain (.br) detected.")

            extracted_cnpj = None
            if resolved_domain and resolved_domain.endswith(".br"):
                extracted_cnpj, rdap_data = rdap_registro_br(resolved_domain)
                session["rdap"] = rdap_data

            if not extracted_cnpj:
                extracted_cnpj = extract_cnpj(whois_data)
                if extracted_cnpj:
                    print(f"[+] CNPJ extracted from WHOIS text: {extracted_cnpj}")

            if extracted_cnpj:
                session["cnpj"] = extracted_cnpj
                session["cnpj_data"] = lookup_cnpj(extracted_cnpj)
            else:
                print("[i] Could not automatically extract a CNPJ (neither via RDAP nor WHOIS).")
                answer = input("Enter the CNPJ manually (or press Enter to skip): ").strip()
                if answer:
                    session["cnpj"] = answer
                    session["cnpj_data"] = lookup_cnpj(answer)
        else:
            print("\n[i] No clear signs of a Brazilian company found via whois/domain.")

        print("\n[\u2713] Reconnaissance complete.")

        save_answer = input(
            "\nWould you like to save the findings to a file? (y/n): "
        ).strip().lower()
        if save_answer.startswith("y"):
            chosen_directory = choose_base_directory()
            base_name = choose_file_base_name(target)
            formats = choose_export_formats()

            if "txt" in formats:
                save_report(buffer.getvalue(), f"{base_name}.txt", chosen_directory)
            if "json" in formats:
                save_report(build_json_content(session), f"{base_name}.json", chosen_directory)
            if "csv" in formats:
                save_report(build_csv_content(session), f"{base_name}.csv", chosen_directory)
        else:
            print("[i] Report not saved.")

    finally:
        sys.stdout = original_stdout


if __name__ == "__main__":
    main()
