# IPWhoAll

**Designed for p1r1l4mp0**

Initial reconnaissance automation for authorized pentests. Given an IP or web address, the tool identifies the input type, checks host availability (with ICMP-block evasion), resolves DNS, queries WHOIS/RDAP, and — when the target is Brazilian — automatically extracts and looks up the CNPJ.

---

## ⚠️ Legal and Ethical Notice

This tool must be used **exclusively against assets for which you have explicit testing authorization** (signed pentest contract, agreed scope, bug bounty program, your own lab environment, etc.).

Reconnaissance and scanning of systems without authorization may constitute a crime depending on the jurisdiction. Use of this tool is entirely the responsibility of the person running it.

---

## Features

- **Automatic input detection**: identifies whether the given value is an IP or a domain/URL.
- **Adaptive flow**:
  - Domain → `nslookup` (resolves IPs) → availability check → WHOIS/RDAP → CNPJ.
  - IP → availability check → reverse `nslookup` (PTR) → WHOIS/RDAP → CNPJ.
- **Availability check with ICMP-block evasion**: if `ping` gets no response (common in cloud/corporate environments that block ICMP), automatically falls back to testing a TCP connection on common ports (443, 80, 22, 3389, 21, 25, 8080).
- **IP enrichment**: for every resolved IP, queries [ip-api.com](https://ip-api.com) (free, no API key) for ASN, organization/ISP, geolocation (city/region/country, coordinates, timezone), and hosting/mobile/proxy flags.
- **CDN/WAF detection**: flags likely CDN/WAF providers (Cloudflare, Akamai, Fastly, Amazon CloudFront, Imperva Incapsula, Sucuri, Azure Front Door, and others) two ways — by matching the IP's organization/ASN name, and by sending an HTTP(S) request to the domain/hostname and inspecting response headers (`cf-ray`, `x-amz-cf-id`, `Server`, etc.) for known fingerprints.
- **Full, raw output**: shows the actual output of the system's `ping` and `nslookup`, not a summarized version.
- **WHOIS**: queried via `python-whois`, displaying the full response from the server.
- **Official Registro.br RDAP**: for `.br` domains, queries the structured API (`rdap.registro.br`), far more reliable than traditional WHOIS for extracting the domain holder's CNPJ.
- **Automatic CNPJ extraction**: tries RDAP first; if not found, falls back to regex on the WHOIS text; only asks for manual input as a last resort.
- **CNPJ lookup via BrasilAPI**: returns legal name, registration status, CNAE, partners/officers (QSA), address, tax regime, etc., in a readable format.
- **Report generation**: at the end, asks whether to save everything that was displayed to a `.txt` file, letting you choose the directory (current folder or `~/Documents`) and file name, organized under the `IPWhoAll/` folder.

---

## Requirements

- Python 3.10+
- A system with the `ping` and `nslookup` commands available on the PATH (the tool falls back to pure Python if they aren't installed, but detailed output only appears with the system commands).
- Python libraries:
  - [`python-whois`](https://pypi.org/project/python-whois/)
  - [`requests`](https://pypi.org/project/requests/)

---

## Installation

Environments like Kali Linux use an "externally managed" Python (PEP 668), so it's recommended to isolate dependencies in a virtual environment (venv).

```bash
git clone https://github.com/<your-username>/IPWhoAll.git
cd IPWhoAll

python3 -m venv ~/venvs/pentest
source ~/venvs/pentest/bin/activate
pip install python-whois requests
```

### Alternative: automatic wrapper script

The repository includes `run.sh`, which creates the venv (if it doesn't exist), installs dependencies, activates the environment, runs the tool, and deactivates the venv automatically on exit (including on `Ctrl+C`):

```bash
chmod +x run.sh
./run.sh
```

---

## Usage

```bash
source ~/venvs/pentest/bin/activate   # if not using run.sh
python3 recon.py
```

When run, the tool will prompt:

```
Enter the target's IP or web address (domain/URL):
```

Just type an IP (`192.0.2.10`) or a domain/URL (`example.com`, `https://example.com`).

At the end of the run, it asks:

```
Would you like to save the findings to a file? (y/n):
```

If you answer `y`, you'll choose where to save it:

```
Where would you like to save the report?
  1) Current folder (/home/kali/pentest-tools)
  2) Documents (/home/kali/Documents)
Choose an option (1/2) [default: 1]:
```

And then the file name:

```
File name (press Enter to use the default '<target>_<date>_<time>.txt'):
```

- Type a custom name (the `.txt` extension is added automatically if needed), or
- Press Enter to use the suggested default name.

The full session report is saved to:

```
<chosen directory>/IPWhoAll/<file name>.txt
```

The `IPWhoAll/` folder is created automatically on the first run in each chosen directory; on subsequent runs, only the file is added.

---

## Project Structure

```
IPWhoAll/
├── recon.py        # Main script
├── run.sh           # Optional wrapper: creates/activates the venv, runs the script, deactivates on exit
├── README.md        # This file
├── LICENSE           # MIT License
├── .gitignore        # Ignores generated reports, venv, and environment files
└── IPWhoAll/         # Created at runtime, holds saved reports (not versioned)
```

---

## Data Sources Used

| Step                  | Source                                                        |
|------------------------|-----------------------------------------------------------------|
| DNS resolution         | System `nslookup` command (fallback: Python `socket`)          |
| Availability            | System ICMP `ping` + TCP connect fallback                      |
| IP enrichment (ASN/org/geo) | [ip-api.com](https://ip-api.com) (free, no API key)         |
| CDN/WAF detection       | Organization/ASN name matching + HTTP response header fingerprints |
| WHOIS                    | `python-whois` library                                          |
| RDAP (.br domains)      | [rdap.registro.br](https://rdap.registro.br) (official Registro.br/NIC.br API) |
| CNPJ data                | [BrasilAPI](https://brasilapi.com.br) (public Receita Federal data) |

---

## Roadmap / Possible Future Improvements

- [x] IP enrichment (ASN, organization, geolocation, CDN/WAF detection).
- [ ] Export the report in JSON/CSV format as well.
- [ ] Parallelize availability checks when a domain resolves to multiple IPs.
- [ ] Non-interactive mode (command-line arguments) for use in pipelines.

---

## License

Distributed under the [MIT License](LICENSE) — free use (including commercial), with attribution to the original creator.

Copyright (c) 2026 **p1r1l4mp0**

---

## Author

**IPWhoAll** — Designed for **p1r1l4mp0**
