# Domainfox (Domain Information Extractor)
> v1.0.0

**Domainfox** is a modular domain reconnaissance tool designed to extract detailed information about any domain. It gathers DNS records, IP details, SEO data, snapshots, SSL certificates, subdomains, traceroutes, WAF detection, and WHOIS information — all in one place.

---

## Features

- DNS record enumeration (A, MX, TXT, etc.)
- IP address and host information lookup
- SEO-related metadata extraction
- Historical webpage snapshots fetching
- SSL certificate details retrieval
- Subdomain enumeration
- Traceroute analysis
- Web Application Firewall (WAF) detection
- WHOIS lookup and domain registration details
- Multi-threaded scanning for faster results
- Configurable via JSON file (`conf.json`)
- Output results to JSON file or console

---

## Project Structure

```
domainfox/
├── conf.json           # Configuration file for HTTP headers, ports, timeouts, etc.
├── domainfox.py        # Main executable script and CLI interface
├── README.md           # Project documentation (this file)
├── requirements.txt    # Python dependencies
└── recon/              # Recon modules implementing various scans
    ├── dnsrec.py
    ├── ipinfo.py
    ├── seoinfo.py
    ├── snapshot.py
    ├── sslcert.py
    ├── subdomain.py
    ├── tracert.py
    ├── wafcheck.py
    ├── whois.py
    └── __init__.py
```

---

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/devesmaeili/domainfox.git
cd domainfox
```

2. **Create a virtual environment (optional but recommended):**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python domainfox.py example.com [OPTIONS]
```

---

## Options

| Flag              | Description                      |
| ----------------- | -------------------------------- |
| `--output <file>` | Save results to a JSON file      |
| `--no-dnsrec`     | Disable DNS record fetching      |
| `--no-ipinfo`     | Disable IP info fetching         |
| `--no-seoinfo`    | Disable SEO info fetching        |
| `--no-snapshot`   | Disable snapshot fetching        |
| `--no-sslcert`    | Disable SSL certificate fetching |
| `--no-subdomain`  | Disable subdomain enumeration    |
| `--no-tracert`    | Disable traceroute               |
| `--no-wafcheck`   | Disable WAF checking             |
| `--no-whois`      | Disable WHOIS lookup             |

---

## Example

```bash
python domainfox.py example.com --output results.json --no-wafcheck
```
This command runs all scans except WAF detection and saves the output to results.json.

---

## Configuration

The tool reads options such as HTTP headers, timeouts, and port numbers from conf.json. Customize this file to adjust scanning behavior.

Example excerpt from conf.json:

```json
{
  "HTTP_REQ_HEADERS": {"User-Agent": "Domainfox/1.0"},
  "HTTP_REQ_TIMEOUT": 20,
  "HTTPS": true,
  "TCP_CONN_TIMEOUT": 5,
  "SSL_PORT": 443,
  "WAF_PORT": "80,443",
  "DNS_RTYPES": ["A", "MX", "TXT"],
  "SOCIAL_MEDIA": ["twitter.com", "facebook.com"]
}
```

---

## Dependencies

- Python 3.10+
- nmap (for use in WAF detection)
- Contents of file requirements.txt

---

## License

- Apache-2.0 license

