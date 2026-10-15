# WHOIS & DNS CLI Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-Compatible-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

A lightweight command-line reconnaissance tool for WHOIS lookups, DNS record analysis, reverse DNS queries, and bulk domain processing.

Built with Python, it provides concurrent processing, an in-memory cache, structured JSON output, and a simple CLI interface.

## Features

- **WHOIS Lookup** — Retrieve registration information for domains and supported IP targets.
- **Bulk WHOIS** — Process multiple targets concurrently from a text file.
- **DNS Lookup** — Query A, AAAA, MX, NS, TXT, CNAME, and SOA records.
- **Reverse DNS** — Retrieve PTR records for IP addresses.
- **Concurrent Processing** — Use a configurable worker pool for bulk lookups.
- **In-Memory Cache** — Cache successful WHOIS results for 10 minutes.
- **Timeout Configuration** — Configure DNS and WHOIS lookup timeout settings.
- **JSON Export** — Save results in structured JSON format.
- **Input Validation** — Normalize domains and validate target formats.
- **CLI Arguments** — Run queries directly without using the interactive menu.

## Requirements

- Python 3.9 or newer
- pip
- Internet connectivity for external WHOIS and DNS queries

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install python-whois dnspython
```

## Usage

### Interactive mode

```bash
python3 main.py
```

Available menu options:

```text
1) WHOIS lookup
2) Bulk WHOIS lookup
3) DNS lookup
4) Reverse DNS lookup
5) Clear cache
6) Exit
```

### WHOIS lookup

Query a single domain:

```bash
python3 main.py --whois example.com
```

### DNS lookup

Retrieve supported DNS records:

```bash
python3 main.py --dns example.com
```

Save the results to a JSON file:

```bash
python3 main.py --dns example.com --output dns.json
```

### Reverse DNS lookup

Query the PTR record associated with an IP address:

```bash
python3 main.py --ptr 8.8.8.8
```

### Bulk WHOIS lookup

Create a file named `targets.txt`:

```text
example.com
google.com
github.com
```

Run the bulk lookup:

```bash
python3 main.py --file targets.txt
```

Set the number of workers and export the results:

```bash
python3 main.py --file targets.txt --workers 5 --output results.json
```

### Configure timeout

```bash
python3 main.py --whois example.com --timeout 15
```

The timeout value must be between 1 and 120 seconds. Actual WHOIS query duration may exceed the configured timeout because the underlying WHOIS operation cannot always be forcibly interrupted.

### Version information

```bash
python3 main.py --version
```

## Command-Line Options

| Option | Description |
|---|---|
| `--whois TARGET` | Perform a WHOIS lookup |
| `--dns DOMAIN` | Query DNS records |
| `--ptr IP_ADDRESS` | Perform a reverse DNS lookup |
| `--file PATH` | Process targets from a file |
| `--workers NUMBER` | Set concurrent workers for bulk lookups |
| `--timeout SECONDS` | Set the configured lookup timeout |
| `--output PATH` | Export results to JSON |
| `--version` | Display the program version |
| `--help` | Display available arguments |

Choose only one operation per command.

## Example JSON Output

A DNS query returns structured data similar to the following:

```json
{
  "target": "example.com",
  "success": true,
  "records": {
    "A": ["93.184.216.34"],
    "AAAA": [],
    "MX": [],
    "NS": [],
    "TXT": [],
    "CNAME": [],
    "SOA": []
  },
  "errors": {},
  "queried_at": "2026-01-01T12:00:00+00:00"
}
```

Actual records depend on the queried domain and its DNS configuration. The values above are illustrative.

## Project Structure

```text
.
├── main.py
├── README.md
├── targets.txt
└── .gitignore
```

## Technical Details

| Component | Details |
|---|---|
| Language | Python |
| WHOIS library | `python-whois` |
| DNS library | `dnspython` |
| Cache | In-memory, TTL-based |
| Default cache TTL | 10 minutes |
| Default timeout | 10 seconds |
| Default workers | 5 |
| Maximum workers | 20 |
| Output format | JSON |

## Limitations

- WHOIS data availability and formatting depend on the registry and WHOIS server.
- Some domains or DNS records may return no results.
- DNS responses depend on resolver configuration and network connectivity.
- WHOIS servers may rate-limit repeated requests.
- The configured WHOIS timeout is not a guaranteed hard execution limit.
- Cached results may not reflect recent registration or DNS changes.

## Roadmap

- [ ] Retry handling with exponential backoff
- [ ] Additional output formats, including plain text and CSV
- [ ] Configurable DNS resolver
- [ ] Persistent cache storage
- [ ] Improved WHOIS parsing into structured fields
- [ ] Automated tests and continuous integration
- [ ] More detailed logging and error reporting

## Responsible Use

This project is intended for educational purposes, authorized security assessments, and legitimate network reconnaissance.

Only query systems and information you are authorized to investigate. Respect service terms, rate limits, and applicable laws.

The user is responsible for how the tool is used.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

**Built for learning, reconnaissance, and practical Python development.**
