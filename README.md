# JSFinder

**JSFinder** is a fast, safe, and modular domain attack-surface discovery CLI tool engineered for authorized bug-bounty hunters, red teams, and penetration testers. It identifies subdomains, live hosts, JavaScript files, source maps, hidden API endpoints, and other static web resources while enforcing strict scope boundaries and robust per-host rate limiting.

---

## Key Capabilities

- **Strict Scope Enforcement**: Centralized scope validation engine ensures zero requests are made to out-of-scope hosts, including intercepting and aborting redirect chains before contacting foreign origins (e.g. preventing SSRF/phishing traps or accidental scanning of un-scoped third parties).
- **Passive-First Subdomain Discovery**: Integrates Certificate Transparency (crt.sh) logs, HTML page crawling, and JavaScript code mining, with optional active DNS wordlist enumeration (`--active-subdomains`).
- **HTTP/HTTPS Probing**: Safely probes discovered hosts to record status codes, final URLs after redirects, server headers, page titles, content types, and response times.
- **Resource Extraction & Chunk Identification**: Discovers `.js`, `.js.map`, `.css`, `.json`, `.xml`, `.txt`, `.yaml`, and identifies framework chunks (Webpack, Next.js, Vite, Nuxt).
- **Deep JavaScript Static Analysis**: Extracts absolute URLs, relative paths, API routes (`/api/...`, `/v1/...`, `/graphql`), URL query parameters, referenced subdomains, and source map directives (`sourceMappingURL=`), tracking full provenance for each finding.
- **Source Map Detection**: Identifies source maps via directives and conventional `.map` probes, safely checking status and size without exposing raw source code in the terminal unless requested (`--download-sourcemaps`).
- **Per-Host Token Bucket Rate Limiter**: Independent rate limiter buckets per hostname (e.g. `example.com`, `api.example.com`, `cdn.example.com`), respecting `Retry-After`, handling HTTP `429` responses with bounded exponential backoff, and enforcing global concurrency limits.
- **Automatic Multi-Target Directory Output**: Automatically creates `jsresult/<domain>/` containing full structured JSON and individual CSV reports (`endpoints.csv`, `resources.csv`, `hosts.csv`, `subdomains.csv`, `source_maps.csv`). Different target domains are organized neatly side-by-side in the same `jsresult/` parent directory.
- **Comprehensive Output Formats**: Supports structured JSON, tabular CSV, dedicated multi-file directory reports (`--output-dir`), and formatted terminal dashboards.

---

## Architecture

JSFinder is structured into clean, decoupled Python modules:

```text
jsfinder/
├── cli.py            # CLI argument parsing, banner, logging configuration
├── crawler.py        # Asynchronous crawl coordinator, depth & page manager
├── subdomains.py     # Passive CT log discovery, DNS resolver, HTTP host prober
├── http.py           # Safe async HTTP client with scope & redirect interceptors
├── scope.py          # Centralized ScopeManager and ScopeRule matcher
├── ratelimit.py      # Per-host token bucket rate limiter & 429 backoff engine
├── parser.py         # HTML parser, URL normalizer, resource classifier
├── js_analyzer.py    # JavaScript AST/regex scanner, endpoint & parameter extractor
├── models.py         # Dataclass models for findings, probes, and results
├── output.py         # Terminal reporting, JSON export, and CSV writer
└── tests/            # Full test suite (scope, rate limits, parser, mock server)
```

---

## Installation & Quick Start

### Prerequisites

- Python 3.11 or higher
- `pip` package manager
- `git`

### 1. Clone the Repository

```bash
git clone https://github.com/tejassroot/jsfinder.git
cd jsfinder
pip install -r requirements.txt
```

### 2. Install Globally to `/usr/local/bin` (Recommended)

Link `jsfinder` directly to `/usr/local/bin` so it can be executed from any terminal directory:

```bash
chmod +x jsfinder.py
sudo ln -sf "$(pwd)/jsfinder.py" /usr/local/bin/jsfinder
```

*Alternatively, install via pip:*

```bash
pip install .
```

### 3. Verify Installation

```bash
jsfinder --help
# or: python jsfinder.py --help
```

---

## Usage Guide

### Core Command

Scan a single target URL or domain (using either the global `jsfinder` command or `python jsfinder.py`):

```bash
jsfinder -u https://example.com
# or
python jsfinder.py -u https://example.com
```

> **Automatic File Saving**: Scan results are automatically saved into `jsresult/<domain>/` containing `results.json`, `endpoints.csv`, `resources.csv`, `subdomains.csv`, `hosts.csv`, and `source_maps.csv`. Scanning multiple domains organizes them neatly side-by-side inside the same `jsresult/` parent directory!

### Passive & Active Subdomain Enumeration

Discover subdomains passively using Certificate Transparency (crt.sh) and inline scripts:

```bash
python jsfinder.py -u https://example.com --subdomains
```

Enable active DNS enumeration using a wordlist:

```bash
python jsfinder.py -u https://example.com --subdomains --active-subdomains
```

Optionally provide a custom wordlist:

```bash
python jsfinder.py -u https://example.com --active-subdomains --wordlist subdomains.txt
```

### Rate Limiting & Concurrency Control

Maintain conservative traffic profiles to comply with engagement Rules of Engagement (RoE):

```bash
python jsfinder.py -u https://example.com \
  --rate 2 \
  --concurrency 3 \
  --delay 0.5 \
  --jitter
```

- `--rate 2`: Limits requests to 2 requests/sec per individual hostname.
- `--concurrency 3`: Ensures at most 3 simultaneous active connections across all hosts.
- `--delay 0.5`: Minimum 500ms delay between consecutive requests to the same host.
- `--jitter`: Introduces randomized micro-delays to prevent mechanical patterns.

### Defining Custom Scope

By default, JSFinder scopes scans to the target host and its subdomains (`example.com` and `*.example.com`).

To specify an explicit scope file:

```bash
python jsfinder.py -u https://example.com --scope scope.txt
```

**Example `scope.txt`:**

```text
# Exact domain match
example.com

# Wildcard subdomains
*.example.com
*.api.example.com

# Internal IP subnets
10.0.0.0/8
192.168.1.0/24
```

> **Security Guarantee**: Domains such as `evil-example.com`, `example.com.attacker.com`, or external CDNs will be strictly blocked unless explicitly listed in your scope.

### Output Management & Automatic Saving

#### Automatic `jsresult/<domain>/` Directory (Default)

By default, every scan automatically creates a structured output folder under `jsresult/<domain>/`. When you scan multiple domains, they are all neatly organized side-by-side inside the same `jsresult/` parent directory:

```bash
jsfinder -u https://pescheck.io/
# Automatically creates and saves to: jsresult/pescheck.io/

jsfinder -u https://example.com/
# Automatically creates and saves to: jsresult/example.com/
```

Each domain directory contains:
* `results.json` — Complete scan metadata, timestamps, and full discovery records
* `endpoints.csv` — Discovered API & relative routes with source provenance and parameters
* `resources.csv` — Clean list of all discovered JavaScript (`.js`) file URLs
* `subdomains.csv` — Discovered and probed subdomains with IP addresses and status
* `hosts.csv` — Probed live hosts with response status, page titles, and server headers
* `source_maps.csv` — Discovered source maps and probe status codes
* `urls.txt` — Clean deduplicated list of all discovered URLs (one per line, ready for piping)
* `sourcemaps/` — Downloaded `.map` files (when `--download-sourcemaps` is enabled)

#### Print Only Discovered URLs (`--urls-only`)

Print only clean discovered URLs to stdout (one per line, ideal for piping into `httpx`, `nuclei`, `gf`, or `curl`):

```bash
jsfinder -u https://example.com --urls-only
```

Pipe directly into `httpx` or other reconnaissance tools:
```bash
jsfinder -u https://example.com --urls-only | httpx -status-code -title
```

#### Custom Output Directory

Override the default `jsresult/<domain>/` directory with a custom path:

```bash
jsfinder -u https://example.com --output-dir ./audit_results
```

#### Disable Automatic File Saving

If you only want terminal output without writing files to disk, pass `--no-save`:

```bash
jsfinder -u https://example.com --no-save
```

#### Dedicated JSON or CSV Exports

```bash
# Export single JSON file
jsfinder -u https://example.com --json results.json

# Export single endpoints CSV file
jsfinder -u https://example.com --csv endpoints.csv
```

#### Downloading Discovered Source Maps

Safely download discovered `.js.map` files to disk under the output directory:

```bash
jsfinder -u https://example.com --download-sourcemaps
```

---

## CLI Reference Options

| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-u, --url` | `URL` | Target URL or domain to scan (**Required**) | — |
| `--urls-only` | — | Print only discovered URLs to stdout (ideal for piping) | `False` |
| `--scope` | `FILE` | Path to scope file with domains, wildcards, or CIDRs | Default target scope |
| `--subdomains` | — | Enable passive subdomain discovery (crt.sh, HTML/JS extraction) | `False` |
| `--active-subdomains` | — | Enable active DNS subdomain enumeration | `False` |
| `--wordlist` | `FILE` | Custom wordlist for active DNS enumeration | Built-in top words |
| `--rate` | `FLOAT` | Maximum requests per second per host | `2.0` |
| `--concurrency` | `INT` | Maximum global concurrent HTTP requests | `3` |
| `--delay` | `FLOAT` | Minimum delay in seconds between requests to same host | `0.5` |
| `--jitter` | — | Add small randomized jitter to inter-request delays | `False` |
| `--timeout` | `FLOAT` | HTTP request timeout in seconds | `10.0` |
| `--user-agent` | `STR` | Custom User-Agent header string | Chrome/128 JSFinder |
| `--insecure` | — | Disable TLS/SSL certificate verification | `False` |
| `--max-depth` | `INT` | Maximum HTML crawl recursion depth | `2` |
| `--max-pages` | `INT` | Maximum number of HTML pages to crawl | `50` |
| `--download-sourcemaps`| — | Save discovered source map files to output directory | `False` |
| `--output-dir` | `DIR` | Save full multi-table reports and downloaded artifacts | `jsresult/<domain>` |
| `--no-save` | — | Disable automatic saving of results to `jsresult/` | `False` |
| `-o, --output` | `FILE` | Generic output file path | — |
| `--json` | `FILE` | Save structured findings to JSON file | — |
| `--csv` | `FILE` | Save discovered endpoints to CSV file | — |
| `-v, --verbose` | — | Enable detailed debug logging | `False` |
| `-q, --quiet` | — | Suppress banner and progress logs | `False` |

---

## Output Schema Example

JSON output includes discovery provenance:

```json
{
  "target": "https://example.com",
  "scan_time": "2026-08-27T13:30:00Z",
  "scope": [
    "example.com",
    "*.example.com"
  ],
  "subdomains": [
    {
      "hostname": "api.example.com",
      "source": "crt.sh",
      "ips": ["93.184.216.34"],
      "is_live": true
    }
  ],
  "hosts": [
    {
      "url": "https://example.com",
      "status": 200,
      "final_url": "https://example.com",
      "content_type": "text/html",
      "content_length": 1420,
      "response_time": 0.124,
      "server": "cloudflare",
      "title": "Example Domain Portal"
    }
  ],
  "javascript": [
    "https://example.com/assets/app.8b4ef2.js"
  ],
  "source_maps": [
    {
      "url": "https://example.com/assets/app.8b4ef2.js.map",
      "referenced_js": "https://example.com/assets/app.8b4ef2.js",
      "status": 200,
      "content_type": "application/json",
      "size": 245120,
      "detected_via": "directive"
    }
  ],
  "resources": [
    {
      "url": "https://example.com/assets/app.8b4ef2.js",
      "resource_type": "javascript",
      "source_url": "https://example.com",
      "tag": "script",
      "framework_chunk": true
    }
  ],
  "endpoints": [
    {
      "endpoint": "/api/v1/users",
      "source": "https://example.com/assets/app.8b4ef2.js",
      "endpoint_type": "api",
      "parameters": ["page", "limit", "sort"]
    }
  ],
  "parameters": [
    "limit",
    "page",
    "sort"
  ]
}
```

---

## Testing

Run the test suite with `pytest`:

```bash
pytest -v
```

The test suite covers:
1. **Scope validation**: Exact matches, wildcard subdomains, IP/CIDR, and security boundary rejection of tricky suffixes (`evil-example.com`, `example.com.attacker.com`).
2. **URL normalization**: Protocol-relative URLs, dot-segment resolution, trailing slashes, fragment stripping, and non-HTTP scheme discard.
3. **Rate limiting**: Per-host token buckets, minimum inter-request delays, concurrency ceilings, and 429 `Retry-After` backoff.
4. **HTML Resource parsing**: Script, link, image, iframe extraction, extension classification, and framework chunk detection.
5. **JavaScript analysis**: Absolute URLs, relative paths, REST/GraphQL endpoints, query parameters, referenced subdomains, and source map directives.
6. **Deduplication**: Resource, endpoint, and parameter deduplication across crawl cycles.
7. **Redirect scope enforcement**: Following in-scope redirects while aborting out-of-scope hops.
8. **Integration test**: Complete scan against a local mock HTTP server serving HTML, JS chunks, source maps, redirects, and 429 throttling.

---

## Security & Ethics

JSFinder is designed exclusively for authorized penetration testing, security assessments, and bug-bounty engagements. The tool adheres to non-destructive methodologies:
- **No credential attacks** or brute forcing
- **No active exploits** or destructive payloads
- **No denial-of-service** behavior (conservative default rate limits)
- **Strict scope adherence** to prevent unintentional requests to out-of-scope hosts
