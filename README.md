## 📸 Screenshots
## 🎯 Demo Vulnerable App
<img width="1361" height="687" alt="Demo Vulnerable App" src="https://github.com/user-attachments/assets/e87aac87-c2fb-4ea6-bb5a-cf88899b0624" />

## 📊 HTML Report Dashboard
<img width="1339" height="649" alt="WebvulnScanner1" src="https://github.com/user-attachments/assets/bffb654b-054b-44ab-b709-df5be287eec7" />
<img width="1345" height="652" alt="WebvulnScanner2" src="https://github.com/user-attachments/assets/662a8197-d46d-4c4b-8d53-76cd59d356f5" />
<img width="1346" height="650" alt="WebvulnScanner3" src="https://github.com/user-attachments/assets/9f3491f7-12e2-4c82-8020-f25c834b6423" />

## 💻 Terminal Scan Output
<img width="1343" height="722" alt="TerminalReport" src="https://github.com/user-attachments/assets/a261587e-508a-496f-94c7-d39c4bb49d52" />



# 🔍 WebVulnScanner v1.0

> A production-grade, async Python web vulnerability scanner for bug bounty hunting, security research, and CTF/lab environments.

---

## ⚠️ Ethical Disclaimer

**This tool is for authorised security testing only.** Always obtain explicit written permission before scanning any target. Unauthorised scanning is illegal. The authors accept no responsibility for misuse.

---

## ✨ Features

| Module | Techniques |
|--------|-----------|
| **SQL Injection** | Error-based · Boolean blind · Time-based · WAF bypass mutations |
| **XSS** | Reflected · DOM-based (static) · Blind/OOB · Context-aware |
| **SSRF** | Internal IP probes · AWS/GCP/Azure metadata · OOB callback |
| **LFI / RFI** | Path traversal · Null-byte · Linux + Windows targets |
| **Header Injection** | CRLF · Host · X-Forwarded-For · Referer · User-Agent |

**Architecture:**
- Async engine (asyncio + aiohttp) for high-speed concurrent scanning
- Modular design — add new analyzers without touching core code
- Intelligent response analysis with confidence scoring (minimises false positives)
- OOB listener for blind vulnerability detection (blind XSS, SSRF callbacks)
- JSON + dark-theme HTML reports with Charts.js visualisations
- Cookie / Bearer token / custom header authentication
- Rate limiting, retry logic, exponential back-off

---

## 📁 Project Structure

```
web_vuln_scanner/
├── scanner.py              ← Main entry point
├── demo_target.py          ← Intentionally vulnerable Flask app for testing
├── requirements.txt
├── core/
│   ├── config.py           ← All configuration (ScannerConfig dataclass)
│   ├── session.py          ← Async HTTP session manager
│   ├── models.py           ← Finding, Target, ScanResult data models
│   └── logger.py           ← Coloured logging
├── crawler/
│   └── crawler.py          ← BFS async web crawler
├── analyzers/
│   ├── response_analyzer.py← Shared detection logic (error matching, diff, timing)
│   ├── sqli.py             ← SQL injection analyzer
│   ├── xss.py              ← XSS analyzer
│   ├── ssrf.py             ← SSRF analyzer
│   ├── lfi.py              ← LFI / RFI analyzer
│   └── header_injection.py ← Header injection analyzer
├── fuzzer/
│   └── engine.py           ← Async fuzzing orchestrator
├── payloads/
│   ├── sqli_payloads.py    ← SQL injection payload library + WAF bypass mutations
│   ├── xss_payloads.py     ← XSS payload library (reflected, DOM, blind)
│   ├── ssrf_payloads.py    ← SSRF target URLs
│   ├── lfi_payloads.py     ← Path traversal + sensitive file list
│   └── header_payloads.py  ← CRLF, Host, XFF, Referer payloads
├── oob/
│   └── listener.py         ← Async HTTP server for OOB callback capture
├── reports/
│   └── reporter.py         ← JSON + dark-theme HTML report generation
└── utils/
    └── helpers.py          ← URL normalisation, deduplication, terminal output
```

---

## 🚀 Installation

**Requirements:** Python 3.11+

```bash
# 1. Clone / download the project
git clone https://github.com/yourname/web-vuln-scanner.git
cd web-vuln-scanner

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🎯 Quick Start

### Option A — Scan a real (authorised) target

```bash
python scanner.py --url https://target.example.com
```

### Option B — Test against the included vulnerable demo app

```bash
# Terminal 1: Start the demo target
pip install flask
python demo_target.py

# Terminal 2: Run the scanner against it
python scanner.py --url http://127.0.0.1:5000 --depth 2 --concurrency 5
```

---

## 🛠️ CLI Reference

```
usage: scanner.py [options] --url URL

Required:
  --url URL              Target URL to scan

Crawling:
  --depth INT            Crawl depth (default: 3)
  --max-urls INT         Max URLs to crawl (default: 200)

Performance:
  --concurrency INT      Concurrent requests (default: 10)
  --timeout INT          Request timeout in seconds (default: 15)
  --delay FLOAT          Delay between requests in seconds (default: 0.2)

Authentication:
  --cookies STR          Cookies: "name=val,name2=val2"
  --headers STR          Extra headers: "Name:Value,Name2:Value2"
  --token STR            Bearer token for Authorization header

Modules:
  --modules STR          Comma-separated: sqli,xss,ssrf,lfi,headers (default: all)

OOB / Blind detection:
  --oob-url URL          OOB callback URL (e.g. http://yourserver:8888)

Output:
  --output DIR           Output directory (default: scan_results)
  --no-json              Disable JSON report
  --no-html              Disable HTML report
  --min-confidence FLOAT Minimum confidence to report 0.0–1.0 (default: 0.5)
  --log-file PATH        Write logs to file

General:
  --verbose, -v          Verbose debug logging
  --help, -h             Show this help message
```

---

## 💡 Example Commands

```bash
# Basic scan
python scanner.py --url http://testphp.vulnweb.com

# Deep crawl with custom concurrency
python scanner.py --url https://app.example.com --depth 5 --max-urls 500 --concurrency 20

# Authenticated scan (cookie + bearer token)
python scanner.py --url https://app.example.com \
  --cookies "session=abc123;csrftoken=xyz" \
  --token "eyJhbGciOiJIUzI1NiJ9..."

# SQLi and XSS only (faster)
python scanner.py --url http://target.com --modules sqli,xss

# With blind XSS/SSRF OOB listener
python scanner.py --url http://target.com --oob-url http://YOUR_IP:8888

# DVWA (low security)
python scanner.py --url http://localhost/dvwa/vulnerabilities \
  --cookies "PHPSESSID=abc123;security=low" \
  --depth 2

# High confidence only, save logs
python scanner.py --url http://target.com \
  --min-confidence 0.75 \
  --log-file logs/scan.log

# Run standalone OOB listener
python -m oob.listener --host 0.0.0.0 --port 8888
```

---

## 📊 Sample Output

```
╔═══════════════════════════════════════════════════════════╗
║          Web Vulnerability Scanner  v1.0                  ║
║    SQL Injection · XSS · SSRF · LFI · Header Injection    ║
╚═══════════════════════════════════════════════════════════╝

10:23:01  INFO     scanner — Target  : http://127.0.0.1:5000
10:23:01  INFO     scanner — Depth   : 2  |  Max URLs: 200  |  Concurrency: 10
10:23:01  INFO     scanner — Modules : SQLi=True  XSS=True  SSRF=True  LFI=True
10:23:01  INFO     scanner — ─── Phase 1: Crawling ─────────────
10:23:03  INFO     crawler — Crawler finished — 12 URLs crawled, 18 targets built
10:23:03  INFO     scanner — ─── Phase 2: Fuzzing ──────────────
10:23:05  WARNING  sqli    — ⚡ SQLi (error) @ http://127.0.0.1:5000/user param=id
10:23:06  WARNING  xss     — ⚡ Reflected XSS @ http://127.0.0.1:5000/search param=q ctx=html
10:23:08  WARNING  ssrf    — ⚡ SSRF @ http://127.0.0.1:5000/fetch param=url
10:23:10  WARNING  lfi     — ⚡ LFI @ http://127.0.0.1:5000/file param=name

  [Critical]  SQL Injection
  URL:       http://127.0.0.1:5000/user?id='
  Parameter: id  |  Method: GET
  Payload:   '
  Confidence:90%
  Evidence:  ...error in your SQL syntax near ''' at line 1...

  [High]  Cross-Site Scripting
  URL:       http://127.0.0.1:5000/search?q=<script>alert(1)</script>
  Parameter: q  |  Method: GET
  Payload:   <script>alert(1)</script>
  Confidence:85%
  Evidence:  Payload reflected verbatim: <script>alert(1)</script>

────────────────────────────────────────────────────────────
  SCAN COMPLETE  (18.3s)
────────────────────────────────────────────────────────────
  URLs crawled   : 12
  Requests sent  : 847
  Total findings : 6
    Critical      : 2
    High          : 2
    Medium        : 1
    Low           : 1
────────────────────────────────────────────────────────────

Reports saved:
  [JSON] scan_results/scan_report_20240523_102319.json
  [HTML] scan_results/scan_report_20240523_102319.html
```

---

## 🏗️ Adding Custom Modules

1. Create `analyzers/my_module.py` implementing an `async def analyze(self, target) -> list[Finding]` method
2. Add to `fuzzer/engine.py` `_analyzers` list
3. Add toggle in `core/config.py`
4. Done — the engine handles the rest

---

## 🌐 Recommended Practice Targets

| Target | URL | Notes |
|--------|-----|-------|
| DVWA | `http://localhost/dvwa` | Run with Docker |
| WebGoat | `http://localhost:8080/WebGoat` | OWASP Java app |
| Vulnweb (Acunetix) | `http://testphp.vulnweb.com` | Public demo (authorised) |
| HackTheBox / TryHackMe | Various | Legal CTF platforms |

---

## 🔒 False Positive Reduction

The scanner uses a multi-factor confidence scoring system:

- **Error matching**: Specific DB error patterns → 0.75–0.9 confidence
- **Boolean differential**: Response length diff TRUE/FALSE → 0.5–0.85
- **Time delay**: Measured delay vs baseline → 0.7–0.95
- **Reflection**: Exact payload match in body → 0.75–0.98
- **Status change**: Auth bypass indicators → 0.6–0.8

Use `--min-confidence 0.75` for stricter, lower-noise output.

---

## 📄 License

MIT — For educational and authorised security testing purposes only.
