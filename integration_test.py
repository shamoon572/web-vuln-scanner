"""
integration_test.py — Validate scanner logic without network access.

Tests:
  - All payload libraries load correctly
  - Response analysis functions work as expected
  - Model creation + serialisation
  - Report generation (JSON + HTML)
  - Config parsing

Run: python integration_test.py
"""

import sys
import os
import json
import asyncio
from datetime import datetime
from pathlib import Path

# Make sure we can import from the project root
sys.path.insert(0, os.path.dirname(__file__))

# ── Colour helpers ─────────────────────────────────────────────────────────────
G  = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[94m"; RST = "\033[0m"; BD = "\033[1m"
def ok(msg):    print(f"  {G}✓{RST}  {msg}")
def fail(msg):  print(f"  {R}✗{RST}  {msg}"); sys.exit(1)
def section(s): print(f"\n{B}{BD}── {s} {'─'*(54-len(s))}{RST}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Payload libraries
# ─────────────────────────────────────────────────────────────────────────────

section("Payload Libraries")

from payloads.sqli_payloads import (
    ERROR_PAYLOADS, BOOLEAN_PAYLOADS_TRUE, ALL_TIME_PAYLOADS,
    ALL_DB_ERRORS, mutate, get_all_sqli_payloads
)
assert len(ERROR_PAYLOADS)         >= 10, "Too few error payloads"
assert len(BOOLEAN_PAYLOADS_TRUE)  >= 10, "Too few boolean payloads"
assert len(ALL_TIME_PAYLOADS)      >= 10, "Too few time payloads"
assert len(ALL_DB_ERRORS)          >= 20, "Too few DB error signatures"
ok(f"SQLi payloads loaded  ({len(get_all_sqli_payloads())} total)")

mutations = mutate("' UNION SELECT NULL--")
assert len(mutations) >= 5, "WAF bypass mutations too few"
ok(f"WAF bypass mutations  ({len(mutations)} variants for sample payload)")

from payloads.xss_payloads import (
    REFLECTED_PAYLOADS, BYPASS_PAYLOADS, DOM_SINKS, MARKER,
    get_blind_payloads, payloads_for_context, get_all_xss_payloads
)
assert len(REFLECTED_PAYLOADS) >= 15
assert len(BYPASS_PAYLOADS)    >= 10
assert "<script>" in REFLECTED_PAYLOADS[0].lower()
blind = get_blind_payloads("http://attacker.com:8888")
assert "http://attacker.com:8888" in blind[0]
ok(f"XSS payloads loaded   ({len(get_all_xss_payloads())} total, {len(blind)} blind)")

ctx_html  = payloads_for_context("html")
ctx_attr  = payloads_for_context("attribute")
ctx_script= payloads_for_context("script")
assert len(ctx_attr) > 0
ok(f"Context-aware payloads: html={len(ctx_html)}, attr={len(ctx_attr)}, script={len(ctx_script)}")

from payloads.ssrf_payloads import get_ssrf_payloads, SSRF_INDICATORS
ssrf = get_ssrf_payloads("http://oob.example.com")
assert "http://127.0.0.1/" in ssrf
assert "http://oob.example.com" in ssrf
ok(f"SSRF payloads loaded  ({len(ssrf)} targets)")

from payloads.lfi_payloads import get_lfi_payloads, LFI_SIGNATURES, RFI_PAYLOADS
lfi = get_lfi_payloads("both")
assert len(lfi) >= 20
assert any("/etc/passwd" in p for p in lfi)
assert any("win.ini" in p.lower() for p in lfi)
ok(f"LFI/RFI payloads loaded ({len(lfi)} LFI, {len(RFI_PAYLOADS)} RFI)")

from payloads.header_payloads import INJECTABLE_HEADERS, CRLF_PAYLOADS
assert len(INJECTABLE_HEADERS) >= 5
assert any("\r\n" in p or "%0d%0a" in p.lower() for p in CRLF_PAYLOADS)
ok(f"Header payloads loaded ({len(INJECTABLE_HEADERS)} header groups)")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Response analysis engine
# ─────────────────────────────────────────────────────────────────────────────

section("Response Analysis Engine")

# Use a local stub so the test doesn't need aiohttp installed
class HttpResponse:
    def __init__(self, url, status, headers, body, elapsed):
        self.url = url; self.status = status
        self.headers = headers; self.body = body; self.elapsed = elapsed

def make_resp(body="", status=200, elapsed=0.1, url="http://example.com", headers=None):
    return HttpResponse(url=url, status=status, headers=headers or {}, body=body, elapsed=elapsed)

from analyzers.response_analyzer import (
    detect_sql_error, detect_boolean_differential, detect_time_delay,
    detect_reflection, detect_lfi_content, scan_dom_sinks,
    detect_ssrf_response, detect_crlf, length_change, status_anomaly,
)

# SQL error detection
r = make_resp("You have an error in your SQL syntax near '' at line 1")
d, c, e = detect_sql_error(r)
assert d and c > 0.5, "Should detect MySQL error"
ok(f"SQL error detection   (conf={c:.2f}, evidence='{e[:40]}…')")

r2 = make_resp("Normal page content, welcome to the site.")
d2, c2, _ = detect_sql_error(r2)
assert not d2, "Should NOT detect error in clean response"
ok("SQL false-positive check passed")

# Boolean differential
base  = make_resp("Welcome to the site. Here is your profile page content.", elapsed=0.1)
true_ = make_resp("Welcome to the site. Here is your profile page content. Extra data user Alice found.", elapsed=0.1)
false_= make_resp("", elapsed=0.1)
d, c, e = detect_boolean_differential(base, true_, false_)
assert d, "Should detect boolean differential"
ok(f"Boolean differential  (conf={c:.2f})")

# Time delay
baseline = make_resp("fast", elapsed=0.15)
delayed  = make_resp("slow", elapsed=5.3)
d, c, e = detect_time_delay(baseline, delayed, threshold=4.0)
assert d and c > 0.7, "Should detect 5s delay"
ok(f"Time delay detection  (conf={c:.2f}, evidence='{e[:50]}')")

no_delay = make_resp("fast", elapsed=0.2)
d2, _, _ = detect_time_delay(baseline, no_delay, threshold=4.0)
assert not d2, "Should NOT detect delay for fast response"
ok("Time delay false-positive check passed")

# Reflection detection
r = make_resp("<html><body>Your search: <script>alert(1)</script></body></html>")
d, c, e = detect_reflection(r, "<script>alert(1)</script>")
assert d and c >= 0.8
ok(f"Reflection detection  (conf={c:.2f})")

# LFI content detection
r = make_resp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:/usr/sbin/nologin")
d, c, e = detect_lfi_content(r)
assert d and c >= 0.9
ok(f"LFI content detection (conf={c:.2f})")

# DOM sink scan
html_js = """<html><body>
<script>
  var q = location.hash.slice(1);
  document.write('<h1>' + q + '</h1>');
  eval(q);
</script></body></html>"""
sinks = scan_dom_sinks(html_js)
assert "document.write(" in sinks and "eval(" in sinks
ok(f"DOM sink scanner      ({len(sinks)} sinks: {sinks[:3]})")

# SSRF
r = make_resp("ami-id: ami-0abcdef\ninstance-id: i-0abc123")
d, c, e = detect_ssrf_response(r)
assert d
ok(f"SSRF response detect  (conf={c:.2f})")

# CRLF
r = make_resp("", headers={"x-injected": "HeaderInjected"})
d, c, e = detect_crlf(r, "x-injected")
assert d
ok(f"CRLF detection        (conf={c:.2f})")

# Status anomaly
b = make_resp(status=403)
p = make_resp(status=200)
d, c, e = status_anomaly(b, p)
assert d
ok(f"Status anomaly detect (403→200, conf={c:.2f})")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Data models
# ─────────────────────────────────────────────────────────────────────────────

section("Data Models")

from core.models import Finding, Target, Parameter, ScanResult, VulnType, Severity

p = Parameter(name="id", value="1", source="query")
t = Target(url="http://example.com/search?id=1", method="GET", params=[p])
assert t.url == "http://example.com/search?id=1"
ok("Target + Parameter creation")

f = Finding(
    vuln_type  = VulnType.SQLI,
    url        = "http://example.com/search",
    parameter  = "id",
    method     = "GET",
    payload    = "' OR 1=1--",
    evidence   = "MySQL error near '",
    confidence = 0.92,
    description= "Error-based SQLi",
    remediation= "Use prepared statements",
)
assert f.severity == Severity.CRITICAL
d = f.to_dict()
assert d["type"] == "SQL Injection"
assert d["severity"] == "Critical"
assert d["confidence"] == 0.92
ok(f"Finding model + to_dict() (severity auto-assigned: {f.severity.value})")

result = ScanResult(
    target     = "http://example.com",
    start_time = datetime.utcnow().isoformat(),
    findings   = [f],
    urls_crawled  = 42,
    requests_made = 1337,
)
result.end_time = datetime.utcnow().isoformat()
s = result.summary()
assert s["total_findings"] == 1
assert s["by_severity"]["Critical"] == 1
ok(f"ScanResult summary: {s['total_findings']} finding, {s['urls_crawled']} URLs")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Config + argument parsing
# ─────────────────────────────────────────────────────────────────────────────

section("Configuration")

from core.config import ScannerConfig

cfg = ScannerConfig(target_url="http://example.com")
cfg.cookies = {"session": "abc123"}
cfg.enable_sqli = True
cfg.enable_xss  = True
hdrs = cfg.base_headers()
assert "User-Agent" in hdrs
ok(f"ScannerConfig created (UA: {hdrs['User-Agent'][:40]}…)")

import argparse
from scanner import build_parser
parser = build_parser()
args = parser.parse_args([
    "--url", "http://example.com",
    "--depth", "2",
    "--modules", "sqli,xss",
    "--cookies", "a=b,c=d",
])
cfg2 = ScannerConfig.from_args(args)
assert cfg2.target_url    == "http://example.com"
assert cfg2.max_depth     == 2
assert cfg2.enable_sqli   == True
assert cfg2.enable_ssrf   == False   # not in modules
assert cfg2.cookies["a"]  == "b"
ok("CLI arg parsing → ScannerConfig conversion")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Deduplication + sorting
# ─────────────────────────────────────────────────────────────────────────────

section("Deduplication & Sorting")

from utils import deduplicate_findings, sort_findings

findings = []
for i in range(5):
    findings.append(Finding(
        vuln_type  = VulnType.XSS,
        url        = "http://example.com/search",
        parameter  = "q",
        method     = "GET",
        payload    = "<script>alert(1)</script>",
        evidence   = "reflected",
        confidence = 0.9,
    ))
findings.append(Finding(
    vuln_type  = VulnType.SQLI,
    url        = "http://example.com/user",
    parameter  = "id",
    method     = "GET",
    payload    = "'",
    evidence   = "sql error",
    confidence = 0.95,
))
deduped = deduplicate_findings(findings)
assert len(deduped) == 2, f"Expected 2, got {len(deduped)}"
ok(f"Deduplication: 6 findings → {len(deduped)} unique")

sorted_f = sort_findings(deduped)
assert sorted_f[0].severity == Severity.CRITICAL   # SQLi should be first
ok(f"Sorting: first finding = {sorted_f[0].severity.value} ({sorted_f[0].vuln_type.value})")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Report generation
# ─────────────────────────────────────────────────────────────────────────────

section("Report Generation")

# Build a realistic scan result for reporting
all_findings = []
sample_vulns = [
    (VulnType.SQLI,             "http://demo.local/user?id=1",     "id",      "GET",  "' OR 1=1--",                 "MySQL syntax error near '",          0.92),
    (VulnType.SQLI,             "http://demo.local/search",        "q",       "GET",  "' AND SLEEP(5)--",           "Response delayed by 5.12s",          0.88),
    (VulnType.XSS,              "http://demo.local/search",        "q",       "GET",  "<script>alert(1)</script>",  "Payload reflected verbatim",         0.85),
    (VulnType.XSS,              "http://demo.local/comment",       "comment", "POST", "<img src=x onerror=alert(1)>","Payload reflected in POST response", 0.80),
    (VulnType.SSRF,             "http://demo.local/fetch",         "url",     "GET",  "http://169.254.169.254/",    "ami-id found in response body",       0.87),
    (VulnType.LFI,              "http://demo.local/file",          "name",    "GET",  "../../etc/passwd",           "root:x:0:0:root:/root:/bin/bash",     0.95),
    (VulnType.HEADER_INJECTION, "http://demo.local/headers",       "X-Forwarded-For", "GET", "127.0.0.1", "Status changed 403→200", 0.78),
    (VulnType.XSS,              "http://demo.local/profile",       "name",    "GET",  "<svg onload=alert(1)>",      "Payload reflected in HTML context",   0.82),
]
for vt, url, param, method, payload, evidence, conf in sample_vulns:
    all_findings.append(Finding(
        vuln_type=vt, url=url, parameter=param, method=method,
        payload=payload, evidence=evidence, confidence=conf,
        description=f"Demo {vt.value} vulnerability for report testing",
        remediation="Apply proper input validation and output encoding.",
    ))

scan_result = ScanResult(
    target       = "http://demo.local",
    start_time   = "2024-05-23T10:23:01",
    end_time     = "2024-05-23T10:41:37",
    findings     = sort_findings(deduplicate_findings(all_findings)),
    urls_crawled = 12,
    requests_made= 847,
)

out_dir = "/tmp/scanner_test_reports"
Path(out_dir).mkdir(exist_ok=True)

from reports import JSONReporter, HTMLReporter

jr = JSONReporter(out_dir)
jp = jr.generate(scan_result)
assert Path(jp).exists()
with open(jp) as fh:
    jdata = json.load(fh)
assert jdata["summary"]["total_findings"] == len(all_findings)
assert len(jdata["findings"]) == len(all_findings)
ok(f"JSON report generated ({Path(jp).stat().st_size // 1024 + 1}KB) → {jp}")

hr = HTMLReporter(out_dir)
hp = hr.generate(scan_result)
assert Path(hp).exists()
html_content = Path(hp).read_text()
assert "WebVulnScanner" in html_content
assert "SQL Injection" in html_content
assert "chart.js" in html_content.lower()
assert "Critical" in html_content
ok(f"HTML report generated ({Path(hp).stat().st_size // 1024 + 1}KB) → {hp}")

# ── Copy reports to outputs ───────────────────────────────────────────────────
import shutil
out_final = Path("/mnt/user-data/outputs")
out_final.mkdir(exist_ok=True)
shutil.copy(jp, out_final / "sample_scan_report.json")
shutil.copy(hp, out_final / "sample_scan_report.html")
ok("Reports copied to /mnt/user-data/outputs/")


# ─────────────────────────────────────────────────────────────────────────────
# 7. URL utilities
# ─────────────────────────────────────────────────────────────────────────────

section("URL Utilities")

from utils.helpers import normalise_url, is_internal_url, url_encode

n = normalise_url("http://example.com/path?b=2&a=1#frag")
assert "#" not in n
assert "a=1" in n and "b=2" in n
ok(f"URL normalisation: {n}")

assert is_internal_url("http://127.0.0.1/admin")
assert is_internal_url("http://192.168.1.1/")
assert is_internal_url("http://10.0.0.5/api")
assert not is_internal_url("http://example.com/")
ok("Internal URL detection (127.x, 192.168.x, 10.x)")

enc = url_encode("' OR 1=1--")
assert "%" in enc
ok(f"URL encoding: {enc}")


# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────

print(f"""
{G}{BD}{'═'*60}
  ALL TESTS PASSED ✓
{'═'*60}{RST}
  Payload libraries  : {Y}SQLi · XSS · SSRF · LFI · Headers{RST}
  Response analysis  : {Y}Error · Boolean · Time · Reflect · LFI · SSRF · CRLF{RST}
  Data models        : {Y}Finding · Target · Parameter · ScanResult{RST}
  Config/CLI parsing : {Y}ScannerConfig · argparse integration{RST}
  Dedup + sorting    : {Y}Multi-key deduplication · Severity-ordered sort{RST}
  Reports generated  : {Y}JSON + dark-theme HTML (with Chart.js){RST}
  URL utilities      : {Y}Normalise · Internal-IP detect · Encoding{RST}

{BD}Sample reports saved to /mnt/user-data/outputs/{RST}
  • sample_scan_report.json  — Machine-readable findings
  • sample_scan_report.html  — Interactive dashboard report

{BD}To run a real scan:{RST}
  1. pip install aiohttp beautifulsoup4 lxml flask
  2. python demo_target.py          # start demo vulnerable app
  3. python scanner.py --url http://127.0.0.1:5000 --depth 2
""")
