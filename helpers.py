"""
Shared utilities for the Web Vulnerability Scanner.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from typing import Optional

from core.models import Finding


# ── URL utilities ─────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    """Remove fragment, sort query params for consistent deduplication."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    sorted_qs = urlencode(sorted(qs.items()), doseq=True)
    return urlunparse(p._replace(query=sorted_qs, fragment=""))


def is_same_domain(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def is_internal_url(url: str) -> bool:
    """Return True if the URL points to an internal/private address."""
    hostname = urlparse(url).hostname or ""
    private_patterns = [
        r"^127\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^192\.168\.",
        r"^169\.254\.",
        r"^::1$",
        r"^0\.0\.0\.0$",
        r"localhost",
        r"^0$",
    ]
    return any(re.match(p, hostname) for p in private_patterns)


def url_fingerprint(url: str) -> str:
    """Return a short hash for a URL (used for deduplication)."""
    return hashlib.md5(normalise_url(url).encode()).hexdigest()[:8]


def extract_base_url(url: str) -> str:
    """Return scheme + netloc only."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ── Finding deduplication ─────────────────────────────────────────────────────

def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings.
    Two findings are duplicates if they share (vuln_type, url, parameter, payload[:40]).
    """
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.vuln_type, f.url, f.parameter, f.payload[:40])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (Critical first) then confidence (desc)."""
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    return sorted(
        findings,
        key=lambda f: (order.get(f.severity.value, 9), -f.confidence),
    )


# ── Terminal output helpers ───────────────────────────────────────────────────

_SEV_COLORS = {
    "Critical":      "\033[91m",   # bright red
    "High":          "\033[31m",   # red
    "Medium":        "\033[33m",   # yellow
    "Low":           "\033[34m",   # blue
    "Informational": "\033[37m",   # white
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def print_finding(f: Finding) -> None:
    """Pretty-print a single finding to stdout."""
    color = _SEV_COLORS.get(f.severity.value, "")
    print(
        f"\n  {_BOLD}{color}[{f.severity.value}]{_RESET}  "
        f"{_BOLD}{f.vuln_type.value}{_RESET}\n"
        f"  URL:       {f.url}\n"
        f"  Parameter: {f.parameter}  |  Method: {f.method}\n"
        f"  Payload:   {f.payload[:100]}\n"
        f"  Confidence:{int(f.confidence*100)}%\n"
        f"  Evidence:  {f.evidence[:120]}"
    )


def print_banner() -> None:
    banner = r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║          Web Vulnerability Scanner  v1.0                  ║
  ║    SQL Injection · XSS · SSRF · LFI · Header Injection    ║
  ║          For authorised security testing only             ║
  ╚═══════════════════════════════════════════════════════════╝
"""
    print("\033[36m" + banner + "\033[0m")


def print_summary(findings: list[Finding], urls_crawled: int,
                  requests: int, elapsed: float) -> None:
    from collections import Counter
    counts = Counter(f.severity.value for f in findings)
    print(f"\n{'─'*60}")
    print(f"  SCAN COMPLETE  ({elapsed:.1f}s)")
    print(f"{'─'*60}")
    print(f"  URLs crawled   : {urls_crawled}")
    print(f"  Requests sent  : {requests}")
    print(f"  Total findings : {len(findings)}")
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        if counts.get(sev):
            color = _SEV_COLORS.get(sev, "")
            print(f"    {color}{sev:<14}{_RESET}: {counts[sev]}")
    print(f"{'─'*60}\n")


# ── Payload encoding helpers ───────────────────────────────────────────────────

def url_encode(s: str, safe: str = "") -> str:
    from urllib.parse import quote
    return quote(s, safe=safe)


def double_url_encode(s: str) -> str:
    return url_encode(url_encode(s))


def html_encode(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))
