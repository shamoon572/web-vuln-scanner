"""
Response Analysis Engine.

Provides helpers for:
  - Error keyword matching with confidence scoring
  - Response length differential analysis
  - Status code anomaly detection
  - Time-delay detection
  - Reflection detection
  - DOM sink scanning (static)

All public functions return a (detected: bool, confidence: float, evidence: str) tuple.
"""

from __future__ import annotations

import difflib
import re
from typing import Optional

from core.session import HttpResponse
from payloads.sqli_payloads import ALL_DB_ERRORS
from payloads.lfi_payloads  import LFI_SIGNATURES


# ── SQL error detection ───────────────────────────────────────────────────────

def detect_sql_error(response: HttpResponse) -> tuple[bool, float, str]:
    """Scan response body for DB error signatures."""
    body_lower = response.body.lower()
    for err in ALL_DB_ERRORS:
        if err in body_lower:
            # Higher confidence for specific DBMS errors
            conf = 0.9 if any(x in err for x in ["ora-", "pg::", "mssql", "mysql_"]) else 0.75
            snip = _snippet(response.body, err)
            return True, conf, snip
    return False, 0.0, ""


# ── Boolean differential ──────────────────────────────────────────────────────

def detect_boolean_differential(
    baseline: HttpResponse,
    true_resp: HttpResponse,
    false_resp: HttpResponse,
) -> tuple[bool, float, str]:
    """
    Compare TRUE vs FALSE injection responses against baseline.
    A significant length difference between true/false that isn't
    mirrored in the baseline suggests boolean-based SQLi.
    """
    base_len  = len(baseline.body)
    true_len  = len(true_resp.body)
    false_len = len(false_resp.body)

    diff_tf = abs(true_len - false_len)
    diff_bt = abs(base_len - true_len)

    # True response should differ meaningfully from false, and
    # at least one of them should differ from baseline.
    if diff_tf < 50:
        return False, 0.0, ""

    # Ratio-based confidence
    if base_len == 0:
        return False, 0.0, ""

    ratio_tf = diff_tf / max(base_len, 1)
    ratio_bt = diff_bt / max(base_len, 1)

    if ratio_tf > 0.1 and ratio_bt > 0.05:
        conf = min(0.85, 0.5 + ratio_tf * 2)
        evidence = (
            f"Length diff TRUE/FALSE={diff_tf}B, "
            f"TRUE/baseline={diff_bt}B"
        )
        return True, conf, evidence

    return False, 0.0, ""


# ── Time-delay detection ──────────────────────────────────────────────────────

def detect_time_delay(
    baseline: HttpResponse,
    delayed: HttpResponse,
    threshold: float = 4.0,
) -> tuple[bool, float, str]:
    """
    Detect time-based injection by comparing response times.
    threshold: minimum seconds above baseline to consider a delay.
    """
    delay = delayed.elapsed - baseline.elapsed
    if delay >= threshold:
        conf = min(0.95, 0.7 + (delay - threshold) * 0.05)
        evidence = (
            f"Response delayed by {delay:.2f}s "
            f"(baseline={baseline.elapsed:.2f}s, "
            f"injected={delayed.elapsed:.2f}s)"
        )
        return True, conf, evidence
    return False, 0.0, ""


# ── Reflection detection ──────────────────────────────────────────────────────

def detect_reflection(
    response: HttpResponse,
    payload: str,
    marker: str | None = None,
) -> tuple[bool, float, str]:
    """Check if the injected payload (or marker) is reflected in the response."""
    probe = marker or payload
    # Check raw and HTML-decoded
    if probe in response.body:
        return True, 0.85, f"Payload reflected verbatim: {probe[:80]}"

    # URL-decoded
    import urllib.parse
    decoded = urllib.parse.unquote(probe)
    if decoded in response.body:
        return True, 0.80, f"Payload reflected (URL-decoded): {decoded[:80]}"

    # HTML-entity decoded
    import html
    decoded_html = html.unescape(probe)
    if decoded_html in response.body:
        return True, 0.75, f"Payload reflected (HTML-decoded): {decoded_html[:80]}"

    return False, 0.0, ""


# ── LFI content detection ─────────────────────────────────────────────────────

def detect_lfi_content(response: HttpResponse) -> tuple[bool, float, str]:
    """Detect sensitive file content in response body."""
    body_lower = response.body.lower()
    for sig in LFI_SIGNATURES:
        if sig.lower() in body_lower:
            conf = 0.9 if "root:x:0:0:" in sig or "[boot loader]" in sig else 0.75
            return True, conf, _snippet(response.body, sig)
    return False, 0.0, ""


# ── DOM sink scanner ──────────────────────────────────────────────────────────

def scan_dom_sinks(html_body: str) -> list[str]:
    """Return list of dangerous DOM sinks found in HTML/JS."""
    from payloads.xss_payloads import DOM_SINKS
    found = []
    for sink in DOM_SINKS:
        if sink in html_body:
            found.append(sink)
    return found


# ── Status code analysis ──────────────────────────────────────────────────────

def status_anomaly(baseline: HttpResponse, probed: HttpResponse) -> tuple[bool, float, str]:
    """Detect meaningful status code changes."""
    if baseline.status == probed.status:
        return False, 0.0, ""

    # 5xx could indicate SQL error / server crash
    if probed.status >= 500:
        return True, 0.6, f"Status changed {baseline.status} → {probed.status} (server error)"

    # Authentication bypass: 403 → 200
    if baseline.status == 403 and probed.status == 200:
        return True, 0.7, f"Auth bypass: {baseline.status} → {probed.status}"

    return False, 0.0, ""


# ── SSRF response analysis ────────────────────────────────────────────────────

def detect_ssrf_response(response: HttpResponse) -> tuple[bool, float, str]:
    """Detect SSRF by looking for internal resource content in response."""
    from payloads.ssrf_payloads import SSRF_INDICATORS
    body_lower = response.body.lower()
    for indicator in SSRF_INDICATORS:
        if indicator.lower() in body_lower:
            return True, 0.85, _snippet(response.body, indicator)
    return False, 0.0, ""


# ── Content length change ─────────────────────────────────────────────────────

def length_change(baseline: HttpResponse, probed: HttpResponse,
                  min_diff: int = 100) -> tuple[bool, float, str]:
    diff = abs(len(probed.body) - len(baseline.body))
    if diff >= min_diff:
        ratio = diff / max(len(baseline.body), 1)
        conf = min(0.6, 0.3 + ratio)
        return True, conf, f"Response length changed by {diff}B"
    return False, 0.0, ""


# ── CRLF header injection ─────────────────────────────────────────────────────

def detect_crlf(response: HttpResponse, marker: str = "x-injected") -> tuple[bool, float, str]:
    """Check if injected header appears in the response headers."""
    for k, v in response.headers.items():
        if marker.lower() in k.lower():
            return True, 0.9, f"Injected header reflected: {k}: {v}"
    return False, 0.0, ""


# ── Helper ────────────────────────────────────────────────────────────────────

def _snippet(body: str, keyword: str, window: int = 120) -> str:
    """Return a short snippet of body around keyword."""
    idx = body.lower().find(keyword.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 30)
    end   = min(len(body), idx + window)
    return body[start:end].strip()
