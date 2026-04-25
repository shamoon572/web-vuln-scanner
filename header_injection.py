"""
Header Injection Analyzer.

Tests for:
  - CRLF injection (response splitting)
  - Host header injection
  - X-Forwarded-For / IP spoofing with SQLi/XSS payloads
  - Referer injection
  - User-Agent injection
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Optional

from core.config   import ScannerConfig
from core.session  import SessionManager, HttpResponse
from core.models   import Finding, Target, Parameter, VulnType
from core.logger   import setup_logger
from payloads.header_payloads import (
    INJECTABLE_HEADERS, CRLF_PAYLOADS, CRLF_RESPONSE_HEADERS,
)
from analyzers.response_analyzer import (
    detect_crlf, detect_sql_error, detect_reflection, length_change,
)

log = setup_logger("header_injection")

MARKER = "X-Injected"
MARKER_VALUE = "HeaderInjected8675309"


class HeaderInjectionAnalyzer:
    """Test HTTP headers for injection vulnerabilities."""

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session

    async def analyze(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        baseline = await self.session.get(target.url)
        if baseline is None:
            return findings

        for header_name, payloads in INJECTABLE_HEADERS:
            for payload in payloads:
                resp = await self.session.get(
                    target.url,
                    extra_headers={header_name: payload},
                )
                if resp is None:
                    continue

                finding = self._analyse_response(
                    target, baseline, resp, header_name, payload
                )
                if finding:
                    findings.append(finding)
                    log.warning("⚡ Header injection @ %s  header=%s  payload=%s",
                                target.url, header_name, payload[:60])
                    break   # one finding per header name

        return findings

    def _analyse_response(
        self,
        target: Target,
        baseline: HttpResponse,
        resp: HttpResponse,
        header_name: str,
        payload: str,
    ) -> Optional[Finding]:

        # 1. CRLF: injected marker appears in response headers
        detected, conf, evidence = detect_crlf(resp, MARKER)
        if detected and conf >= self.config.min_confidence:
            return _make_finding(
                target, header_name, payload, evidence, conf,
                description="CRLF injection detected. Response headers can be manipulated.",
                remediation=_CRLF_REMEDIATION,
            )

        # 2. SQL error in response after header injection
        detected, conf, evidence = detect_sql_error(resp)
        if detected and conf >= self.config.min_confidence:
            return _make_finding(
                target, header_name, payload, evidence, conf,
                description=(
                    f"SQL injection via {header_name} header. "
                    "Header value is interpolated into a SQL query."
                ),
                remediation=_SQL_REMEDIATION,
            )

        # 3. XSS — header value reflected in body
        detected, conf, evidence = detect_reflection(resp, payload)
        if detected and conf >= self.config.min_confidence:
            return _make_finding(
                target, header_name, payload, evidence, conf,
                description=(
                    f"XSS via {header_name} header. "
                    "Header value is reflected unsanitised into the response body."
                ),
                remediation=_XSS_REMEDIATION,
            )

        # 4. Significant response length change (possible info disclosure or bypass)
        detected, conf, evidence = length_change(baseline, resp, min_diff=500)
        if detected and conf >= self.config.min_confidence:
            return _make_finding(
                target, header_name, payload, evidence, conf,
                description=(
                    f"Unexpected response change via {header_name} header injection. "
                    "Possible access control bypass or information disclosure."
                ),
                remediation=_GENERIC_REMEDIATION,
            )

        # 5. Status code change (e.g. 403 → 200 via XFF spoofing)
        if baseline.status != resp.status:
            if resp.status == 200 and baseline.status in (403, 401):
                return _make_finding(
                    target, header_name, payload,
                    evidence=f"Status changed {baseline.status} → {resp.status}",
                    confidence=0.8,
                    description=(
                        f"Access control bypass via {header_name} header. "
                        "Server trusts the injected IP/host value for authorisation."
                    ),
                    remediation=_GENERIC_REMEDIATION,
                )

        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(target, header_name, payload, evidence, confidence,
                  description="", remediation="") -> Finding:
    return Finding(
        vuln_type   = VulnType.HEADER_INJECTION,
        url         = target.url,
        parameter   = header_name,
        method      = "GET",
        payload     = payload,
        evidence    = evidence[:500],
        confidence  = confidence,
        description = description,
        remediation = remediation,
    )


_CRLF_REMEDIATION = (
    "Sanitise CR (\\r) and LF (\\n) characters from all user-supplied values "
    "before using them in HTTP response headers."
)
_SQL_REMEDIATION = (
    "Never interpolate HTTP header values into SQL queries. "
    "Use parameterised queries."
)
_XSS_REMEDIATION = (
    "HTML-encode header values before reflecting them in the response body."
)
_GENERIC_REMEDIATION = (
    "Do not use client-supplied headers (X-Forwarded-For, Host, etc.) "
    "for authorisation or routing decisions without strict validation."
)
