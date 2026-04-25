"""
SSRF (Server-Side Request Forgery) Analyzer.

Detection strategy:
  1. Identify URL-like parameters in GET/POST
  2. Inject SSRF probes (internal IPs, cloud metadata, OOB URL)
  3. Analyse response for internal resource content
  4. Record OOB injection attempts for async callback detection
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import Optional

from core.config   import ScannerConfig
from core.session  import SessionManager, HttpResponse
from core.models   import Finding, Target, Parameter, VulnType
from core.logger   import setup_logger
from payloads.ssrf_payloads import get_ssrf_payloads, SSRF_INDICATORS
from analyzers.response_analyzer import detect_ssrf_response, length_change

log = setup_logger("ssrf")

# Heuristics for URL-like parameter names
URL_PARAM_PATTERNS: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"url", r"uri", r"src", r"source", r"dest(?:ination)?",
    r"redirect", r"redir", r"return", r"callback", r"endpoint",
    r"host", r"server", r"domain", r"site", r"target", r"link",
    r"path", r"file", r"resource", r"proxy", r"load", r"fetch",
    r"image", r"img", r"page", r"api",
]]


def _is_url_param(name: str, value: str) -> bool:
    """Heuristic: is this parameter likely to contain a URL?"""
    for pat in URL_PARAM_PATTERNS:
        if pat.search(name):
            return True
    # Check value
    if value.startswith(("http://", "https://", "ftp://", "//")):
        return True
    return False


class SSRFAnalyzer:
    """Detect SSRF in URL-bearing parameters."""

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session

    async def analyze(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        url_params = [p for p in target.params if _is_url_param(p.name, p.value)]
        if not url_params:
            return findings

        payloads = get_ssrf_payloads(self.config.oob_url)
        baseline = await self.session.baseline(target.url, target.method,
                                               {p.name: p.value for p in target.params})

        for param in url_params:
            for payload in payloads:
                resp = await self._send(target, param, payload)
                if resp is None:
                    continue

                # Check for internal content in response
                detected, conf, evidence = detect_ssrf_response(resp)
                if not detected and baseline:
                    detected, conf, evidence = length_change(baseline, resp, min_diff=200)

                # OOB payloads: record as injection attempt
                if self.config.oob_url and self.config.oob_url in payload:
                    findings.append(Finding(
                        vuln_type   = VulnType.SSRF,
                        url         = target.url,
                        parameter   = param.name,
                        method      = target.method,
                        payload     = payload,
                        evidence    = "SSRF OOB payload injected — monitor callback server",
                        confidence  = 0.4,
                        description = "SSRF OOB probe injected into URL parameter.",
                        remediation = _REMEDIATION,
                    ))
                    continue

                if detected and conf >= self.config.min_confidence:
                    findings.append(Finding(
                        vuln_type   = VulnType.SSRF,
                        url         = target.url,
                        parameter   = param.name,
                        method      = target.method,
                        payload     = payload,
                        evidence    = evidence[:500],
                        confidence  = conf,
                        description = (
                            "SSRF detected. The server appears to be fetching the injected URL "
                            "and returning its contents (or an observable side-effect)."
                        ),
                        remediation = _REMEDIATION,
                    ))
                    log.warning("⚡ SSRF @ %s param=%s payload=%s",
                                target.url, param.name, payload[:60])
                    return findings   # one per param

        return findings

    async def _send(self, target: Target, param: Parameter,
                    payload: str) -> Optional[HttpResponse]:
        if target.method == "POST":
            data = {p.name: p.value for p in target.params}
            data[param.name] = payload
            return await self.session.post(target.url, data=data)
        else:
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query)
            qs[param.name] = [payload]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self.session.get(new_url)


_REMEDIATION = (
    "Validate and whitelist allowed URL schemes and hosts. "
    "Use a firewall to restrict outbound connections from the web server. "
    "Never fetch URLs supplied directly by users."
)
