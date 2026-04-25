"""
XSS Analyzer.

Techniques:
  1. Reflection probing — inject unique marker, check if reflected
  2. Reflected XSS      — full payload injection + reflection check
  3. DOM-based          — static analysis for dangerous sinks in JS
  4. Blind XSS (OOB)    — inject callback payloads when OOB URL configured
  5. Context-aware      — detect reflection context (HTML / attr / script / url)
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core.config   import ScannerConfig
from core.session  import SessionManager, HttpResponse
from core.models   import Finding, Target, Parameter, VulnType
from core.logger   import setup_logger
from payloads.xss_payloads import (
    REFLECTED_PAYLOADS, BYPASS_PAYLOADS, MARKER, MARKER_PAYLOAD,
    get_blind_payloads, payloads_for_context, mutate_xss,
)
from analyzers.response_analyzer import (
    detect_reflection, scan_dom_sinks,
)

log = setup_logger("xss")


class XSSAnalyzer:
    """Detect XSS vulnerabilities across a Target's parameters."""

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session

    async def analyze(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # 1. DOM sink analysis (static, no requests needed)
        resp0 = await self.session.get(target.url)
        if resp0:
            dom_findings = self._check_dom(target, resp0)
            findings.extend(dom_findings)

        # 2. Per-parameter tests
        for param in target.params:
            # Probe for reflection first (cheap)
            reflected = await self._probe_reflection(target, param)
            if not reflected:
                continue   # parameter is not reflected, skip heavy testing

            # Context detection
            ctx = await self._detect_context(target, param)

            # Reflected XSS payloads
            f = await self._reflected_xss(target, param, ctx)
            findings.extend(f)

            # Blind XSS (if OOB configured)
            if self.config.oob_url:
                f = await self._blind_xss(target, param)
                findings.extend(f)

        return findings

    # ── Reflection probe ──────────────────────────────────────────────────────

    async def _probe_reflection(self, target: Target, param: Parameter) -> bool:
        """Return True if the marker is reflected in the response."""
        resp = await self._send(target, param, MARKER_PAYLOAD)
        if resp is None:
            return False
        detected, _, _ = detect_reflection(resp, MARKER_PAYLOAD, MARKER)
        return detected

    # ── Context detection ──────────────────────────────────────────────────────

    async def _detect_context(self, target: Target, param: Parameter) -> str:
        """
        Detect where the reflection occurs:
        html | attribute | script | url | css | unknown
        """
        probe = f"CTXPROBE{MARKER}CTXPROBE"
        resp  = await self._send(target, param, probe)
        if resp is None:
            return "unknown"

        body = resp.body
        idx  = body.find(probe)
        if idx == -1:
            # Try case-insensitive
            idx = body.lower().find(probe.lower())
        if idx == -1:
            return "unknown"

        # Grab surrounding context
        ctx_window = body[max(0, idx - 100) : idx + 100]

        if re.search(r"<script[^>]*>.*" + re.escape(probe), ctx_window, re.DOTALL | re.IGNORECASE):
            return "script"
        if re.search(r'<[^>]+=[\'"]*' + re.escape(probe), ctx_window, re.IGNORECASE):
            return "attribute"
        if re.search(r'url\s*\(.*' + re.escape(probe), ctx_window, re.IGNORECASE):
            return "url"
        if re.search(r'style\s*=.*' + re.escape(probe), ctx_window, re.IGNORECASE):
            return "css"
        return "html"

    # ── Reflected XSS ────────────────────────────────────────────────────────

    async def _reflected_xss(self, target: Target, param: Parameter,
                              ctx: str) -> list[Finding]:
        findings = []
        payloads = payloads_for_context(ctx) + REFLECTED_PAYLOADS[:5] + BYPASS_PAYLOADS[:5]

        for payload in payloads:
            resp = await self._send(target, param, payload)
            if resp is None:
                continue

            detected, conf, evidence = detect_reflection(resp, payload)
            if detected and conf >= self.config.min_confidence:
                # Extra confidence if a functional event handler is reflected
                if re.search(r"on\w+\s*=\s*['\"]?alert", resp.body, re.IGNORECASE):
                    conf = min(0.98, conf + 0.1)
                if "<script>" in resp.body.lower() and "alert" in resp.body.lower():
                    conf = min(0.98, conf + 0.1)

                findings.append(Finding(
                    vuln_type   = VulnType.XSS,
                    url         = target.url,
                    parameter   = param.name,
                    method      = target.method,
                    payload     = payload,
                    evidence    = evidence[:500],
                    confidence  = conf,
                    description = (
                        f"Reflected XSS in {ctx} context. "
                        "User-supplied input is reflected without sanitisation."
                    ),
                    remediation = (
                        "Encode output using context-appropriate escaping "
                        "(HTML entities, JavaScript escaping). "
                        "Implement a Content Security Policy (CSP)."
                    ),
                    extra={"context": ctx},
                ))
                log.warning("⚡ Reflected XSS @ %s param=%s ctx=%s",
                            target.url, param.name, ctx)
                return findings   # one confirmed finding per param is enough

        return findings

    # ── DOM-based XSS ────────────────────────────────────────────────────────

    def _check_dom(self, target: Target, resp: HttpResponse) -> list[Finding]:
        findings = []
        sinks = scan_dom_sinks(resp.body)
        if not sinks:
            return findings

        findings.append(Finding(
            vuln_type   = VulnType.XSS,
            url         = target.url,
            parameter   = "DOM",
            method      = "GET",
            payload     = "(static analysis)",
            evidence    = f"Dangerous DOM sinks detected: {', '.join(sinks[:5])}",
            confidence  = 0.6,
            description = (
                "Potentially dangerous JavaScript DOM sinks were found. "
                "If user-controlled data flows to these sinks, DOM-based XSS may be possible."
            ),
            remediation = (
                "Avoid using innerHTML, document.write, eval() with user data. "
                "Use textContent / createElement for safe DOM manipulation."
            ),
            extra={"sinks": sinks[:10]},
        ))
        log.info("DOM sinks found at %s: %s", target.url, sinks[:5])
        return findings

    # ── Blind XSS (OOB) ──────────────────────────────────────────────────────

    async def _blind_xss(self, target: Target, param: Parameter) -> list[Finding]:
        findings = []
        for payload in get_blind_payloads(self.config.oob_url)[:3]:
            await self._send(target, param, payload)
            # OOB detection happens asynchronously via the OOB listener.
            # We record the injection attempt as low-confidence finding.
            findings.append(Finding(
                vuln_type   = VulnType.XSS,
                url         = target.url,
                parameter   = param.name,
                method      = target.method,
                payload     = payload,
                evidence    = "Blind XSS payload injected — monitor OOB callback",
                confidence  = 0.4,
                description = (
                    "Blind XSS payload injected. "
                    "If executed in an admin panel, the OOB server will receive a callback."
                ),
                remediation = (
                    "Sanitise all user input before storing or rendering. "
                    "Implement strict CSP."
                ),
            ))
            log.info("Blind XSS injected @ %s param=%s", target.url, param.name)
        return findings

    # ── HTTP helper ───────────────────────────────────────────────────────────

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
