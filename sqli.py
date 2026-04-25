"""
SQL Injection Analyzer.

Techniques:
  1. Error-based  — inject quote chars, look for DB error messages
  2. Boolean-based blind — compare TRUE vs FALSE response differences
  3. Time-based blind — measure response time delays (SLEEP / pg_sleep / WAITFOR)

All methods use WAF-bypass payload mutations.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from core.config    import ScannerConfig
from core.session   import SessionManager, HttpResponse
from core.models    import Finding, Target, Parameter, VulnType
from core.logger    import setup_logger
from payloads.sqli_payloads import (
    ERROR_PAYLOADS, BOOLEAN_PAYLOADS_TRUE, BOOLEAN_PAYLOADS_FALSE,
    ALL_TIME_PAYLOADS, mutate,
)
from analyzers.response_analyzer import (
    detect_sql_error, detect_boolean_differential,
    detect_time_delay, status_anomaly,
)

log = setup_logger("sqli")

TIME_DELAY  = 5    # seconds
TIME_THRESH = 4.0  # detect if at least this many seconds above baseline


class SQLiAnalyzer:
    """
    Runs SQL injection checks against a Target's parameters.
    Returns a list of Finding objects.
    """

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session

    async def analyze(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for param in target.params:
            results = await asyncio.gather(
                self._error_based(target, param),
                self._boolean_based(target, param),
                self._time_based(target, param),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)
        return findings

    # ── Error-based ───────────────────────────────────────────────────────────

    async def _error_based(self, target: Target, param: Parameter) -> list[Finding]:
        findings = []
        baseline = await self.session.baseline(target.url, target.method,
                                               _build_data(target))
        if baseline is None:
            return findings

        for payload in ERROR_PAYLOADS[:15]:   # limit to top 15 for speed
            for variant in mutate(payload)[:3]:   # max 3 mutations per payload
                resp = await self._send(target, param, variant)
                if resp is None:
                    continue

                detected, conf, evidence = detect_sql_error(resp)
                if not detected:
                    detected, conf, evidence = status_anomaly(baseline, resp)

                if detected and conf >= self.config.min_confidence:
                    findings.append(_make_finding(
                        target, param, variant,
                        evidence=evidence,
                        confidence=conf,
                        description=(
                            "Error-based SQL injection detected. "
                            "Database error messages were observed in the response."
                        ),
                        remediation=(
                            "Use parameterised queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                    ))
                    log.warning("⚡ SQLi (error) @ %s param=%s payload=%s",
                                target.url, param.name, variant[:60])
                    return findings   # one finding per param is enough

        return findings

    # ── Boolean-based ─────────────────────────────────────────────────────────

    async def _boolean_based(self, target: Target, param: Parameter) -> list[Finding]:
        findings = []
        baseline = await self.session.baseline(target.url, target.method,
                                               _build_data(target))
        if baseline is None:
            return findings

        true_payloads  = BOOLEAN_PAYLOADS_TRUE[:8]
        false_payloads = BOOLEAN_PAYLOADS_FALSE[:8]

        for t_pay, f_pay in zip(true_payloads, false_payloads):
            true_resp  = await self._send(target, param, t_pay)
            false_resp = await self._send(target, param, f_pay)

            if true_resp is None or false_resp is None:
                continue

            detected, conf, evidence = detect_boolean_differential(
                baseline, true_resp, false_resp
            )
            if detected and conf >= self.config.min_confidence:
                findings.append(_make_finding(
                    target, param,
                    payload=f"{t_pay}  /  {f_pay}",
                    evidence=evidence,
                    confidence=conf,
                    description=(
                        "Boolean-based blind SQL injection detected. "
                        "Application returns different responses for TRUE vs FALSE conditions."
                    ),
                    remediation=(
                        "Use parameterised queries. "
                        "Avoid exposing conditional page differences based on SQL results."
                    ),
                ))
                log.warning("⚡ SQLi (boolean) @ %s param=%s", target.url, param.name)
                return findings

        return findings

    # ── Time-based ────────────────────────────────────────────────────────────

    async def _time_based(self, target: Target, param: Parameter) -> list[Finding]:
        findings = []
        baseline = await self.session.baseline(target.url, target.method,
                                               _build_data(target))
        if baseline is None:
            return findings

        for payload in ALL_TIME_PAYLOADS[:20]:
            resp = await self._send(target, param, payload)
            if resp is None:
                continue

            detected, conf, evidence = detect_time_delay(
                baseline, resp, threshold=TIME_THRESH
            )
            if detected and conf >= self.config.min_confidence:
                findings.append(_make_finding(
                    target, param, payload,
                    evidence=evidence,
                    confidence=conf,
                    description=(
                        "Time-based blind SQL injection detected. "
                        "Injected delay payload caused observable server response delay."
                    ),
                    remediation=(
                        "Use parameterised queries / prepared statements. "
                        "Implement strict input validation."
                    ),
                    extra={"delay": f"{resp.elapsed:.2f}s"},
                ))
                log.warning("⚡ SQLi (time) @ %s param=%s delay=%.2fs",
                            target.url, param.name, resp.elapsed)
                return findings

        return findings

    # ── HTTP helper ───────────────────────────────────────────────────────────

    async def _send(self, target: Target, param: Parameter,
                    payload: str) -> Optional[HttpResponse]:
        """Send request with payload injected into param."""
        if target.method == "POST":
            data = _build_data(target)
            data[param.name] = payload
            return await self.session.post(target.url, data=data)
        else:
            from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query)
            qs[param.name] = [payload]
            new_url = urlunparse(parsed._replace(
                query=urlencode(qs, doseq=True)
            ))
            return await self.session.get(new_url)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_data(target: Target) -> dict:
    return {p.name: p.value for p in target.params}


def _make_finding(target, param, payload, evidence, confidence,
                  description="", remediation="", extra=None) -> Finding:
    return Finding(
        vuln_type   = VulnType.SQLI,
        url         = target.url,
        parameter   = param.name,
        method      = target.method,
        payload     = payload,
        evidence    = evidence[:500],
        confidence  = confidence,
        description = description,
        remediation = remediation,
        extra       = extra or {},
    )
