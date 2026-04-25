"""
LFI / RFI (Local / Remote File Inclusion) Analyzer.

Strategy:
  1. Find parameters that look like file paths
  2. Inject path traversal payloads
  3. Detect sensitive file contents in response
  4. Also test RFI with external URL payloads
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import Optional

from core.config   import ScannerConfig
from core.session  import SessionManager, HttpResponse
from core.models   import Finding, Target, Parameter, VulnType
from core.logger   import setup_logger
from payloads.lfi_payloads import get_lfi_payloads, LFI_SIGNATURES, RFI_PAYLOADS
from analyzers.response_analyzer import detect_lfi_content

log = setup_logger("lfi")

# Parameter names that often control file paths
FILE_PARAM_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"file", r"path", r"page", r"template", r"inc(?:lude)?",
    r"module", r"view", r"doc", r"document", r"content",
    r"load", r"dir", r"folder", r"lang", r"language", r"locale",
    r"config", r"conf", r"cfg", r"log", r"report", r"read",
]]


def _is_file_param(name: str, value: str) -> bool:
    for pat in FILE_PARAM_PATTERNS:
        if pat.search(name):
            return True
    # Value looks like a path
    if value and ("/" in value or "\\" in value or "." in value):
        return True
    return False


class LFIAnalyzer:
    """Detect LFI / RFI vulnerabilities."""

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session

    async def analyze(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        file_params = [p for p in target.params if _is_file_param(p.name, p.value)]
        if not file_params:
            # Test ALL params if none obviously look like file params
            file_params = target.params[:3]   # limit to first 3

        lfi_payloads = get_lfi_payloads(os="both")[:40]   # top 40 for speed
        rfi_payloads = RFI_PAYLOADS[:5]

        for param in file_params:
            # LFI
            for payload in lfi_payloads:
                resp = await self._send(target, param, payload)
                if resp is None:
                    continue
                detected, conf, evidence = detect_lfi_content(resp)
                if detected and conf >= self.config.min_confidence:
                    findings.append(Finding(
                        vuln_type   = VulnType.LFI,
                        url         = target.url,
                        parameter   = param.name,
                        method      = target.method,
                        payload     = payload,
                        evidence    = evidence[:500],
                        confidence  = conf,
                        description = (
                            "Local File Inclusion detected. "
                            "Server is reading and returning local files based on user input."
                        ),
                        remediation = _LFI_REMEDIATION,
                    ))
                    log.warning("⚡ LFI @ %s param=%s payload=%s",
                                target.url, param.name, payload[:60])
                    break   # one confirmed finding per param

            # RFI (only makes sense if LFI not already found for this param)
            if not any(f.parameter == param.name and f.vuln_type == VulnType.LFI
                       for f in findings):
                for payload in rfi_payloads:
                    resp = await self._send(target, param, payload)
                    if resp is None:
                        continue
                    # RFI heuristic: significant response length increase
                    if resp and len(resp.body) > 500:
                        findings.append(Finding(
                            vuln_type   = VulnType.RFI,
                            url         = target.url,
                            parameter   = param.name,
                            method      = target.method,
                            payload     = payload,
                            evidence    = f"Response length {len(resp.body)}B with RFI payload",
                            confidence  = 0.5,
                            description = "Potential RFI — server may be fetching remote files.",
                            remediation = _LFI_REMEDIATION,
                        ))
                        log.warning("⚡ RFI (potential) @ %s param=%s",
                                    target.url, param.name)
                        break

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


_LFI_REMEDIATION = (
    "Never pass user-supplied filenames directly to file system functions. "
    "Use a whitelist of permitted files/paths. "
    "Chroot / jail the web server process so it cannot access sensitive paths."
)
