"""
Shared data models used across the scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Informational"


class VulnType(str, Enum):
    SQLI             = "SQL Injection"
    XSS              = "Cross-Site Scripting"
    SSRF             = "Server-Side Request Forgery"
    LFI              = "Local File Inclusion"
    RFI              = "Remote File Inclusion"
    HEADER_INJECTION = "Header Injection"
    OPEN_REDIRECT    = "Open Redirect"
    INFO_DISCLOSURE  = "Information Disclosure"


# Severity mapping per vuln type (default)
SEVERITY_MAP: dict[VulnType, Severity] = {
    VulnType.SQLI:             Severity.CRITICAL,
    VulnType.XSS:              Severity.HIGH,
    VulnType.SSRF:             Severity.CRITICAL,
    VulnType.LFI:              Severity.HIGH,
    VulnType.RFI:              Severity.CRITICAL,
    VulnType.HEADER_INJECTION: Severity.MEDIUM,
    VulnType.OPEN_REDIRECT:    Severity.MEDIUM,
    VulnType.INFO_DISCLOSURE:  Severity.LOW,
}


@dataclass
class Parameter:
    name:   str
    value:  str
    source: str = "query"   # query | form | json | header | cookie


@dataclass
class Target:
    """Represents a single HTTP endpoint with its attack surface."""
    url:    str
    method: str = "GET"
    params: list[Parameter] = field(default_factory=list)
    data:   dict = field(default_factory=dict)    # POST body
    headers: dict = field(default_factory=dict)

    def __hash__(self):
        return hash((self.url, self.method, tuple(p.name for p in self.params)))

    def __eq__(self, other):
        return (self.url, self.method) == (other.url, other.method)


@dataclass
class Finding:
    """Represents a discovered vulnerability."""
    vuln_type:   VulnType
    url:         str
    parameter:   str
    method:      str
    payload:     str
    evidence:    str
    confidence:  float          # 0.0 – 1.0
    severity:    Severity = field(init=False)
    description: str = ""
    remediation: str = ""
    timestamp:   str = field(default_factory=lambda: datetime.utcnow().isoformat())
    extra:       dict = field(default_factory=dict)

    def __post_init__(self):
        self.severity = SEVERITY_MAP.get(self.vuln_type, Severity.MEDIUM)

    def to_dict(self) -> dict:
        return {
            "type":        self.vuln_type.value,
            "severity":    self.severity.value,
            "url":         self.url,
            "parameter":   self.parameter,
            "method":      self.method,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "confidence":  round(self.confidence, 2),
            "description": self.description,
            "remediation": self.remediation,
            "timestamp":   self.timestamp,
            **self.extra,
        }


@dataclass
class ScanResult:
    """Aggregated results for a completed scan."""
    target:     str
    start_time: str
    end_time:   str = ""
    findings:   list[Finding] = field(default_factory=list)
    urls_crawled: int = 0
    requests_made: int = 0
    errors:     list[str] = field(default_factory=list)

    def summary(self) -> dict:
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "target":         self.target,
            "start_time":     self.start_time,
            "end_time":       self.end_time,
            "urls_crawled":   self.urls_crawled,
            "requests_made":  self.requests_made,
            "total_findings": len(self.findings),
            "by_severity":    by_sev,
        }
