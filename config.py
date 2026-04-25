"""
Global configuration and settings for the Web Vulnerability Scanner.
All tunable parameters live here to keep other modules clean.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScannerConfig:
    # ── Target ────────────────────────────────────────────────────────────────
    target_url: str = ""
    scope_domain: str = ""          # Restrict crawling to this domain

    # ── Crawler ───────────────────────────────────────────────────────────────
    max_depth: int = 3
    max_urls: int = 200
    follow_redirects: bool = True

    # ── Concurrency / Rate limiting ───────────────────────────────────────────
    concurrency: int = 10           # asyncio semaphore size
    request_delay: float = 0.2      # seconds between requests (per worker)
    request_timeout: int = 15       # seconds
    max_retries: int = 3
    retry_delay: float = 2.0

    # ── Authentication ────────────────────────────────────────────────────────
    cookies: dict[str, str]    = field(default_factory=dict)
    headers: dict[str, str]    = field(default_factory=dict)
    auth_token: Optional[str]  = None   # Bearer token

    # ── Modules to enable ─────────────────────────────────────────────────────
    enable_sqli:             bool = True
    enable_xss:              bool = True
    enable_ssrf:             bool = True
    enable_lfi:              bool = True
    enable_header_injection: bool = True

    # ── OOB / Callback ────────────────────────────────────────────────────────
    oob_url: Optional[str] = None   # e.g. https://your-burp-collab.net/abc
    oob_listen_host: str   = "0.0.0.0"
    oob_listen_port: int   = 8888

    # ── Reporting ─────────────────────────────────────────────────────────────
    output_dir: str     = "scan_results"
    report_json: bool   = True
    report_html: bool   = True

    # ── Logging ───────────────────────────────────────────────────────────────
    log_file: Optional[str] = None
    verbose: bool           = False

    # ── User-Agent pool ──────────────────────────────────────────────────────
    user_agents: list[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ])

    # ── False-positive reduction ──────────────────────────────────────────────
    min_confidence: float = 0.5     # Only report findings >= this score

    # ── Derived helpers ───────────────────────────────────────────────────────
    def base_headers(self) -> dict[str, str]:
        import random
        hdrs = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if self.auth_token:
            hdrs["Authorization"] = f"Bearer {self.auth_token}"
        hdrs.update(self.headers)
        return hdrs

    @classmethod
    def from_args(cls, args) -> "ScannerConfig":
        """Build config from argparse Namespace."""
        cfg = cls(target_url=args.url)
        cfg.max_depth          = args.depth
        cfg.max_urls           = args.max_urls
        cfg.concurrency        = args.concurrency
        cfg.request_timeout    = args.timeout
        cfg.request_delay      = args.delay
        cfg.output_dir         = args.output
        cfg.verbose            = args.verbose
        cfg.oob_url            = getattr(args, "oob_url", None)

        # Cookies: key=value,key2=value2
        if getattr(args, "cookies", None):
            for pair in args.cookies.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cfg.cookies[k.strip()] = v.strip()

        # Extra headers: Header:Value,Header2:Value2
        if getattr(args, "headers", None):
            for pair in args.headers.split(","):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    cfg.headers[k.strip()] = v.strip()

        if getattr(args, "token", None):
            cfg.auth_token = args.token

        # Module toggles
        modules = getattr(args, "modules", None)
        if modules:
            active = {m.strip().lower() for m in modules.split(",")}
            cfg.enable_sqli             = "sqli"    in active
            cfg.enable_xss              = "xss"     in active
            cfg.enable_ssrf             = "ssrf"    in active
            cfg.enable_lfi              = "lfi"     in active
            cfg.enable_header_injection = "headers" in active

        if getattr(args, "log_file", None):
            cfg.log_file = args.log_file

        return cfg
