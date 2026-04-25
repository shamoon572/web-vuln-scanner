"""
scanner.py — Main Scanner Engine

Orchestrates the full scan pipeline:
  1. Crawl target website
  2. Build attack surface (targets)
  3. Fuzz all targets with all enabled modules
  4. Deduplicate and score findings
  5. Generate JSON + HTML reports
  6. Print summary to console

Usage:
    python scanner.py --url https://target.example.com [options]

For full help:
    python scanner.py --help
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime

from core.config   import ScannerConfig
from core.session  import SessionManager
from core.models   import ScanResult
from core.logger   import setup_logger
from crawler       import Crawler
from fuzzer        import FuzzingEngine
from oob           import OOBManager
from reports       import JSONReporter, HTMLReporter
from utils         import (
    deduplicate_findings, sort_findings,
    print_finding, print_banner, print_summary,
)

log = setup_logger("scanner")


# ─────────────────────────────────────────────────────────────────────────────
# Core scan pipeline
# ─────────────────────────────────────────────────────────────────────────────

async def run_scan(config: ScannerConfig) -> ScanResult:
    """
    Execute a full vulnerability scan against config.target_url.
    Returns a ScanResult with all findings.
    """
    start_time = datetime.utcnow().isoformat()
    result = ScanResult(target=config.target_url, start_time=start_time)
    t0 = time.monotonic()

    # ── Logging setup ─────────────────────────────────────────────────────────
    if config.verbose:
        import logging
        log.setLevel(logging.DEBUG)
        for name in ["crawler", "sqli", "xss", "ssrf", "lfi",
                     "header_injection", "fuzzer", "session"]:
            setup_logger(name, logging.DEBUG, config.log_file)
    elif config.log_file:
        setup_logger("scanner", log_file=config.log_file)

    print_banner()
    log.info("Target  : %s", config.target_url)
    log.info("Depth   : %d  |  Max URLs: %d  |  Concurrency: %d",
             config.max_depth, config.max_urls, config.concurrency)
    log.info("Modules : SQLi=%s  XSS=%s  SSRF=%s  LFI=%s  Headers=%s",
             config.enable_sqli, config.enable_xss, config.enable_ssrf,
             config.enable_lfi, config.enable_header_injection)
    if config.oob_url:
        log.info("OOB URL : %s", config.oob_url)

    async with SessionManager(config) as session:
        # ── Phase 1: Crawl ────────────────────────────────────────────────────
        log.info("─── Phase 1: Crawling ───────────────────────────────")
        crawler = Crawler(config, session)
        targets = await crawler.crawl()
        result.urls_crawled = crawler._url_count

        if not targets:
            log.warning("No targets discovered during crawling. Exiting.")
            result.end_time = datetime.utcnow().isoformat()
            return result

        log.info("Crawl complete — %d URLs visited, %d targets extracted",
                 result.urls_crawled, len(targets))

        # ── Phase 2: Fuzz ──────────────────────────────────────────────────────
        log.info("─── Phase 2: Fuzzing ────────────────────────────────")
        engine   = FuzzingEngine(config, session)
        findings = await engine.fuzz(targets)

        # Deduplicate and sort
        findings = deduplicate_findings(findings)
        findings = sort_findings(findings)

        result.findings      = findings
        result.requests_made = engine.stats.requests_sent

        elapsed = time.monotonic() - t0

        # ── Print findings to console ──────────────────────────────────────────
        if findings:
            log.info("─── Findings ────────────────────────────────────────")
            for f in findings:
                if f.confidence >= config.min_confidence:
                    print_finding(f)
        else:
            log.info("No vulnerabilities found (above confidence threshold).")

        print_summary(findings, result.urls_crawled,
                      result.requests_made, elapsed)

    result.end_time = datetime.utcnow().isoformat()
    return result


async def run_scan_with_oob(config: ScannerConfig) -> ScanResult:
    """
    Wrap run_scan with an OOB listener when --oob-listen is specified.
    The OOB server captures blind XSS / SSRF callbacks.
    """
    if not config.oob_url:
        return await run_scan(config)

    # If the OOB URL looks like it belongs to our local listener, start it
    from urllib.parse import urlparse
    parsed = urlparse(config.oob_url)
    if parsed.hostname in ("0.0.0.0", "127.0.0.1", "localhost") or not parsed.hostname:
        async with OOBManager(config.oob_listen_host, config.oob_listen_port) as oob:
            config.oob_url = oob.url
            result = await run_scan(config)
            if oob.hits:
                log.info("OOB hits captured: %d", len(oob.hits))
                for hit in oob.hits:
                    result.errors.append(f"OOB callback: {hit}")
            return result
    else:
        return await run_scan(config)


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def generate_reports(result: ScanResult, config: ScannerConfig) -> dict[str, str]:
    """Generate enabled reports and return their file paths."""
    paths = {}
    if config.report_json:
        r = JSONReporter(config.output_dir)
        paths["json"] = r.generate(result)
    if config.report_html:
        r = HTMLReporter(config.output_dir)
        paths["html"] = r.generate(result)
    return paths


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "WebVulnScanner — Async web vulnerability scanner\n"
            "For authorised security testing and bug bounty research only.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python scanner.py --url http://testphp.vulnweb.com

  # Deep scan with authentication
  python scanner.py --url https://app.example.com --depth 4 --cookies "session=abc123"

  # SQLi + XSS only, fast
  python scanner.py --url http://target.com --modules sqli,xss --concurrency 20

  # Full scan with OOB listener for blind XSS/SSRF
  python scanner.py --url http://target.com --oob-url http://your-server:8888

  # Scan DVWA (authenticated)
  python scanner.py --url http://localhost/dvwa --cookies "PHPSESSID=abc;security=low"
        """,
    )

    parser.add_argument("--url",         required=True, help="Target URL to scan")
    parser.add_argument("--depth",       type=int, default=3,   help="Crawl depth (default: 3)")
    parser.add_argument("--max-urls",    type=int, default=200,  help="Max URLs to crawl (default: 200)")
    parser.add_argument("--concurrency", type=int, default=10,   help="Concurrent requests (default: 10)")
    parser.add_argument("--timeout",     type=int, default=15,   help="Request timeout in seconds (default: 15)")
    parser.add_argument("--delay",       type=float, default=0.2, help="Delay between requests (default: 0.2s)")
    parser.add_argument("--output",      default="scan_results", help="Output directory (default: scan_results)")
    parser.add_argument("--modules",     default="sqli,xss,ssrf,lfi,headers",
                        help="Comma-separated modules to enable (default: all)")
    parser.add_argument("--cookies",     help='Cookies: "name=val,name2=val2"')
    parser.add_argument("--headers",     help='Extra headers: "Name:Value,Name2:Value2"')
    parser.add_argument("--token",       help="Bearer token for Authorization header")
    parser.add_argument("--oob-url",     dest="oob_url", help="OOB callback URL for blind detection")
    parser.add_argument("--log-file",    dest="log_file", help="Path to log file")
    parser.add_argument("--no-json",     action="store_true", help="Disable JSON report")
    parser.add_argument("--no-html",     action="store_true", help="Disable HTML report")
    parser.add_argument("--min-confidence", type=float, default=0.5,
                        help="Minimum confidence score to report (default: 0.5)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    return parser


async def main_async(args: argparse.Namespace) -> int:
    config = ScannerConfig.from_args(args)
    config.report_json    = not args.no_json
    config.report_html    = not args.no_html
    config.min_confidence = args.min_confidence

    try:
        result = await run_scan_with_oob(config)
    except KeyboardInterrupt:
        log.warning("Scan interrupted by user.")
        return 1
    except Exception as exc:
        log.error("Fatal scanner error: %s", exc, exc_info=True)
        return 2

    # Generate reports
    paths = generate_reports(result, config)
    if paths:
        log.info("Reports saved:")
        for fmt, path in paths.items():
            log.info("  [%s] %s", fmt.upper(), path)

    return 0 if result.findings else 0   # 0 = success (non-zero = error)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    try:
        exit_code = asyncio.run(main_async(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
