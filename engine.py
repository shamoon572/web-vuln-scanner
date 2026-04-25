"""
Fuzzing Engine.

Orchestrates payload injection across all target parameters.
Supports:
  - GET / POST / Header fuzzing
  - Concurrency control via asyncio Semaphore
  - Payload mutation (encoding, case, comment bypass)
  - Progress reporting
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Awaitable

from core.config   import ScannerConfig
from core.session  import SessionManager
from core.models   import Finding, Target
from core.logger   import setup_logger
from analyzers     import (
    SQLiAnalyzer, XSSAnalyzer, SSRFAnalyzer,
    LFIAnalyzer, HeaderInjectionAnalyzer,
)

log = setup_logger("fuzzer")


@dataclass
class FuzzStats:
    targets_tested: int = 0
    requests_sent:  int = 0
    findings:       int = 0


class FuzzingEngine:
    """
    Dispatches each target to the appropriate vulnerability analyzers
    and collects findings.

    Usage:
        engine  = FuzzingEngine(config, session)
        results = await engine.fuzz(targets)
    """

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session
        self.stats   = FuzzStats()
        self._sem    = asyncio.Semaphore(config.concurrency)

        # Instantiate analyzers once (they are stateless)
        self._analyzers: list[tuple[str, bool, object]] = [
            ("SQLi",             config.enable_sqli,             SQLiAnalyzer(config, session)),
            ("XSS",              config.enable_xss,              XSSAnalyzer(config, session)),
            ("SSRF",             config.enable_ssrf,             SSRFAnalyzer(config, session)),
            ("LFI/RFI",          config.enable_lfi,              LFIAnalyzer(config, session)),
            ("Header Injection", config.enable_header_injection, HeaderInjectionAnalyzer(config, session)),
        ]

    async def fuzz(
        self,
        targets: list[Target],
        progress_cb: Callable[[int, int], Awaitable[None]] | None = None,
    ) -> list[Finding]:
        """
        Run all enabled analyzers against every target.

        Args:
            targets:     List of Target objects (from crawler)
            progress_cb: Optional async callback(done, total) for progress reporting
        """
        all_findings: list[Finding] = []
        total  = len(targets)
        done   = 0

        log.info("Fuzzing engine started — %d targets, %d analyzers enabled",
                 total,
                 sum(1 for _, enabled, _ in self._analyzers if enabled))

        # Deduplicate targets
        seen: set = set()
        unique: list[Target] = []
        for t in targets:
            key = (t.url, t.method)
            if key not in seen:
                seen.add(key)
                unique.append(t)

        log.info("Unique targets after dedup: %d", len(unique))

        tasks = [self._fuzz_target(t) for t in unique]
        for coro in asyncio.as_completed(tasks):
            try:
                findings = await coro
                all_findings.extend(findings)
                self.stats.findings += len(findings)
            except Exception as exc:
                log.error("Fuzzer task error: %s", exc)
            finally:
                done += 1
                self.stats.targets_tested += 1
                if progress_cb:
                    await progress_cb(done, len(unique))
                if done % 10 == 0 or done == len(unique):
                    log.info("Progress: %d/%d targets  |  %d findings so far",
                             done, len(unique), self.stats.findings)

        log.info("Fuzzing complete — %d findings across %d targets",
                 self.stats.findings, self.stats.targets_tested)
        return all_findings

    async def _fuzz_target(self, target: Target) -> list[Finding]:
        """Run all enabled analyzers against a single target."""
        findings: list[Finding] = []
        async with self._sem:
            for name, enabled, analyzer in self._analyzers:
                if not enabled:
                    continue
                try:
                    if self.config.verbose:
                        log.debug("  [%s] %s %s (%d params)",
                                  name, target.method, target.url, len(target.params))
                    partial = await analyzer.analyze(target)
                    findings.extend(partial)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.error("[%s] Error on %s: %s", name, target.url, exc)
        return findings
