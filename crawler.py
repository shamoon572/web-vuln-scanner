"""
Async web crawler.

Discovers:
  - Internal links (href, src, action)
  - GET / POST forms with all input fields
  - URL query parameters
  - Hidden inputs
  - JSON API endpoints (best-effort)

Respects:
  - Domain scope restrictions
  - Max depth
  - Max URL budget
  - Already-visited URL deduplication
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Optional
from urllib.parse import (
    urljoin, urlparse, urlunparse, urlencode, parse_qs, urlencode
)

from bs4 import BeautifulSoup

from core.config   import ScannerConfig
from core.session  import SessionManager, HttpResponse
from core.models   import Target, Parameter
from core.logger   import setup_logger

log = setup_logger("crawler")


def _normalise_url(url: str) -> str:
    """Remove fragment, normalise trailing slash."""
    p = urlparse(url)
    return urlunparse(p._replace(fragment=""))


def _same_domain(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def _extract_params_from_url(url: str) -> list[Parameter]:
    qs = urlparse(url).query
    params = []
    for k, vals in parse_qs(qs).items():
        params.append(Parameter(name=k, value=vals[0], source="query"))
    return params


class Crawler:
    """
    BFS async web crawler.

    Usage:
        async with SessionManager(config) as session:
            crawler = Crawler(config, session)
            targets = await crawler.crawl()
    """

    def __init__(self, config: ScannerConfig, session: SessionManager) -> None:
        self.config  = config
        self.session = session
        self._visited: set[str] = set()
        self._queue:   deque    = deque()   # (url, depth)
        self.targets:  list[Target] = []
        self._url_count = 0

    async def crawl(self, start_url: str | None = None) -> list[Target]:
        """Crawl from start_url and return discovered Targets."""
        url = start_url or self.config.target_url
        self._queue.append((url, 0))
        log.info("Crawler started → %s  (depth=%d, max_urls=%d)",
                 url, self.config.max_depth, self.config.max_urls)

        while self._queue and self._url_count < self.config.max_urls:
            batch = []
            while self._queue and len(batch) < self.config.concurrency:
                batch.append(self._queue.popleft())

            tasks = [self._process_url(u, d) for u, d in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        log.info("Crawler finished — %d URLs crawled, %d targets built",
                 self._url_count, len(self.targets))
        return self.targets

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _process_url(self, url: str, depth: int) -> None:
        norm = _normalise_url(url)
        if norm in self._visited:
            return
        if not _same_domain(norm, self.config.target_url) and self.config.scope_domain:
            return

        self._visited.add(norm)
        self._url_count += 1

        resp = await self.session.get(norm)
        if resp is None:
            return

        if self.config.verbose:
            log.debug("Crawled [%d] %s", resp.status, norm)

        # Build GET target for the URL itself
        params = _extract_params_from_url(norm)
        if params:
            self.targets.append(Target(url=norm, method="GET", params=params))
        else:
            # Still register the URL (for header injection tests etc.)
            self.targets.append(Target(url=norm, method="GET"))

        # Parse HTML for more URLs and forms
        if depth < self.config.max_depth and _is_html(resp):
            links, form_targets = self._parse_html(norm, resp.body)
            for link in links:
                n = _normalise_url(link)
                if n not in self._visited and self._url_count < self.config.max_urls:
                    self._queue.append((n, depth + 1))
            self.targets.extend(form_targets)

    def _parse_html(self, base_url: str, html: str) -> tuple[list[str], list[Target]]:
        """Parse HTML → (list of links, list of form Targets)."""
        soup  = BeautifulSoup(html, "html.parser")
        links = self._extract_links(base_url, soup)
        forms = self._extract_forms(base_url, soup)
        return links, forms

    def _extract_links(self, base_url: str, soup: BeautifulSoup) -> list[str]:
        links = []
        for tag in soup.find_all(["a", "link", "script", "iframe", "frame"]):
            for attr in ("href", "src", "action"):
                val = tag.get(attr, "")
                if not val or val.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                full = urljoin(base_url, val)
                parsed = urlparse(full)
                if parsed.scheme in ("http", "https"):
                    if _same_domain(full, self.config.target_url):
                        links.append(full)
        return list(set(links))

    def _extract_forms(self, base_url: str, soup: BeautifulSoup) -> list[Target]:
        targets = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = urljoin(base_url, action) if action else base_url

            params = []
            data   = {}

            for inp in form.find_all(["input", "textarea", "select"]):
                name  = inp.get("name", "")
                value = inp.get("value", "") or ""
                itype = inp.get("type", "text").lower()

                if not name:
                    continue
                if itype in ("submit", "button", "image", "reset"):
                    continue

                # Use placeholder values for empty fields
                if not value:
                    value = self._default_value(itype, name)

                param = Parameter(
                    name   = name,
                    value  = value,
                    source = "form_hidden" if itype == "hidden" else "form",
                )
                params.append(param)
                data[name] = value

            if not params:
                continue

            if method == "POST":
                t = Target(url=action_url, method="POST", params=params, data=data)
            else:
                t = Target(url=action_url, method="GET", params=params)

            targets.append(t)
            log.debug("Form found: %s %s (%d params)", method, action_url, len(params))

        return targets

    @staticmethod
    def _default_value(input_type: str, name: str) -> str:
        defaults = {
            "email":    "test@example.com",
            "password": "Test1234!",
            "number":   "1",
            "tel":      "1234567890",
            "url":      "http://example.com",
            "date":     "2024-01-01",
            "search":   "test",
        }
        return defaults.get(input_type, "test")


def _is_html(resp: HttpResponse) -> bool:
    ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
    return "html" in ct.lower() or ct == ""
