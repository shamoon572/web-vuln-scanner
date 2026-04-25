"""
Async HTTP session manager.
Handles retries, auth injection, rate limiting, and response normalisation.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Optional
from urllib.parse import urljoin

try:
    import aiohttp
    from aiohttp import ClientSession, TCPConnector, ClientTimeout
    _AIOHTTP = True
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore
    ClientSession = ClientTimeout = TCPConnector = None  # type: ignore
    _AIOHTTP = False

from core.config import ScannerConfig
from core.logger import setup_logger

log = setup_logger("session")


class HttpResponse:
    """Normalised HTTP response wrapper."""

    def __init__(
        self,
        url: str,
        status: int,
        headers: dict[str, str],
        body: str,
        elapsed: float,
    ) -> None:
        self.url     = url
        self.status  = status
        self.headers = headers
        self.body    = body
        self.elapsed = elapsed          # seconds

    def __repr__(self) -> str:
        return f"<HttpResponse {self.status} {self.url} ({len(self.body)}B, {self.elapsed:.2f}s)>"


class SessionManager:
    """
    Async HTTP session manager with:
      - Connection pooling
      - Automatic retry with exponential back-off
      - Random delay injection
      - Cookie / header auth injection
      - Response time measurement
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config  = config
        self._session: Optional[ClientSession] = None
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def __aenter__(self) -> "SessionManager":
        await self.start()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def start(self) -> None:
        if not _AIOHTTP:
            raise RuntimeError("aiohttp is required: pip install aiohttp")
        connector = TCPConnector(
            ssl=False,
            limit=self.config.concurrency * 2,
            ttl_dns_cache=300,
        )
        timeout = ClientTimeout(total=self.config.request_timeout)
        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            cookies=self.config.cookies,
        )
        log.debug("HTTP session started (concurrency=%d)", self.config.concurrency)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        log.debug("HTTP session closed")

    # ── Public request helpers ────────────────────────────────────────────────

    async def get(
        self,
        url: str,
        params: dict | None = None,
        extra_headers: dict | None = None,
    ) -> Optional[HttpResponse]:
        return await self._request("GET", url, params=params,
                                   extra_headers=extra_headers)

    async def post(
        self,
        url: str,
        data: dict | None = None,
        json: Any = None,
        extra_headers: dict | None = None,
    ) -> Optional[HttpResponse]:
        return await self._request("POST", url, data=data, json=json,
                                   extra_headers=extra_headers)

    # ── Core request method ───────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data:   dict | None = None,
        json:   Any  = None,
        extra_headers: dict | None = None,
    ) -> Optional[HttpResponse]:
        headers = self.config.base_headers()
        if extra_headers:
            headers.update(extra_headers)

        async with self._semaphore:
            for attempt in range(1, self.config.max_retries + 1):
                try:
                    # Rate-limit delay with ±20 % jitter
                    delay = self.config.request_delay * random.uniform(0.8, 1.2)
                    await asyncio.sleep(delay)

                    t0 = time.monotonic()
                    async with self._session.request(
                        method,
                        url,
                        params=params,
                        data=data,
                        json=json,
                        headers=headers,
                        allow_redirects=self.config.follow_redirects,
                        ssl=False,
                    ) as resp:
                        body    = await resp.text(errors="replace")
                        elapsed = time.monotonic() - t0

                    return HttpResponse(
                        url=str(resp.url),
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        elapsed=elapsed,
                    )

                except asyncio.TimeoutError:
                    log.warning("Timeout on %s %s (attempt %d/%d)",
                                method, url, attempt, self.config.max_retries)
                except aiohttp.ClientConnectorError as exc:
                    log.warning("Connection error %s: %s (attempt %d/%d)",
                                url, exc, attempt, self.config.max_retries)
                except aiohttp.ClientError as exc:
                    log.warning("Client error %s: %s (attempt %d/%d)",
                                url, exc, attempt, self.config.max_retries)
                except Exception as exc:
                    log.error("Unexpected error %s: %s", url, exc)
                    return None

                if attempt < self.config.max_retries:
                    backoff = self.config.retry_delay * (2 ** (attempt - 1))
                    log.debug("Retrying in %.1fs …", backoff)
                    await asyncio.sleep(backoff)

        return None

    # ── Baseline helper ───────────────────────────────────────────────────────

    async def baseline(self, url: str, method: str = "GET",
                       data: dict | None = None) -> Optional[HttpResponse]:
        """Fetch a clean baseline response used for differential analysis."""
        if method.upper() == "POST":
            return await self.post(url, data=data)
        return await self.get(url)
