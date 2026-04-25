"""
Out-of-Band (OOB) Callback Listener.

Runs a lightweight async HTTP server that listens for callbacks
from injected blind-XSS and SSRF payloads.

Usage (standalone):
    python -m oob.listener --host 0.0.0.0 --port 8888

Or embedded in the scanner:
    listener = OOBListener(host, port)
    await listener.start()
    ...
    await listener.stop()
    hits = listener.hits
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
try:
    from aiohttp import web
    _AIOHTTP = True
except ImportError:
    web = None  # type: ignore
    _AIOHTTP = False

from core.logger import setup_logger

log = setup_logger("oob")


class OOBListener:
    """
    Async HTTP server that captures OOB callbacks.

    Attributes:
        hits: List of captured callback records
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8888) -> None:
        self.host = host
        self.port = port
        self.hits: list[dict] = []
        self._runner: web.AppRunner | None = None
        self._site:   web.TCPSite   | None = None

    async def start(self) -> None:
        app = web.Application()
        app.router.add_route("*", "/{path_info:.*}", self._handle)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        log.info("OOB listener started on http://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        log.info("OOB listener stopped. Total hits: %d", len(self.hits))

    async def _handle(self, request: web.Request) -> web.Response:
        hit = {
            "timestamp":  datetime.utcnow().isoformat(),
            "method":     request.method,
            "path":       str(request.rel_url),
            "remote":     request.remote,
            "headers":    dict(request.headers),
            "query":      dict(request.rel_url.query),
        }

        try:
            body = await request.text()
            if body:
                hit["body"] = body[:2000]
        except Exception:
            pass

        self.hits.append(hit)
        log.warning(
            "⚡ OOB callback! method=%s path=%s remote=%s params=%s",
            hit["method"], hit["path"], hit["remote"],
            json.dumps(hit["query"])[:200],
        )

        return web.Response(
            text="OK",
            status=200,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    def report(self) -> list[dict]:
        return self.hits


class OOBManager:
    """
    Context-manager wrapper for OOBListener.
    Starts the server in background, collects hits.

    async with OOBManager("0.0.0.0", 8888) as oob:
        oob_url = oob.url
        # run scan ...
    hits = oob.hits
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8888) -> None:
        self._listener = OOBListener(host, port)
        self.host = host
        self.port = port

    @property
    def url(self) -> str:
        """Public URL to embed in payloads."""
        return f"http://{self.host}:{self.port}"

    @property
    def hits(self) -> list[dict]:
        return self._listener.hits

    async def __aenter__(self) -> "OOBManager":
        await self._listener.start()
        return self

    async def __aexit__(self, *_) -> None:
        await self._listener.stop()


# ── CLI entry point ───────────────────────────────────────────────────────────

async def _run_listener(host: str, port: int) -> None:
    listener = OOBListener(host, port)
    await listener.start()
    log.info("Listening for OOB callbacks… press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await listener.stop()
        if listener.hits:
            log.info("Captured %d hits:", len(listener.hits))
            for h in listener.hits:
                log.info("  %s  %s  %s", h["timestamp"], h["remote"], h["path"])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OOB Callback Listener")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()
    asyncio.run(_run_listener(args.host, args.port))
