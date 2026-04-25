"""
demo_target.py — Intentionally Vulnerable Demo Application

A minimal Flask app with deliberately vulnerable endpoints for testing the scanner.
DO NOT deploy on public-facing infrastructure.

Vulnerabilities included (for demo/learning purposes only):
  - SQL Injection (simulated error + boolean responses)
  - Reflected XSS
  - Path traversal / LFI (simulated)
  - SSRF (simulated)
  - Header injection (echo endpoint)
  - Open redirect

Run:
    pip install flask
    python demo_target.py

Then scan:
    python scanner.py --url http://127.0.0.1:5000 --depth 2 --concurrency 5
"""

from flask import Flask, request, render_template_string, redirect, make_response
import os

app = Flask(__name__)

# ── HTML template helper ───────────────────────────────────────────────────────

BASE = """<!DOCTYPE html>
<html>
<head><title>Demo Vulnerable App</title>
<style>
  body {{ font-family: monospace; background:#1a1a2e; color:#e0e0e0; padding:2rem; }}
  a {{ color:#00d4ff; }} h1 {{ color:#ff6b6b; }}
  pre {{ background:#0d0d1a; padding:1rem; border-radius:5px; overflow:auto; }}
  input,select {{ background:#0d0d1a; color:#e0e0e0; border:1px solid #444; padding:4px 8px; }}
  button {{ background:#ff6b6b; color:#fff; border:none; padding:6px 16px; cursor:pointer; border-radius:3px; }}
</style>
</head>
<body>
<h1>🎯 Demo Vulnerable App</h1>
<p><em>For scanner testing only — not for public deployment</em></p>
<hr>
<h3>Pages</h3>
<ul>
  <li><a href="/search?q=hello">Search (Reflected XSS)</a></li>
  <li><a href="/user?id=1">User Lookup (SQLi)</a></li>
  <li><a href="/file?name=readme.txt">File View (LFI)</a></li>
  <li><a href="/fetch?url=http://example.com">URL Fetch (SSRF)</a></li>
  <li><a href="/redirect?to=http://example.com">Redirect (Open Redirect)</a></li>
  <li><a href="/login">Login Form</a></li>
  <li><a href="/comment">Comment Form (Stored XSS sim)</a></li>
  <li><a href="/headers">Header Echo</a></li>
</ul>
{content}
</body>
</html>"""


def page(content: str) -> str:
    return BASE.format(content=content)


# ── Index ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return page("")


# ── Reflected XSS ─────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: user input reflected without escaping
    content = f"""
    <h3>Search Results for: {q}</h3>
    <form method="GET">
      <input name="q" value="{q}" size="40">
      <button>Search</button>
    </form>
    <p>No results found.</p>
    """
    return page(content)


# ── SQL Injection ─────────────────────────────────────────────────────────────

FAKE_USERS = {
    "1": {"name": "Alice Admin", "email": "alice@example.com", "role": "admin"},
    "2": {"name": "Bob User",    "email": "bob@example.com",   "role": "user"},
}

@app.route("/user")
def user():
    uid = request.args.get("id", "1")

    # VULNERABLE: simulates SQLi detection
    sql_error_triggers = ["'", '"', "--", "/*", "UNION", "SELECT", "OR 1=1", "SLEEP"]
    for trigger in sql_error_triggers:
        if trigger.lower() in uid.lower():
            # Simulate DB error
            content = f"""
            <h3>User Lookup</h3>
            <pre style="color:#ff4444">
You have an error in your SQL syntax; check the manual that corresponds to your
MySQL server version for the right syntax to use near '{uid}' at line 1
Warning: mysql_fetch_array() expects parameter 1 to be resource
            </pre>"""
            return page(content)

    user_data = FAKE_USERS.get(uid, None)
    if user_data:
        content = f"""
        <h3>User: {user_data['name']}</h3>
        <p>Email: {user_data['email']}</p>
        <p>Role:  {user_data['role']}</p>
        <form method="GET">ID: <input name="id" value="{uid}"> <button>Lookup</button></form>
        """
    else:
        # Boolean-blind sim: empty response for invalid IDs
        content = f"<h3>No user found for id={uid}</h3>"

    return page(content)


# ── LFI / Path traversal ──────────────────────────────────────────────────────

@app.route("/file")
def file_view():
    name = request.args.get("name", "readme.txt")

    # VULNERABLE: simulates LFI detection
    lfi_triggers = [
        "../", "..\\", "/etc/passwd", "/etc/shadow",
        "win.ini", "boot.ini", "%2e%2e", "proc/self",
    ]
    for trigger in lfi_triggers:
        if trigger.lower() in name.lower():
            # Simulate /etc/passwd being returned
            content = f"""
            <h3>File: {name}</h3>
            <pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</pre>"""
            return page(content)

    content = f"""
    <h3>File: {name}</h3>
    <pre>This is the contents of {name}.
    It is a safe demo file.</pre>
    <form method="GET"><input name="name" value="{name}"> <button>View</button></form>
    """
    return page(content)


# ── SSRF ──────────────────────────────────────────────────────────────────────

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")

    ssrf_triggers = [
        "127.0.0.1", "localhost", "169.254.169.254",
        "10.", "192.168.", "172.16.", "0.0.0.0", "::1",
        "file://", "dict://", "gopher://",
    ]
    for trigger in ssrf_triggers:
        if trigger.lower() in url.lower():
            content = f"""
            <h3>Fetch: {url}</h3>
            <pre>ami-id: ami-0abcdef1234567890
instance-id: i-0a1b2c3d4e5f67890
hostname: ip-10-0-0-1.ec2.internal
iam/security-credentials/EC2-role</pre>"""
            return page(content)

    content = f"""
    <h3>URL Fetcher</h3>
    <form method="GET">
      URL: <input name="url" value="{url}" size="50"> <button>Fetch</button>
    </form>
    <p>Enter a URL to fetch its content.</p>
    """
    return page(content)


# ── Open Redirect ──────────────────────────────────────────────────────────────

@app.route("/redirect")
def open_redirect():
    target = request.args.get("to", "/")
    # VULNERABLE: unvalidated redirect
    return redirect(target)


# ── Login Form ────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Simulate SQLi in login
        sqli_chars = ["'", '"', "--", "OR 1=1", "/*"]
        for c in sqli_chars:
            if c.lower() in username.lower() or c.lower() in password.lower():
                msg = f"""<pre style="color:#ff4444">
MySQL error: You have an error in your SQL syntax near '{username}' at line 1
</pre>"""
                break
        else:
            msg = "<p>Invalid credentials.</p>"

    content = f"""
    <h3>Login</h3>
    {msg}
    <form method="POST">
      <input type="hidden" name="csrf_token" value="demo_token_12345">
      Username: <input name="username" type="text"><br><br>
      Password: <input name="password" type="password"><br><br>
      <button>Login</button>
    </form>
    """
    return page(content)


# ── Comment Form ───────────────────────────────────────────────────────────────

_comments: list[str] = ["Great site!", "Very helpful."]

@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "POST":
        c = request.form.get("comment", "")
        _comments.append(c)

    # VULNERABLE: comments rendered without escaping
    comments_html = "".join(f"<li>{c}</li>" for c in _comments)
    content = f"""
    <h3>Comments</h3>
    <form method="POST">
      <textarea name="comment" rows="3" cols="40"></textarea><br>
      <button>Submit</button>
    </form>
    <ul>{comments_html}</ul>
    """
    return page(content)


# ── Header Echo ────────────────────────────────────────────────────────────────

@app.route("/headers")
def headers_echo():
    xff     = request.headers.get("X-Forwarded-For", "not set")
    ua      = request.headers.get("User-Agent",       "not set")
    referer = request.headers.get("Referer",           "not set")

    # VULNERABLE: XFF reflected without escaping (simulates logging to page)
    content = f"""
    <h3>Header Echo</h3>
    <pre>
X-Forwarded-For : {xff}
User-Agent      : {ua}
Referer         : {referer}
    </pre>
    """
    resp = make_response(page(content))
    # Simulate CRLF vulnerability in a custom header
    resp.headers["X-Your-IP"] = xff
    return resp


# ── JSON API (for parameter discovery testing) ─────────────────────────────────

@app.route("/api/data")
def api_data():
    uid = request.args.get("user_id", "1")
    return {"user_id": uid, "status": "ok", "data": "sample"}


@app.route("/api/load", methods=["POST"])
def api_load():
    payload = request.get_json(silent=True) or {}
    url  = payload.get("url", "")
    path = payload.get("path", "")
    return {"url": url, "path": path, "loaded": True}


if __name__ == "__main__":
    print("\n🎯 Demo Vulnerable App starting on http://127.0.0.1:5000")
    print("   Scan it with: python scanner.py --url http://127.0.0.1:5000 --depth 2\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
