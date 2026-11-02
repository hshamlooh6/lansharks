import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import sys
import urllib.parse
from contextlib import contextmanager
from http.cookies import CookieError, SimpleCookie

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "python.db")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
SESSION_HOURS = 8

NAV = """<header class="site-header">
  <a class="brand" href="index.html">LAN SHARKS</a>
  <nav>
    <a href="index.html">Home</a>
    <a href="index.html#services">Services</a>
    <a href="index.html#threats">Threats</a>
    <a href="contact.html">Contact</a>
    <a href="index.html#about">About</a>
    <a href="login.html">Login</a>
  </nav>
</header>"""

esc = html.escape


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${digest.hex()}"


def check_password(password, stored):
    salt = stored.split("$", 1)[0]
    return hmac.compare_digest(hash_password(password, salt), stored)


def is_post():
    return os.environ.get("REQUEST_METHOD", "GET").upper() == "POST"


def read_form():
    fields = urllib.parse.parse_qs(os.environ.get("QUERY_STRING", ""), keep_blank_values=True)
    if is_post():
        length = int(os.environ.get("CONTENT_LENGTH") or 0)
        body = sys.stdin.buffer.read(length).decode("utf-8", "replace")
        fields.update(urllib.parse.parse_qs(body, keep_blank_values=True))
    return {key: values[0] for key, values in fields.items()}


def respond(body, status="200 OK", headers=()):
    head = "\n".join([f"Status: {status}", "Content-Type: text/html; charset=utf-8", *headers])
    sys.stdout.buffer.write(f"{head}\n\n{body}".encode("utf-8"))


def redirect(location, headers=()):
    head = "\n".join(["Status: 303 See Other", f"Location: {location}", *headers])
    sys.stdout.buffer.write(f"{head}\n\n".encode("utf-8"))


def page(title, content):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | LAN Sharks</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
{NAV}
<main>
<section class="panel">
{content}
</section>
</main>
</body>
</html>"""


def show_message(title, text, link, action, status="200 OK"):
    parts = [f"<h1>{esc(title)}</h1>"]
    if text:
        parts.append(f"<p>{esc(text)}</p>")
    parts.append(f'<p>Click <a href="{link}">here</a> {esc(action)}</p>')
    respond(page(title, "\n".join(parts)), status)


def start_session(username):
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE created < datetime('now', ?)", (f"-{SESSION_HOURS} hours",))
        conn.execute(
            "INSERT INTO sessions (token, username, created) VALUES (?, ?, datetime('now'))",
            (token, username),
        )
    return f"Set-Cookie: session={token}; HttpOnly; SameSite=Lax"


def session_token():
    try:
        cookie = SimpleCookie(os.environ.get("HTTP_COOKIE", ""))
    except CookieError:
        return None
    morsel = cookie.get("session")
    return morsel.value if morsel else None


def current_user():
    token = session_token()
    if not token:
        return None
    with db() as conn:
        return conn.execute(
            """SELECT u.* FROM sessions s
               JOIN users u ON u.username = s.username
               WHERE s.token = ? AND s.created >= datetime('now', ?)""",
            (token, f"-{SESSION_HOURS} hours"),
        ).fetchone()


def end_session():
    token = session_token()
    if token:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return "Set-Cookie: session=; Max-Age=0; HttpOnly; SameSite=Lax"


def require_user():
    user = current_user()
    if user is None:
        redirect("login.html")
        sys.exit()
    return user


def load_person(user):
    with db() as conn:
        if user["type"] == "e":
            return conn.execute("SELECT * FROM employees WHERE username = ?", (user["username"],)).fetchone()
        return conn.execute("SELECT * FROM customers WHERE customerNumber = ?", (user["customerNumber"],)).fetchone()


def full_name(person):
    return f"{person['firstName']} {person['lastName']}"
