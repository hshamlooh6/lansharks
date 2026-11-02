#!/usr/bin/env python3
import os
import subprocess
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
PAGES = {"login.py", "dashboard.py", "contact.py", "change_password.py", "update_contact.py", "logout.py"}
STATIC = {".html", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico"}
PORT = int(os.environ.get("PORT", "8000"))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def route(self):
        url = urlsplit(self.path)
        name = unquote(url.path).lstrip("/") or "index.html"
        if name in PAGES:
            self.run_page(name, url.query)
        elif self.command == "GET" and "/" not in name and os.path.splitext(name)[1].lower() in STATIC:
            super().do_GET()
        else:
            self.send_error(404)

    def run_page(self, name, query):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        env = dict(
            os.environ,
            GATEWAY_INTERFACE="CGI/1.1",
            REQUEST_METHOD=self.command,
            QUERY_STRING=query,
            CONTENT_LENGTH=str(len(body)),
            CONTENT_TYPE=self.headers.get("Content-Type", ""),
            HTTP_COOKIE=self.headers.get("Cookie", ""),
        )
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, name)],
            input=body, capture_output=True, env=env, cwd=ROOT,
        )
        if result.stderr:
            sys.stderr.write(result.stderr.decode("utf-8", "replace"))

        head, _, content = result.stdout.partition(b"\n\n")
        if result.returncode != 0 or not head:
            self.send_error(500)
            return

        status, headers = 200, []
        for line in head.decode("utf-8").splitlines():
            key, _, value = line.partition(":")
            if key.lower() == "status":
                status = int(value.split()[0])
            else:
                headers.append((key, value.strip()))

        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    if not os.path.exists(os.path.join(ROOT, "python.db")):
        subprocess.run([sys.executable, os.path.join(ROOT, "createdatabase.py")], check=True, cwd=ROOT)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"LAN Sharks is running at http://127.0.0.1:{PORT}  (press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
