"""Loopback-only, read-only workspace for locally imported evidence reports.

Reports never pass through this HTTP server: the browser reads JSON with FileReader.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import webbrowser

ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/workspace.css": ("workspace.css", "text/css; charset=utf-8"),
    "/workspace.js": ("workspace.js", "text/javascript; charset=utf-8"),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class WorkspaceHandler(BaseHTTPRequestHandler):
    """Serve only the three bundled assets; no POST, API or filesystem access."""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        asset = ASSETS.get(path)
        if asset is None:
            self.send_error(404)
            return
        name, media_type = asset
        body = files("ahmad_sec").joinpath("assets", name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.send_error(405)

    def log_message(self, format, *args):
        # Avoid printing paths or other user-provided values in logs.
        pass


def serve(*, port: int = 8765, open_browser: bool = True) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("Port must be in the range 1–65535")
    with ThreadingHTTPServer(("127.0.0.1", port), WorkspaceHandler) as server:
        url = f"http://127.0.0.1:{server.server_port}/"
        print(f"AHMAD-IB Security Workspace: {url}")
        print("Only this computer can access the workspace. Press Ctrl+C to stop.")
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
