"""Read-only workspace regression checks.

These tests do not make any external network connection or scan applications.
"""
from __future__ import annotations

from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ahmad_sec.workspace import ASSETS, CSP, WorkspaceHandler


@pytest.fixture
def local_workspace():
    server = ThreadingHTTPServer(("127.0.0.1", 0), WorkspaceHandler)
    runner = Thread(target=server.serve_forever, daemon=True)
    runner.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        runner.join(timeout=2)
        server.server_close()


@pytest.mark.parametrize("path,content_type", [
    ("/", "text/html"),
    ("/workspace.css", "text/css"),
    ("/workspace.js", "text/javascript"),
])
def test_bundled_assets_return_correct_type(local_workspace, path, content_type):
    with urlopen(local_workspace + path, timeout=2) as response:
        assert response.status == 200
        assert content_type in response.headers["Content-Type"]
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Content-Security-Policy"] == CSP
        assert len(response.read()) > 20


@pytest.mark.parametrize("path", ["/api/scan", "/../../etc/passwd", "/secret", "/workspace.js/../../x"])
def test_unknown_routes_are_not_served(local_workspace, path):
    request = Request(local_workspace + path)
    with pytest.raises(HTTPError) as caught:
        urlopen(request, timeout=2)
    assert caught.value.code == 404


def test_server_disallows_post(local_workspace):
    request = Request(local_workspace, data=b'{"apk":"not allowed"}', method="POST")
    with pytest.raises(HTTPError) as caught:
        urlopen(request, timeout=2)
    assert caught.value.code == 405


def test_exact_allowlist():
    assert set(ASSETS) == {"/", "/workspace.css", "/workspace.js"}
    assert "connect-src 'none'" in CSP
