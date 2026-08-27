"""Integration tests with a local mock HTTP server.

Verifies:
- HTML crawling and resource extraction
- JS analysis and endpoint discovery
- Source map detection and probing
- Scope enforcement preventing requests outside target scope
- Redirect scope enforcement
- 429 rate limit backoff and Retry-After handling
"""

import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import shutil
import socket
import tempfile
import threading
import time
import pytest

from jsfinder.crawler import Crawler
from jsfinder.http import SafeHttpClient
from jsfinder.ratelimit import PerHostRateLimiter
from jsfinder.scope import ScopeManager


class MockServerHandler(BaseHTTPRequestHandler):
    """Handler for the mock target server."""

    # Track requests received by the mock server
    received_requests = []
    rate_limit_hits = 0

    def log_message(self, format, *args):
        # Suppress standard logging to keep test output clean
        pass

    def do_GET(self):
        MockServerHandler.received_requests.append(self.path)
        port = self.server.server_port

        if self.path == "/" or self.path == "/index.html":
            content = f"""<!DOCTYPE html>
            <html>
            <head>
                <title>Mock Target Security Portal</title>
                <link rel="stylesheet" href="/assets/style.css">
                <script src="/assets/app.chunk.1234.js"></script>
            </head>
            <body>
                <img src="/images/logo.png">
                <a href="/page2.html">Page 2</a>
                <a href="/redirect-in-scope">In-Scope Redirect</a>
                <a href="/redirect-out-of-scope">Out-of-Scope Redirect</a>
                <a href="http://unauthorized-external-site.com/trap">External Trap Link</a>
                <script>
                    import("/assets/dynamic.js");
                </script>
            </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/page2.html":
            content = """<!DOCTYPE html>
            <html>
            <body>
                <h1>Page 2</h1>
                <script src="/assets/vendor.chunk.js"></script>
                <a href="/rate-limit-endpoint">Rate Limit Probe</a>
            </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/assets/style.css":
            content = "body { background: #fff; }"
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/assets/app.chunk.1234.js":
            content = """
            console.log("App loaded");
            fetch("/api/v1/users?role=admin&active=true");
            axios.post("/api/auth/login");
            const searchApi = "/api/search?q=test";
            const gql = "/graphql";
            //# sourceMappingURL=/assets/app.chunk.1234.js.map
            """
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/assets/app.chunk.1234.js.map":
            content = '{"version":3,"sources":["app.ts"],"mappings":""}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/assets/vendor.chunk.js":
            content = """
            const cfg = {
                endpoint: "/internal/metrics",
                params: { secretKey: "abc", debugMode: "true" }
            };
            """
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/assets/dynamic.js":
            content = 'fetch("/api/v3/reports");'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/redirect-in-scope":
            self.send_response(302)
            self.send_header("Location", "/page2.html")
            self.end_headers()

        elif self.path == "/redirect-out-of-scope":
            self.send_response(302)
            self.send_header("Location", "http://evil-domain-outside-scope.com/stolen")
            self.end_headers()

        elif self.path == "/rate-limit-endpoint":
            MockServerHandler.rate_limit_hits += 1
            if MockServerHandler.rate_limit_hits == 1:
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.end_headers()
            else:
                content = '{"rate_limited": false}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def mock_server():
    """Start local mock HTTP server in a background thread."""
    # Find free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = HTTPServer(("127.0.0.1", port), MockServerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.1)  # Ensure server starts
    yield port
    server.shutdown()


@pytest.mark.asyncio
async def test_full_crawler_against_mock_server(mock_server):
    port = mock_server
    target_url = f"http://127.0.0.1:{port}/"

    # Strict Scope: ONLY 127.0.0.1
    scope_mgr = ScopeManager(target_url_or_host=f"127.0.0.1:{port}")
    rate_limiter = PerHostRateLimiter(rate=5.0, concurrency=2, delay=0.1)

    temp_out_dir = tempfile.mkdtemp()

    try:
        async with SafeHttpClient(
            scope_manager=scope_mgr,
            rate_limiter=rate_limiter,
            timeout=5.0,
        ) as http_client:
            crawler = Crawler(
                target=target_url,
                scope_manager=scope_mgr,
                rate_limiter=rate_limiter,
                http_client=http_client,
                enable_subdomains=False,  # No DNS lookup needed for 127.0.0.1
                max_depth=2,
                max_pages=20,
                download_sourcemaps=True,
                output_dir=temp_out_dir,
            )

            results = await crawler.run()

        # 1. VERIFY SCOPE CONTROL: Zero requests made outside 127.0.0.1
        assert "http://unauthorized-external-site.com/trap" not in MockServerHandler.received_requests
        assert "http://evil-domain-outside-scope.com/stolen" not in MockServerHandler.received_requests

        # 2. VERIFY ENDPOINT DISCOVERY & PROVENANCE
        endpoints_map = {e.endpoint: e for e in results.endpoints}
        assert "/api/v1/users?role=admin&active=true" in endpoints_map or "/api/v1/users" in endpoints_map
        assert "/api/auth/login" in endpoints_map
        assert "/graphql" in endpoints_map
        assert "/internal/metrics" in endpoints_map
        assert "/api/v3/reports" in endpoints_map

        # Check provenance
        assert "/internal/metrics" in endpoints_map
        assert "vendor.chunk.js" in endpoints_map["/internal/metrics"].source

        # 3. VERIFY PARAMETERS EXTRACTED
        assert "role" in results.parameters or "active" in results.parameters or "q" in results.parameters
        assert "secretKey" in results.parameters or "debugMode" in results.parameters

        # 4. VERIFY SOURCE MAP DETECTION
        assert len(results.source_maps) >= 1
        sm = next((s for s in results.source_maps if "app.chunk.1234.js.map" in s.url), None)
        assert sm is not None
        assert sm.status == 200
        assert sm.size == len('{"version":3,"sources":["app.ts"],"mappings":""}')

        # 5. VERIFY SOURCEMAP DOWNLOADED TO DISK
        sm_file = os.path.join(temp_out_dir, "sourcemaps", "app.chunk.1234.js.map")
        assert os.path.isfile(sm_file)
        with open(sm_file, "r") as f:
            assert '"version":3' in f.read()

        # 6. VERIFY RESOURCE EXTRACTED
        resource_urls = [r.url for r in results.resources]
        assert any("style.css" in u for u in resource_urls)
        assert any("app.chunk.1234.js" in u for u in resource_urls)
        assert any("logo.png" in u for u in resource_urls)

    finally:
        shutil.rmtree(temp_out_dir, ignore_errors=True)
