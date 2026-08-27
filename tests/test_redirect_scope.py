"""Unit tests for redirect scope enforcement."""

import httpx
import pytest

from jsfinder.http import SafeHttpClient
from jsfinder.ratelimit import PerHostRateLimiter
from jsfinder.scope import ScopeManager


class MockRedirectTransport(httpx.AsyncBaseTransport):
    """Mock HTTP transport to test redirect following and scope interception."""

    def __init__(self):
        self.requested_urls = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        self.requested_urls.append(url_str)

        if url_str == "https://example.com/redirect-in-scope":
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://sub.example.com/welcome"},
            )
        elif url_str == "https://sub.example.com/welcome":
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "text/html"},
                content=b"<h1>Welcome</h1>",
            )
        elif url_str == "https://example.com/redirect-out-of-scope":
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://evil-example.com/login"},
            )
        elif url_str == "https://evil-example.com/login":
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "text/html"},
                content=b"<h1>Phishing</h1>",
            )
        return httpx.Response(status_code=404)


@pytest.mark.asyncio
async def test_in_scope_redirect_is_followed():
    scope_mgr = ScopeManager("example.com")
    rate_limiter = PerHostRateLimiter()
    transport = MockRedirectTransport()

    async with SafeHttpClient(scope_mgr, rate_limiter) as client:
        # Patch the underlying httpx client transport
        client._client._transport = transport

        resp = await client.get("https://example.com/redirect-in-scope")
        assert resp is not None
        assert resp.status_code == 200
        assert resp.final_url == "https://sub.example.com/welcome"
        assert "https://example.com/redirect-in-scope" in transport.requested_urls
        assert "https://sub.example.com/welcome" in transport.requested_urls


@pytest.mark.asyncio
async def test_out_of_scope_redirect_is_intercepted_and_blocked():
    scope_mgr = ScopeManager("example.com")
    rate_limiter = PerHostRateLimiter()
    transport = MockRedirectTransport()

    async with SafeHttpClient(scope_mgr, rate_limiter) as client:
        client._client._transport = transport

        resp = await client.get("https://example.com/redirect-out-of-scope")
        assert resp is not None
        # The response returned is the 302 redirect response, and the hop was aborted
        assert resp.status_code == 302
        assert resp.redirect_blocked == "https://evil-example.com/login"

        # CRITICAL: Verify NO network request was ever sent to evil-example.com!
        assert "https://evil-example.com/login" not in transport.requested_urls
        assert not any("evil-example.com" in u for u in transport.requested_urls)
