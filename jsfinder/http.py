"""Asynchronous HTTP client with scope enforcement, per-host rate limiting, and safe redirect following."""

from __future__ import annotations

import logging
import ssl
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from jsfinder.ratelimit import PerHostRateLimiter
from jsfinder.scope import ScopeManager

logger = logging.getLogger("jsfinder.http")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 JSFinder/1.0"
)


class SafeResponse:
    """Wrapper around HTTP response data."""

    def __init__(
        self,
        url: str,
        final_url: str,
        status_code: int,
        headers: Dict[str, str],
        content: bytes,
        elapsed: float,
        redirect_history: Optional[List[str]] = None,
        redirect_blocked: Optional[str] = None,
    ):
        self.url = url
        self.final_url = final_url
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.elapsed = elapsed
        self.redirect_history = redirect_history or []
        self.redirect_blocked = redirect_blocked

    @property
    def text(self) -> str:
        """Decode content with fallback to latin-1."""
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return self.content.decode("latin-1")
            except Exception:
                return self.content.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def content_length(self) -> int:
        header_len = self.headers.get("content-length")
        if header_len and header_len.isdigit():
            return int(header_len)
        return len(self.content)

    @property
    def server(self) -> Optional[str]:
        return self.headers.get("server")


class SafeHttpClient:
    """HTTP client that enforces scope rules and per-host rate limits on every request."""

    def __init__(
        self,
        scope_manager: ScopeManager,
        rate_limiter: PerHostRateLimiter,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = True,
        max_redirects: int = 5,
        max_response_size: int = 10 * 1024 * 1024,  # 10 MB limit
    ):
        self.scope_manager = scope_manager
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.max_redirects = max_redirects
        self.max_response_size = max_response_size

        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> SafeHttpClient:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self._client = httpx.AsyncClient(
            headers=headers,
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout, connect=min(4.0, self.timeout)),
            follow_redirects=False,  # Redirects manually checked against scope
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            await self._client.aclose()

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[SafeResponse]:
        """Perform a safe GET request with scope checks and per-host rate limiting."""
        return await self.request("GET", url, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[SafeResponse]:
        """Perform an HTTP request with strict scope and rate limiting validation."""
        # 1. SCOPE CHECK: Ensure the initial target URL is strictly in-scope
        if not self.scope_manager.is_in_scope(url):
            logger.warning(f"[SCOPE REJECTED] Cannot make request to out-of-scope URL: {url}")
            return None

        if self._client is None:
            raise RuntimeError("SafeHttpClient must be used within an 'async with' context")

        current_url = url
        redirect_history: List[str] = []
        redirect_blocked: Optional[str] = None

        hops = 0
        while hops <= self.max_redirects:
            # Check scope on current_url (crucial for redirect hops)
            if not self.scope_manager.is_in_scope(current_url):
                logger.warning(
                    f"[SCOPE REDIRECT BLOCKED] Aborting redirect to out-of-scope URL: {current_url}"
                )
                redirect_blocked = current_url
                break

            # Per-host rate limiting and concurrency gate
            start_time = time.monotonic()
            try:
                async with self.rate_limiter.acquire(current_url):
                    req_headers = headers or {}
                    response = await self._client.request(
                        method=method,
                        url=current_url,
                        headers=req_headers,
                    )
            except (httpx.ConnectError, ssl.SSLError) as e:
                logger.debug(f"Connection/TLS error for {current_url}: {e}")
                return None
            except httpx.TimeoutException as e:
                logger.debug(f"Timeout requesting {current_url}: {e}")
                return None
            except httpx.RequestError as e:
                logger.debug(f"Request error for {current_url}: {e}")
                return None
            except Exception as e:
                logger.debug(f"Unexpected HTTP error for {current_url}: {e}")
                return None

            elapsed = time.monotonic() - start_time

            # Report response to rate limiter (e.g. for 429 and Retry-After)
            retry_after = response.headers.get("retry-after")
            self.rate_limiter.report_response(current_url, response.status_code, retry_after)

            # Check if this is a redirect
            if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
                location = response.headers["location"]
                next_url = urljoin(current_url, location)
                redirect_history.append(current_url)
                hops += 1

                # Check if the next redirect target is within scope
                if not self.scope_manager.is_in_scope(next_url):
                    logger.warning(
                        f"[SCOPE REDIRECT BLOCKED] Redirect target {next_url} is out of scope. Stopping redirect chain."
                    )
                    # Return the redirect response but do not follow to out-of-scope target
                    content = response.content[:self.max_response_size]
                    headers_dict = {k.lower(): v for k, v in response.headers.items()}
                    return SafeResponse(
                        url=url,
                        final_url=current_url,
                        status_code=response.status_code,
                        headers=headers_dict,
                        content=content,
                        elapsed=elapsed,
                        redirect_history=redirect_history,
                        redirect_blocked=next_url,
                    )

                # In-scope redirect: follow to next hop
                current_url = next_url
                continue

            # Non-redirect response or final hop reached
            content = response.content[:self.max_response_size]
            headers_dict = {k.lower(): v for k, v in response.headers.items()}
            return SafeResponse(
                url=url,
                final_url=current_url,
                status_code=response.status_code,
                headers=headers_dict,
                content=content,
                elapsed=elapsed,
                redirect_history=redirect_history,
                redirect_blocked=redirect_blocked,
            )

        # Reached max redirects
        logger.warning(f"Exceeded max redirects ({self.max_redirects}) for {url}")
        return None
