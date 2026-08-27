"""Per-host rate limiting, concurrency control, and backoff handling for JSFinder."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from email.utils import parsedate_to_datetime
import logging
import random
import time
from typing import AsyncGenerator, Dict, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("jsfinder.ratelimit")


class HostBucket:
    """Tracks token bucket rate limit and backoff state for an individual host."""

    def __init__(self, host: str, rate: float = 2.0, delay: float = 0.5, jitter: bool = False):
        self.host = host
        self.rate = max(0.1, rate)  # Requests per second
        self.delay = max(0.0, delay)  # Min seconds between requests
        self.jitter = jitter

        # Token bucket state
        self.capacity = max(1.0, self.rate)
        self.tokens = self.capacity
        self.fill_rate = self.rate
        self.last_update = time.monotonic()
        self.last_request_time = 0.0

        # Backoff / 429 state
        self.consecutive_429 = 0
        self.backoff_until = 0.0

        # Host-level lock to coordinate requests to this host
        self.lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now

    async def wait_permission(self) -> None:
        """Wait until this host is allowed to make another request."""
        async with self.lock:
            # 1. Handle active 429 / Retry-After backoff
            now = time.monotonic()
            if self.backoff_until > now:
                wait_backoff = self.backoff_until - now
                logger.info(f"[{self.host}] Rate limit backoff active; waiting {wait_backoff:.2f}s")
                await asyncio.sleep(wait_backoff)

            # 2. Enforce minimum inter-request delay
            now = time.monotonic()
            elapsed_since_last = now - self.last_request_time
            if elapsed_since_last < self.delay:
                wait_delay = self.delay - elapsed_since_last
                if self.jitter and self.delay > 0:
                    wait_delay += random.uniform(0.01, min(0.2, self.delay * 0.25))
                await asyncio.sleep(wait_delay)

            # 3. Token bucket check
            self._refill()
            if self.tokens < 1.0:
                deficit = 1.0 - self.tokens
                wait_token = deficit / self.fill_rate
                if self.jitter:
                    wait_token += random.uniform(0.01, 0.05)
                await asyncio.sleep(wait_token)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

            # 4. Update last request time
            self.last_request_time = time.monotonic()

    def handle_response(self, status_code: int, retry_after: Optional[str] = None) -> None:
        """Update backoff state based on response status."""
        if status_code == 429:
            self.consecutive_429 += 1
            backoff_secs: float = 0.0

            # Check Retry-After header
            if retry_after:
                try:
                    # Integer seconds
                    backoff_secs = float(retry_after.strip())
                except ValueError:
                    # HTTP date
                    try:
                        dt = parsedate_to_datetime(retry_after.strip())
                        diff = dt.timestamp() - time.time()
                        backoff_secs = max(1.0, diff)
                    except Exception:
                        backoff_secs = 0.0

            # Fallback to bounded exponential backoff
            if backoff_secs <= 0.0:
                # 2s, 4s, 8s, up to max 30s
                backoff_secs = min(30.0, 2.0 * (2 ** (self.consecutive_429 - 1)))

            # Cap maximum backoff to 60 seconds to avoid stall
            backoff_secs = min(60.0, max(1.0, backoff_secs))
            self.backoff_until = time.monotonic() + backoff_secs
            logger.warning(
                f"[{self.host}] HTTP 429 received (count={self.consecutive_429}). Backing off for {backoff_secs:.1f}s"
            )
        elif 200 <= status_code < 400:
            # Successful response, reset consecutive 429 counter
            if self.consecutive_429 > 0:
                self.consecutive_429 = 0
                self.backoff_until = 0.0


class PerHostRateLimiter:
    """Manages per-host rate limiters and global request concurrency."""

    def __init__(
        self,
        rate: float = 2.0,
        concurrency: int = 3,
        delay: float = 0.5,
        jitter: bool = False,
    ):
        self.rate = rate
        self.concurrency = max(1, concurrency)
        self.delay = delay
        self.jitter = jitter

        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._buckets: Dict[str, HostBucket] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def extract_host(url_or_host: str) -> str:
        """Extract normalized host name from URL or host string."""
        if not url_or_host:
            return "unknown"
        if "://" in url_or_host or url_or_host.startswith("//"):
            try:
                parsed = urlsplit(url_or_host if "://" in url_or_host else "http:" + url_or_host)
                host = parsed.hostname or url_or_host
            except Exception:
                host = url_or_host
        else:
            host = url_or_host.split("/")[0].split(":")[0]
        return host.strip().lower()

    async def get_bucket(self, host: str) -> HostBucket:
        """Get or create the rate limiter bucket for a given host."""
        async with self._lock:
            if host not in self._buckets:
                self._buckets[host] = HostBucket(
                    host=host,
                    rate=self.rate,
                    delay=self.delay,
                    jitter=self.jitter,
                )
            return self._buckets[host]

    @asynccontextmanager
    async def acquire(self, url_or_host: str) -> AsyncGenerator[HostBucket, None]:
        """Acquire both global concurrency slot and host-level rate limit slot."""
        host = self.extract_host(url_or_host)
        bucket = await self.get_bucket(host)

        # Acquire global concurrency semaphore
        async with self._semaphore:
            # Enforce per-host rate limiting and delay
            await bucket.wait_permission()
            yield bucket

    def report_response(self, url_or_host: str, status_code: int, retry_after: Optional[str] = None) -> None:
        """Report response code to update host rate limiting backoff if needed."""
        host = self.extract_host(url_or_host)
        if host not in self._buckets:
            self._buckets[host] = HostBucket(
                host=host,
                rate=self.rate,
                delay=self.delay,
                jitter=self.jitter,
            )
        self._buckets[host].handle_response(status_code, retry_after)
