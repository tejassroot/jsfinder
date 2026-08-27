"""Unit tests for PerHostRateLimiter, concurrency, and 429 backoff."""

import asyncio
import time
import pytest

from jsfinder.ratelimit import PerHostRateLimiter


@pytest.mark.asyncio
async def test_per_host_separation():
    """Verify that rate limits on one host do not block requests to a different host."""
    limiter = PerHostRateLimiter(rate=1.0, delay=1.0, concurrency=5)

    # Acquire host-a
    async with limiter.acquire("https://host-a.com/page1"):
        pass

    # Making a request to host-b immediately should not wait for host-a's 1.0s delay
    start = time.monotonic()
    async with limiter.acquire("https://host-b.com/page1"):
        pass
    elapsed = time.monotonic() - start

    assert elapsed < 0.3, f"host-b took {elapsed:.2f}s; should not be blocked by host-a"


@pytest.mark.asyncio
async def test_per_host_delay_enforcement():
    """Verify that requests to the same host respect the minimum delay."""
    limiter = PerHostRateLimiter(rate=10.0, delay=0.2, concurrency=5)

    start = time.monotonic()
    async with limiter.acquire("https://example.com/1"):
        pass
    async with limiter.acquire("https://example.com/2"):
        pass
    elapsed = time.monotonic() - start

    assert elapsed >= 0.18, f"Two requests to same host took {elapsed:.2f}s, expected >= 0.18s"


@pytest.mark.asyncio
async def test_concurrency_limiting():
    """Verify that global concurrency does not exceed specified limit."""
    concurrency_limit = 2
    limiter = PerHostRateLimiter(rate=50.0, delay=0.0, concurrency=concurrency_limit)

    active_count = 0
    max_active = 0
    lock = asyncio.Lock()

    async def worker(idx: int):
        nonlocal active_count, max_active
        async with limiter.acquire(f"https://host-{idx}.com"):
            async with lock:
                active_count += 1
                if active_count > max_active:
                    max_active = active_count
            await asyncio.sleep(0.05)
            async with lock:
                active_count -= 1

    tasks = [worker(i) for i in range(6)]
    await asyncio.gather(*tasks)

    assert max_active <= concurrency_limit


@pytest.mark.asyncio
async def test_rate_limit_429_backoff():
    """Verify that HTTP 429 triggers backoff and Retry-After is respected."""
    limiter = PerHostRateLimiter(rate=10.0, delay=0.0, concurrency=3)

    # Report a 429 with Retry-After: 1
    limiter.report_response("https://example.com/test", 429, retry_after="1")

    bucket = await limiter.get_bucket("example.com")
    assert bucket.consecutive_429 == 1
    assert bucket.backoff_until > time.monotonic()

    # Reset on 200
    limiter.report_response("https://example.com/test", 200)
    assert bucket.consecutive_429 == 0
    assert bucket.backoff_until == 0.0
