"""Subdomain discovery, DNS resolution, and HTTP host probing for JSFinder."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from jsfinder.http import SafeHttpClient
from jsfinder.models import HostProbeResult, SubdomainFinding
from jsfinder.scope import ScopeManager

logger = logging.getLogger("jsfinder.subdomains")

# Title regex from HTML response
TITLE_REGEX = re.compile(r"""<title[^>]*>(.*?)</title>""", re.IGNORECASE | re.DOTALL)

# Default active subdomain wordlist for --active-subdomains
DEFAULT_ACTIVE_PREFIXES = [
    "www",
    "api",
    "app",
    "dev",
    "stage",
    "staging",
    "test",
    "admin",
    "portal",
    "auth",
    "login",
    "mail",
    "corp",
    "vpn",
    "cdn",
    "static",
    "assets",
    "beta",
    "v1",
    "v2",
    "docs",
    "internal",
    "status",
    "dashboard",
    "monitor",
    "cloud",
    "mobile",
    "secure",
    "gateway",
    "ws",
    "backend",
    "prod",
    "demo",
    "direct",
]


class SubdomainDiscoverer:
    """Discovers subdomains using passive CT logs and optional active DNS resolution."""

    def __init__(
        self,
        domain: str,
        scope_manager: ScopeManager,
        enable_active: bool = False,
        active_wordlist: Optional[List[str]] = None,
        dns_timeout: float = 2.5,
    ):
        self.domain = domain.lower().strip(".")
        if self.domain.startswith("www."):
            self.domain = self.domain[4:]

        self.scope_manager = scope_manager
        self.enable_active = enable_active
        self.active_wordlist = active_wordlist or DEFAULT_ACTIVE_PREFIXES
        self.dns_timeout = dns_timeout

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.timeout = self.dns_timeout
        self._resolver.lifetime = self.dns_timeout

    async def discover_passive_crtsh(self) -> List[str]:
        """Query Certificate Transparency logs via crt.sh."""
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; JSFinder/1.0; +https://github.com)",
            "Accept": "application/json",
        }

        logger.info(f"Querying crt.sh CT logs for domain: {self.domain}")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list):
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                for name in name_value.split("\n"):
                                    name = name.strip().lower().lstrip("*.")
                                    # Scope check
                                    if name and self.scope_manager.is_in_scope(name):
                                        subdomains.add(name)
                    except Exception as e:
                        logger.debug(f"Failed to parse crt.sh JSON: {e}")
                else:
                    logger.debug(f"crt.sh returned status code {resp.status_code}")
        except Exception as e:
            logger.info(f"crt.sh query unavailable or timed out: {e}")

        logger.info(f"crt.sh returned {len(subdomains)} unique in-scope subdomains")
        return sorted(list(subdomains))

    async def resolve_host(self, hostname: str) -> Tuple[str, List[str]]:
        """Resolve A/AAAA DNS records for a hostname."""
        ips: List[str] = []
        try:
            # Resolve IPv4
            try:
                answers = await self._resolver.resolve(hostname, "A")
                for rdata in answers:
                    ips.append(rdata.to_text())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass

            # Resolve IPv6 if no IPv4
            if not ips:
                try:
                    answers = await self._resolver.resolve(hostname, "AAAA")
                    for rdata in answers:
                        ips.append(rdata.to_text())
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    pass
        except Exception as e:
            logger.debug(f"DNS resolution error for {hostname}: {e}")

        # Fallback to system getaddrinfo if resolver returned empty
        if not ips:
            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(hostname, None)
                for item in addr_info:
                    sockaddr = item[4]
                    ip = sockaddr[0]
                    if ip not in ips:
                        ips.append(ip)
            except Exception:
                pass

        return hostname, sorted(list(set(ips)))

    async def run_active_enumeration(self) -> List[str]:
        """Perform active DNS enumeration using wordlist if enabled."""
        if not self.enable_active:
            return []

        logger.info(f"Starting active subdomain enumeration with {len(self.active_wordlist)} words")
        candidates = [f"{prefix}.{self.domain}" for prefix in self.active_wordlist]
        in_scope_candidates = [c for c in candidates if self.scope_manager.is_in_scope(c)]

        # Bound concurrent DNS queries
        semaphore = asyncio.Semaphore(10)

        async def _check(sub: str) -> Optional[str]:
            async with semaphore:
                _, ips = await self.resolve_host(sub)
                if ips:
                    return sub
            return None

        tasks = [_check(cand) for cand in in_scope_candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found = [r for r in results if isinstance(r, str) and r]
        logger.info(f"Active enumeration found {len(found)} live subdomains")
        return found

    async def run_discovery(self) -> List[SubdomainFinding]:
        """Run full subdomain discovery workflow and resolve IPs."""
        findings: List[SubdomainFinding] = []
        discovered_map: dict[str, str] = {}  # hostname -> source

        # Always include the base target domain
        if self.scope_manager.is_in_scope(self.domain):
            discovered_map[self.domain] = "target"

        # 1. Passive CT logs
        crt_subs = await self.discover_passive_crtsh()
        for sub in crt_subs:
            if sub not in discovered_map:
                discovered_map[sub] = "crt.sh"

        # 2. Active enumeration (if enabled)
        if self.enable_active:
            active_subs = await self.run_active_enumeration()
            for sub in active_subs:
                if sub not in discovered_map:
                    discovered_map[sub] = "active_dns"

        # 3. Resolve all discovered hostnames
        resolve_tasks = [self.resolve_host(host) for host in discovered_map.keys()]
        resolved_pairs = await asyncio.gather(*resolve_tasks, return_exceptions=True)

        for item in resolved_pairs:
            if isinstance(item, tuple):
                host, ips = item
                source = discovered_map.get(host, "passive")
                findings.append(
                    SubdomainFinding(
                        hostname=host,
                        source=source,
                        ips=ips,
                        is_live=len(ips) > 0,
                    )
                )

        return findings


class HostProber:
    """Probes HTTP and HTTPS ports for discovered hosts."""

    def __init__(self, http_client: SafeHttpClient, scope_manager: ScopeManager):
        self.http_client = http_client
        self.scope_manager = scope_manager

    async def probe_url(self, url: str) -> Optional[HostProbeResult]:
        """Probe a specific full URL and record its HTTP response."""
        if not self.scope_manager.is_in_scope(url):
            return None

        resp = await self.http_client.get(url)
        if not resp:
            return None

        title: Optional[str] = None
        if "html" in resp.content_type:
            m = TITLE_REGEX.search(resp.text)
            if m:
                title = m.group(1).strip()

        return HostProbeResult(
            url=url,
            status=resp.status_code,
            final_url=resp.final_url,
            content_type=resp.content_type,
            content_length=resp.content_length,
            response_time=round(resp.elapsed, 3),
            server=resp.server,
            title=title,
        )

    async def probe_host(self, hostname: str, port: Optional[int] = None) -> List[HostProbeResult]:
        """Probe HTTPS and HTTP endpoints for a hostname."""
        results: List[HostProbeResult] = []
        if not hostname:
            return results

        host_str = f"{hostname}:{port}" if port and port not in (80, 443) else hostname

        # Try HTTPS first, then HTTP
        protocols = ["https", "http"]
        for proto in protocols:
            url = f"{proto}://{host_str}"
            probe = await self.probe_url(url)
            if probe:
                results.append(probe)
            else:
                logger.debug(f"Host probe failed or timed out for {url}")

        return results
