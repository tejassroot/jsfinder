"""Crawler and discovery coordinator for JSFinder."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from jsfinder.http import SafeHttpClient
from jsfinder.js_analyzer import JavaScriptAnalyzer
from jsfinder.models import (
    DiscoveredEndpoint,
    DiscoveredResource,
    HostProbeResult,
    ScanResults,
    SourceMapFinding,
    SubdomainFinding,
)
from jsfinder.parser import HtmlResourceParser, normalize_url
from jsfinder.ratelimit import PerHostRateLimiter
from jsfinder.scope import ScopeManager
from jsfinder.subdomains import HostProber, SubdomainDiscoverer

logger = logging.getLogger("jsfinder.crawler")


class Crawler:
    """Coordinates subdomain discovery, host probing, HTML crawling, and JS analysis."""

    def __init__(
        self,
        target: str,
        scope_manager: ScopeManager,
        rate_limiter: PerHostRateLimiter,
        http_client: SafeHttpClient,
        enable_subdomains: bool = False,
        enable_active_subdomains: bool = False,
        active_wordlist: Optional[List[str]] = None,
        max_depth: int = 2,
        max_pages: int = 50,
        download_sourcemaps: bool = False,
        output_dir: Optional[str] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ):
        self.target = target
        self.scope_manager = scope_manager
        self.rate_limiter = rate_limiter
        self.http_client = http_client
        self.enable_subdomains = enable_subdomains
        self.enable_active_subdomains = enable_active_subdomains
        self.active_wordlist = active_wordlist
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.download_sourcemaps = download_sourcemaps
        self.output_dir = output_dir
        self.progress_callback = progress_callback

        # Extract normalized base domain
        parsed = urlsplit(self.target)
        self.target_host = parsed.hostname or self.target.split("/")[0].split(":")[0]
        self.target_port = parsed.port
        self.target_domain = self.target_host.lower().lstrip("www.")

        self.js_analyzer = JavaScriptAnalyzer(target_domain=self.target_domain)
        self.subdomain_discoverer = SubdomainDiscoverer(
            domain=self.target_domain,
            scope_manager=self.scope_manager,
            enable_active=self.enable_active_subdomains,
            active_wordlist=self.active_wordlist,
        )
        self.host_prober = HostProber(self.http_client, self.scope_manager)

        # State tracking to avoid duplicate work
        self.visited_urls: Set[str] = set()
        self.visited_js_urls: Set[str] = set()
        self.discovered_resources_map: dict[str, DiscoveredResource] = {}
        self.discovered_endpoints_map: dict[Tuple[str, str], DiscoveredEndpoint] = {}
        self.discovered_parameters: Set[str] = set()
        self.discovered_subdomains_map: dict[str, SubdomainFinding] = {}
        self.probed_hosts_map: dict[str, HostProbeResult] = {}
        self.discovered_sourcemaps_map: dict[str, SourceMapFinding] = {}

    def _log(self, msg: str) -> None:
        logger.info(msg)
        if self.progress_callback:
            self.progress_callback(msg)

    def _register_host_subdomain(self, url_or_host: str, source: str) -> None:
        """Track newly discovered in-scope subdomains."""
        if not url_or_host:
            return
        if "://" in url_or_host or url_or_host.startswith("//"):
            try:
                host = urlsplit(url_or_host if "://" in url_or_host else "http:" + url_or_host).hostname
            except Exception:
                host = None
        else:
            host = url_or_host.split("/")[0].split(":")[0]

        if not host:
            return
        host = host.lower().strip(".")
        if host not in self.discovered_subdomains_map and self.scope_manager.is_in_scope(host):
            self.discovered_subdomains_map[host] = SubdomainFinding(
                hostname=host,
                source=source,
                ips=[],
                is_live=True,
            )

    async def run(self) -> ScanResults:
        """Execute the full discovery and analysis workflow."""
        start_time = datetime.now(timezone.utc).isoformat()
        self._log(f"Starting JSFinder scan on target: {self.target}")
        self._log(f"Active scope: {', '.join(self.scope_manager.get_rules())}")

        # Always register target host
        self._register_host_subdomain(self.target_host, "target")

        # 1. Subdomain Discovery
        if self.enable_subdomains or self.enable_active_subdomains:
            self._log("Discovering subdomains...")
            sub_findings = await self.subdomain_discoverer.run_discovery()
            for sf in sub_findings:
                self.discovered_subdomains_map[sf.hostname] = sf

            self._log(f"Subdomains discovered: {len(self.discovered_subdomains_map)}")

            # Probe discovered live subdomains
            self._log("Probing discovered subdomains...")
            for hostname, finding in list(self.discovered_subdomains_map.items()):
                if finding.is_live or finding.hostname == self.target_host:
                    probes = await self.host_prober.probe_host(hostname)
                    for probe in probes:
                        self.probed_hosts_map[probe.url] = probe
                        finding.is_live = True

        # Always probe the primary target URL / host if not probed yet
        normalized_target = normalize_url(self.target) or self.target
        target_probe = await self.host_prober.probe_url(normalized_target)
        if target_probe:
            self.probed_hosts_map[target_probe.url] = target_probe
        elif not any(h.startswith(self.target) or normalized_target.startswith(h) for h in self.probed_hosts_map):
            self._log(f"Probing target host: {self.target_host}")
            target_probes = await self.host_prober.probe_host(self.target_host, port=self.target_port)
            for probe in target_probes:
                self.probed_hosts_map[probe.url] = probe

        # 2. HTML Crawling & Resource Extraction
        crawl_queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue(maxsize=1000)
        js_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)

        # Seed crawl queue with normalized target URL
        if normalized_target:
            await crawl_queue.put((normalized_target, 0))
            self.visited_urls.add(normalized_target)

        # Also seed with any live HTML hosts discovered
        for host_url, probe in self.probed_hosts_map.items():
            norm_h = normalize_url(host_url)
            if norm_h and norm_h not in self.visited_urls and "html" in probe.content_type:
                if crawl_queue.qsize() < self.max_pages:
                    await crawl_queue.put((norm_h, 0))
                    self.visited_urls.add(norm_h)

        page_count = 0
        self._log("Crawling HTML pages and identifying resources...")

        while not crawl_queue.empty() and page_count < self.max_pages:
            current_url, depth = await crawl_queue.get()
            page_count += 1

            self._log(f"Crawling [{page_count}/{self.max_pages}] (depth {depth}): {current_url}")
            resp = await self.http_client.get(current_url)
            if not resp or resp.status_code >= 400:
                continue

            # If redirected to another URL, record and check
            if resp.final_url and resp.final_url != current_url:
                norm_final = normalize_url(resp.final_url)
                if norm_final:
                    self.visited_urls.add(norm_final)

            # Parse resources if response contains HTML
            content_type = resp.content_type
            if "html" in content_type or not content_type:
                parser = HtmlResourceParser(base_url=resp.final_url or current_url)
                resources, page_links, inline_scripts = parser.parse(resp.text)

                # Store discovered resources
                for res in resources:
                    if res.url not in self.discovered_resources_map:
                        self.discovered_resources_map[res.url] = res
                    self._register_host_subdomain(res.url, "resource_discovery")
                    # If it's a JavaScript file and in-scope, queue it for JS analysis
                    if res.resource_type == "javascript" and self.scope_manager.is_in_scope(res.url):
                        if res.url not in self.visited_js_urls:
                            self.visited_js_urls.add(res.url)
                            await js_queue.put(res.url)

                # Analyze inline scripts immediately
                for idx, script_content in enumerate(inline_scripts):
                    inline_source = f"{current_url}#inline-script-{idx + 1}"
                    js_result = self.js_analyzer.analyze(inline_source, script_content)
                    self._merge_js_results(js_result, js_queue)

                # Enqueue in-scope page links if within depth limit
                if depth < self.max_depth:
                    for link in page_links:
                        norm_link = normalize_url(link, base_url=current_url)
                        if (
                            norm_link
                            and norm_link not in self.visited_urls
                            and self.scope_manager.is_in_scope(norm_link)
                            and crawl_queue.qsize() < self.max_pages
                        ):
                            self.visited_urls.add(norm_link)
                            self._register_host_subdomain(norm_link, "html_crawl")
                            await crawl_queue.put((norm_link, depth + 1))

        # 3. JavaScript Analysis
        self._log(f"Analyzing {js_queue.qsize()} discovered JavaScript files...")
        js_count = 0

        while not js_queue.empty():
            js_url = await js_queue.get()
            js_count += 1

            # Scope check before downloading JS
            if not self.scope_manager.is_in_scope(js_url):
                logger.debug(f"Skipping out-of-scope JS: {js_url}")
                continue

            self._log(f"Analyzing JS [{js_count}]: {js_url}")
            resp = await self.http_client.get(js_url)
            if not resp or resp.status_code >= 400:
                continue

            js_result = self.js_analyzer.analyze(js_url, resp.text)
            self._merge_js_results(js_result, js_queue)

        # 4. Source Map Verification
        self._log(f"Probing {len(self.discovered_sourcemaps_map)} discovered source maps...")
        await self._probe_sourcemaps()

        # Build final ScanResults object
        results = ScanResults(
            target=self.target,
            scan_time=start_time,
            scope=self.scope_manager.get_rules(),
            subdomains=list(self.discovered_subdomains_map.values()),
            hosts=list(self.probed_hosts_map.values()),
            javascript=list(self.visited_js_urls),
            source_maps=list(self.discovered_sourcemaps_map.values()),
            resources=list(self.discovered_resources_map.values()),
            endpoints=list(self.discovered_endpoints_map.values()),
            parameters=sorted(list(self.discovered_parameters)),
        )

        self._log(f"Scan completed: {len(results.endpoints)} endpoints, {len(results.resources)} resources found.")
        return results

    def _merge_js_results(self, js_result, js_queue: asyncio.Queue[str]) -> None:
        """Merge findings from JS analysis into crawler tracking state."""
        # 1. Endpoints
        for ep in js_result.endpoints:
            key = (ep.endpoint, ep.source)
            if key not in self.discovered_endpoints_map:
                self.discovered_endpoints_map[key] = ep

        # 2. Parameters
        for param in js_result.parameters:
            self.discovered_parameters.add(param)

        # 3. Discovered Subdomains
        for sub in js_result.subdomains:
            if sub not in self.discovered_subdomains_map:
                if self.scope_manager.is_in_scope(sub):
                    self.discovered_subdomains_map[sub] = SubdomainFinding(
                        hostname=sub,
                        source="js_analysis",
                        ips=[],
                        is_live=False,
                    )

        # 4. Source maps
        for sm in js_result.source_maps:
            if sm.url not in self.discovered_sourcemaps_map:
                self.discovered_sourcemaps_map[sm.url] = sm

    async def _probe_sourcemaps(self) -> None:
        """Check status and headers for discovered source maps within scope."""
        for sm_url, sm_finding in list(self.discovered_sourcemaps_map.items()):
            if not self.scope_manager.is_in_scope(sm_url):
                logger.debug(f"Source map out of scope: {sm_url}")
                continue

            resp = await self.http_client.get(sm_url)
            if resp:
                sm_finding.status = resp.status_code
                sm_finding.content_type = resp.content_type
                sm_finding.size = resp.content_length

                # Optionally save source map to disk if requested
                if self.download_sourcemaps and resp.status_code == 200 and self.output_dir:
                    self._save_sourcemap_to_disk(sm_url, resp.content)
            else:
                sm_finding.status = None

    def _save_sourcemap_to_disk(self, url: str, content: bytes) -> None:
        """Save source map content securely into output directory."""
        if not self.output_dir:
            return
        try:
            sm_dir = os.path.join(self.output_dir, "sourcemaps")
            os.makedirs(sm_dir, exist_ok=True)
            # Safe filename
            parsed = urlsplit(url)
            filename = os.path.basename(parsed.path) or "unknown.map"
            if not filename.endswith(".map"):
                filename += ".map"
            # Prevent path traversal in filename
            filename = os.path.basename(filename)
            filepath = os.path.join(sm_dir, filename)
            with open(filepath, "wb") as f:
                f.write(content)
            logger.info(f"Saved source map to {filepath}")
        except Exception as e:
            logger.warning(f"Failed to save source map {url} to disk: {e}")
