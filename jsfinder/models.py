"""Data models for JSFinder."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Any, Dict


@dataclass
class HostProbeResult:
    """Represents HTTP probing result for a host."""
    url: str
    status: int
    final_url: str
    content_type: str = ""
    content_length: int = 0
    response_time: float = 0.0
    server: Optional[str] = None
    title: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredResource:
    """Represents a discovered static or dynamic web resource."""
    url: str
    resource_type: str
    source_url: str
    tag: Optional[str] = None
    framework_chunk: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredEndpoint:
    """Represents an API or path endpoint discovered in JS/HTML."""
    endpoint: str
    source: str
    endpoint_type: str = "relative"  # absolute, relative, api
    parameters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SourceMapFinding:
    """Represents a discovered JavaScript source map."""
    url: str
    referenced_js: str
    status: Optional[int] = None
    content_type: Optional[str] = None
    size: Optional[int] = None
    detected_via: str = "directive"  # "directive", "extension_probe"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubdomainFinding:
    """Represents a discovered subdomain."""
    hostname: str
    source: str
    ips: List[str] = field(default_factory=list)
    is_live: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResults:
    """Consolidated container for scan findings."""
    target: str
    scan_time: str
    scope: List[str] = field(default_factory=list)
    subdomains: List[SubdomainFinding] = field(default_factory=list)
    hosts: List[HostProbeResult] = field(default_factory=list)
    javascript: List[str] = field(default_factory=list)
    source_maps: List[SourceMapFinding] = field(default_factory=list)
    resources: List[DiscoveredResource] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "scope": self.scope,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "hosts": [h.to_dict() for h in self.hosts],
            "javascript": self.javascript,
            "source_maps": [m.to_dict() for m in self.source_maps],
            "resources": [r.to_dict() for r in self.resources],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "parameters": self.parameters,
        }

    def get_all_urls(self, resolve_relative: bool = True) -> List[str]:
        """Return a deduplicated list of all discovered URLs."""
        from urllib.parse import urljoin
        urls: set[str] = set()

        # 1. Target URL
        if self.target:
            urls.add(self.target)

        # 2. Live probed hosts
        for host in self.hosts:
            if host.url:
                urls.add(host.url)
            if host.final_url:
                urls.add(host.final_url)

        # 3. JavaScript files
        for js in self.javascript:
            urls.add(js)

        # 4. Resources
        for res in self.resources:
            if res.url:
                urls.add(res.url)

        # 5. Active source maps
        for sm in self.source_maps:
            if sm.status == 200:
                urls.add(sm.url)

        # 6. Discovered endpoints & routes
        for ep in self.endpoints:
            if not ep.endpoint:
                continue
            if ep.endpoint.startswith("http://") or ep.endpoint.startswith("https://") or ep.endpoint.startswith("//"):
                urls.add(ep.endpoint)
            elif resolve_relative and self.target:
                urls.add(urljoin(self.target, ep.endpoint))
            else:
                urls.add(ep.endpoint)

        return sorted(urls)
