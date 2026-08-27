"""JSFinder - Domain Attack-Surface & Static Resource Discovery Tool."""

__version__ = "1.0.0"
__author__ = "Security Team"

from jsfinder.crawler import Crawler
from jsfinder.http import SafeHttpClient, SafeResponse
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
from jsfinder.scope import ScopeManager, ScopeRule

__all__ = [
    "Crawler",
    "SafeHttpClient",
    "SafeResponse",
    "JavaScriptAnalyzer",
    "DiscoveredEndpoint",
    "DiscoveredResource",
    "HostProbeResult",
    "ScanResults",
    "SourceMapFinding",
    "SubdomainFinding",
    "HtmlResourceParser",
    "normalize_url",
    "PerHostRateLimiter",
    "ScopeManager",
    "ScopeRule",
]
