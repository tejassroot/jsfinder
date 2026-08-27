"""JavaScript static analysis, endpoint discovery, parameter extraction, and source-map detection."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit

from jsfinder.models import DiscoveredEndpoint, DiscoveredResource, SourceMapFinding

logger = logging.getLogger("jsfinder.js_analyzer")

# Regex for sourceMappingURL directives
SOURCEMAP_DIRECTIVE_REGEX = re.compile(
    r"""(?:/\*|//)[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)(?:\s*\*\/)?""",
    re.MULTILINE,
)

# Regex for absolute HTTP/HTTPS URLs
ABSOLUTE_URL_REGEX = re.compile(
    r"""(?i)\b(https?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d+)?(?:/[^\s"'`<>{}|\^\[\]\\]*)?)"""
)

# Standard non-target URI namespaces to filter out
STANDARD_URI_SCHEMAS = (
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://schemas.xmlsoap.org/",
    "https://schemas.xmlsoap.org/",
    "http://schemas.microsoft.com/",
    "http://xml.org/",
    "http://apache.org/",
    "https://apache.org/",
    "http://json-schema.org/",
    "https://json-schema.org/",
)

# Common API / route patterns in JavaScript
ROUTE_DECLARATION_PATTERNS = [
    # fetch('/api/...'), axios.get('/api/...')
    re.compile(r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch|options|head))?|\$\.(?:get|post|ajax))\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # path: '/api/...', url: '/api/...', endpoint: '/api/...'
    re.compile(r"""\b(?:path|url|endpoint|route|api|href|src)\s*:\s*['"`](/[^'"`\s]+)['"`]"""),
    # router.get('/users', ...), app.post('/api/auth', ...)
    re.compile(r"""\b(?:router|app)\.(?:get|post|put|delete|patch|use)\s*\(\s*['"`](/[^'"`\s]+)['"`]"""),
]

# Quoted string candidates for relative paths
QUOTED_PATH_CANDIDATE = re.compile(
    r"""(?:['"`])(/[-a-zA-Z0-9_.~!$&'()*+,;=:@%/?#]+)(?:['"`])"""
)

# MIME types or common JS idioms that start with '/' but aren't endpoints
FALSE_POSITIVE_PREFIXES = (
    "/html",
    "/plain",
    "/json",
    "/xml",
    "/javascript",
    "/css",
    "/svg",
    "/x-www-form-urlencoded",
    "/form-data",
    "/octet-stream",
    "/div>",
    "/span>",
    "/a>",
    "/p>",
    "/tr>",
    "/td>",
    "/ul>",
    "/li>",
)

FALSE_POSITIVE_EXACT = {
    "/",
    "//",
    "/*",
    "*/",
    "/g",
    "/i",
    "/m",
    "/gi",
    "/gm",
    "/gim",
    "/#",
    "/?",
    "/index",
}

# Regex to extract query parameter names from URL or endpoint
QUERY_PARAM_REGEX = re.compile(r"""[?&]([a-zA-Z0-9_-]+)(?:=([^&#]*))?""")

# Regex to extract parameters from URLSearchParams and params objects
JS_PARAMS_OBJECT_REGEX = re.compile(
    r"""params\s*:\s*\{([^}]+)\}""",
    re.IGNORECASE,
)


@dataclass
class JsAnalysisResult:
    """Findings from analyzing a single JavaScript file."""
    js_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    source_maps: List[SourceMapFinding] = field(default_factory=list)
    resources: List[DiscoveredResource] = field(default_factory=list)


class JavaScriptAnalyzer:
    """Performs static analysis on JavaScript source code."""

    def __init__(self, target_domain: Optional[str] = None):
        self.target_domain = target_domain.lower() if target_domain else None
        if self.target_domain and self.target_domain.startswith("www."):
            self.target_domain = self.target_domain[4:]

        # Regex for subdomains of target domain
        if self.target_domain:
            escaped_domain = re.escape(self.target_domain)
            self.subdomain_regex = re.compile(
                rf"""\b([a-zA-Z0-9][-a-zA-Z0-9_]*\.(?:[-a-zA-Z0-9_]+\.)*{escaped_domain})\b""",
                re.IGNORECASE,
            )
        else:
            self.subdomain_regex = None

    def analyze(self, js_url: str, js_content: str) -> JsAnalysisResult:
        """Analyze JavaScript code and return structured discoveries."""
        result = JsAnalysisResult(js_url=js_url)
        if not js_content:
            return result

        seen_endpoints: Set[str] = set()
        seen_params: Set[str] = set()
        seen_subdomains: Set[str] = set()
        seen_maps: Set[str] = set()

        # 1. Source Map Detection
        self._extract_source_maps(js_url, js_content, result, seen_maps)

        # 2. Extract Absolute URLs
        self._extract_absolute_urls(js_url, js_content, result, seen_endpoints, seen_params)

        # 3. Extract Relative and API Endpoints
        self._extract_relative_endpoints(js_url, js_content, result, seen_endpoints, seen_params)

        # 4. Extract Query Parameters from JS parameter patterns
        self._extract_js_params(js_content, result, seen_params)

        # 5. Extract Referenced Subdomains
        if self.subdomain_regex:
            for match in self.subdomain_regex.finditer(js_content):
                sub = match.group(1).lower().strip(".")
                if sub and sub not in seen_subdomains:
                    seen_subdomains.add(sub)
                    result.subdomains.append(sub)

        return result

    def _extract_source_maps(
        self,
        js_url: str,
        content: str,
        result: JsAnalysisResult,
        seen_maps: Set[str],
    ) -> None:
        """Extract sourceMappingURL directives and potential .map references."""
        for match in SOURCEMAP_DIRECTIVE_REGEX.finditer(content):
            map_ref = match.group(1).strip()
            # Ignore inline data URIs for source maps
            if map_ref.startswith("data:"):
                continue
            full_map_url = urljoin(js_url, map_ref)
            if full_map_url not in seen_maps:
                seen_maps.add(full_map_url)
                result.source_maps.append(
                    SourceMapFinding(
                        url=full_map_url,
                        referenced_js=js_url,
                        detected_via="directive",
                    )
                )

        # Also register convention-based .map probe candidate if no directive found
        # Only for actual standalone JS files (ending in .js, .mjs, .cjs) and not inline scripts
        if not js_url.endswith(".map") and "#inline-script" not in js_url:
            parsed_path = urlsplit(js_url).path.lower()
            if parsed_path.endswith((".js", ".mjs", ".cjs")):
                conventional_map_url = f"{js_url}.map"
                if conventional_map_url not in seen_maps and not result.source_maps:
                    seen_maps.add(conventional_map_url)
                    result.source_maps.append(
                        SourceMapFinding(
                            url=conventional_map_url,
                            referenced_js=js_url,
                            detected_via="convention",
                        )
                    )

    def _extract_absolute_urls(
        self,
        js_url: str,
        content: str,
        result: JsAnalysisResult,
        seen_endpoints: Set[str],
        seen_params: Set[str],
    ) -> None:
        """Extract absolute URLs and their query parameters."""
        for match in ABSOLUTE_URL_REGEX.finditer(content):
            url = match.group(1).rstrip(")]}.,;'\"")
            # Filter standard URI schemas
            if any(url.startswith(s) for s in STANDARD_URI_SCHEMAS):
                continue

            params = self._extract_params_from_url(url, result, seen_params)

            # Classify endpoint
            ep_type = "api" if ("/api/" in url or "/v1/" in url or "/v2/" in url or "/graphql" in url) else "absolute"

            if url not in seen_endpoints:
                seen_endpoints.add(url)
                result.endpoints.append(
                    DiscoveredEndpoint(
                        endpoint=url,
                        source=js_url,
                        endpoint_type=ep_type,
                        parameters=params,
                    )
                )

    def _extract_relative_endpoints(
        self,
        js_url: str,
        content: str,
        result: JsAnalysisResult,
        seen_endpoints: Set[str],
        seen_params: Set[str],
    ) -> None:
        """Extract relative paths, route declarations, and API patterns."""
        # Check explicit route patterns first
        for pat in ROUTE_DECLARATION_PATTERNS:
            for match in pat.finditer(content):
                path = match.group(1).strip()
                self._process_path_candidate(path, js_url, result, seen_endpoints, seen_params)

        # Check all quoted path strings
        for match in QUOTED_PATH_CANDIDATE.finditer(content):
            path = match.group(1).strip()
            self._process_path_candidate(path, js_url, result, seen_endpoints, seen_params)

    def _process_path_candidate(
        self,
        path: str,
        js_url: str,
        result: JsAnalysisResult,
        seen_endpoints: Set[str],
        seen_params: Set[str],
    ) -> None:
        """Filter and classify a potential relative endpoint path."""
        # Basic cleanliness
        if not path or path in FALSE_POSITIVE_EXACT:
            return

        # Strip trailing punctuation
        path = path.rstrip(")]};,'\"")

        lower_path = path.lower()

        # Reject common false positive MIME types and HTML tag fragments
        if any(lower_path.startswith(fp) for fp in FALSE_POSITIVE_PREFIXES):
            return

        # Reject paths with spaces or newlines or backslashes
        if any(c in path for c in (" ", "\n", "\r", "\t", "\\", "<", ">", "{", "}")):
            return

        # Reject SVG paths (e.g. /M12 2C... or /M0 0h24...)
        if re.search(r"/[MCLHVCSQTAZ0-9,\s.-]{10,}", path, re.I):
            return

        # Must have at least one alphanumeric character
        if not re.search(r"[a-zA-Z0-9]", path):
            return

        # Determine if it is an API or relative endpoint
        is_api = bool(
            re.search(
                r"^/(?:api|v[0-9]+|rest|graphql|oauth|auth|admin|internal|users?|account|service)/",
                lower_path,
            )
            or "api/" in lower_path
            or "/graphql" in lower_path
        )

        params = self._extract_params_from_url(path, result, seen_params)

        if path not in seen_endpoints:
            seen_endpoints.add(path)
            result.endpoints.append(
                DiscoveredEndpoint(
                    endpoint=path,
                    source=js_url,
                    endpoint_type="api" if is_api else "relative",
                    parameters=params,
                )
            )

    def _extract_params_from_url(
        self,
        url_or_path: str,
        result: JsAnalysisResult,
        seen_params: Set[str],
    ) -> List[str]:
        """Extract parameter names from query string in URL or path."""
        params_found: List[str] = []
        try:
            parsed = urlsplit(url_or_path)
            query = parsed.query
            if query:
                qs = parse_qs(query, keep_blank_values=True)
                for p in qs.keys():
                    if p and p not in seen_params:
                        seen_params.add(p)
                        result.parameters.append(p)
                    if p:
                        params_found.append(p)
        except Exception:
            pass

        # Also fallback regex matching
        for match in QUERY_PARAM_REGEX.finditer(url_or_path):
            pname = match.group(1)
            if pname and pname not in seen_params:
                seen_params.add(pname)
                result.parameters.append(pname)
            if pname and pname not in params_found:
                params_found.append(pname)

        return params_found

    def _extract_js_params(
        self,
        content: str,
        result: JsAnalysisResult,
        seen_params: Set[str],
    ) -> None:
        """Extract parameter names from JS object patterns like `params: { id, query, token }`."""
        for match in JS_PARAMS_OBJECT_REGEX.finditer(content):
            body = match.group(1)
            # Match keys: key: val or key,
            keys = re.findall(r"""([a-zA-Z0-9_]+)\s*[:=,]""", body)
            for k in keys:
                k = k.strip()
                if len(k) > 1 and k not in seen_params:
                    # Ignore common JS keywords
                    if k in {"function", "return", "var", "let", "const", "true", "false", "null"}:
                        continue
                    seen_params.add(k)
                    result.parameters.append(k)
