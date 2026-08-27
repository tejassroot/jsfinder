"""HTML parsing, URL normalization, and resource discovery for JSFinder."""

from __future__ import annotations

import logging
import posixpath
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from jsfinder.models import DiscoveredResource

logger = logging.getLogger("jsfinder.parser")

# Ignored non-HTTP URL schemes
IGNORED_SCHEMES = {
    "javascript",
    "mailto",
    "tel",
    "data",
    "about",
    "blob",
    "android-app",
    "ios-app",
    "callto",
    "sms",
    "whatsapp",
}

# Framework chunk detection patterns
FRAMEWORK_CHUNK_PATTERNS = [
    re.compile(r"chunk[-_]vendors", re.I),
    re.compile(r"[._-]chunk\.(?:min\.)?js$", re.I),
    re.compile(r"app\.[a-f0-9]{6,}\.js$", re.I),
    re.compile(r"vendor\.[a-f0-9]{6,}\.js$", re.I),
    re.compile(r"runtime\.[a-f0-9]{6,}\.js$", re.I),
    re.compile(r"main\.[a-f0-9]{6,}\.js$", re.I),
    re.compile(r"[0-9]+\.[a-f0-9]{8,}\.js$", re.I),
    re.compile(r"/_next/static/chunks/", re.I),
    re.compile(r"/_next/static/[a-zA-Z0-9_-]+/_buildManifest\.js", re.I),
    re.compile(r"/_nuxt/", re.I),
    re.compile(r"/assets/[a-zA-Z0-9_-]+\.[a-f0-9]{8,}\.js$", re.I),
    re.compile(r"/bundle(?:\.[a-f0-9]+)?\.js$", re.I),
]

# Extension classification map
EXT_TO_TYPE = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".map": "source_map",
    ".js.map": "source_map",
    ".css": "css",
    ".json": "json",
    ".xml": "xml",
    ".txt": "text",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".svg": "image",
    ".webp": "image",
    ".ico": "image",
    ".woff": "font",
    ".woff2": "font",
    ".ttf": "font",
    ".eot": "font",
}

# Regex to detect dynamic script strings in HTML / inline scripts
DYNAMIC_SCRIPT_REGEX = re.compile(
    r"""(?:import\s*\(|src\s*:\s*|href\s*:\s*|['"])([/a-zA-Z0-9_.-]+\.(?:js|json|css|map))['"]""",
    re.IGNORECASE,
)


def normalize_url(url: str, base_url: Optional[str] = None) -> Optional[str]:
    """Normalize and canonicalize a URL string.

    - Resolves relative URLs against base_url.
    - Strips URL fragments (#...).
    - Discards non-HTTP pseudo-schemes (javascript:, mailto:, data:, etc.).
    - Normalizes schemes to lowercase.
    - Normalizes hostname to lowercase.
    - Collapses dot segments and redundant path slashes.
    - Strips default HTTP/HTTPS ports (:80, :443).
    """
    if not url or not isinstance(url, str):
        return None

    cleaned = url.strip()
    if not cleaned:
        return None

    # Check for pseudo schemes
    lower_prefix = cleaned.lower()
    for scheme in IGNORED_SCHEMES:
        if lower_prefix.startswith(f"{scheme}:"):
            return None

    # Protocol-relative URLs (//example.com/foo)
    if cleaned.startswith("//"):
        base_scheme = "https:"
        if base_url:
            parsed_base = urlsplit(base_url)
            if parsed_base.scheme:
                base_scheme = f"{parsed_base.scheme}:"
        cleaned = f"{base_scheme}{cleaned}"

    # Resolve against base URL if relative
    if base_url:
        cleaned = urljoin(base_url, cleaned)

    try:
        parsed = urlsplit(cleaned)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None

    netloc = parsed.netloc.lower()
    if not netloc:
        return None

    # Remove standard ports if explicitly present
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Normalize path: remove dot segments and collapse duplicate slashes
    raw_path = parsed.path or "/"
    # Collapse multiple consecutive slashes in path
    clean_path = re.sub(r"/+", "/", raw_path)
    # Resolve posix dot segments (/a/b/../c -> /a/c)
    clean_path = posixpath.normpath(clean_path)
    if raw_path.endswith("/") and not clean_path.endswith("/"):
        clean_path += "/"
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path

    # Keep query parameters as-is, strip fragments
    query = parsed.query

    normalized = urlunsplit((scheme, netloc, clean_path, query, ""))
    return normalized


def is_framework_chunk(url: str) -> bool:
    """Detect if a JavaScript URL matches common framework chunk naming conventions."""
    for pattern in FRAMEWORK_CHUNK_PATTERNS:
        if pattern.search(url):
            return True
    return False


def classify_resource_type(url: str) -> str:
    """Classify the resource type based on its URL path extension."""
    parsed = urlsplit(url)
    path = parsed.path.lower()

    if path.endswith(".js.map"):
        return "source_map"

    ext = posixpath.splitext(path)[1]
    return EXT_TO_TYPE.get(ext, "other")


class HtmlResourceParser:
    """Parses HTML content to extract web resources, scripts, links, and inline code."""

    def __init__(self, base_url: str):
        self.base_url = base_url

    def parse(self, html_content: str) -> Tuple[List[DiscoveredResource], List[str], List[str]]:
        """Parse HTML string and return (resources, crawlable_page_links, inline_scripts)."""
        resources: List[DiscoveredResource] = []
        page_links: List[str] = []
        inline_scripts: List[str] = []
        seen_res_urls: Set[str] = set()
        seen_page_links: Set[str] = set()

        if not html_content:
            return resources, page_links, inline_scripts

        soup = BeautifulSoup(html_content, "html.parser")

        # 1. <script> tags
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                norm = normalize_url(src, self.base_url)
                if norm and norm not in seen_res_urls:
                    seen_res_urls.add(norm)
                    rtype = classify_resource_type(norm)
                    if rtype == "other":
                        rtype = "javascript"
                    resources.append(
                        DiscoveredResource(
                            url=norm,
                            resource_type=rtype,
                            source_url=self.base_url,
                            tag="script",
                            framework_chunk=is_framework_chunk(norm),
                        )
                    )
            else:
                # Inline script content
                script_text = script.string or script.get_text()
                if script_text and script_text.strip():
                    inline_scripts.append(script_text)
                    # Dynamically referenced resources inside inline scripts
                    for match in DYNAMIC_SCRIPT_REGEX.finditer(script_text):
                        dyn_ref = match.group(1)
                        norm_dyn = normalize_url(dyn_ref, self.base_url)
                        if norm_dyn and norm_dyn not in seen_res_urls:
                            seen_res_urls.add(norm_dyn)
                            rtype = classify_resource_type(norm_dyn)
                            resources.append(
                                DiscoveredResource(
                                    url=norm_dyn,
                                    resource_type=rtype,
                                    source_url=self.base_url,
                                    tag="inline_script_dynamic",
                                    framework_chunk=is_framework_chunk(norm_dyn),
                                )
                            )

        # 2. <link> tags (stylesheets, preloads, manifests, icons, etc.)
        for link in soup.find_all("link"):
            href = link.get("href")
            if href:
                norm = normalize_url(href, self.base_url)
                if norm and norm not in seen_res_urls:
                    seen_res_urls.add(norm)
                    rtype = classify_resource_type(norm)
                    resources.append(
                        DiscoveredResource(
                            url=norm,
                            resource_type=rtype,
                            source_url=self.base_url,
                            tag="link",
                            framework_chunk=is_framework_chunk(norm),
                        )
                    )

        # 3. <img>, <iframe>, <source>, <video>, <audio>, <embed> tags
        for tag_name, attr_name in [
            ("img", "src"),
            ("iframe", "src"),
            ("source", "src"),
            ("video", "src"),
            ("audio", "src"),
            ("embed", "src"),
        ]:
            for el in soup.find_all(tag_name):
                attr_val = el.get(attr_name)
                if attr_val:
                    norm = normalize_url(attr_val, self.base_url)
                    if norm and norm not in seen_res_urls:
                        seen_res_urls.add(norm)
                        rtype = classify_resource_type(norm)
                        resources.append(
                            DiscoveredResource(
                                url=norm,
                                resource_type=rtype,
                                source_url=self.base_url,
                                tag=tag_name,
                                framework_chunk=is_framework_chunk(norm),
                            )
                        )

        # 4. <a> and <area> links for crawling
        for a in soup.find_all(["a", "area"]):
            href = a.get("href")
            if href:
                norm = normalize_url(href, self.base_url)
                if norm:
                    # Check if it's a static resource or a page link
                    rtype = classify_resource_type(norm)
                    if rtype != "other":
                        if norm not in seen_res_urls:
                            seen_res_urls.add(norm)
                            resources.append(
                                DiscoveredResource(
                                    url=norm,
                                    resource_type=rtype,
                                    source_url=self.base_url,
                                    tag="a",
                                    framework_chunk=is_framework_chunk(norm),
                                )
                            )
                    else:
                        if norm not in seen_page_links:
                            seen_page_links.add(norm)
                            page_links.append(norm)

        return resources, page_links, inline_scripts
