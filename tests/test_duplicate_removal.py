"""Unit tests for deduplication of URLs, endpoints, and parameters."""

import pytest
from jsfinder.js_analyzer import JavaScriptAnalyzer
from jsfinder.models import DiscoveredEndpoint
from jsfinder.parser import HtmlResourceParser


def test_html_duplicate_resource_removal():
    html = """
    <html>
    <head>
        <script src="/app.js"></script>
        <script src="/app.js"></script>
        <script src="/app.js?v=1"></script>
        <link rel="stylesheet" href="/style.css">
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <a href="/about">About</a>
        <a href="/about">About</a>
        <a href="/about#team">About Team</a>
    </body>
    </html>
    """
    parser = HtmlResourceParser("https://example.com")
    resources, page_links, _ = parser.parse(html)

    # Check unique resources
    res_urls = [r.url for r in resources]
    assert res_urls.count("https://example.com/app.js") == 1
    assert res_urls.count("https://example.com/style.css") == 1

    # Check unique page links (and fragment stripped)
    assert page_links.count("https://example.com/about") == 1


def test_js_endpoint_and_parameter_deduplication():
    js_code = """
    fetch("/api/v1/users?page=1");
    fetch("/api/v1/users?page=2");
    axios.get("/api/v1/users");
    const p = { params: { page: 1, limit: 10 } };
    const p2 = { params: { page: 2, limit: 20 } };
    """
    analyzer = JavaScriptAnalyzer(target_domain="example.com")
    res = analyzer.analyze("https://example.com/app.js", js_code)

    # Parameters must be deduplicated
    assert res.parameters.count("page") == 1
    assert res.parameters.count("limit") == 1

    # Endpoints
    paths = [e.endpoint for e in res.endpoints]
    assert len(paths) == len(set(paths))
