"""Unit tests for HTML parsing and resource extraction."""

import pytest
from jsfinder.parser import (
    HtmlResourceParser,
    classify_resource_type,
    is_framework_chunk,
)


class TestHtmlResourceParser:
    def test_html_tag_resource_extraction(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <link rel="stylesheet" href="/css/styles.css">
            <link rel="icon" href="/favicon.ico">
            <script src="/static/js/app.123456.js"></script>
            <script src="https://cdn.example.com/vendor.chunk.js"></script>
        </head>
        <body>
            <img src="/images/logo.png" alt="Logo">
            <iframe src="/embedded/widget.html"></iframe>
            <video><source src="/media/intro.mp4" type="video/mp4"></video>
            <a href="/about.html">About</a>
            <a href="/docs/guide.pdf">Guide</a>
            <a href="javascript:void(0)">Click</a>
            <script>
                // Inline script with dynamic chunk import
                import("/chunks/lazy-module.js");
                console.log("Loading");
            </script>
        </body>
        </html>
        """
        parser = HtmlResourceParser("https://example.com/app/")
        resources, page_links, inline_scripts = parser.parse(html)

        res_urls = {r.url for r in resources}
        assert "https://example.com/css/styles.css" in res_urls
        assert "https://example.com/favicon.ico" in res_urls
        assert "https://example.com/static/js/app.123456.js" in res_urls
        assert "https://cdn.example.com/vendor.chunk.js" in res_urls
        assert "https://example.com/images/logo.png" in res_urls
        assert "https://example.com/chunks/lazy-module.js" in res_urls

        # Page links
        assert "https://example.com/about.html" in page_links
        # javascript:void(0) must not be in page links
        assert not any("javascript" in l for l in page_links)

        # Inline script extracted
        assert len(inline_scripts) == 1
        assert "lazy-module.js" in inline_scripts[0]

    def test_extension_classification(self):
        assert classify_resource_type("https://example.com/app.js") == "javascript"
        assert classify_resource_type("https://example.com/app.js.map") == "source_map"
        assert classify_resource_type("https://example.com/style.css") == "css"
        assert classify_resource_type("https://example.com/data.json") == "json"
        assert classify_resource_type("https://example.com/sitemap.xml") == "xml"
        assert classify_resource_type("https://example.com/robots.txt") == "text"
        assert classify_resource_type("https://example.com/config.yaml") == "yaml"
        assert classify_resource_type("https://example.com/config.yml") == "yaml"
        assert classify_resource_type("https://example.com/photo.png") == "image"

    def test_framework_chunk_detection(self):
        assert is_framework_chunk("https://example.com/static/js/chunk-vendors.8b4ef2.js") is True
        assert is_framework_chunk("https://example.com/dist/app.a1b2c3d4.js") is True
        assert is_framework_chunk("https://example.com/_next/static/chunks/main-app.js") is True
        assert is_framework_chunk("https://example.com/123.456789ab.js") is True
        assert is_framework_chunk("https://example.com/simple.js") is False
