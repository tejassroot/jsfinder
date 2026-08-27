"""Unit tests for URL normalization and validation."""

import pytest
from jsfinder.parser import normalize_url


class TestUrlNormalization:
    def test_relative_url_resolution(self):
        base = "https://example.com/app/index.html"
        assert normalize_url("assets/main.js", base) == "https://example.com/app/assets/main.js"
        assert normalize_url("/static/bundle.js", base) == "https://example.com/static/bundle.js"
        assert normalize_url("../vendor/chunk.js", base) == "https://example.com/vendor/chunk.js"

    def test_protocol_relative_urls(self):
        base = "https://example.com"
        assert normalize_url("//cdn.example.com/lib.js", base) == "https://cdn.example.com/lib.js"
        base_http = "http://example.com"
        assert normalize_url("//cdn.example.com/lib.js", base_http) == "http://cdn.example.com/lib.js"

    def test_fragment_stripping(self):
        base = "https://example.com"
        assert normalize_url("/page#section2", base) == "https://example.com/page"
        assert normalize_url("https://example.com/app.js#hash", None) == "https://example.com/app.js"

    def test_default_port_removal(self):
        assert normalize_url("http://example.com:80/path") == "http://example.com/path"
        assert normalize_url("https://example.com:443/path") == "https://example.com/path"
        # Non-standard ports preserved
        assert normalize_url("https://example.com:8443/path") == "https://example.com:8443/path"

    def test_dot_segments_and_double_slashes(self):
        url = "https://example.com/foo/bar/../../baz/app.js"
        assert normalize_url(url) == "https://example.com/baz/app.js"

        url_double_slash = "https://example.com//foo///bar/app.js"
        assert normalize_url(url_double_slash) == "https://example.com/foo/bar/app.js"

    def test_query_parameters_preserved(self):
        url = "https://example.com/api/v1/search?q=security&limit=10"
        assert normalize_url(url) == "https://example.com/api/v1/search?q=security&limit=10"

    def test_non_http_pseudo_schemes_rejected(self):
        base = "https://example.com"
        assert normalize_url("javascript:alert(1)", base) is None
        assert normalize_url("mailto:security@example.com", base) is None
        assert normalize_url("tel:+1234567890", base) is None
        assert normalize_url("data:text/html;base64,PHNjcmlwdD4=", base) is None
        assert normalize_url("about:blank", base) is None
        assert normalize_url("blob:https://example.com/uuid", base) is None

    def test_empty_and_malformed_inputs(self):
        assert normalize_url("") is None
        assert normalize_url("   ") is None
        assert normalize_url(None) is None
        assert normalize_url("not a url at all :::") is None
