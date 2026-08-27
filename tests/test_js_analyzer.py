"""Unit tests for JavaScriptAnalyzer: endpoints, params, subdomains, source maps."""

import pytest
from jsfinder.js_analyzer import JavaScriptAnalyzer


class TestJavaScriptAnalyzer:
    def test_source_map_extraction(self):
        js_code = """
        console.log("App loaded");
        //# sourceMappingURL=app.js.map
        """
        analyzer = JavaScriptAnalyzer(target_domain="example.com")
        res = analyzer.analyze("https://example.com/static/app.js", js_code)

        assert len(res.source_maps) >= 1
        assert res.source_maps[0].url == "https://example.com/static/app.js.map"
        assert res.source_maps[0].referenced_js == "https://example.com/static/app.js"
        assert res.source_maps[0].detected_via == "directive"

    def test_absolute_and_relative_endpoints(self):
        js_code = """
        const API_URL = "https://api.example.com/v1/users";
        function login(user, pass) {
            return axios.post("/api/auth/login", { user, pass });
        }
        function search(q) {
            return fetch('/api/search?q=' + q + '&filter=active');
        }
        const config = {
            endpoint: "/graphql",
            backup: "https://backup-api.example.com/sync"
        };
        """
        analyzer = JavaScriptAnalyzer(target_domain="example.com")
        res = analyzer.analyze("https://example.com/bundle.js", js_code)

        endpoint_paths = {ep.endpoint for ep in res.endpoints}
        assert "https://api.example.com/v1/users" in endpoint_paths
        assert "/api/auth/login" in endpoint_paths
        assert "/api/search?q=" in endpoint_paths or "/api/search" in endpoint_paths
        assert "/graphql" in endpoint_paths
        assert "https://backup-api.example.com/sync" in endpoint_paths

        # Verify provenance
        for ep in res.endpoints:
            assert ep.source == "https://example.com/bundle.js"

    def test_query_parameter_extraction(self):
        js_code = """
        const url = "/api/v2/items?category=books&sort=desc&page=1";
        axios.get("/api/profile", {
            params: {
                userId: 123,
                authToken: "secret"
            }
        });
        """
        analyzer = JavaScriptAnalyzer(target_domain="example.com")
        res = analyzer.analyze("https://example.com/main.js", js_code)

        assert "category" in res.parameters
        assert "sort" in res.parameters
        assert "page" in res.parameters
        assert "userId" in res.parameters
        assert "authToken" in res.parameters

    def test_subdomain_extraction_from_js(self):
        js_code = """
        window.analyticsEndpoint = "https://metrics.example.com/collect";
        window.oauthEndpoint = "https://auth.stage.example.com/oauth/token";
        window.foreign = "https://evil-example.com/steal";
        """
        analyzer = JavaScriptAnalyzer(target_domain="example.com")
        res = analyzer.analyze("https://example.com/app.js", js_code)

        assert "metrics.example.com" in res.subdomains
        assert "auth.stage.example.com" in res.subdomains
        # evil-example.com must NOT be extracted as a subdomain of example.com!
        assert "evil-example.com" not in res.subdomains

    def test_false_positive_filtering(self):
        js_code = """
        const headers = { "Content-Type": "application/json" };
        const mime = "/html";
        const svgPath = "/M10 20C30 40 50 60 70 80Z";
        const fragment = "</div>";
        const slash = "/";
        """
        analyzer = JavaScriptAnalyzer(target_domain="example.com")
        res = analyzer.analyze("https://example.com/vendor.js", js_code)

        endpoints = {e.endpoint for e in res.endpoints}
        assert "/html" not in endpoints
        assert "/" not in endpoints
        assert "</div>" not in endpoints
        assert not any("M10 20" in e for e in endpoints)
