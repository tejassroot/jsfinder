"""Unit tests for ScopeManager and ScopeRule."""

import os
import tempfile
import pytest

from jsfinder.scope import ScopeManager, ScopeRule


class TestScopeRule:
    def test_exact_domain_match(self):
        rule = ScopeRule("example.com")
        assert rule.matches("example.com") is True
        assert rule.matches("EXAMPLE.COM") is True
        assert rule.matches("sub.example.com") is False
        assert rule.matches("evil-example.com") is False
        assert rule.matches("example.com.attacker.com") is False

    def test_wildcard_domain_match(self):
        rule = ScopeRule("*.example.com")
        assert rule.matches("example.com") is True
        assert rule.matches("sub.example.com") is True
        assert rule.matches("a.b.c.example.com") is True
        # Critical security boundary tests
        assert rule.matches("evil-example.com") is False
        assert rule.matches("notexample.com") is False
        assert rule.matches("example.com.attacker.com") is False
        assert rule.matches("attacker.com") is False
        assert rule.matches("external-cdn.com") is False

    def test_ip_network_match(self):
        rule = ScopeRule("192.168.1.0/24")
        assert rule.matches("192.168.1.1") is True
        assert rule.matches("192.168.1.254") is True
        assert rule.matches("192.168.2.1") is False

    def test_port_matching(self):
        rule = ScopeRule("example.com:8443")
        assert rule.matches("example.com", 8443) is True
        assert rule.matches("example.com", 80) is False
        assert rule.matches("example.com", None) is True  # If no port in target, matches


class TestScopeManager:
    def test_default_target_scope(self):
        mgr = ScopeManager(target_url_or_host="https://example.com/test/path?q=1")
        assert mgr.is_in_scope("https://example.com") is True
        assert mgr.is_in_scope("https://example.com/assets/app.js") is True
        assert mgr.is_in_scope("https://api.example.com/v1/users") is True
        assert mgr.is_in_scope("https://sub.sub2.example.com/test") is True

        # Rejections
        assert mgr.is_in_scope("https://evil-example.com") is False
        assert mgr.is_in_scope("https://attacker.com/evil.js") is False
        assert mgr.is_in_scope("https://external-cdn.com/lib.js") is False
        assert mgr.is_in_scope("https://example.com.attacker.com") is False

    def test_scope_file_loading(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("# Scope definition\n")
            f.write("target.org\n")
            f.write("*.internal.target.org\n")
            f.write("10.0.0.0/8\n")
            temp_path = f.name

        try:
            mgr = ScopeManager(scope_file=temp_path)
            assert mgr.is_in_scope("target.org") is True
            assert mgr.is_in_scope("foo.internal.target.org") is True
            assert mgr.is_in_scope("other.target.org") is False
            assert mgr.is_in_scope("10.1.2.3") is True
            assert mgr.is_in_scope("192.168.1.1") is False
        finally:
            os.remove(temp_path)

    def test_url_with_credentials_and_ports(self):
        mgr = ScopeManager("example.com")
        assert mgr.is_in_scope("https://user:pass@example.com/path") is True
        assert mgr.is_in_scope("//api.example.com/resource") is True
        assert mgr.is_in_scope("http://example.com:8080/data") is True
        assert mgr.is_in_scope("https://evil.com/fake?target=example.com") is False
