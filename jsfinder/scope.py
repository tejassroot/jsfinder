"""Scope enforcement and validation for JSFinder."""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, List, Optional, Set, Union
from urllib.parse import urlsplit

logger = logging.getLogger("jsfinder.scope")


class ScopeRule:
    """Represents a single scope rule (domain, wildcard domain, or IP/CIDR)."""

    def __init__(self, raw_rule: str):
        self.raw = raw_rule.strip()
        self.is_wildcard = False
        self.domain: Optional[str] = None
        self.ip_network: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None
        self.port: Optional[int] = None
        self._parse(self.raw)

    def _parse(self, raw: str) -> None:
        # Strip scheme if accidentally included
        if "://" in raw:
            parsed = urlsplit(raw)
            raw = parsed.netloc or parsed.path

        # Check for port
        port: Optional[int] = None
        if ":" in raw and not raw.endswith("]"):  # Not raw IPv6 without port
            parts = raw.split(":")
            # Handle potential IPv6 [::1]:8080 or host:port
            if len(parts) == 2:
                try:
                    port = int(parts[1])
                    raw = parts[0]
                except ValueError:
                    pass

        self.port = port
        raw = raw.strip().lower()

        # Check if it's an IP network / CIDR
        try:
            # If plain IP without prefix, make it /32 or /128
            self.ip_network = ipaddress.ip_network(raw, strict=False)
            return
        except ValueError:
            pass

        # Domain rule
        if raw.startswith("*."):
            self.is_wildcard = True
            self.domain = raw[2:].lstrip(".")
        elif raw.startswith("."):
            self.is_wildcard = True
            self.domain = raw.lstrip(".")
        else:
            self.domain = raw

    def matches(self, hostname: str, port: Optional[int] = None) -> bool:
        """Check if a given hostname and port match this rule."""
        if not hostname:
            return False

        hostname = hostname.strip().lower().rstrip(".")

        # Port check (if this rule specified a port)
        if self.port is not None and port is not None:
            if self.port != port:
                return False

        # If rule is IP network
        if self.ip_network is not None:
            try:
                ip = ipaddress.ip_address(hostname)
                return ip in self.ip_network
            except ValueError:
                return False

        # Domain matching
        if self.domain is None:
            return False

        rule_domain = self.domain

        if self.is_wildcard:
            # *.example.com matches example.com, sub.example.com, a.b.example.com
            # BUT MUST NOT match evil-example.com, attacker.com, or notexample.com
            if hostname == rule_domain:
                return True
            if hostname.endswith("." + rule_domain):
                return True
            return False
        else:
            # Exact domain match
            return hostname == rule_domain

    def __repr__(self) -> str:
        p_str = f":{self.port}" if self.port else ""
        if self.ip_network:
            return f"<ScopeRule IP:{self.ip_network}{p_str}>"
        if self.is_wildcard:
            return f"<ScopeRule Wildcard:*.{self.domain}{p_str}>"
        return f"<ScopeRule Exact:{self.domain}{p_str}>"


class ScopeManager:
    """Manages target scope rules and validates URLs against scope."""

    def __init__(self, target_url_or_host: Optional[str] = None, scope_file: Optional[str] = None):
        self.rules: List[ScopeRule] = []
        self._raw_rules: Set[str] = set()

        if target_url_or_host:
            self.add_target(target_url_or_host)

        if scope_file:
            self.load_from_file(scope_file)

    def add_target(self, target: str) -> None:
        """Add target host and its subdomains as default scope."""
        target = target.strip()
        if "://" in target:
            parsed = urlsplit(target)
            host = parsed.hostname or ""
            port = parsed.port
        else:
            # May be host or host:port
            if ":" in target and not target.endswith("]"):
                parts = target.split(":")
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = None
            else:
                host = target
                port = None

        host = host.strip().lower()
        if not host:
            return

        # By default, add exact host and wildcard subdomains
        self.add_rule(host)
        self.add_rule(f"*.{host}")

    def add_rule(self, raw_rule: str) -> None:
        """Add a scope rule string."""
        raw_rule = raw_rule.strip()
        if not raw_rule or raw_rule.startswith("#"):
            return
        if raw_rule not in self._raw_rules:
            self._raw_rules.add(raw_rule)
            self.rules.append(ScopeRule(raw_rule))
            logger.debug(f"Added scope rule: {raw_rule}")

    def load_from_file(self, file_path: str) -> None:
        """Load scope rules from a file, one rule per line."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.add_rule(line)
            logger.info(f"Loaded {len(self.rules)} scope rules from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load scope file '{file_path}': {e}")
            raise

    def is_in_scope(self, url_or_host: str) -> bool:
        """Check whether the given URL or host is within scope.

        Returns True only if matched by at least one active scope rule.
        """
        if not url_or_host or not isinstance(url_or_host, str):
            return False

        url_or_host = url_or_host.strip()
        if not url_or_host:
            return False

        # Extract hostname and port
        hostname: Optional[str] = None
        port: Optional[int] = None

        if "://" in url_or_host or url_or_host.startswith("//"):
            try:
                # Handle protocol-relative URLs
                parsed_url = url_or_host if "://" in url_or_host else "http:" + url_or_host
                parsed = urlsplit(parsed_url)
                hostname = parsed.hostname
                port = parsed.port
            except Exception as e:
                logger.debug(f"URL parsing failed for '{url_or_host}': {e}")
                return False
        else:
            # May be host or host:port
            if "/" in url_or_host:
                # e.g., example.com/path
                parts = url_or_host.split("/", 1)
                host_part = parts[0]
            else:
                host_part = url_or_host

            if ":" in host_part and not host_part.endswith("]"):
                parts = host_part.split(":")
                hostname = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = None
            else:
                hostname = host_part

        if not hostname:
            return False

        # Check against all rules
        for rule in self.rules:
            if rule.matches(hostname, port):
                return True

        logger.debug(f"Out-of-scope rejected: {hostname} ({url_or_host})")
        return False

    def get_rules(self) -> List[str]:
        """Return list of active scope rule strings."""
        return sorted(list(self._raw_rules))
