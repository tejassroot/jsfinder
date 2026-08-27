"""Reporting, console formatting, JSON, and CSV export for JSFinder."""

from __future__ import annotations

import csv
import json
import os
import sys
from typing import Optional

from jsfinder.models import ScanResults

# ANSI color codes for clean terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner() -> None:
    """Print the JSFinder ASCII art banner."""
    art = r"""
     ___  ____  _____ _           _           
    |_  |/ ___||  ___(_)_ __   __| | ___ _ __ 
      | |\___ \| |_  | | '_ \ / _` |/ _ \ '__|
  /\__/ / ___) |  _| | | | | | (_| |  __/ |   
  \____/ |____/|_|   |_|_| |_|\__,_|\___|_|   
"""
    banner = f"{CYAN}{BOLD}{art}{RESET}{DIM}  Domain Attack-Surface & Static Resource Discovery Tool\n  Authorized Bug-Bounty & Security Testing CLI{RESET}\n"
    sys.stderr.write(banner + "\n")


def print_scope_summary(target: str, scope_rules: list[str]) -> None:
    """Print the active scope and target clearly before scanning."""
    lines = [
        f"{BOLD}[*] Target:{RESET} {CYAN}{target}{RESET}",
        f"{BOLD}[*] Active Scope ({len(scope_rules)} rules):{RESET}",
    ]
    for rule in scope_rules:
        lines.append(f"    - {GREEN}{rule}{RESET}")
    lines.append(f"{DIM}{'─' * 60}{RESET}")
    print("\n".join(lines))


def print_terminal_results(results: ScanResults) -> None:
    """Print formatted findings to terminal."""
    print(f"\n{BOLD}{CYAN}══════════════════════ DISCOVERY FINDINGS ══════════════════════{RESET}\n")

    # 1. Hosts
    if results.hosts:
        print(f"{BOLD}[+] Live Hosts Probed ({len(results.hosts)}):{RESET}")
        for host in results.hosts:
            status_col = GREEN if host.status < 400 else RED
            srv = f" [{host.server}]" if host.server else ""
            title = f" - \"{host.title}\"" if host.title else ""
            print(f"  • {host.url} -> {status_col}{host.status}{RESET} ({host.content_type}, {host.content_length} bytes, {host.response_time}s){srv}{title}")
        print()

    # 2. Subdomains
    if results.subdomains:
        print(f"{BOLD}[+] Subdomains Discovered ({len(results.subdomains)}):{RESET}")
        for sub in results.subdomains:
            ips = f" [{', '.join(sub.ips)}]" if sub.ips else " [unresolved]"
            status_tag = f"{GREEN}live{RESET}" if sub.is_live else f"{DIM}passive{RESET}"
            print(f"  • {sub.hostname}{ips} ({status_tag}, source: {sub.source})")
        print()

    # 3. JavaScript Files
    if results.javascript:
        print(f"{BOLD}[+] JavaScript Files Analyzed ({len(results.javascript)}):{RESET}")
        for js in results.javascript:
            print(f"  • {js}")
        print()

    # 4. Source Maps
    if results.source_maps:
        active_maps = [sm for sm in results.source_maps if sm.status == 200]
        other_maps = [sm for sm in results.source_maps if sm.status != 200]
        if active_maps:
            print(f"{BOLD}[+] Source Maps ({len(active_maps)} active, {len(other_maps)} inactive):{RESET}")
            for sm in active_maps:
                size_str = f", size: {sm.size} bytes" if sm.size is not None else ""
                print(f"  • {GREEN}{sm.url}{RESET}")
                print(f"      Referenced JS: {DIM}{sm.referenced_js}{RESET}")
                print(f"      {GREEN}[ACTIVE 200{size_str}, detected via {sm.detected_via}]{RESET}")
        else:
            print(f"{BOLD}[+] Source Maps:{RESET} {DIM}0 active found ({len(results.source_maps)} convention probes returned 404/inactive){RESET}")
        print()

    # 5. Discovered URLs & Endpoints
    if results.endpoints:
        unique_eps = sorted({ep.endpoint for ep in results.endpoints if ep.endpoint})
        print(f"{BOLD}[+] Discovered URLs & Endpoints ({len(unique_eps)} unique):{RESET}")
        for ep_url in unique_eps:
            is_api = any(ep.endpoint == ep_url and ep.endpoint_type == "api" for ep in results.endpoints)
            col = YELLOW if is_api else GREEN
            tag = f"{col}[API]{RESET} " if is_api else ""
            print(f"  • {tag}{ep_url}")
        print()

    # 6. Parameters
    if results.parameters:
        print(f"{BOLD}[+] Discovered Parameters ({len(results.parameters)}):{RESET}")
        print(f"  {', '.join(sorted(results.parameters))}")
        print()

    # Summary box
    print(f"{BOLD}{GREEN}══════════════════════════ SCAN SUMMARY ══════════════════════════{RESET}")
    print(f"  Target:            {results.target}")
    print(f"  Subdomains:        {len(results.subdomains)}")
    print(f"  Live Hosts:        {len(results.hosts)}")
    print(f"  JavaScript Files:  {len(results.javascript)}")
    print(f"  Resources:         {len(results.resources)}")
    print(f"  Source Maps:       {len(results.source_maps)}")
    print(f"  Endpoints:         {len(results.endpoints)}")
    print(f"  Unique Parameters: {len(results.parameters)}")
    print(f"{BOLD}{GREEN}══════════════════════════════════════════════════════════════════{RESET}\n")


class OutputManager:
    """Handles saving results to JSON, CSV, and output directories."""

    def __init__(
        self,
        results: ScanResults,
        json_file: Optional[str] = None,
        csv_file: Optional[str] = None,
        txt_file: Optional[str] = None,
        output_dir: Optional[str] = None,
        quiet: bool = False,
    ):
        self.results = results
        self.json_file = json_file
        self.csv_file = csv_file
        self.txt_file = txt_file
        self.output_dir = output_dir
        self.quiet = quiet

    def save_all(self) -> None:
        """Save results according to configured options."""
        if not self.output_dir and not self.json_file and not self.csv_file and not self.txt_file:
            if not self.quiet:
                print(f"{DIM}[*] Tip: No output file specified. To save findings, pass -o urls.txt, --txt urls.txt, or --output-dir ./results{RESET}\n")
            return
        # 1. Output directory export
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            if not self.quiet:
                print(f"\n{BOLD}[*] Saving scan artifacts to directory:{RESET} {self.output_dir}/")
            default_json_path = os.path.join(self.output_dir, "results.json")
            self.export_json(default_json_path)
            self.export_directory_csvs(self.output_dir)
            if not self.quiet:
                print(f"{BOLD}{GREEN}[✓] All findings organized in:{RESET} {self.output_dir}/\n")

        # 2. Explicit JSON export
        if self.json_file and (not self.output_dir or os.path.abspath(self.json_file) != os.path.abspath(os.path.join(self.output_dir, "results.json"))):
            parent = os.path.dirname(self.json_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self.export_json(self.json_file)

        # 3. Explicit CSV export
        if self.csv_file:
            parent = os.path.dirname(self.csv_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self.export_endpoints_csv(self.csv_file)

        # 4. Explicit TXT export
        if self.txt_file:
            parent = os.path.dirname(self.txt_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self.export_txt(self.txt_file)

    def export_txt(self, path: str) -> None:
        """Export clean discovered URLs to a plain text file (one URL per line)."""
        all_urls = self.results.get_all_urls(resolve_relative=True)
        with open(path, "w", encoding="utf-8") as f:
            for u in all_urls:
                f.write(f"{u}\n")
        if not self.quiet:
            print(f"{GREEN}[✓] URLs text file written to:{RESET} {path}")

    def export_json(self, path: str) -> None:
        """Export full scan results to JSON."""
        data = self.results.to_dict()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if not self.quiet:
            print(f"{GREEN}[✓] JSON results written to:{RESET} {path}")

    def export_endpoints_csv(self, path: str) -> None:
        """Export discovered endpoints (clean unique URLs) to CSV."""
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL"])
            unique_endpoints = sorted({ep.endpoint for ep in self.results.endpoints if ep.endpoint})
            for ep in unique_endpoints:
                writer.writerow([ep])
        if not self.quiet:
            print(f"{GREEN}[✓] Endpoints CSV written to:{RESET} {path}")

    def export_directory_csvs(self, directory: str) -> None:
        """Write individual clean CSVs for each entity inside output directory."""
        # endpoints.csv (only unique endpoint URLs)
        ep_path = os.path.join(directory, "endpoints.csv")
        self.export_endpoints_csv(ep_path)

        # resources.csv (only JavaScript URLs)
        res_path = os.path.join(directory, "resources.csv")
        with open(res_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL"])
            seen_js: set[str] = set()
            for r in self.results.resources:
                if r.resource_type == "javascript" and r.url not in seen_js:
                    seen_js.add(r.url)
                    writer.writerow([r.url])
            for j in self.results.javascript:
                if j not in seen_js:
                    seen_js.add(j)
                    writer.writerow([j])
        if not self.quiet:
            print(f"{GREEN}[✓] Resources CSV (JavaScript URLs) written to:{RESET} {res_path}")

        # hosts.csv (only unique live host URLs)
        host_path = os.path.join(directory, "hosts.csv")
        with open(host_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL"])
            unique_hosts = sorted({h.url for h in self.results.hosts if h.url})
            for h in unique_hosts:
                writer.writerow([h])
        if not self.quiet:
            print(f"{GREEN}[✓] Hosts CSV written to:{RESET} {host_path}")

        # subdomains.csv (only unique subdomains)
        sub_path = os.path.join(directory, "subdomains.csv")
        with open(sub_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain"])
            unique_subs = sorted({s.hostname for s in self.results.subdomains if s.hostname})
            for s in unique_subs:
                writer.writerow([s])
        if not self.quiet:
            print(f"{GREEN}[✓] Subdomains CSV written to:{RESET} {sub_path}")

        # source_maps.csv (only unique source map URLs)
        sm_path = os.path.join(directory, "source_maps.csv")
        with open(sm_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL"])
            unique_sms = sorted({sm.url for sm in self.results.source_maps if sm.url})
            for sm in unique_sms:
                writer.writerow([sm])
        if not self.quiet:
            print(f"{GREEN}[✓] Source Maps CSV written to:{RESET} {sm_path}")

        # urls.txt
        urls_path = os.path.join(directory, "urls.txt")
        all_urls = self.results.get_all_urls(resolve_relative=True)
        with open(urls_path, "w", encoding="utf-8") as f:
            for u in all_urls:
                f.write(f"{u}\n")
        if not self.quiet:
            print(f"{GREEN}[✓] Discovered URLs list written to:{RESET} {urls_path}")
