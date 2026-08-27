"""Command-line interface and entry point for JSFinder."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
from urllib.parse import urlsplit

from jsfinder.crawler import Crawler
from jsfinder.http import DEFAULT_USER_AGENT, SafeHttpClient
from jsfinder.output import (
    OutputManager,
    print_banner,
    print_scope_summary,
    print_terminal_results,
)
from jsfinder.ratelimit import PerHostRateLimiter
from jsfinder.scope import ScopeManager


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure console logging level and format."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="jsfinder",
        description="JSFinder: Domain Attack-Surface & Static Resource Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jsfinder.py -u https://example.com
  python jsfinder.py -u https://example.com --subdomains
  python jsfinder.py -u https://example.com --active-subdomains
  python jsfinder.py -u https://example.com --rate 2 --concurrency 3 --delay 0.5
  python jsfinder.py -u https://example.com --json results.json
  python jsfinder.py -u https://example.com --scope scope.txt --output-dir ./results
""",
    )

    # Target & Scope
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL or domain (e.g. https://example.com or example.com)",
    )
    parser.add_argument(
        "--scope",
        metavar="FILE",
        help="File containing explicit scope rules (one domain, wildcard, or CIDR per line)",
    )

    # Subdomain Discovery
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Enable passive subdomain discovery (Certificate Transparency, page extraction)",
    )
    parser.add_argument(
        "--active-subdomains",
        action="store_true",
        help="Enable active DNS subdomain enumeration using wordlist",
    )
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        help="Custom wordlist file for active subdomain discovery",
    )

    # Rate Limiting & Concurrency
    parser.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help="Maximum requests per second per host (default: 2.0)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Maximum global concurrent HTTP requests (default: 3)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Minimum delay in seconds between requests to the same host (default: 0.5)",
    )
    parser.add_argument(
        "--jitter",
        action="store_true",
        help="Add small randomized jitter to inter-request delays",
    )

    # Network & HTTP
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="Custom User-Agent HTTP header string",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS/SSL certificate verification",
    )

    # Crawl Scope Limits
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum HTML crawl depth (default: 2)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum number of HTML pages to crawl (default: 50)",
    )
    parser.add_argument(
        "--download-sourcemaps",
        action="store_true",
        help="Download discovered source map files into output directory",
    )

    # Output Options
    parser.add_argument(
        "-o",
        "--output",
        help="Generic output file path (defaults to JSON format)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export structured findings to JSON file",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Export discovered endpoints to CSV file",
    )
    parser.add_argument(
        "--txt",
        metavar="FILE",
        help="Export discovered URLs to plain text file (one per line)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory to save full reports (default: jsresult/<domain>)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Disable automatic saving of results to jsresult/ directory",
    )

    # Verbosity
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress banner and verbose progress messages",
    )
    parser.add_argument(
        "--urls-only",
        "--only-urls",
        action="store_true",
        dest="urls_only",
        help="Print only discovered URLs to stdout (one per line, ideal for piping)",
    )

    return parser.parse_args(args)


def normalize_target_url(raw_target: str) -> str:
    """Ensure the target has a valid scheme and host."""
    target = raw_target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"https://{target}"
    parsed = urlsplit(target)
    if not parsed.hostname:
        raise ValueError(f"Invalid target URL or domain: {raw_target}")
    return target


async def async_main(args: argparse.Namespace) -> int:
    """Asynchronous main scanner routine."""
    # 1. Normalize target
    try:
        target_url = normalize_target_url(args.url)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1

    # 2. Scope setup
    scope_mgr = ScopeManager(target_url_or_host=target_url)
    if args.scope:
        if not os.path.isfile(args.scope):
            sys.stderr.write(f"Error: Scope file not found: {args.scope}\n")
            return 1
        scope_mgr.load_from_file(args.scope)

    # 3. Print Banner & Scope Summary
    if not args.quiet and not args.urls_only:
        print_banner()
        print_scope_summary(target=target_url, scope_rules=scope_mgr.get_rules())

    # 4. Load custom wordlist if specified
    active_wordlist = None
    if args.wordlist:
        if os.path.isfile(args.wordlist):
            with open(args.wordlist, "r", encoding="utf-8") as f:
                active_wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            sys.stderr.write(f"Warning: Wordlist file not found: {args.wordlist}. Using defaults.\n")

    # 5. Initialize Rate Limiter & HTTP Client
    rate_limiter = PerHostRateLimiter(
        rate=args.rate,
        concurrency=args.concurrency,
        delay=args.delay,
        jitter=args.jitter,
    )

    async with SafeHttpClient(
        scope_manager=scope_mgr,
        rate_limiter=rate_limiter,
        timeout=args.timeout,
        user_agent=args.user_agent,
        verify_ssl=not args.insecure,
    ) as http_client:
        # Determine output directory (defaults to jsresult/<domain>)
        output_dir = args.output_dir
        if not output_dir and not args.no_save:
            target_host = urlsplit(target_url).hostname or "target"
            safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "_", target_host).strip("._") or "target"
            output_dir = os.path.join("jsresult", safe_domain)

        crawler = Crawler(
            target=target_url,
            scope_manager=scope_mgr,
            rate_limiter=rate_limiter,
            http_client=http_client,
            enable_subdomains=args.subdomains or args.active_subdomains,
            enable_active_subdomains=args.active_subdomains,
            active_wordlist=active_wordlist,
            max_depth=args.max_depth,
            max_pages=args.max_pages,
            download_sourcemaps=args.download_sourcemaps,
            output_dir=output_dir,
            progress_callback=(lambda m: None) if (args.quiet or args.urls_only) else None,
        )

        results = await crawler.run()

    # 6. Terminal Reporting
    if args.urls_only:
        all_urls = results.get_all_urls(resolve_relative=True)
        for u in all_urls:
            print(u)
    elif not args.quiet:
        print_terminal_results(results)

    # 7. File Outputs
    txt_path = args.txt or (args.output if args.output and args.output.endswith(".txt") else None)
    json_path = args.json or (args.output if args.output and args.output.endswith(".json") else None)
    csv_path = args.csv or (args.output if args.output and args.output.endswith(".csv") else None)
    if args.output and not json_path and not csv_path and not txt_path:
        json_path = args.output

    out_mgr = OutputManager(
        results=results,
        json_file=json_path,
        csv_file=csv_path,
        txt_file=txt_path,
        output_dir=output_dir,
        quiet=args.urls_only or args.quiet,
    )
    out_mgr.save_all()

    return 0


def main(args: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parsed_args = parse_args(args)
    setup_logging(verbose=parsed_args.verbose, quiet=parsed_args.quiet or parsed_args.urls_only)
    try:
        return asyncio.run(async_main(parsed_args))
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Scan aborted by user (KeyboardInterrupt).\n")
        return 130
    except Exception as e:
        sys.stderr.write(f"\n[Fatal Error] {e}\n")
        if parsed_args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
