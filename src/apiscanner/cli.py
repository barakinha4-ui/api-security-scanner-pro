"""
cli.py — Advanced CLI for API Security Scanner v2.0
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from typing import Any, cast

# Ensure the src/apiscanner directory is in the path for internal imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.engine import AsyncEngine
from core.models import Severity
from scanner import Scanner, PRESETS
from reports.reporter import JSONReporter, MarkdownReporter, HTMLReporter
from scanner_config import ScannerConfig
from core.ui import C, c
from core.logger import setup_logger, logger

BANNER = f"""{C.CYAN}
  ╔══════════════════════════════════════════════════════════════╗
  ║  ▄▀█ █▀█ █   █▀ █▀▀ █▀▀   █▀ █▀▀ ▄▀█ █▄ █ █▄ █ █▀▀ █▀█   ║
  ║  █▀█ █▀▀ █   ▄█ ██▄ █▄▄   ▄█ █▄▄ █▀█ █ ▀█ █ ▀█ ██▄ █▀▄   ║
  ║                                                              ║
  ║       Advanced API Security Scanner  ·  v2.0                ║
  ║       asyncio · OWASP API Top 10 · CVSS 3.1 · REST+GQL      ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  ⚠  FOR AUTHORIZED SECURITY TESTING ONLY                   ║
  ╚══════════════════════════════════════════════════════════════╝
{C.RESET}"""

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python cli.py",
        description="Advanced Async API Security Scanner — OWASP Top 10 + API Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.CYAN}SCAN TYPES:{C.RESET}
  quick    Headers, CORS, SSL, debug endpoints (fast recon)
  auth     Authentication, JWT, default credentials
  inject   SQLi, NoSQLi, XSS, SSRF, SSTI
  api      IDOR, GraphQL, CORS, mass assignment
  full     All modules (default)
  stealth  Minimal footprint, slow pacing

{C.CYAN}EXAMPLES:{C.RESET}
  python cli.py --target https://api.example.com --scan full --output report.html
  python cli.py --target https://api.example.com --dry-run
        """,
    )
    p.add_argument("--target", "-t",   metavar="URL",  help="Target API base URL (required)")
    p.add_argument("--scan",   "-s",   default="full",
                   choices=list(PRESETS.keys()) if PRESETS else ["full"],
                   metavar="TYPE",     help="Scan type (default: full)")
    p.add_argument("--plugins", "-p",  nargs="+", metavar="PLUGIN",
                   help="Plugins to run when --scan custom")
    p.add_argument("--output",  "-o",  metavar="FILE",  help="Output report file (.html/.json/.md)")
    p.add_argument("--format",  "-f",  nargs="+", choices=["html","json","md"],
                   help="Report format(s)")
    p.add_argument("--auth",    "-a",  metavar="TOKEN", help="Authorization header (e.g. 'Bearer …')")
    p.add_argument("--auth-attacker",  metavar="TOKEN", help="Attacker Authorization header (for BOLA)")
    p.add_argument("--threads",        type=int, default=20, help="Concurrency (default: 20)")
    p.add_argument("--timeout",        type=int, default=10, help="Timeout seconds")
    p.add_argument("--delay",          type=float, default=0.2, help="Delay between requests")
    p.add_argument("--stealth",        action="store_true", help="Enable stealth mode")
    p.add_argument("--no-ssl-verify",  action="store_true", help="Disable SSL verification")
    p.add_argument("--proxy",          metavar="URL", help="HTTP proxy")
    p.add_argument("--verbose",  "-v", action="store_true", help="Verbose output")
    p.add_argument("--quiet",    "-q", action="store_true", help="Minimal output")
    p.add_argument("--no-confirm",     action="store_true", help="Skip authorization check")
    p.add_argument("--dry-run",        action="store_true", help="Simulate scan without payloads")
    p.add_argument("--list-plugins",   action="store_true", help="List plugins and exit")
    return p

def print_finding_live(f):
    col = C.RED if f.severity in ("CRITICAL", "HIGH") else C.YELLOW
    print(f"\n  {col}⚠  [{f.severity}]{C.RESET} {f.title}")
    print(f"     {C.DIM}→ {f.endpoint}{C.RESET}")

def print_summary(result):
    s = result.summary
    print(f"\n{'═'*60}")
    print(c("  SCAN COMPLETE", C.BOLD))
    print(f"{'═'*60}")
    print(f"  Target:   {result.target}")
    print(f"  Duration: {result.duration_seconds:.1f}s")
    print(f"  Score:    {c(str(s['security_score']), C.GREEN)}/100")
    print(f"  Findings: {s['total']} ({s['confirmed_count']} confirmed)")
    print(f"{'═'*60}\n")

async def main_async(args) -> int:
    setup_logger(level=10 if args.verbose else 20)
    
    headers = {}
    if args.auth:
        headers["Authorization"] = args.auth if " " in args.auth else f"Bearer {args.auth}"

    conf = ScannerConfig(
        max_concurrency = args.threads,
        request_timeout = args.timeout,
        verify_ssl = not args.no_ssl_verify,
        oast_provider = "interact.sh"
    )

    engine = AsyncEngine(
        concurrency = args.threads,
        timeout     = args.timeout,
        delay       = args.delay,
        stealth     = args.stealth,
        verify_ssl  = not args.no_ssl_verify,
        headers     = headers,
        proxy       = args.proxy,
        dry_run     = args.dry_run
    )

    scanner = Scanner(
        target     = args.target,
        engine     = engine,
        scan_type  = args.scan,
        plugins    = args.plugins,
        config     = conf,
        on_finding = print_finding_live if not args.quiet else None,
        dry_run    = args.dry_run
    )

    print(f"\n  {c('Starting scan…', C.BOLD)}\n")

    async with engine:
        result = await scanner.run()

    if not args.quiet:
        print_summary(result)

    if args.output:
        base, ext = os.path.splitext(args.output)
        formats = args.format or ([ext.lstrip('.')] if ext else ['html'])
        
        if 'html' in formats or ext == '.html':
            HTMLReporter().generate(result, base + ".html")
            print(f"  {c('✓', C.GREEN)} HTML Report saved: {base}.html")
        
        if 'json' in formats or ext == '.json':
            JSONReporter().generate(result, base + ".json")
            print(f"  {c('✓', C.GREEN)} JSON Report saved: {base}.json")
            
        if 'md' in formats or ext == '.md':
            MarkdownReporter().generate(result, base + ".md")
            print(f"  {c('✓', C.GREEN)} Markdown Report saved: {base}.md")

    s = result.summary
    if s["by_severity"].get("CRITICAL", 0) > 0: return 2
    if s["by_severity"].get("HIGH", 0) > 0: return 1
    return 0

def main():
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    if args.list_plugins:
        from core.plugins import Registry
        Registry.discover()
        for p in Registry.list_info():
            print(f"  {c(p['name'], C.CYAN):20} {p['description']}")
        return

    if not args.target:
        parser.error("--target is required")

    if not args.no_confirm:
        ans = input(f"  {C.YELLOW}Confirm authorization to test {args.target}? [y/N]: {C.RESET}")
        if ans.lower() not in ('y', 'yes'):
            print("  Cancelled.")
            return

    try:
        sys.exit(asyncio.run(main_async(args)))
    except KeyboardInterrupt:
        print("\n  [!] User interrupted.")
        sys.exit(1)

if __name__ == "__main__":
    main()
