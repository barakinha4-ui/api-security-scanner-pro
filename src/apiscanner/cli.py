"""
cli.py — Advanced CLI for API Security Scanner v2.0

Usage:
    python cli.py --target https://api.site.com --scan full --output report.html
    python cli.py --target https://api.site.com --auth "Bearer TOKEN" --threads 50
    python cli.py --list-plugins
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

# Allow import from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import AsyncEngine
from core.models import Severity
from scanner import Scanner, PRESETS
from reports.reporter import JSONReporter, MarkdownReporter, HTMLReporter


# ─── Terminal colours ─────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def c(text, colour): return f"{colour}{text}{C.RESET}"

_SEV_COL = {
    "CRITICAL": C.RED, "HIGH": C.RED,
    "MEDIUM": C.YELLOW, "LOW": C.BLUE, "INFO": C.DIM,
}


# ─── Banner ───────────────────────────────────────────────────────────────────

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


# ─── Argument parser ──────────────────────────────────────────────────────────

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

  python cli.py \\
    --target https://api.example.com \\
    --auth "Bearer eyJ..." \\
    --scan full --threads 50 \\
    --output report.html

  python cli.py --target https://api.example.com --scan quick --stealth

  python cli.py --target https://api.example.com \\
    --scan custom --plugins sqli xss jwt graphql

  python cli.py --list-plugins
        """,
    )

    p.add_argument("--target", "-t",   metavar="URL",  help="Target API base URL (required)")
    p.add_argument("--scan",   "-s",   default="full",
                   choices=list(PRESETS.keys()) + ["custom"],
                   metavar="TYPE",     help=f"Scan type: {', '.join(PRESETS)} (default: full)")
    p.add_argument("--plugins", "-p",  nargs="+", metavar="PLUGIN",
                   help="Plugins to run when --scan custom")
    p.add_argument("--output",  "-o",  metavar="FILE",  help="Output report file (.html/.json/.md)")
    p.add_argument("--format",  "-f",  nargs="+", choices=["html","json","md"],
                   help="Report format(s) — inferred from --output if omitted")
    p.add_argument("--auth",    "-a",  metavar="TOKEN", help="Authorization header value for Victim (e.g. 'Bearer …')")
    p.add_argument("--auth-attacker",  metavar="TOKEN", help="Authorization header value for Attacker (for IDOR confirmation)")
    p.add_argument("--headers", "-H",  nargs="+", metavar="Name:Value",
                   help="Extra HTTP headers")
    p.add_argument("--threads",        type=int, default=20, metavar="N",
                   help="Concurrency (default: 20)")
    p.add_argument("--timeout",        type=int, default=10, metavar="SEC",
                   help="Request timeout seconds (default: 10)")
    p.add_argument("--delay",          type=float, default=0.2, metavar="SEC",
                   help="Delay between requests (default: 0.2)")
    p.add_argument("--stealth",        action="store_true",
                   help="Stealth mode: slower pacing, UA rotation, IP randomization")
    p.add_argument("--no-ssl-verify",  action="store_true",
                   help="Disable TLS certificate verification")
    p.add_argument("--proxy",          metavar="URL",
                   help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    p.add_argument("--verbose",  "-v", action="store_true",
                   help="Show each finding as it is discovered")
    p.add_argument("--quiet",    "-q", action="store_true",
                   help="Minimal output — findings summary only")
    p.add_argument("--no-confirm",     action="store_true",
                   help="Skip authorization confirmation prompt")
    p.add_argument("--list-plugins",   action="store_true",
                   help="List available plugins and exit")
    return p


# ─── Helpers ──────────────────────────────────────────────────────────────────

def parse_headers(raw: list | None) -> dict:
    headers = {}
    for h in (raw or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def print_finding_live(f):
    col = _SEV_COL.get(f.severity, C.DIM)
    print(f"\n  {col}⚠  [{f.severity}]{C.RESET} {f.title}")
    print(f"     {C.DIM}→ {f.endpoint}{C.RESET}")
    if f.cvss_score:
        print(f"     {C.DIM}CVSS {f.cvss_score}  |  {f.owasp_category}{C.RESET}")


def print_summary(result):
    s = result.summary
    print(f"\n{'═'*60}")
    print(c("  SCAN COMPLETE", C.BOLD))
    print(f"{'═'*60}")
    print(f"  {c('Target', C.DIM)}:   {result.target}")
    print(f"  {c('Duration', C.DIM)}: {result.duration_seconds:.1f}s  ·  {result.total_requests} requests")
    if result.waf_detected:
        print(f"  {c('WAF', C.DIM)}:      {c(result.waf_detected, C.YELLOW)} ({result.waf_confidence:.0f}%)")
    if result.technologies:
        print(f"  {c('Stack', C.DIM)}:    {', '.join(result.technologies)}")

    # Score bar
    score = s["security_score"]
    rating = s["security_rating"]
    scol = C.GREEN if score >= 75 else (C.YELLOW if score >= 50 else C.RED)
    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    print(f"\n  {c('SECURITY SCORE', C.BOLD)}")
    print(f"  {scol}{score}/100{C.RESET}  [{bar}]  Rating: {c(rating, scol)}")

    # Severity counts
    print(f"\n  {c('FINDINGS', C.BOLD)}")
    total = s["total"]
    print(f"  Total: {c(str(total), C.BOLD)}  ·  Confirmed: {s['confirmed_count']}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = s["by_severity"].get(sev, 0)
        if n:
            col = _SEV_COL.get(sev, C.DIM)
            emoji = Severity(sev).emoji
            bar_s = "■" * min(n * 2, 30)
            print(f"  {emoji} {sev:<10} {c(str(n).rjust(4), col)}  {bar_s}")

    if total == 0:
        print(f"\n  {c('✓ No vulnerabilities found.', C.GREEN)}")
        return

    # Top findings
    print(f"\n  {c('TOP FINDINGS', C.BOLD)}")
    for f in result.sorted_findings()[:10]:
        col = _SEV_COL.get(f.severity, C.DIM)
        conf = c("✓", C.GREEN) if f.confirmed else c("?", C.YELLOW)
        print(f"  {conf} {col}[{f.severity}]{C.RESET} {f.title[:55]}")
        print(f"      {C.DIM}→ {f.endpoint}  CVSS {f.cvss_score}{C.RESET}")

    print(f"\n{'═'*60}\n")


def save_reports(result, output: str, formats: list | None) -> list:
    base, ext = os.path.splitext(output)
    reporters = {
        "html": (HTMLReporter,     base + ".html"),
        "json": (JSONReporter,     base + ".json"),
        "md":   (MarkdownReporter, base + ".md"),
    }
    fmt_ext = ext.lstrip(".")
    target_fmts = formats or ([fmt_ext] if fmt_ext in reporters else ["html"])

    saved = []
    for fmt in target_fmts:
        if fmt in reporters:
            cls, path = reporters[fmt]
            cls().generate(result, path)
            size = os.path.getsize(path) / 1024
            print(f"  {c('✓', C.GREEN)} {fmt.upper()} report: {c(path, C.CYAN)} ({size:.1f} KB)")
            saved.append(path)
    return saved


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main_async(args) -> int:
    # Build headers
    headers = parse_headers(args.headers)
    if args.auth:
        auth = args.auth
        if not any(auth.lower().startswith(p) for p in ["bearer ", "basic ", "apikey ", "token "]):
            auth = f"Bearer {auth}"
        headers["Authorization"] = auth
        if not args.quiet:
            print(c(f"  [+] Auth: {auth[:40]}…", C.GREEN))

    auth_attacker = None
    if args.auth_attacker:
        raw_attacker = str(args.auth_attacker)
        if not any(raw_attacker.lower().startswith(p) for p in ["bearer ", "basic ", "apikey ", "token "]):
            auth_attacker = f"Bearer {raw_attacker}"
        else:
            auth_attacker = raw_attacker
            
        if not args.quiet:
            short_auth = auth_attacker[:40] if len(auth_attacker) > 40 else auth_attacker
            print(c(f"  [+] Attacker Auth: {short_auth}…", C.GREEN))

    if args.stealth and not args.quiet:
        print(c("  [+] Stealth mode enabled", C.CYAN))
    if args.proxy and not args.quiet:
        print(c(f"  [+] Proxy: {args.proxy}", C.CYAN))

    if not args.quiet:
        print(f"\n  {c('SCAN CONFIG', C.BOLD)}")
        print(f"  Target  : {c(args.target, C.CYAN)}")
        print(f"  Type    : {c(args.scan, C.CYAN)}")
        print(f"  Threads : {args.threads}  ·  Timeout: {args.timeout}s  ·  Delay: {args.delay}s")

    engine = AsyncEngine(
        concurrency = min(max(args.threads, 1), 200),
        timeout     = args.timeout,
        delay       = args.delay,
        stealth     = args.stealth,
        verify_ssl  = not args.no_ssl_verify,
        headers     = headers,
        proxy       = args.proxy,
    )

    plugins = args.plugins if args.scan == "custom" and args.plugins else None

    # Config shared with plugins
    scanner_config = {
        "auth_attacker": auth_attacker,
        "verbose": args.verbose
    }

    scanner = Scanner(
        target     = args.target,
        engine     = engine,
        scan_type  = args.scan,
        plugins    = plugins,
        config     = scanner_config,
        on_finding = print_finding_live if args.verbose else None,
    )

    print(f"\n  {c('Starting scan…', C.BOLD)}\n")

    async with engine:
        result = await scanner.run()

    if not args.quiet:
        print_summary(result)

    if args.output:
        if not args.quiet:
            print(f"  {c('Generating reports…', C.BOLD)}")
        save_reports(result, args.output, args.format)

    # Exit code: 2=critical, 1=high, 0=ok
    s = result.summary
    if s["by_severity"].get("CRITICAL", 0) > 0:
        return 2
    if s["by_severity"].get("HIGH", 0) > 0:
        return 1
    return 0


def main():
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    # List plugins mode
    if args.list_plugins:
        from core.plugins import Registry
        Registry.discover()
        plugins = Registry.list_info()
        print(f"  {c('AVAILABLE PLUGINS', C.BOLD)} ({len(plugins)} loaded)\n")
        for p in plugins:
            print(f"  {c(p['name'],''):20} {c(p['name'], C.CYAN)}")
            print(f"  {C.DIM}  {p['description']}")
            print(f"  OWASP: {p['owasp']}  |  Tags: {', '.join(p['tags'])}{C.RESET}\n")
        return

    if not args.target:
        parser.error("--target is required (use --list-plugins to see available plugins)")

    if not args.target.startswith(("http://", "https://")):
        print(c("  [!] Target must start with http:// or https://", C.RED))
        sys.exit(1)

    # Authorization confirmation
    if not args.no_confirm:
        print(c("  ⚠  AUTHORIZATION CHECK", C.YELLOW))
        print(c("  This tool performs active security testing.", C.YELLOW))
        print(c("  Only use on systems you own or have written permission to test.\n", C.YELLOW))
        ans = input("  Confirm you are authorized to test this target? [y/N]: ")
        if ans.strip().lower() not in ("y", "yes", "s", "sim"):
            print(c("  Scan cancelled.", C.RED))
            sys.exit(0)

    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
