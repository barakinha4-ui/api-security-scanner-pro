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
from reports.reporter import JSONReporter, MarkdownReporter, HTMLReporter, PDFReporter
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
    p.add_argument("--encrypt",        action="store_true", help="Encrypt report data (AES-256)")
    p.add_argument("--api-key",        metavar="KEY", help="API Key for authorized execution")
    p.add_argument("--ws-port",        type=int, help="Optional WebSocket port for LIVE findings streaming")
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

    ws_clients = set()
    ws_server = None
    progress_task = None
    if args.ws_port:
        try:
            import websockets
            import jwt
            import json
            import uuid
            from datetime import datetime, timezone
            from urllib.parse import urlparse
            from pydantic import BaseModel, ValidationError, Field

            jwt_secret = os.getenv("SUPABASE_JWT_SECRET", "super-secret-jwt-token-from-supabase")

            class AuthMessage(BaseModel):
                """Schema for initial WebSocket Auth Message."""
                token: str
                
            class JWTPayload(BaseModel):
                """Model for internal Payload extraction."""
                sub: uuid.UUID
                exp: int
                roles: list[str] = Field(default_factory=list)

                def is_valid(self) -> bool:
                    return time.time() < self.exp
            
            class ProgressMessage(BaseModel):
                """Schema for WebSocket Progress Broadcast."""
                host: str
                port: int
                status: str
                severity: str
                timestamp: str
                
            ACTIVE_CLIENTS: dict[websockets.WebSocketServerProtocol, dict] = {}

            async def websocket_handler(websocket: websockets.WebSocketServerProtocol, path: str = ""):
                """
                Handles incoming WebSocket connections exactly per specification.
                1. Expects {"token": "JWT"}
                2. Validates JWTPayload (Pydantic)
                3. Invalid -> Close 1008
                4. Valid -> Active list
                """
                peer = websocket.remote_address
                conn_ts = datetime.now(timezone.utc).isoformat()
                
                try:
                    auth_msg_raw = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    auth_msg = AuthMessage.model_validate_json(auth_msg_raw) if hasattr(AuthMessage, 'model_validate_json') else AuthMessage.parse_raw(auth_msg_raw)
                    
                    decoded = jwt.decode(auth_msg.token, jwt_secret, algorithms=["HS256"], options={"verify_exp": False, "verify_aud": False})
                    payload = JWTPayload(**decoded)
                    
                    if not payload.is_valid():
                        raise ValueError("JWT is expired")
                        
                    user_id = payload.sub
                except (asyncio.TimeoutError, ValidationError, jwt.InvalidTokenError, ValueError) as e:
                    logger.warning(json.dumps({"event": "ws_auth_failed", "reason": str(e), "ip": peer[0], "ts": conn_ts}))
                    await websocket.close(1008, "Invalid or missing JWT Token")
                    return
                except Exception as e:
                    await websocket.close(1008, "Internal Auth Error")
                    return

                # Auth Success
                ACTIVE_CLIENTS[websocket] = {"last_seen": time.time(), "user_id": user_id}
                logger.info(json.dumps({"event": "ws_connected", "user_id": str(user_id), "ip": peer[0], "ts": conn_ts}))

                async def heartbeat_task():
                    """Sends heartbeat every 30s"""
                    while True:
                        await asyncio.sleep(30)
                        try:
                            await websocket.send(json.dumps({"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat()}))
                        except Exception:
                            break

                async def inactivity_task():
                    """Monitors inactivity and closes with 1000 if > 5min unseen"""
                    while True:
                        await asyncio.sleep(10)
                        state = ACTIVE_CLIENTS.get(websocket)
                        if not state:
                            break
                        if time.time() - state["last_seen"] > 300: # 5 min timeout
                            logger.info(json.dumps({"event": "ws_timeout", "user_id": str(state["user_id"]), "ip": peer[0], "ts": datetime.now(timezone.utc).isoformat()}))
                            await websocket.close(1000, "Inactive for 5 minutes")
                            break

                hb_t = asyncio.create_task(heartbeat_task())
                inact_t = asyncio.create_task(inactivity_task())

                try:
                    async for msg in websocket:
                        if websocket in ACTIVE_CLIENTS:
                            ACTIVE_CLIENTS[websocket]["last_seen"] = time.time()
                except websockets.exceptions.ConnectionClosed:
                    pass
                finally:
                    hb_t.cancel()
                    inact_t.cancel()
                    state = ACTIVE_CLIENTS.pop(websocket, None)
                    if state:
                        logger.info(json.dumps({"event": "ws_disconnected", "user_id": str(state["user_id"]), "ip": peer[0], "ts": datetime.now(timezone.utc).isoformat()}))

            ws_server = await websockets.serve(websocket_handler, "0.0.0.0", args.ws_port)
            print(f"  {c('✓', C.GREEN)} Native WebSocket server started on ws://0.0.0.0:{args.ws_port} (JWT Protected)")

            async def broadcast_progress(scanner_event: ProgressMessage):
                """Broadcasts to active authenticated clients"""
                if not ACTIVE_CLIENTS:
                    return
                    
                msg_dict = {"type": "finding"} # Frontend assumes findings or progress typings
                msg_dict.update(scanner_event.model_dump() if hasattr(scanner_event, "model_dump") else scanner_event.dict())
                msg_json = json.dumps(msg_dict)
                
                closed_clients = []
                for ws_client in list(ACTIVE_CLIENTS.keys()):
                    try:
                        await ws_client.send(msg_json)
                    except Exception:
                        closed_clients.append(ws_client)
                        
                for c in closed_clients:
                    ACTIVE_CLIENTS.pop(c, None)

            async def scanner_callback(f):
                """Interceptor connecting engine matches to JS WS clients"""
                if not args.quiet:
                    print_finding_live(f)
                    
                parsed = urlparse(args.target)
                target_host = parsed.hostname or args.target
                target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                
                prog = ProgressMessage(
                    host=target_host,
                    port=target_port,
                    status="discovering",
                    severity=f.severity,
                    timestamp=datetime.now(timezone.utc).isoformat()
                )
                await broadcast_progress(prog)

            scanner = Scanner(
                target     = args.target,
                engine     = engine,
                scan_type  = args.scan,
                plugins    = args.plugins,
                config     = conf,
                on_finding = scanner_callback,
                dry_run    = args.dry_run
            )

        except ImportError as e:
            print(f"  [!] Requirements 'websockets', 'PyJWT', or 'pydantic' dependencies missing: {e}")
            args.ws_port = None
            
            scanner = Scanner(
                target     = args.target,
                engine     = engine,
                scan_type  = args.scan,
                plugins    = args.plugins,
                config     = conf,
                on_finding = print_finding_live if not args.quiet else None,
                dry_run    = args.dry_run
            )
    else:
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
            JSONReporter().generate(result, base + ".json", encrypt=args.encrypt)
            msg = "Encrypted JSON Report saved" if args.encrypt else "JSON Report saved"
            print(f"  {c('✓', C.GREEN)} {msg}: {base}.json")
            
        if 'md' in formats or ext == '.md':
            MarkdownReporter().generate(result, base + ".md")
            print(f"  {c('✓', C.GREEN)} Markdown Report saved: {base}.md")

        if 'pdf' in formats or ext == '.pdf':
            path = PDFReporter().generate(result, base + ".pdf")
            if path:
                print(f"  {c('✓', C.GREEN)} PDF Report saved: {base}.pdf")

    if ws_server:
        ws_server.close()
        await ws_server.wait_closed()

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

    conf = ScannerConfig()
    if conf.api_key_required:
        provided_key = args.api_key or os.environ.get("API_KEY") or os.environ.get("SCANNER_API_KEY")
        if not provided_key:
            try:
                import json
                with open("keys.json", "r") as f:
                    keys_data = json.load(f)
                    provided_key = keys_data.get("API_KEY")
            except Exception:
                pass
        
        if not provided_key:
            logger.error("Unauthorized execution attempt: Missing API Key.")
            parser.error("--api-key is required by system policy (via arg, .env, or keys.json)")

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
