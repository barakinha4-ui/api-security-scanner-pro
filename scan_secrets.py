#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   SECRET SCANNER — Git History Secret Detector      ║
║   Scans ALL commits for leaked secrets/passwords     ║
╚══════════════════════════════════════════════════════╝
Usage:
  python scan_secrets.py
"""

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# ── ANSI Colors ──────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; B = "\033[1m"; D = "\033[2m"; X = "\033[0m"

# ── Secret Patterns ──────────────────────────────────────
PATTERNS = [
    ("API Key / Password (generic)",   r'(?i)(api_key|api_secret|password|passwd|secret|token|auth)\s*[=:]\s*["\']?([A-Za-z0-9\-_@#$%!&]{12,})["\']?'),
    ("JWT Token",                       r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
    ("Hex Secret (32+ chars)",          r'(?<![a-f0-9])[a-f0-9]{32,}(?![a-f0-9])'),
    ("Base64 Secret (40+ chars)",       r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])'),
    ("Private Key header",              r'-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----'),
    ("Supabase URL",                    r'supabase\.co'),
    ("Redis URL with password",         r'redis://:?[^@\s]{6,}@'),
    ("GitHub Token",                    r'gh[pousr]_[A-Za-z0-9]{36,}'),
    ("AWS Key",                         r'AKIA[0-9A-Z]{16}'),
    ("Slack Token",                     r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    ("Hardcoded IP:Port cred",          r'https?://[a-zA-Z0-9]+:[a-zA-Z0-9@#$%!]{6,}@'),
]

# Files to always skip
SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                   '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.zip',
                   '.tar', '.gz', '.pyc'}
SKIP_FILES      = {'package-lock.json', 'yarn.lock', 'poetry.lock',
                   '.gitignore', '.env.example', 'scan_secrets.py',
                   'git_security_cleanup.py'}

# Known-safe values to whitelist (never flag these)
WHITELIST = {
    'change_me', 'your_password', 'example', 'placeholder',
    'your_redis_password', 'your_api_key', 'changeme',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
}

@dataclass
class Hit:
    commit: str
    file: str
    line_num: int
    pattern: str
    snippet: str  # NEVER the real secret — masked

def mask(value: str) -> str:
    """Show only first 4 chars, mask the rest."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * min(len(value) - 4, 20) + f" ({len(value)} chars)"

def run(cmd: list) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return r.stdout

def get_all_commits() -> list[str]:
    out = run(["git", "log", "--all", "--format=%H"])
    return [h.strip() for h in out.strip().splitlines() if h.strip()]

def get_commit_files(sha: str) -> list[str]:
    out = run(["git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha])
    return [f.strip() for f in out.strip().splitlines() if f.strip()]

def get_file_at_commit(sha: str, filepath: str) -> str:
    r = subprocess.run(["git", "show", f"{sha}:{filepath}"],
                        capture_output=True, errors='replace')
    try:
        return r.stdout.decode('utf-8', errors='replace')
    except Exception:
        return ""

def scan_content(content: str, filepath: str, sha: str, hits: list):
    for line_num, line in enumerate(content.splitlines(), 1):
        for name, pattern in PATTERNS:
            matches = re.findall(pattern, line)
            for m in matches:
                # m could be a tuple (group captures) or string
                val = m[1] if isinstance(m, tuple) and len(m) > 1 else (m if isinstance(m, str) else m[0])
                val_low = val.lower() if isinstance(val, str) else ""
                # Skip whitelisted / too-short values
                if any(w in val_low for w in WHITELIST) or len(val) < 8:
                    continue
                # Mask for display — NEVER log raw secret
                snippet = line.strip()[:80]
                # Mask any high-entropy substring in snippet
                masked = re.sub(r'[A-Za-z0-9\-_@#$%!&]{12,}',
                                lambda x: mask(x.group()), snippet)
                hits.append(Hit(sha[:8], filepath, line_num, name, masked))

def scan_current_files(hits: list):
    """Also scan untracked local files (not yet committed)."""
    print(f"\n{C}  ► Scanning working directory...{X}")
    sensitive_names = ['.env', '.env.local', '.env.production', 'api_log.txt']
    for name in sensitive_names:
        p = Path(name)
        if p.exists():
            content = p.read_text(encoding='utf-8', errors='replace')
            scan_content(content, f"[LOCAL] {name}", "working-dir", hits)
            print(f"  {Y}  ⚠ Scanned local file: {name}{X}")

def main():
    print(f"""
{B}{C}
╔══════════════════════════════════════════════════════╗
║       SECRET SCANNER — Git History Audit             ║
╚══════════════════════════════════════════════════════╝{X}
  {D}Note: No secret values are printed — only masked previews{X}
""")

    # Verify git repo
    r = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                        capture_output=True)
    if r.returncode != 0:
        print(f"{R}Not a git repo!{X}"); sys.exit(1)

    commits = get_all_commits()
    print(f"  {G}Found {len(commits)} commits to scan{X}\n")

    hits: list[Hit] = []
    scanned = 0

    for sha in commits:
        files = get_commit_files(sha)
        for fpath in files:
            ext = Path(fpath).suffix.lower()
            name = Path(fpath).name
            if ext in SKIP_EXTENSIONS or name in SKIP_FILES:
                continue
            content = get_file_at_commit(sha, fpath)
            if not content:
                continue
            scan_content(content, fpath, sha, hits)
            scanned += 1

    scan_current_files(hits)

    print(f"\n  {G}► Scanned {scanned} file-versions across {len(commits)} commits{X}")

    # ── REPORT ──────────────────────────────────────────────
    if not hits:
        print(f"\n  {G}{B}✔  No secrets detected!{X}")
    else:
        print(f"\n  {R}{B}✘  {len(hits)} potential secret(s) found:{X}\n")
        # Group by file
        by_file: dict = {}
        for h in hits:
            by_file.setdefault(h.file, []).append(h)

        for fpath, file_hits in by_file.items():
            print(f"  {R}📁 {fpath}{X}  ({len(file_hits)} hit(s))")
            for h in file_hits[:5]:  # show max 5 per file
                print(f"     {D}commit:{h.commit}  line:{h.line_num}{X}")
                print(f"     {Y}pattern: {h.pattern}{X}")
                print(f"     {D}snippet: {h.snippet}{X}")
            if len(file_hits) > 5:
                print(f"     {D}... and {len(file_hits)-5} more{X}")
            print()

        print(f"""
  {R}{B}ACTION REQUIRED:{X}
  {Y}1. Run: python git_security_cleanup.py — to purge from history{X}
  {Y}2. Rotate ALL exposed credentials immediately{X}
  {Y}3. After purge, force-push and notify collaborators to re-clone{X}
""")

    # Summary
    print(f"  {D}Scan completed at {__import__('datetime').datetime.now().isoformat()}{X}\n")

if __name__ == "__main__":
    main()
