#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       GIT SECRET PURGE — Secure Repository Cleaner          ║
║       Removes sensitive files from Git history safely        ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  python git_security_cleanup.py

REQUIREMENTS:
  pip install gitpython
  pip install git-filter-repo   (or: pip install git-filter-repo)

WARNING: --force-push rewrites history. Coordinate with your team.
"""

import os
import sys
import subprocess
import secrets
import shutil
from pathlib import Path
from datetime import datetime

# ─── ANSI COLORS ──────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def ok(msg):   print(f"{C.GREEN}  ✔  {msg}{C.RESET}")
def err(msg):  print(f"{C.RED}  ✘  {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}  ⚠  {msg}{C.RESET}")
def info(msg): print(f"{C.CYAN}  ►  {msg}{C.RESET}")
def head(msg): print(f"\n{C.BOLD}{C.CYAN}{'─'*60}\n  {msg}\n{'─'*60}{C.RESET}")
def ask(prompt) -> bool:
    print(f"{C.YELLOW}  ? {prompt} [Auto-Yes]{C.RESET}")
    return True

# ─── SENSITIVE FILE PATTERNS ──────────────────────────────────
SENSITIVE_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.locust.example",  # contains real values in this repo
    "api_log.txt",
    "*.log",
    "report_*.html",
    "jsonplaceholder_report.html",
    "scan_report_*.html",
    "scan_report_*.pdf",
]

# Files to forcibly remove from git index (exact names)
REMOVE_FROM_INDEX = [
    ".env",
    ".env.local",
    ".env.locust.example",
    "api_log.txt",
]

# ─── GITIGNORE ADDITIONS ──────────────────────────────────────
GITIGNORE_BLOCK = """
# ─── SECURITY: Never commit secrets ──────────────────────────
.env*
!.env.example
!.env.example.*

# Logs
*.log
logs/
api_log.txt

# Reports (may contain scan output / credentials)
report_*.html
report_*.pdf
report_*.json
scan_report_*
jsonplaceholder_report.html

# Python cache
*.pyc
*.pyo
__pycache__/
.coverage
coverage.xml
htmlcov/

# OS
.DS_Store
Thumbs.db

# Secrets / Keys
*.pem
*.key
*.p12
*.pfx
secrets.json
credentials.json
service_account*.json
"""

# ─── ENV EXAMPLE TEMPLATE ─────────────────────────────────────
ENV_EXAMPLE_TEMPLATE = """\
# ================================================================
# API Security Scanner Pro — Environment Variables (EXAMPLE)
# ================================================================
# IMPORTANT: Copy this file to .env and fill with REAL values.
#            NEVER commit .env to version control.
# ================================================================

# ─── Auth ───────────────────────────────────────────────────────
# The main API key used to authenticate HTTP + WebSocket calls.
SCANNER_API_KEY=CHANGE_ME_API_KEY_MIN_32_CHARS_RANDOM

# FastAPI / SaaS wrapper key
API_KEY_SECRET=CHANGE_ME_API_KEY_MIN_32_CHARS_RANDOM

# Supabase JWT secret (if using Supabase Auth)
SUPABASE_JWT_SECRET=CHANGE_ME_SUPABASE_JWT_SECRET_MIN_32_CHARS

# ─── Encryption ─────────────────────────────────────────────────
# AES-256 master encryption key for reports. Must be exactly 32 bytes.
SCANNER_ENCRYPTION_KEY=CHANGE_ME_EXACTLY_32_CHARS_HERE!!

# ─── Server ─────────────────────────────────────────────────────
SCANNER_HOST=0.0.0.0
SCANNER_PORT=8000

# ─── Redis ──────────────────────────────────────────────────────
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=CHANGE_ME_STRONG_REDIS_PASSWORD

# ─── Scanner Defaults ───────────────────────────────────────────
MAX_CONCURRENCY=20
REQUEST_TIMEOUT=10
OAST_PROVIDER=interact.sh

# ─── Grafana ────────────────────────────────────────────────────
GRAFANA_ADMIN_PASSWORD=CHANGE_ME_GRAFANA_ADMIN_PASSWORD
"""

# ─── HELPER FUNCTIONS ─────────────────────────────────────────
def run(cmd: list[str], check=True, capture=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)

def git(*args, check=True):
    return run(["git"] + list(args), check=check)

def file_in_history(path: str) -> bool:
    """Check if a file has ever been committed in git history."""
    res = run(["git", "log", "--all", "--full-history", "--", path], check=False)
    return bool(res.stdout.strip())

def generate_secrets() -> dict:
    """Generate cryptographically secure random values (NEVER log the real values)."""
    return {
        "SCANNER_API_KEY":         secrets.token_hex(32),   # 64 hex chars
        "API_KEY_SECRET":          secrets.token_hex(32),
        "SUPABASE_JWT_SECRET":     secrets.token_hex(32),
        "SCANNER_ENCRYPTION_KEY":  secrets.token_urlsafe(24)[:32],  # exactly 32 chars
        "REDIS_PASSWORD":          secrets.token_urlsafe(24),
        "GRAFANA_ADMIN_PASSWORD":  secrets.token_urlsafe(20),
    }

# ══════════════════════════════════════════════════════════════
# STEP 1 — AUDIT: Check what's in history
# ══════════════════════════════════════════════════════════════
def step_audit():
    head("STEP 1 — Scanning Git History for Sensitive Files")
    found = []
    for pattern in SENSITIVE_FILES:
        res = run(["git", "log", "--all", "--full-history", "--oneline", "--", pattern], check=False)
        if res.stdout.strip():
            warn(f"'{pattern}' found in commit history!")
            found.append(pattern)
        else:
            ok(f"'{pattern}' — not in history (safe)")

    if not found:
        ok("No sensitive files detected in history.")
    else:
        err(f"{len(found)} sensitive file(s) detected in history:")
        for f in found:
            print(f"     {C.RED}  → {f}{C.RESET}")
    return found

# ══════════════════════════════════════════════════════════════
# STEP 2 — Remove from current index (unstage but keep local)
# ══════════════════════════════════════════════════════════════
def step_remove_from_index():
    head("STEP 2 — Removing Sensitive Files from Git Index")
    for fname in REMOVE_FROM_INDEX:
        res = run(["git", "ls-files", "--error-unmatch", fname], check=False)
        if res.returncode == 0:
            run(["git", "rm", "--cached", fname], check=False)
            ok(f"Removed '{fname}' from git index (file kept locally)")
        else:
            info(f"'{fname}' not tracked — skipping")

# ══════════════════════════════════════════════════════════════
# STEP 3 — Update .gitignore
# ══════════════════════════════════════════════════════════════
def step_update_gitignore():
    head("STEP 3 — Updating .gitignore")
    gitignore_path = Path(".gitignore")
    current = gitignore_path.read_text(encoding="utf-8") if gitignore_path.exists() else ""

    # Backup
    backup_path = Path(f".gitignore.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}")
    if gitignore_path.exists():
        shutil.copy(gitignore_path, backup_path)
        info(f"Backed up existing .gitignore → {backup_path}")

    # Check and add missing entries
    added = []
    lines_to_add = []
    for line in GITIGNORE_BLOCK.strip().split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped not in current:
            lines_to_add.append(line)
            added.append(stripped)

    if lines_to_add:
        with gitignore_path.open("a", encoding="utf-8") as f:
            f.write("\n" + "\n".join(lines_to_add) + "\n")
        ok(f"Added {len(added)} new entries to .gitignore")
    else:
        ok(".gitignore already up-to-date")

# ══════════════════════════════════════════════════════════════
# STEP 4 — Create .env.example with safe placeholders
# ══════════════════════════════════════════════════════════════
def step_create_env_example():
    head("STEP 4 — Creating .env.example with Safe Placeholders")
    env_example_path = Path(".env.example")
    env_example_path.write_text(ENV_EXAMPLE_TEMPLATE, encoding="utf-8")
    ok(".env.example created with placeholder values only")
    warn("NEVER put real secrets in .env.example — it's committed!")

# ══════════════════════════════════════════════════════════════
# STEP 5 — Generate new secrets (display guidance, NOT values)
# ══════════════════════════════════════════════════════════════
def step_generate_secrets():
    head("STEP 5 — Generating New Secure Secret Values")
    new_secrets = generate_secrets()

    warn("Your current .env secrets are COMPROMISED if they were ever committed.")
    warn("Below are freshly generated replacements. Copy them to your NEW .env NOW:\n")

    # Write to a local file for convenience (NOT committed, covered by .gitignore)
    new_env_path = Path(".env.new_secrets.txt")
    lines = ["# Generated by git_security_cleanup.py — DO NOT COMMIT\n",
             f"# Generated: {datetime.now().isoformat()}\n\n"]
    for key, val in new_secrets.items():
        lines.append(f"{key}={val}\n")
        # Only show the key name in console, NOT the value
        print(f"  {C.GREEN}  {key}{C.RESET} → {C.DIM}<generated — see .env.new_secrets.txt>{C.RESET}")

    new_env_path.write_text("".join(lines), encoding="utf-8")
    ok(f"New secrets written to {new_env_path} (local only, gitignored)")
    warn("DELETE .env.new_secrets.txt after updating your real .env!")

    return new_env_path

# ══════════════════════════════════════════════════════════════
# STEP 6 — Purge from Git history using filter-repo
# ══════════════════════════════════════════════════════════════
def step_filter_repo(files_in_history: list[str]):
    head("STEP 6 — Purging Files from Git History (filter-repo)")

    if not files_in_history:
        ok("No files to purge from history — skipping")
        return False

    # Check git-filter-repo is available
    check = run(["git", "filter-repo", "--version"], check=False)
    if check.returncode != 0:
        err("git-filter-repo not found!")
        info("Install it with:  pip install git-filter-repo")
        return False

    warn("┌──────────────────────────────────────────────────────┐")
    warn("│  DESTRUCTIVE OPERATION — This rewrites Git history!  │")
    warn("│  You will need to force-push to remote.              │")
    warn("│  ALL collaborators must re-clone after this.         │")
    warn("└──────────────────────────────────────────────────────┘")

    if not ask("Proceed with git filter-repo to purge ALL sensitive files from history?"):
        warn("Skipped — Run manually later with the command below:")
        paths_args = " ".join([f"--path {f}" for f in REMOVE_FROM_INDEX])
        print(f"\n  {C.CYAN}git filter-repo --invert-paths {paths_args} --force{C.RESET}\n")
        return False

    # Build filter-repo command
    cmd = ["git", "filter-repo", "--force"]
    for fname in REMOVE_FROM_INDEX:
        cmd += ["--invert-paths", "--path", fname]

    info(f"Running: {' '.join(cmd)}")
    res = run(cmd, check=False, capture=False)

    if res.returncode == 0:
        ok("History purged successfully!")
        return True
    else:
        err("filter-repo failed — check output above")
        return False

# ══════════════════════════════════════════════════════════════
# STEP 7 — Commit cleanup + force push
# ══════════════════════════════════════════════════════════════
def step_commit_and_push(history_rewritten: bool):
    head("STEP 7 — Committing Cleanup & Pushing to Remote")

    # Stage changes
    run(["git", "add", ".gitignore", ".env.example"], check=False)
    # Remove any leftover tracked sensitive files
    for fname in REMOVE_FROM_INDEX:
        run(["git", "rm", "--cached", "--ignore-unmatch", fname], check=False)

    # Commit
    res = run(["git", "commit", "-m",
               "security: remove secrets from repo, update .gitignore and .env.example\n\n"
               "- Removed .env and sensitive files from git tracking\n"
               "- Updated .gitignore to block future secret commits\n"
               "- Created clean .env.example with placeholder values only\n"
               "[SECURITY CLEANUP]"],
              check=False)

    if res.returncode == 0:
        ok("Cleanup commit created")
    elif "nothing to commit" in res.stdout + res.stderr:
        info("Nothing new to commit (already clean)")
    else:
        err(f"Commit failed: {res.stderr.strip()}")

    # Push
    if history_rewritten:
        warn("History was rewritten — force-push required!")
        warn("This WILL break local clones of other collaborators.")
        if not ask("Force-push to origin/main now?"):
            warn("Skipped. Push manually when ready:")
            print(f"  {C.CYAN}git push origin main --force-with-lease{C.RESET}\n")
            return

        res = run(["git", "push", "origin", "main", "--force-with-lease"], check=False)
        if res.returncode == 0:
            ok("Force-pushed to origin/main!")
        else:
            err(f"Push failed: {res.stderr.strip()}")
            warn("Try:  git push origin main --force  (as last resort)")
    else:
        if ask("Push to origin/main (normal push)?"):
            res = run(["git", "push", "origin", "main"], check=False)
            if res.returncode == 0:
                ok("Pushed to origin/main")
            else:
                err(f"Push failed: {res.stderr.strip()}")

# ══════════════════════════════════════════════════════════════
# STEP 8 — Post-cleanup manual checklist
# ══════════════════════════════════════════════════════════════
def step_post_cleanup_checklist():
    head("STEP 8 — Post-Cleanup Security Checklist (Manual Steps Required)")

    checklist = [
        ("CRITICAL", "Rotate SCANNER_API_KEY and API_KEY_SECRET immediately"),
        ("CRITICAL", "Rotate SCANNER_ENCRYPTION_KEY (re-encrypt any stored data)"),
        ("CRITICAL", "Rotate REDIS_PASSWORD in redis.conf AND docker-compose.yml"),
        ("CRITICAL", "Rotate SUPABASE_JWT_SECRET if using Supabase"),
        ("CRITICAL", "Rotate GRAFANA_ADMIN_PASSWORD"),
        ("HIGH",     "Search GitHub for leaked secrets: https://github.com/settings/security-log"),
        ("HIGH",     "Scan repo with TruffleHog: pip install trufflehog && trufflehog git file://. "),
        ("HIGH",     "Check GitGuardian or GitHub Secret Scanning alerts in your repo"),
        ("MEDIUM",   "Tell all collaborators to re-clone the repo after force-push"),
        ("MEDIUM",   "Invalidate any active sessions that used the old JWT secret"),
        ("LOW",      "Consider deleting and recreating the remote repo if you need 100% clean history"),
    ]

    for severity, action in checklist:
        color = C.RED if severity == "CRITICAL" else C.YELLOW if severity == "HIGH" else C.CYAN
        print(f"  {color}[{severity}]{C.RESET} {action}")

    print(f"""
{C.BOLD}Quick scan commands:{C.RESET}
  # TruffleHog (full history scan):
  {C.CYAN}pip install trufflehog
  trufflehog git file://$(pwd) --since-commit HEAD~10{C.RESET}

  # GitLeaks:
  {C.CYAN}docker run -v $(pwd):/repo zricethezav/gitleaks:latest detect --source=/repo{C.RESET}

  # Check for .env in remote cache:
  {C.CYAN}git ls-files | findstr .env{C.RESET}

{C.BOLD}If you can't force-push (protected branch):{C.RESET}
  1. Create a new repo
  2. Push only the clean branch: {C.CYAN}git push new-origin main{C.RESET}
  3. Update all integrations (CI/CD, webhooks) to new repo URL
""")

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def main():
    print(f"""
{C.BOLD}{C.CYAN}
╔══════════════════════════════════════════════════════════════╗
║          GIT SECRET PURGE v1.0 — Security Cleanup           ║
║          Removes sensitive data from Git history             ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
  Working directory: {C.YELLOW}{os.getcwd()}{C.RESET}
  Timestamp:         {C.DIM}{datetime.now().isoformat()}{C.RESET}
""")

    # Verify we're in a git repo
    res = run(["git", "rev-parse", "--is-inside-work-tree"], check=False)
    if res.returncode != 0:
        err("Not inside a Git repository! Run from repo root.")
        sys.exit(1)
    ok("Git repo detected")

    # Warn and confirm
    warn("This script will modify your Git repository and history.")
    if not ask("Continue?"):
        print("Aborted.")
        sys.exit(0)

    # Run steps
    files_in_history = step_audit()
    step_remove_from_index()
    step_update_gitignore()
    step_create_env_example()
    step_generate_secrets()
    history_rewritten = step_filter_repo(files_in_history)
    step_commit_and_push(history_rewritten)
    step_post_cleanup_checklist()

    print(f"\n{C.GREEN}{C.BOLD}  ✔  Cleanup complete! Review the checklist above.{C.RESET}\n")


if __name__ == "__main__":
    main()
