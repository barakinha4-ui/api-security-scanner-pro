"""
scanner.py — Async Scan Orchestrator

Coordinates: WAF detection → fingerprinting → discovery → attack modules.
All phases use asyncio.gather for maximum parallelism.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Callable, Dict, List, Optional

from core.engine import AsyncEngine
from core.models import ScanResult
from core.plugins import Registry


# Preset scan profiles — which plugins run in each mode
PRESETS: Dict[str, List[str]] = {
    "quick":   ["discovery", "misconfig"],
    "auth":    ["discovery", "auth", "jwt"],
    "inject":  ["discovery", "sqli", "xss", "ssrf"],
    "api":     ["discovery", "idor", "graphql", "misconfig"],
    "full":    ["discovery", "sqli", "xss", "ssrf", "idor",
                "auth", "jwt", "graphql", "misconfig"],
    "stealth": ["discovery", "misconfig"],
}


class Scanner:
    """
    Fully async security scanner.

    Usage:
        engine = AsyncEngine(concurrency=20, stealth=True)
        scanner = Scanner("https://target.com", engine, scan_type="full")

        async with engine:
            result = await scanner.run()

    Or from sync context:
        result = scanner.run_sync()
    """

    def __init__(
        self,
        target:    str,
        engine:    AsyncEngine,
        scan_type: str                    = "full",
        plugins:   Optional[List[str]]    = None,
        config:    Optional[Dict]         = None,
        on_finding: Optional[Callable]    = None,
    ):
        self.target      = target.rstrip("/")
        self.engine      = engine
        self.scan_type   = scan_type
        self.config      = config or {}
        self.on_finding  = on_finding  # callback(finding) for live output

        # Resolve plugin list
        if plugins:
            self.plugin_names = plugins
        else:
            self.plugin_names = PRESETS.get(scan_type, PRESETS["full"])

        Registry.discover()

    async def run(self) -> ScanResult:
        result = ScanResult(
            target         = self.target,
            scan_type      = self.scan_type,
            start_time     = datetime.utcnow().isoformat() + "Z",
            threads_used   = self.engine.concurrency,
            stealth_mode   = self.engine.stealth,
        )

        print(f"\n  ◈ Target:    {self.target}")
        print(f"  ◈ Scan type: {self.scan_type}")
        print(f"  ◈ Plugins:   {', '.join(self.plugin_names)}")
        print(f"  ◈ Threads:   {self.engine.concurrency}")
        print(f"  ◈ Stealth:   {'yes' if self.engine.stealth else 'no'}\n")

        # ── Phase 1: WAF + fingerprint ────────────────────────────────────
        print("  [1/3] WAF detection + technology fingerprinting …")
        waf, waf_conf, techs = await asyncio.gather(
            self.engine.detect_waf(self.target),
            asyncio.sleep(0),
            self.engine.fingerprint(self.target),
            return_exceptions=True,
        )

        # detect_waf returns a tuple; asyncio.sleep returns None
        if isinstance(waf, tuple):
            result.waf_detected   = waf[0]
            result.waf_confidence = waf[1]
            if waf[0]:
                print(f"  ⚡ WAF detected: {waf[0]} ({waf[1]:.0f}% confidence)")

        if isinstance(techs, list) and techs:
            result.technologies = techs
            print(f"  · Technologies: {', '.join(techs)}")

        # ── Phase 2: Endpoint discovery ───────────────────────────────────
        print("\n  [2/3] Endpoint discovery …")
        if "discovery" in self.plugin_names:
            disc = Registry.instantiate("discovery", self.engine, self.config)
            if disc:
                await disc.run(self.target, result)
                print(f"  · Discovered: {len(result.discovered_endpoints)} endpoints")

        # ── Phase 3: Security modules ─────────────────────────────────────
        sec_plugins = [n for n in self.plugin_names if n != "discovery"]
        print(f"\n  [3/3] Running {len(sec_plugins)} security module(s) …\n")

        plugin_instances = [
            p for name in sec_plugins
            if (p := Registry.instantiate(name, self.engine, self.config))
        ]

        # Run all modules concurrently
        all_findings_lists = await asyncio.gather(
            *[p.run(self.target, result) for p in plugin_instances],
            return_exceptions=True,
        )

        # Fire on_finding callbacks
        if self.on_finding:
            for findings_list in all_findings_lists:
                if isinstance(findings_list, list):
                    for f in findings_list:
                        self.on_finding(f)

        # ── Finalize ──────────────────────────────────────────────────────
        result.end_time          = datetime.utcnow().isoformat() + "Z"
        result.total_requests    = self.engine.request_count
        result.errors            = self.engine.error_count

        try:
            from datetime import timezone
            t0 = datetime.fromisoformat(result.start_time.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(result.end_time.replace("Z",   "+00:00"))
            result.duration_seconds = (t1 - t0).total_seconds()
        except Exception:
            result.duration_seconds = 0.0

        return result

    def run_sync(self) -> ScanResult:
        """Convenience wrapper for use in non-async contexts."""
        return asyncio.run(self._run_with_context())

    async def _run_with_context(self) -> ScanResult:
        async with self.engine:
            return await self.run()

    def list_plugins(self):
        return Registry.list_info()
