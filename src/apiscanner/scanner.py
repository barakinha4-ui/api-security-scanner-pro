# Copyright (c) 2026 Gustavo Barakinha. Licensed under MIT
"""
scanner.py — Async Scan Orchestrator
"""
from __future__ import annotations

import os
import asyncio
from datetime import datetime
from typing import Callable, Dict, List, Optional, Any, cast

from .core.engine import AsyncEngine
from .core.models import ScanResult
from .core.plugins import Registry, BasePlugin
from .core.oast import OASTIntegration
from .scanner_config import ScannerConfig
from .core.logger import logger
from .core.ui import C, c
from .core.metrics import SCAN_PHASE_DURATION, ACTIVE_SCANS_PER_TARGET
from .core.reports import ReportGenerator

# Preset scan profiles
PRESETS: Dict[str, List[str]] = {
    "quick":   ["discovery", "misconfig"],
    "auth":    ["discovery", "auth", "jwt"],
    "inject":  ["discovery", "sqli", "xss", "ssrf"],
    "api":     ["discovery", "bola", "idor", "graphql", "misconfig"],
    "full":    ["discovery", "sqli", "xss", "ssrf", "bola", "idor",
                "auth", "jwt", "graphql", "misconfig"],
    "stealth": ["discovery", "misconfig"],
}

class Scanner:
    """
    Async security scanner orchestrator.
    """

    def __init__(
        self,
        target:    str,
        engine:    AsyncEngine,
        scan_type: str                     = "full",
        plugins:   Optional[List[str]]     = None,
        config:    Optional[ScannerConfig] = None,
        on_finding: Optional[Callable[[Any], None]] = None,
        on_log:     Optional[Callable[[str], None]] = None,
        dry_run:     bool = False,
        ws_clients: Optional[set] = None,
    ):
        """
        Initializes the Scanner.

        Args:
            target: API base URL.
            engine: Async engine.
            scan_type: Profile name.
            plugins: Specific list of plugins.
            config: Configuration object.
            on_finding: Live result callback.
            on_log: Live progress callback.
            dry_run: Simulation mode.
        """
        self.target      = target.rstrip("/")
        self.engine      = engine
        self.scan_type   = scan_type
        self.plugins     = plugins
        self.config_obj  = config or ScannerConfig()
        self.on_finding  = on_finding
        self.on_log      = on_log
        self.dry_run     = dry_run
        self.ws_clients  = ws_clients or set()
        
        self.oast = OASTIntegration(self.engine, provider=self.config_obj.oast_provider or "interact.sh")

    async def _log(self, message: str):
        """Helper to print to console and send to callback."""
        print(message)
        if self.on_log:
            if asyncio.iscoroutinefunction(self.on_log):
                await self.on_log(message)
            else:
                self.on_log(message)

    @property
    def plugin_names(self) -> List[str]:
        if self.scan_type == "custom" and self.plugins:
            return self.plugins
        return PRESETS.get(self.scan_type, PRESETS["full"])

    async def run(self) -> ScanResult:
        """
        Executes the scan phases.
        """
        result = ScanResult(target=self.target, scan_type=self.scan_type)
        
        print(f"  {C.BOLD}CONFIGURATION{C.RESET}")
        print(f"  ◈ Target:    {self.target}")
        print(f"  ◈ Scan type: {self.scan_type}")
        print(f"  ◈ Threads:   {self.engine.concurrency}")
        if self.dry_run:
            print(f"  ◈ Mode:      {C.YELLOW}DRY-RUN{C.RESET}")
        
        if not self.dry_run:
            await self.oast.setup_session()
            print(f"  ◈ OAST:      {await self.oast.get_domain()}")
        
        # Discover plugins
        Registry.discover()

        # Phase 1: Recon
        await self._log(f"\n  {C.CYAN}[1/3]{C.RESET} Reconnaissance …")
        with SCAN_PHASE_DURATION.labels(phase="recon").time():
            tech = await self.engine.fingerprint(self.target)
            result.waf_detected = self.engine.waf_name
            result.technologies = tech
            
            # New technical info
            result.extra_data["ssl_info"] = await self.engine.get_ssl_info(self.target)
            result.extra_data["server_time"] = datetime.now().isoformat()
            result.extra_data["waf_confidence"] = self.engine.waf_confidence

        # Phase 2: Discovery
        await self._log(f"  {C.CYAN}[2/3]{C.RESET} Discovery …")
        if "discovery" in self.plugin_names:
            with SCAN_PHASE_DURATION.labels(phase="discovery").time():
                disc = Registry.instantiate("discovery", self.engine, self.config_obj.dict(), self.oast)
                if disc:
                    await disc.run(self.target, result)

        # Phase 3: Attacks
        await self._log(f"  {C.CYAN}[3/3]{C.RESET} Security Analysis …")
        attack_plugins = [n for n in self.plugin_names if n != "discovery"]
        instances = []
        for name in attack_plugins:
            p = Registry.instantiate(name, self.engine, self.config_obj.dict(), self.oast)
            if p: instances.append(p)

        with SCAN_PHASE_DURATION.labels(phase="security_analysis").time():
            results = await asyncio.gather(
                *[p.run(self.target, result) for p in instances],
                return_exceptions=True
            )

        for findings in results:
            if isinstance(findings, list):
                for f in findings:
                    result.add_finding(f)
                    
                    if self.ws_clients:
                        import json
                        import websockets
                        msg = json.dumps({"type": "finding", "data": f.to_dict()})
                        # Broadcast to all connected clients
                        websockets.broadcast(self.ws_clients, msg)

                    if self.on_finding:
                        if asyncio.iscoroutinefunction(self.on_finding):
                            await self.on_finding(f)
                        else:
                            self.on_finding(f)

        end_time = datetime.utcnow()
        result.end_time = end_time.isoformat() + "Z"
        
        # Calculate duration
        start_dt = datetime.fromisoformat(result.start_time.rstrip('Z'))
        result.duration_seconds = (end_time - start_dt).total_seconds()
        
        result.total_requests = self.engine.request_count
        
        # Gera relatórios finais (HTML e PDF se WeasyPrint disponível)
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            template_path = os.path.join(base_dir, "templates")
            generator = ReportGenerator(template_path)
            
            # Salva no diretório reports/
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(base_dir)), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            report_name = os.path.join(reports_dir, f"report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            generator.export(result, report_name)
            
            await self._log(f"  {C.GREEN}✔{C.RESET} Relatório gerado: {os.path.basename(report_name)}")
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            await self._log(f"  {C.RED}✘{C.RESET} Falha ao gerar relatório: {e}")

        return result
