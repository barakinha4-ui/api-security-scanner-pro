"""
core/plugins.py — Plugin base class and auto-discovery registry

All scan modules must subclass BasePlugin and implement run().
They are auto-discovered from the modules/ directory at runtime.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

from core.engine import AsyncEngine
from core.models import Finding, ScanResult


class BasePlugin(ABC):
    """
    Abstract base for all scan modules.

    Subclass and set:
        NAME           : short identifier (used in CLI --plugins)
        DESCRIPTION    : one-line description
        OWASP_CATEGORY : OWASP reference
        TAGS           : list of string tags for filtering

    Implement:
        async def run(target, result) -> List[Finding]
    """

    NAME:           str       = "unnamed"
    DESCRIPTION:    str       = ""
    OWASP_CATEGORY: str       = ""
    TAGS:           List[str] = []
    ENABLED:        bool      = True

    def __init__(self, engine: AsyncEngine, config: Optional[dict] = None):
        self.engine  = engine
        self.config  = config or {}
        self._findings: List[Finding] = []

    @abstractmethod
    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        """Execute security tests and return a list of findings."""
        ...

    # ── Helpers ───────────────────────────────────────────────────────────

    def add(self, f: Finding) -> Finding:
        """Register a finding (call from run())."""
        self._findings.append(f)
        return f

    def log(self, msg: str, level: str = "INFO") -> None:
        icon = {"INFO": "·", "WARN": "⚡", "FOUND": "⚠", "ERROR": "✗"}.get(level, "·")
        print(f"    {icon} [{self.NAME}] {msg}")

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings)


# ─── Registry ─────────────────────────────────────────────────────────────────

class Registry:
    """Discovers and manages all scan plugins."""

    _store: Dict[str, Type[BasePlugin]] = {}

    @classmethod
    def register(cls, klass: Type[BasePlugin]) -> Type[BasePlugin]:
        cls._store[klass.NAME] = klass
        return klass

    @classmethod
    def discover(cls, modules_dir: Optional[str] = None) -> None:
        """
        Auto-discovers all BasePlugin subclasses in the modules/ directory.
        Imports every .py file and registers classes that subclass BasePlugin.
        """
        if modules_dir is None:
            modules_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "modules",
            )
        if not os.path.isdir(modules_dir):
            return

        for fname in sorted(os.listdir(modules_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            path = os.path.join(modules_dir, fname)
            name = fname[:-3]
            try:
                spec = importlib.util.spec_from_file_location(f"modules.{name}", path)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if (issubclass(obj, BasePlugin)
                            and obj is not BasePlugin
                            and obj.ENABLED
                            and obj.NAME not in cls._store):
                        cls._store[obj.NAME] = obj
            except Exception as e:
                print(f"  [!] Cannot load plugin {name}: {e}")

    @classmethod
    def get(cls, name: str) -> Optional[Type[BasePlugin]]:
        return cls._store.get(name)

    @classmethod
    def all(cls) -> Dict[str, Type[BasePlugin]]:
        return dict(cls._store)

    @classmethod
    def instantiate(cls, name: str, engine: AsyncEngine,
                    config: Optional[dict] = None) -> Optional[BasePlugin]:
        klass = cls._store.get(name)
        return klass(engine, config) if klass else None

    @classmethod
    def instantiate_all(cls, engine: AsyncEngine,
                        config: Optional[dict] = None) -> List[BasePlugin]:
        return [k(engine, config) for k in cls._store.values() if k.ENABLED]

    @classmethod
    def list_info(cls) -> List[dict]:
        return [
            {"name": k.NAME, "description": k.DESCRIPTION,
             "owasp": k.OWASP_CATEGORY, "tags": k.TAGS}
            for k in cls._store.values()
        ]
