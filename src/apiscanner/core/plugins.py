"""
core/plugins.py — Plugin base class and auto-discovery registry

All scan modules must subclass BasePlugin and implement run().
They are auto-discovered from the modules/ directory at runtime.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import sys
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type, Any, cast
from pathlib import Path

from core.engine import AsyncEngine
from core.models import Finding, ScanResult
from core.oast import OASTIntegration


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

    def __init__(self, engine: AsyncEngine, config: Optional[dict] = None, oast: Optional[OASTIntegration] = None):
        self.engine  = engine
        self.config  = config or {}
        self.oast    = oast # Can be None if OAST is disabled
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
    _watcher: Any = None

    @classmethod
    def register(cls, klass: Type[BasePlugin]) -> Type[BasePlugin]:
        cls._store[klass.NAME] = klass
        return klass

    @classmethod
    def discover(cls, modules_dir: Optional[str] = None) -> None:
        """Auto-discovers all BasePlugin subclasses in the modules/ directory."""
        if modules_dir is None:
            modules_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "modules",
            )
        
        path_obj = Path(modules_dir)
        if not path_obj.is_dir():
            return

        for p in path_obj.glob("*.py"):
            if p.name.startswith("_"):
                continue
            cls._load_plugin(p)

    @classmethod
    def _load_plugin(cls, path: Path) -> None:
        """Loads or reloads a plugin from a file path."""
        name = path.stem
        try:
            # Force reload if already in sys.modules
            module_name = f"apiscanner.modules.{name}"
            spec = importlib.util.spec_from_file_location(module_name, str(path))
            if spec is not None and spec.loader is not None:
                mod = importlib.util.module_from_spec(spec)
                # Ensure the module is discoverable by the loader
                sys.modules[module_name] = mod
                cast(Any, spec.loader).exec_module(mod)
                
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if (issubclass(obj, BasePlugin)
                            and obj is not BasePlugin
                            and obj.ENABLED):
                        cls._store[obj.NAME] = obj
                        # logging.info(f"Loaded plugin: {obj.NAME}")
        except Exception as e:
            print(f"  [!] Cannot load plugin {name}: {e}")

    @classmethod
    def enable_hot_reload(cls, modules_dir: str):
        """Monitors changes in .py files and reloads plugins."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class PluginReloadHandler(FileSystemEventHandler):
                def on_modified(self, event):
                    if not event.is_directory and event.src_path.endswith(".py"):
                        cls._load_plugin(Path(event.src_path))

            observer = Observer()
            observer.schedule(PluginReloadHandler(), modules_dir, recursive=False)
            observer.start()
            cls._watcher = observer
        except ImportError:
            print("  [!] watchdog not installed. Hot-reload disabled.")
        except Exception as e:
            print(f"  [!] Failed to start hot-reload: {e}")

    @classmethod
    def get(cls, name: str) -> Optional[Type[BasePlugin]]:
        return cls._store.get(name)

    @classmethod
    def all(cls) -> Dict[str, Type[BasePlugin]]:
        return dict(cls._store)

    @classmethod
    def instantiate(cls, name: str, engine: AsyncEngine,
                    config: Optional[dict] = None,
                    oast: Optional[OASTIntegration] = None) -> Optional[BasePlugin]:
        klass = cls._store.get(name)
        return klass(engine, config, oast) if klass else None

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
