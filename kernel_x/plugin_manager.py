"""
kernel_x.plugin_manager
=======================

Module 4 - Plugin System Framework.

Design
------
- :class:`BasePlugin` is an abstract class exposing four lifecycle hooks:
  ``on_initialize()``, ``on_scan()``, ``on_simulate()`` and ``on_report()``.
  Hooks receive a shared, JSON-safe :class:`PluginContext` (the audit session's
  fingerprint, risk assessment, simulation outcomes and an observations bag) so
  plugins never need to touch privileged system state themselves.
- :class:`PluginManager` discovers ``*.py`` modules inside a plugins directory
  (default ``kernel_x/plugins``), imports them through ``importlib``, locates
  concrete :class:`BasePlugin` subclasses, instantiates them, registers them in
  priority order and dispatches the hooks with per-plugin error isolation: a
  crashing plugin is recorded as ``FAILED`` and never aborts the pipeline.
- Safety policy: plugins declaring forbidden capabilities (raw memory access,
  payload injection, credential attack primitives) are refused at registration
  time. The toolkit only accepts analysis/simulation/reporting extensions.

Writing a plugin
----------------
Drop a file into ``kernel_x/plugins/``::

    from kernel_x.plugin_manager import BasePlugin, PluginHookResult

    class MyAnalysis(BasePlugin):
        name = "my-analysis"
        version = "1.0.0"

        def on_scan(self, context):
            return PluginHookResult("OK", {"note": "scanned"})
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import logging
import os
import sys
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Type

logger = logging.getLogger("kernel_x.plugin_manager")


class HookName(str, Enum):
    INITIALIZE = "on_initialize"
    SCAN = "on_scan"
    SIMULATE = "on_simulate"
    REPORT = "on_report"


@dataclass(slots=True)
class PluginHookResult:
    """Uniform return value for every hook implementation."""

    status: str = "OK"  # OK | SKIPPED | FAILED
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "data": self.data, "message": self.message}


@dataclass(slots=True)
class PluginContext:
    """Read-only-ish view of the current audit session handed to plugins."""

    session_id: str
    fingerprint: Optional[Any] = None          # DeviceFingerprint
    assessment: Optional[Any] = None           # RiskAssessment
    scenarios: List[Any] = field(default_factory=list)      # ScenarioOutcome list
    simulator: Optional[Any] = None            # KeystoreSimulator (dry-run env)
    observations: Dict[str, Any] = field(default_factory=dict)
    settings: Dict[str, Any] = field(default_factory=dict)

    def snapshot(self) -> Dict[str, Any]:
        """JSON-safe projection used for reports and dashboards."""
        out: Dict[str, Any] = {
            "session_id": self.session_id,
            "observations": _jsonable(self.observations),
            "settings": _jsonable(self.settings),
        }
        if self.fingerprint is not None and hasattr(self.fingerprint, "as_dict"):
            out["fingerprint"] = self.fingerprint.as_dict()
        if self.assessment is not None and hasattr(self.assessment, "as_dict"):
            out["assessment"] = self.assessment.as_dict()
        if self.scenarios:
            out["scenarios"] = [
                s.as_dict() if hasattr(s, "as_dict") else s for s in self.scenarios
            ]
        return out


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if isinstance(value, dict):
            return {str(k): _jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_jsonable(item) for item in value]
        return str(value)


class PluginSecurityError(RuntimeError):
    """Raised when a plugin violates the toolkit's defensive-use policy."""


class BasePlugin(ABC):
    """Abstract base class for Kernel-X analysis plugins."""

    #: Unique short identifier; override in subclasses.
    name: str = "base-plugin"
    version: str = "0.0.0"
    description: str = "abstract base plugin"
    author: str = "unknown"
    #: Execution order (lower runs earlier).
    priority: int = 100
    #: Declared capability tags. Anything outside ALLOWED_CAPABILITIES is refused.
    capabilities: Iterable[str] = ("read-telemetry", "analysis", "reporting")

    FORBIDDEN_CAPABILITY_TOKENS = (
        "exploit", "payload", "inject", "memory-read", "/dev/mem", "ptrace",
        "credential-attack", "brute-force", "bypass",
    )
    ALLOWED_CAPABILITY_TOKENS = (
        "telemetry", "analysis", "simulation", "modeling", "reporting",
        "visualization", "knowledge-base", "scan", "audit",
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config: Dict[str, Any] = dict(config or {})
        self.state: str = "constructed"
        self.last_error: Optional[str] = None
        self.invocations: List[Dict[str, Any]] = []

    # -- capability policy ---------------------------------------------------

    @classmethod
    def validate_capabilities(cls) -> None:
        lowered = [c.lower() for c in cls.capabilities]
        joined = "|".join(lowered)
        for token in cls.FORBIDDEN_CAPABILITY_TOKENS:
            if token in joined:
                raise PluginSecurityError(
                    f"plugin '{cls.name}' declares forbidden capability containing '{token}'"
                )
        if not any(any(allowed in c for allowed in cls.ALLOWED_CAPABILITY_TOKENS) for c in lowered):
            raise PluginSecurityError(
                f"plugin '{cls.name}' declares no recognised analytical capability "
                f"(allowed: {', '.join(cls.ALLOWED_CAPABILITY_TOKENS)})"
            )

    # -- hooks (override any subset) -----------------------------------------

    def on_initialize(self, context: PluginContext) -> PluginHookResult:
        """Prepare plugin state. Default implementation validates configuration."""
        required = self.config.get("required_config_keys", [])
        missing = [key for key in required if key not in self.config]
        if missing:
            return PluginHookResult("FAILED", {"missing": missing}, "missing required config keys")
        return PluginHookResult("OK", {"plugin": self.name, "version": self.version})

    def on_scan(self, context: PluginContext) -> PluginHookResult:
        """Analyse the fingerprint/assessment. Default: no-op pass-through."""
        return PluginHookResult("SKIPPED", {}, "no scan logic implemented")

    def on_simulate(self, context: PluginContext) -> PluginHookResult:
        """Inspect/augment dry-run simulation results. Default: skipped."""
        return PluginHookResult("SKIPPED", {}, "no simulate logic implemented")

    def on_report(self, context: PluginContext) -> PluginHookResult:
        """Contribute material to the academic report. Default: summary block."""
        return PluginHookResult(
            "OK",
            {"summary": f"{self.name} v{self.version}: {len(self.invocations)} hook invocations"},
        )

    # -- bookkeeping -----------------------------------------------------------

    def record_invocation(self, hook: HookName, result: PluginHookResult, duration_s: float) -> None:
        self.invocations.append(
            {
                "hook": hook.value,
                "status": result.status,
                "duration_s": round(duration_s, 5),
                "message": result.message,
            }
        )

    def manifest(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "priority": self.priority,
            "capabilities": list(self.capabilities),
            "state": self.state,
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Plugin manager
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LoadReport:
    """Outcome of a discovery/load cycle."""

    loaded: List[str] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    failed: List[Dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "loaded": self.loaded,
            "skipped": self.skipped,
            "failed": self.failed,
            "counts": {
                "loaded": len(self.loaded),
                "skipped": len(self.skipped),
                "failed": len(self.failed),
            },
        }


class PluginManager:
    """Discovers, validates and orchestrates :class:`BasePlugin` instances."""

    HOOK_ORDER: List[HookName] = [
        HookName.INITIALIZE,
        HookName.SCAN,
        HookName.SIMULATE,
        HookName.REPORT,
    ]

    def __init__(self, plugins_dir: Optional[str] = None, config: Optional[Dict[str, Any]] = None) -> None:
        default_dir = os.path.join(os.path.dirname(__file__), "plugins")
        self.plugins_dir: str = os.path.abspath(plugins_dir or default_dir)
        self.global_config: Dict[str, Any] = dict(config or {})
        self._plugins: List[BasePlugin] = []
        self.load_report: LoadReport = LoadReport()

    # -- discovery ------------------------------------------------------------

    @property
    def plugins(self) -> List[BasePlugin]:
        return list(self._plugins)

    def get(self, name: str) -> Optional[BasePlugin]:
        for plugin in self._plugins:
            if plugin.name == name:
                return plugin
        return None

    def discover(self) -> List[str]:
        """Return candidate module paths in the plugins directory."""
        if not os.path.isdir(self.plugins_dir):
            logger.info("plugins directory %s does not exist; creating it", self.plugins_dir)
            os.makedirs(self.plugins_dir, exist_ok=True)
            return []
        candidates: List[str] = []
        for entry in sorted(os.listdir(self.plugins_dir)):
            if entry.startswith("_") or not entry.endswith(".py"):
                continue
            candidates.append(os.path.join(self.plugins_dir, entry))
        return candidates

    def load_plugins(self) -> LoadReport:
        """Import every candidate module and register its concrete plugins."""
        report = LoadReport()
        self._plugins.clear()
        for path in self.discover():
            module_name = f"kx_plugin_{os.path.splitext(os.path.basename(path))[0]}"
            source_hash = self._hash_file(path)
            try:
                module = self._import_module(module_name, path)
            except Exception as exc:  # noqa: BLE001 - isolate plugin faults
                logger.error("failed to import plugin %s: %s", path, exc)
                report.failed.append({"path": path, "reason": f"import error: {exc}", "hash": source_hash})
                continue

            found = False
            for _, obj in vars(module).items():
                if not (inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin):
                    continue
                if inspect.isabstract(obj):
                    report.skipped.append({"path": path, "reason": f"{obj.__name__} is abstract", "hash": source_hash})
                    continue
                found = True
                try:
                    obj.validate_capabilities()
                    plugin_config = dict(self.global_config.get(obj.name, {}))
                    instance = obj(plugin_config)
                except PluginSecurityError as exc:
                    logger.warning("refused plugin %s: %s", obj.__name__, exc)
                    report.skipped.append({"path": path, "reason": f"policy: {exc}", "hash": source_hash})
                    continue
                except Exception as exc:  # noqa: BLE001
                    report.failed.append({"path": path, "reason": f"constructor error: {exc}", "hash": source_hash})
                    continue
                if self.get(instance.name) is not None:
                    report.skipped.append(
                        {"path": path, "reason": f"duplicate plugin name '{instance.name}'", "hash": source_hash}
                    )
                    continue
                self._plugins.append(instance)
                report.loaded.append(instance.name)
            if not found:
                report.skipped.append({"path": path, "reason": "no BasePlugin subclass found", "hash": source_hash})

        self._plugins.sort(key=lambda p: (p.priority, p.name))
        self.load_report = report
        logger.info(
            "plugin load: %d loaded, %d skipped, %d failed",
            len(report.loaded), len(report.skipped), len(report.failed),
        )
        return report

    @staticmethod
    def _hash_file(path: str) -> str:
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(65_536), b""):
                    digest.update(chunk)
        except OSError:
            return "unreadable"
        return digest.hexdigest()[:16]

    @staticmethod
    def _import_module(module_name: str, path: str) -> Any:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot create import spec for {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
        return module

    # -- registration of inline plugins (tests / embedding) --------------------

    def register(self, plugin: BasePlugin) -> bool:
        """Register an already-instantiated plugin (used by tests/embedders)."""
        if self.get(plugin.name) is not None:
            logger.warning("plugin '%s' already registered", plugin.name)
            return False
        plugin.validate_capabilities()
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda p: (p.priority, p.name))
        self.load_report.loaded.append(plugin.name)
        return True

    # -- dispatch ---------------------------------------------------------------

    def dispatch(self, hook: HookName, context: PluginContext) -> Dict[str, PluginHookResult]:
        """Run one hook across all plugins with per-plugin fault isolation."""
        results: Dict[str, PluginHookResult] = {}
        for plugin in self._plugins:
            method = getattr(plugin, hook.value, None)
            if not callable(method):
                results[plugin.name] = PluginHookResult("SKIPPED", {}, "hook missing")
                continue
            started = time.monotonic()
            try:
                outcome = method(context)
                if not isinstance(outcome, PluginHookResult):
                    outcome = PluginHookResult("OK", {"raw": _jsonable(outcome)})
            except Exception as exc:  # noqa: BLE001 - isolate plugin faults
                logger.error("plugin '%s' raised in %s: %s", plugin.name, hook.value, exc)
                plugin.last_error = f"{type(exc).__name__}: {exc}"
                plugin.state = "FAILED"
                outcome = PluginHookResult(
                    "FAILED", {"traceback_tail": traceback.format_exc().splitlines()[-3:]}, str(exc)
                )
            duration = time.monotonic() - started
            plugin.record_invocation(hook, outcome, duration)
            if outcome.status != "FAILED":
                plugin.state = hook.value
            results[plugin.name] = outcome
            context.observations.setdefault(plugin.name, {})[hook.value] = outcome.as_dict()
        return results

    def run_pipeline(self, context: PluginContext) -> Dict[str, Dict[str, PluginHookResult]]:
        """Execute initialize -> scan -> simulate -> report for all plugins."""
        pipeline: Dict[str, Dict[str, PluginHookResult]] = {}
        for hook in self.HOOK_ORDER:
            pipeline[hook.value] = self.dispatch(hook, context)
        return pipeline

    def collect_report_sections(self, context: PluginContext) -> Dict[str, Any]:
        """Aggregate the ``on_report`` outputs into the reporter's section map."""
        sections: Dict[str, Any] = {}
        for plugin in self._plugins:
            contributions = [
                entry for entry in plugin.invocations if entry["hook"] == HookName.REPORT.value
            ]
            if not contributions:
                continue
            latest = context.observations.get(plugin.name, {}).get(HookName.REPORT.value, {})
            sections[plugin.name] = {
                "manifest": plugin.manifest(),
                "report_data": latest.get("data", {}),
                "invocations": contributions,
            }
        return sections

    def manifest_all(self) -> List[Dict[str, Any]]:
        return [plugin.manifest() for plugin in self._plugins]


__all__ = [
    "BasePlugin",
    "PluginManager",
    "PluginContext",
    "PluginHookResult",
    "PluginSecurityError",
    "HookName",
    "LoadReport",
]
