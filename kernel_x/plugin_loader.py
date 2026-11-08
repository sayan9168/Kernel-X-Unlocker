"""
kernel_x.plugin_loader
======================

Plugin Marketplace / Auto Plugin Loader
=======================================

Extends :class:`kernel_x.plugin_manager.PluginManager` with:

* **Drop-in auto-loading** — drop a ``*.py`` plugin into the user plugins
  directory and it is picked up on the next load (or immediately while
  watching).
* **Hot-reload** — a background watcher polls file mtimes/hashes; when a
  plugin file changes it is re-imported, re-validated and re-registered
  without restarting the toolkit.  A crashing plugin is isolated and never
  aborts the pipeline (same fault-isolation contract as the base manager).
* **Marketplace index** — ``data/plugin_marketplace.json`` records every
  discovered/installed plugin (id, name, version, author, capabilities,
  source path, install state, content hash).  ``install_plugin()`` copies a
  plugin into the drop-ins directory, validates it and registers it in the
  index.

All loading runs through the base manager's capability policy, so forbidden
capabilities (raw memory access, payload injection, credential attacks, …)
are still refused at registration time.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import logging
import os
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .plugin_manager import (
    BasePlugin,
    HookName,
    PluginContext,
    PluginHookResult,
    PluginManager,
    PluginSecurityError,
)

logger = logging.getLogger("kernel_x.plugin_loader")

DEFAULT_MARKETPLACE_PATH = os.path.join("data", "plugin_marketplace.json")
DEFAULT_USER_PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "plugins", "user")


@dataclass(slots=True)
class PluginIndexEntry:
    """One row of the plugin marketplace index."""

    plugin_id: str          # stable id (usually the file name)
    name: str
    version: str
    description: str
    author: str
    capabilities: List[str] = field(default_factory=list)
    source: str = ""        # original path/url it was installed from
    installed_path: str = ""  # path inside the drop-ins directory
    installed: bool = False
    content_hash: str = ""
    loaded: bool = False
    last_error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HotReloadPluginManager(PluginManager):
    """Plugin manager with drop-in install + hot-reload (mtime/hash polling)."""

    def __init__(
        self,
        plugins_dir: Optional[str] = None,
        user_plugins_dir: Optional[str] = None,
        marketplace_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        watch_interval: float = 2.0,
    ) -> None:
        default_dir = os.path.join(os.path.dirname(__file__), "plugins")
        super().__init__(plugins_dir=plugins_dir or default_dir, config=config)
        self.user_plugins_dir: str = os.path.abspath(
            user_plugins_dir or DEFAULT_USER_PLUGINS_DIR
        )
        os.makedirs(self.user_plugins_dir, exist_ok=True)
        self.marketplace_path: str = marketplace_path or DEFAULT_MARKETPLACE_PATH
        if self.marketplace_path and not os.path.isabs(self.marketplace_path):
            self.marketplace_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), self.marketplace_path
            )
        self.marketplace: Dict[str, PluginIndexEntry] = {}
        self._watch_interval = max(0.5, float(watch_interval))
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_stop = threading.Event()
        self._file_signatures: Dict[str, Tuple[float, str]] = {}  # path -> (mtime, hash)
        self._generation = 0
        self._load_marketplace()

    # -- marketplace index -----------------------------------------------------

    def _load_marketplace(self) -> None:
        self.marketplace = {}
        if not self.marketplace_path or not os.path.isfile(self.marketplace_path):
            return
        try:
            with open(self.marketplace_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("cannot read marketplace index %s: %s", self.marketplace_path, exc)
            return
        rows = payload.get("plugins", [])
        if not isinstance(rows, list):
            rows = []
        for row in rows:
            try:
                entry = PluginIndexEntry(
                    plugin_id=str(row.get("plugin_id", "")),
                    name=str(row.get("name", "")),
                    version=str(row.get("version", "")),
                    description=str(row.get("description", "")),
                    author=str(row.get("author", "")),
                    capabilities=list(row.get("capabilities", []) or []),
                    source=str(row.get("source", "")),
                    installed_path=str(row.get("installed_path", "")),
                    installed=bool(row.get("installed", False)),
                    content_hash=str(row.get("content_hash", "")),
                    loaded=bool(row.get("loaded", False)),
                    last_error=row.get("last_error"),
                )
            except (TypeError, ValueError):
                continue
            if entry.plugin_id:
                self.marketplace[entry.plugin_id] = entry

    def _save_marketplace(self) -> None:
        if not self.marketplace_path:
            return
        try:
            os.makedirs(os.path.dirname(self.marketplace_path) or ".", exist_ok=True)
            payload = {
                "schema": "kx-marketplace/1.0",
                "count": len(self.marketplace),
                "plugins": [e.as_dict() for e in self.marketplace.values()],
            }
            with open(self.marketplace_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            logger.warning("cannot write marketplace index %s: %s", self.marketplace_path, exc)

    @staticmethod
    def _file_signature(path: str) -> Tuple[float, str]:
        """Return (mtime, sha256-prefix) for a file; (0.0, '') on failure."""
        try:
            st = os.stat(path)
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            return (st.st_mtime, digest.hexdigest()[:16])
        except OSError:
            return (0.0, "")

    # -- install / discover ----------------------------------------------------

    def install_plugin(self, source_path: str) -> PluginIndexEntry:
        """Copy ``source_path`` into the drop-ins dir, validate and index it.

        The plugin is not activated until :meth:`load_plugins` runs (which
        discovers every ``*.py`` in both the core and user plugins dirs).
        """
        source_path = os.path.abspath(source_path)
        if not os.path.isfile(source_path) or not source_path.endswith(".py"):
            raise ValueError(f"not a Python plugin file: {source_path}")

        plugin_id = os.path.splitext(os.path.basename(source_path))[0]
        dest = os.path.join(self.user_plugins_dir, os.path.basename(source_path))
        shutil.copy2(source_path, dest)
        mtime, content_hash = self._file_signature(dest)

        # Validate before indexing: import into a throwaway module name.
        tmp_name = f"kx_install_check_{plugin_id}_{int(time.time()*1000)}"
        try:
            spec = importlib.util.spec_from_file_location(tmp_name, dest)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot create import spec for {dest}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[tmp_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                sys.modules.pop(tmp_name, None)
                raise

            found = None
            for _, obj in vars(module).items():
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and not inspect.isabstract(obj)
                ):
                    found = obj
                    break
            if found is None:
                raise ValueError("no concrete BasePlugin subclass in file")

            instance = found()
            instance.validate_capabilities()
            name, version, description, author, capabilities = (
                instance.name,
                instance.version,
                instance.description,
                instance.author,
                list(instance.capabilities),
            )
        except Exception as exc:
            # Still record the attempt so the user sees the failure reason.
            entry = PluginIndexEntry(
                plugin_id=plugin_id,
                name=plugin_id,
                version="",
                description="install failed",
                author="unknown",
                source=source_path,
                installed_path=dest,
                installed=False,
                content_hash=content_hash,
                loaded=False,
                last_error=f"{type(exc).__name__}: {exc}",
            )
            self.marketplace[plugin_id] = entry
            self._save_marketplace()
            logger.error("plugin install rejected %s: %s", source_path, exc)
            return entry
        finally:
            sys.modules.pop(tmp_name, None)

        entry = PluginIndexEntry(
            plugin_id=plugin_id,
            name=name,
            version=version,
            description=description,
            author=author,
            capabilities=capabilities,
            source=source_path,
            installed_path=dest,
            installed=True,
            content_hash=content_hash,
            loaded=False,
        )
        self.marketplace[plugin_id] = entry
        self._save_marketplace()
        logger.info("plugin installed: %s (%s v%s) -> %s", name, plugin_id, version, dest)
        return entry

    def uninstall_plugin(self, plugin_id: str) -> bool:
        """Remove an installed drop-in plugin from disk and the index."""
        entry = self.marketplace.get(plugin_id)
        if not entry or not entry.installed_path:
            return False
        try:
            if os.path.isfile(entry.installed_path):
                os.remove(entry.installed_path)
        except OSError as exc:
            logger.warning("cannot remove plugin file %s: %s", entry.installed_path, exc)
        self.marketplace.pop(plugin_id, None)
        self._save_marketplace()
        logger.info("plugin uninstalled: %s", plugin_id)
        return True

    # -- load with hot-reload support ------------------------------------------

    def _import_module(self, module_name: str, path: str) -> Any:
        """Generation-aware import: each reload gets fresh module names so
        previously loaded plugin code is fully replaced rather than reused."""
        self._generation += 1
        gen_name = f"kx_plugin_g{self._generation}_{os.path.splitext(os.path.basename(path))[0]}"
        return super()._import_module(gen_name, path)

    def load_plugins(self) -> PluginManager.LoadReport:  # type: ignore[override]
        """Discover + load core plugins and user drop-ins, then refresh index."""
        # Ensure user drop-ins are part of the discovery surface.
        for directory in {self.user_plugins_dir, self.plugins_dir}:
            if os.path.isdir(directory):
                pass  # PluginManager.discover() is pointed at self.plugins_dir only;
                      # we load user dirs explicitly below.

        report = super().load_plugins()  # loads core plugins_dir

        # Load user drop-ins too (same validation, isolated faults).
        for path in sorted(self._list_py(self.user_plugins_dir)):
            module_name = f"kx_user_plugin_{os.path.splitext(os.path.basename(path))[0]}"
            try:
                module = self._import_module(module_name, path)
            except Exception as exc:  # noqa: BLE001
                logger.error("failed to import user plugin %s: %s", path, exc)
                report.failed.append(
                    {"path": path, "reason": f"import error: {exc}", "hash": ""}
                )
                continue

            found_any = False
            for _, obj in vars(module).items():
                if not (
                    inspect.isclass(obj)
                    and issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and not inspect.isabstract(obj)
                ):
                    continue
                found_any = True
                try:
                    obj.validate_capabilities()
                    plugin_config = dict(self.global_config.get(obj.name, {}))
                    instance = obj(plugin_config)
                except PluginSecurityError as exc:
                    logger.warning("refused user plugin %s: %s", obj.__name__, exc)
                    report.skipped.append(
                        {"path": path, "reason": f"policy: {exc}", "hash": ""}
                    )
                    continue
                except Exception as exc:  # noqa: BLE001
                    report.failed.append(
                        {"path": path, "reason": f"constructor error: {exc}", "hash": ""}
                    )
                    continue
                if self.get(instance.name) is not None:
                    report.skipped.append(
                        {
                            "path": path,
                            "reason": f"duplicate plugin name '{instance.name}'",
                            "hash": "",
                        }
                    )
                    continue
                self._plugins.append(instance)
                report.loaded.append(instance.name)
            if not found_any:
                report.skipped.append(
                    {"path": path, "reason": "no BasePlugin subclass found", "hash": ""}
                )

        self._plugins.sort(key=lambda p: (p.priority, p.name))
        self.load_report = report
        self._refresh_index_from_loaded()
        self._capture_file_signatures()
        logger.info(
            "plugin load (incl. user drop-ins): %d loaded, %d skipped, %d failed",
            len(report.loaded),
            len(report.skipped),
            len(report.failed),
        )
        return report

    @staticmethod
    def _list_py(directory: str) -> List[str]:
        if not os.path.isdir(directory):
            return []
        return [
            os.path.join(directory, entry)
            for entry in sorted(os.listdir(directory))
            if not entry.startswith("_") and entry.endswith(".py")
        ]

    def _refresh_index_from_loaded(self) -> None:
        """Mirror current load state into the marketplace index."""
        loaded_names = {p.name for p in self._plugins}
        for entry in self.marketplace.values():
            entry.loaded = entry.name in loaded_names
            entry.last_error = None
        # Index any core plugins not yet present.
        for plugin in self._plugins:
            if plugin.name not in {e.name for e in self.marketplace.values()}:
                self.marketplace[plugin.name] = PluginIndexEntry(
                    plugin_id=plugin.name,
                    name=plugin.name,
                    version=plugin.version,
                    description=plugin.description,
                    author=plugin.author,
                    capabilities=list(plugin.capabilities),
                    source="core",
                    installed_path=self.plugins_dir,
                    installed=True,
                    content_hash="",
                    loaded=True,
                )
        self._save_marketplace()

    def _capture_file_signatures(self) -> None:
        self._file_signatures = {}
        for directory in {self.plugins_dir, self.user_plugins_dir}:
            for path in self._list_py(directory):
                self._file_signatures[path] = self._file_signature(path)

    # -- hot-reload watcher ----------------------------------------------------

    def start_watcher(self, interval: Optional[float] = None) -> None:
        """Start the background hot-reload watcher (daemon thread)."""
        if self._watch_thread is not None and self._watch_thread.is_alive():
            logger.warning("hot-reload watcher already running")
            return
        if interval is not None:
            self._watch_interval = max(0.5, float(interval))
        self._watch_stop.clear()
        self._watch_thread = threading.Thread(
            target=self._watch_loop, name="kx-plugin-watcher", daemon=True
        )
        self._watch_thread.start()
        logger.info(
            "hot-reload watcher started (interval %.1fs, dirs=%s, %s)",
            self._watch_interval,
            self.plugins_dir,
            self.user_plugins_dir,
        )

    def stop_watcher(self) -> None:
        """Stop the background hot-reload watcher."""
        self._watch_stop.set()
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=5.0)
        logger.info("hot-reload watcher stopped")

    def _watch_loop(self) -> None:
        while not self._watch_stop.is_set():
            self._watch_stop.wait(self._watch_interval)
            if self._watch_stop.is_set():
                break
            try:
                self._check_and_reload()
            except Exception as exc:  # watcher must never die
                logger.error("hot-reload check errored: %s", exc)

    def _check_and_reload(self) -> None:
        """Detect changed/added/removed plugin files and reload affected ones."""
        changed = False
        current: Dict[str, Tuple[float, str]] = {}
        for directory in {self.plugins_dir, self.user_plugins_dir}:
            for path in self._list_py(directory):
                sig = self._file_signature(path)
                current[path] = sig
                previous = self._file_signatures.get(path)
                if previous is None:
                    logger.info("new plugin detected: %s", path)
                    changed = True
                elif sig != previous:
                    logger.info("plugin changed: %s", path)
                    changed = True
        removed = set(self._file_signatures) - set(current)
        if removed:
            logger.info("plugin(s) removed: %s", sorted(removed))
            changed = True

        if changed:
            self._file_signatures = current
            self.reload()
            self._capture_file_signatures()

    def reload(self) -> PluginManager.LoadReport:
        """Full reload: clear all plugins and re-discover from disk."""
        logger.info("reloading all plugins (hot-reload)")
        self._plugins.clear()
        self.load_report = PluginManager.LoadReport()
        return self.load_plugins()

    # -- status ----------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """JSON-safe snapshot of the whole loader state (dashboard friendly)."""
        return {
            "plugins_dir": self.plugins_dir,
            "user_plugins_dir": self.user_plugins_dir,
            "marketplace_path": self.marketplace_path,
            "watch_running": self._watch_thread is not None
            and self._watch_thread.is_alive(),
            "load_report": (self.load_report.as_dict() if self.load_report else {}),
            "marketplace": [e.as_dict() for e in self.marketplace.values()],
            "loaded": [p.name for p in self._plugins],
            "manifest": self.manifest_all(),
        }

    def manifest_all(self) -> List[Dict[str, Any]]:  # type: ignore[override]
        return [plugin.manifest() for plugin in self._plugins]


__all__ = [
    "PluginIndexEntry",
    "HotReloadPluginManager",
    "DEFAULT_MARKETPLACE_PATH",
    "DEFAULT_USER_PLUGINS_DIR",
]
