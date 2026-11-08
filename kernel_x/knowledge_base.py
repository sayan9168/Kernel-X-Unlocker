"""
kernel_x.knowledge_base
=======================

Offline knowledge base of common Android security findings and CVE mapping.

This module loads a *static, locally bundled* CVE/surface knowledge base
(data/knowledge_base.json) so that every lookup works completely offline --
no network, no package indexes, no external advisories fetched at runtime.

It is the single source of truth used by:

* kernel_x.risk_engine (fallback when the JSON is absent),
* kernel_x.compatibility (module/device compatibility),
* kernel_x.kernel_diff (security-relevant change triage),
* report generators (CVE -> remediation mapping, citations).

All records are descriptive only: affected version ranges, subsystems and
public remediation guidance.  The bundle deliberately contains **no**
exploitation material, payloads or PoC logic.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger("kernel_x.knowledge_base")

#: Bundle location relative to the repository root.
DEFAULT_BUNDLE_PATH = os.path.join("data", "knowledge_base.json")


def _series_key(series: Tuple[int, int]) -> float:
    """Kernel series key (major * 1000 + minor) used for range membership."""
    major, minor = series
    return major * 1000.0 + minor


def _version_key(text: str) -> float:
    """Turn ``5.10.134``-ish strings into a comparable float."""
    match = re.match(r"\s*(\d+)\.(\d+)", text or "")
    if not match:
        return 0.0
    return float(match.group(1)) * 1000.0 + float(match.group(2))


@dataclass(slots=True)
class KBEntry:
    """One curated knowledge-base record (descriptive, no exploit data)."""

    cve_id: str
    subsystem: str
    title: str
    cvss_vector: str
    cvss_base: float
    exploit_maturity: str
    affected_min: float
    affected_max: float
    affected_range: str
    required_configs: Tuple[str, ...] = field(default_factory=tuple)
    excluded_configs: Tuple[str, ...] = field(default_factory=tuple)
    requires_binder: bool = False
    requires_ion: bool = False
    requires_ebpf: bool = False
    patch_exempt_before: str = ""
    remediation: str = ""
    reference: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "subsystem": self.subsystem,
            "title": self.title,
            "cvss_vector": self.cvss_vector,
            "cvss_base": self.cvss_base,
            "exploit_maturity": self.exploit_maturity,
            "affected_range": self.affected_range,
            "affected_min": self.affected_min,
            "affected_max": self.affected_max,
            "required_configs": list(self.required_configs),
            "excluded_configs": list(self.excluded_configs),
            "requires_binder": self.requires_binder,
            "requires_ion": self.requires_ion,
            "requires_ebpf": self.requires_ebpf,
            "patch_exempt_before": self.patch_exempt_before,
            "remediation": self.remediation,
            "reference": self.reference,
        }

    def covers_series(self, series: Tuple[int, int]) -> bool:
        """True when this advisory documents the given kernel series."""
        key = _series_key(series)
        return self.affected_min <= key <= self.affected_max


class OfflineKnowledgeBase:
    """In-memory, offline CVE/surface knowledge base.

    Parameters
    ----------
    bundle_path:
        Path to data/knowledge_base.json.  When the file is missing the base
        falls back to an empty catalogue and logs a debug notice; callers
        degrade gracefully (empty results, never crashes).
    """

    def __init__(self, bundle_path: Optional[str] = None) -> None:
        self.bundle_path = bundle_path or DEFAULT_BUNDLE_PATH
        self._entries: Dict[str, KBEntry] = {}
        self._by_subsystem: Dict[str, List[KBEntry]] = {}
        self.schema: str = "kx-kb/1.0"
        self.count: int = 0
        self._loaded: bool = False
        self.load()

    # -- loading ------------------------------------------------------------

    def load(self, bundle_path: Optional[str] = None) -> int:
        """Load (or re-load) the bundle; returns the number of entries."""
        path = bundle_path or self.bundle_path
        self.bundle_path = path
        self._entries = {}
        self._by_subsystem = {}
        self.count = 0
        self._loaded = False

        if not path or not os.path.isfile(path):
            logger.debug(
                "knowledge base bundle not found at %s; running empty", path
            )
            return 0

        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("cannot load knowledge base %s: %s", path, exc)
            return 0

        self.schema = str(payload.get("schema", "kx-kb/1.0"))
        raw_entries: Iterable[Any] = payload.get("entries", [])
        if not isinstance(raw_entries, list):
            raw_entries = []

        for item in raw_entries:
            try:
                entry = KBEntry(
                    cve_id=str(item.get("cve_id", "")),
                    subsystem=str(item.get("subsystem", "generic")),
                    title=str(item.get("title", "")),
                    cvss_vector=str(item.get("cvss_vector", "")),
                    cvss_base=float(item.get("cvss_base", 0.0) or 0.0),
                    exploit_maturity=str(item.get("exploit_maturity", "unknown")),
                    affected_min=float(item.get("affected_min", 0.0) or 0.0),
                    affected_max=float(item.get("affected_max", 0.0) or 0.0),
                    affected_range=str(item.get("affected_range", "")),
                    required_configs=tuple(
                        str(x) for x in (item.get("required_configs") or [])
                    ),
                    excluded_configs=tuple(
                        str(x) for x in (item.get("excluded_configs") or [])
                    ),
                    requires_binder=bool(item.get("requires_binder", False)),
                    requires_ion=bool(item.get("requires_ion", False)),
                    requires_ebpf=bool(item.get("requires_ebpf", False)),
                    patch_exempt_before=str(item.get("patch_exempt_before", "") or ""),
                    remediation=str(item.get("remediation", "")),
                    reference=str(item.get("reference", "")),
                )
            except (TypeError, ValueError) as exc:
                logger.debug("skipping malformed KB entry: %s", exc)
                continue
            self._entries[entry.cve_id] = entry
            self._by_subsystem.setdefault(entry.subsystem, []).append(entry)

        self.count = len(self._entries)
        self._loaded = True
        logger.info(
            "offline knowledge base loaded: %d entries from %s", self.count, path
        )
        return self.count

    # -- lookups -------------------------------------------------------------

    def get(self, cve_id: str) -> Optional[KBEntry]:
        """Return the entry for ``cve_id`` (case-insensitive), or None."""
        return self._entries.get(cve_id.upper()) or self._entries.get(cve_id)

    def by_subsystem(self, subsystem: str) -> List[KBEntry]:
        """All entries for a subsystem (e.g. ``binder-ipc``, ``ebpf-verifier``)."""
        return list(self._by_subsystem.get(subsystem, []))

    def subsystems(self) -> List[str]:
        """Sorted list of subsystems present in the catalogue."""
        return sorted(self._by_subsystem)

    def applicable_to(
        self,
        kernel_series: Tuple[int, int],
        sdk_level: Optional[int] = None,
    ) -> List[KBEntry]:
        """Entries whose documented affected range covers ``kernel_series``.

        ``sdk_level`` is accepted for future Android-version filtering and is
        currently advisory only (the bundle is kernel-series oriented).
        """
        return [
            entry
            for entry in self._entries.values()
            if entry.covers_series(kernel_series)
        ]

    def cve_map(self) -> Dict[str, str]:
        """``cve_id -> remediation guidance`` for every catalogue entry."""
        return {cve: entry.remediation for cve, entry in self._entries.items()}

    def reference_map(self) -> Dict[str, str]:
        """``cve_id -> public reference URL``."""
        return {cve: entry.reference for cve, entry in self._entries.items()}

    def to_dict(self) -> Dict[str, Any]:
        """Full catalogue as JSON-safe dicts."""
        return {
            "schema": self.schema,
            "count": self.count,
            "loaded": self._loaded,
            "bundle_path": self.bundle_path,
            "entries": [entry.as_dict() for entry in self._entries.values()],
        }

    def maturity_summary(self) -> Dict[str, int]:
        """Count of entries per exploit-maturity tag."""
        summary: Dict[str, int] = {}
        for entry in self._entries.values():
            summary[entry.exploit_maturity] = (
                summary.get(entry.exploit_maturity, 0) + 1
            )
        return summary


#: Shared default catalogue instance (imported by other modules).
DEFAULT_KNOWLEDGE_BASE = OfflineKnowledgeBase()


__all__ = [
    "KBEntry",
    "OfflineKnowledgeBase",
    "DEFAULT_KNOWLEDGE_BASE",
    "DEFAULT_BUNDLE_PATH",
]
