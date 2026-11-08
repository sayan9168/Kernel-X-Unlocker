"""
kernel_x.compatibility
======================

Device Fingerprint + Compatibility Matrix
=========================================

Auto-detects which *Kernel-X modules* work on a given device/kernel/Android
build and reports the result as a compatibility matrix:

* which analysis modules can run (fingerprinter, risk mapper, plugins,
  simulator scenarios, side-channel timing analyzer),
* which are degraded (partial support, e.g. kconfig unavailable so
  applicability is inferred),
* which are not applicable (missing prerequisites, wrong kernel series,
  root-only components on non-rooted hosts),
* per-module reasons and required preconditions.

Everything is derived from the already-collected :class:`DeviceFingerprint`
(:mod:`kernel_x.risk_engine`) -- no new privileged access, no network.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .risk_engine import DeviceFingerprint, DeviceFingerprinter

logger = logging.getLogger("kernel_x.compatibility")

#: Compatibility verdicts.
COMPATIBLE = "compatible"
PARTIAL = "partial"
INCOMPATIBLE = "incompatible"
UNVERIFIED = "unverified"

#: Module registry key -> human name.
MODULE_DISPLAY_NAMES: Dict[str, str] = {
    "fingerprinter": "Device Fingerprinter",
    "risk_mapper": "Vulnerability Surface Mapper",
    "fbe_config_plugin": "FBE Config Checker (plugin)",
    "gki_lineage_plugin": "GKI Lineage Analyzer (plugin)",
    "keystore_policy_plugin": "Keystore/StrongBox Policy Probe (plugin)",
    "patch_latency_plugin": "Patch Latency Tracker (plugin)",
    "keystore_simulator": "Keystore/FBE Simulator",
    "side_channel_analyzer": "Side-Channel Timing Analyzer",
    "report_generator": "Research Report Generator",
    "kernel_diff": "GKI/Vendor Kernel Diff Analyzer",
    "memory_dump_diff": "Memory Dump Diff Tool",
}


@dataclass(slots=True)
class ModuleVerdict:
    """Compatibility outcome for one module on one device build."""

    module: str
    name: str
    verdict: str  # COMPATIBLE | PARTIAL | INCOMPATIBLE | UNVERIFIED
    score: float  # 0.0 .. 1.0 confidence in the verdict
    prerequisites_met: List[str] = field(default_factory=list)
    prerequisites_missing: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    requires_root: bool = False
    android_min_sdk: Optional[int] = None
    kernel_series_range: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CompatibilityReport:
    """Full matrix for one fingerprint: per-module verdicts + summary."""

    fingerprint: DeviceFingerprint
    module_verdicts: List[ModuleVerdict] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def compatible_count(self) -> int:
        return sum(1 for v in self.module_verdicts if v.verdict == COMPATIBLE)

    @property
    def partial_count(self) -> int:
        return sum(1 for v in self.module_verdicts if v.verdict == PARTIAL)

    @property
    def incompatible_count(self) -> int:
        return sum(1 for v in self.module_verdicts if v.verdict == INCOMPATIBLE)

    @property
    def unverified_count(self) -> int:
        return sum(1 for v in self.module_verdicts if v.verdict == UNVERIFIED)

    def as_dict(self) -> Dict[str, Any]:
        fp = self.fingerprint
        return {
            "generated_at": self.generated_at,
            "device": {
                "model": fp.model,
                "manufacturer": fp.manufacturer,
                "android_version": fp.android_version,
                "sdk_level": fp.sdk_level,
                "kernel_version": fp.kernel_version,
                "kernel_series": list(fp.kernel_series),
                "gki_variant": fp.gki_variant,
                "soc": f"{fp.soc_vendor} {fp.soc_codename}",
                "bootloader_state": fp.bootloader_state,
                "verified_boot_state": fp.verified_boot_state,
            },
            "summary": {
                "total": len(self.module_verdicts),
                "compatible": self.compatible_count,
                "partial": self.partial_count,
                "incompatible": self.incompatible_count,
                "unverified": self.unverified_count,
            },
            "modules": [v.as_dict() for v in self.module_verdicts],
        }


# ---------------------------------------------------------------------------
# Module requirement definitions
# ---------------------------------------------------------------------------

# Each spec: (module_key, prerequisite checkables, min sdk, kernel hint, needs root)
# Prerequisite callables receive the fingerprint and return (met: bool, detail: str).


def _kconfig_visible(fp: DeviceFingerprint) -> Tuple[bool, str]:
    visible = fp.extra.get("kconfig_available", "no") == "yes"
    return visible, (
        "kernel config visible (IKCONFIG/proc config.gz)"
        if visible
        else "kernel config not visible; applicability inferred"
    )


def _sdk_ge(sdk: int):
    def check(fp: DeviceFingerprint) -> Tuple[bool, str]:
        ok = bool(fp.sdk_level) and fp.sdk_level >= sdk
        return ok, f"SDK >= {sdk} (observed {fp.sdk_level or 'n/a'})"
    return check


def _root_only(fp: DeviceFingerprint) -> Tuple[bool, str]:
    # Root cannot be determined from static telemetry alone; mark unverified.
    return False, "root requirement cannot be confirmed from static telemetry"


MODULE_SPECS: Tuple[Tuple[str, Tuple, Optional[int], Optional[str], bool], ...] = (
    # key, checks, min sdk, kernel series hint, needs root
    ("fingerprinter", (), None, None, False),
    ("risk_mapper", (_kconfig_visible,), None, None, False),
    ("fbe_config_plugin", (), 30, None, False),
    ("gki_lineage_plugin", (), None, None, False),
    ("keystore_policy_plugin", (), 28, None, False),
    ("patch_latency_plugin", (), None, None, False),
    ("keystore_simulator", (), None, None, False),
    ("side_channel_analyzer", (), None, None, False),
    ("report_generator", (), None, None, False),
    ("kernel_diff", (_kconfig_visible,), None, None, False),
    ("memory_dump_diff", (), None, None, False),
)


# ---------------------------------------------------------------------------
# Compatibility matrix engine
# ---------------------------------------------------------------------------


class CompatibilityMatrix:
    """Builds a per-module compatibility matrix for a device fingerprint."""

    def __init__(self, specs: Optional[Sequence[Tuple]] = None) -> None:
        self.specs: Sequence[Tuple] = tuple(specs or MODULE_SPECS)

    def evaluate(self, fingerprint: DeviceFingerprint) -> CompatibilityReport:
        """Return the full compatibility matrix for ``fingerprint``."""
        report = CompatibilityReport(fingerprint=fingerprint)
        for key, checks, min_sdk, series_hint, needs_root in self.specs:
            verdict, score, met, missing, notes = self._evaluate_one(
                fingerprint, key, checks, min_sdk, series_hint, needs_root
            )
            report.module_verdicts.append(
                ModuleVerdict(
                    module=key,
                    name=MODULE_DISPLAY_NAMES.get(key, key),
                    verdict=verdict,
                    score=score,
                    prerequisites_met=met,
                    prerequisites_missing=missing,
                    notes=notes,
                    requires_root=needs_root,
                    android_min_sdk=min_sdk,
                    kernel_series_range=series_hint,
                )
            )
        report.module_verdicts.sort(
            key=lambda v: (v.verdict != COMPATIBLE, v.module)
        )
        return report

    @staticmethod
    def _evaluate_one(
        fingerprint: DeviceFingerprint,
        key: str,
        checks: Tuple,
        min_sdk: Optional[int],
        series_hint: Optional[str],
        needs_root: bool,
    ) -> Tuple[str, float, List[str], List[str], List[str]]:
        met: List[str] = []
        missing: List[str] = []
        notes: List[str] = []

        for check in checks:
            ok, detail = check(fingerprint)
            if ok:
                met.append(detail)
            else:
                missing.append(detail)

        if min_sdk is not None:
            ok, detail = _sdk_ge(min_sdk)(fingerprint)
            if ok:
                met.append(detail)
            else:
                missing.append(detail)

        if series_hint is not None:
            notes.append(
                "target kernel series: %s; observed %d.%d"
                % (series_hint, fingerprint.kernel_series[0], fingerprint.kernel_series[1])
            )

        if needs_root:
            ok, detail = _root_only(fingerprint)
            notes.append("root-required module; static telemetry cannot confirm root")
            missing.append("root access (unverifiable from static telemetry)")

        # Verdict logic -----------------------------------------------------
        if missing:
            if key == "fingerprinter":
                # The fingerprinter always degrades gracefully, never hard-fails.
                verdict = PARTIAL if missing else COMPATIBLE
                score = 0.9
            elif any("config" in m.lower() for m in missing):
                verdict = PARTIAL
                score = 0.65
            else:
                verdict = INCOMPATIBLE
                score = 0.3
        else:
            verdict = COMPATIBLE
            score = 0.95

        # Kernel-series hint cross-check
        if series_hint is not None:
            major, minor = fingerprint.kernel_series
            hint_major = int(series_hint.split(".")[0]) if series_hint else 0
            if major < hint_major:
                if verdict == COMPATIBLE:
                    verdict = PARTIAL
                score = min(score, 0.6)
                notes.append(
                    "kernel series %d.%d below hinted minimum %s; results may be indicative"
                    % (major, minor, series_hint)
                )

        notes.extend(met)
        return verdict, score, met, missing, notes


# ---------------------------------------------------------------------------
# Convenience pipeline
# ---------------------------------------------------------------------------


def analyze_compatibility(
    mock_properties: Optional[Dict[str, str]] = None,
    sysroot: Optional[str] = None,
) -> CompatibilityReport:
    """Fingerprint a host then build its compatibility matrix.

    ``mock_properties`` enables lab/emulator mode (see
    :class:`kernel_x.risk_engine.DeviceFingerprinter`).
    """
    fingerprinter = DeviceFingerprinter(
        mock_properties=mock_properties, sysroot=sysroot
    )
    fingerprint = fingerprinter.run()
    return CompatibilityMatrix().evaluate(fingerprint)


__all__ = [
    "COMPATIBLE",
    "PARTIAL",
    "INCOMPATIBLE",
    "UNVERIFIED",
    "ModuleVerdict",
    "CompatibilityReport",
    "CompatibilityMatrix",
    "analyze_compatibility",
    "MODULE_SPECS",
]
