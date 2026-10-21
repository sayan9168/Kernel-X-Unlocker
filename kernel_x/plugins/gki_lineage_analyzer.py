"""Reference plugin: GKI / vendor-kernel lineage analyser.

Demonstrates the ``on_scan`` hook by classifying the audited kernel against the
GKI (Generic Kernel Image) LTS baseline and flagging non-standard build markers
that commonly indicate a downstream vendor tree without upstream fix backports.
Pure analysis over the already-collected fingerprint - performs no I/O.
"""

from __future__ import annotations

from typing import Any, Dict, List

from kernel_x.plugin_manager import BasePlugin, PluginContext, PluginHookResult

#: Android GKI train -> upstream LTS baseline expectations.
GKI_BASELINES: Dict[str, int] = {
    "android12": 5_004,   # 5.4 LTS baseline era
    "android13": 5_010,
    "android14": 5_015,
    "android15": 6_001,
}


class GKILineageAnalyzer(BasePlugin):
    name = "gki-lineage-analyzer"
    version = "1.2.0"
    description = "Classifies kernel lineage vs GKI LTS baselines and flags downstream drift."
    author = "Kernel-X core team"
    priority = 20
    capabilities = ("telemetry", "analysis")

    def on_initialize(self, context: PluginContext) -> PluginHookResult:
        self._threshold = float(self.config.get("drift_threshold", 0.5))
        return PluginHookResult("OK", {"drift_threshold": self._threshold})

    def on_scan(self, context: PluginContext) -> PluginHookResult:
        fingerprint = context.fingerprint
        if fingerprint is None:
            return PluginHookResult("SKIPPED", {}, "no fingerprint in context")

        series = tuple(fingerprint.kernel_series)
        observations: List[str] = []
        gki_expected = None
        for token, expected in GKI_BASELINES.items():
            if token in (fingerprint.gki_variant or "").lower() or token in (fingerprint.kernel_version or "").lower():
                gki_expected = expected
                break

        major_minor = series[0] * 1000 + series[1]
        if gki_expected is not None and major_minor < gki_expected:
            observations.append(
                f"GKI train declares baseline {gki_expected / 1000:.3f} but running series is "
                f"{series[0]}.{series[1]} - possible stale generic image"
            )
        if not fingerprint.gki_variant.startswith("GKI"):
            observations.append(
                "non-GKI vendor kernel: upstream fix adoption must be verified per-advisory "
                "(version strings alone do not prove patch presence)"
            )
        if fingerprint.extra.get("kconfig_available") == "no":
            observations.append(
                "IKCONFIG unavailable: subsystem applicability was inferred from SDK/kernel series"
            )

        data: Dict[str, Any] = {
            "kernel_series": list(series),
            "lineage": fingerprint.gki_variant,
            "soc": f"{fingerprint.soc_vendor} {fingerprint.soc_codename}",
            "observations": observations,
            "observation_count": len(observations),
        }
        context.observations.setdefault(self.name, {})["scan_detail"] = data
        return PluginHookResult("OK", data, f"{len(observations)} lineage observations")

    def on_report(self, context: PluginContext) -> PluginHookResult:
        detail = context.observations.get(self.name, {}).get("scan_detail", {})
        lines = [
            f"- Lineage: **{detail.get('lineage', 'n/a')}** "
            f"(series {'.'.join(map(str, detail.get('kernel_series', [])))})",
            f"- SoC: {detail.get('soc', 'n/a')}",
        ]
        lines += [f"- Observation: {item}" for item in detail.get("observations", [])]
        return PluginHookResult("OK", {"markdown_lines": "\n".join(lines) or "- no lineage notes"})
