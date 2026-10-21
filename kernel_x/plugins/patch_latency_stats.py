"""Reference plugin: patch-latency statistics for academic reporting.

Computes descriptive statistics over the audit population implied by the risk
assessment: how far the device's declared security-patch level lags behind the
fix bulletin of every mapped advisory, and summarises that distribution for the
report ("mean bulletin lag", per-subsystem latency). Pure computation over data
already present in the context - no I/O, no external calls.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from kernel_x.plugin_manager import BasePlugin, PluginContext, PluginHookResult


def _days_between(later: str, earlier: str) -> Optional[int]:
    try:
        a = datetime.strptime(later, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        b = datetime.strptime(earlier, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (a - b).days


class PatchLatencyStats(BasePlugin):
    name = "patch-latency-stats"
    version = "1.0.3"
    description = "Bulletin-lag statistics across mapped advisories (academic metrics)."
    author = "Kernel-X core team"
    priority = 40
    capabilities = ("analysis", "knowledge-base")

    def on_scan(self, context: PluginContext) -> PluginHookResult:
        assessment = context.assessment
        fingerprint = context.fingerprint
        if assessment is None or fingerprint is None:
            return PluginHookResult("SKIPPED", {}, "no assessment/fingerprint available")

        patch = getattr(fingerprint, "security_patch_level", "") or ""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        bulletin_lag: List[int] = []
        per_subsystem: Dict[str, List[int]] = {}
        for finding in assessment.findings:
            fix_date = self._extract_fix_date(finding.rationale)
            if not fix_date:
                continue
            lag = _days_between(today, fix_date)
            if lag is None:
                continue
            bulletin_lag.append(lag)
            per_subsystem.setdefault(finding.subsystem, []).append(lag)

        if not bulletin_lag:
            return PluginHookResult("OK", {"note": "no dated bulletins among findings"})

        stats: Dict[str, Any] = {
            "advisories_dated": len(bulletin_lag),
            "device_patch_level": patch or "n/a",
            "bulletin_age_mean_days": round(statistics.fmean(bulletin_lag), 1),
            "bulletin_age_median_days": statistics.median(bulletin_lag),
            "bulletin_age_max_days": max(bulletin_lag),
            "oldest_open_advisory_days": max(bulletin_lag),
            "per_subsystem_mean_days": {
                subsystem: round(statistics.fmean(values), 1)
                for subsystem, values in sorted(per_subsystem.items())
            },
        }
        context.observations.setdefault(self.name, {})["stats"] = stats
        return PluginHookResult("OK", stats, "latency metrics computed")

    @staticmethod
    def _extract_fix_date(rationale: str) -> Optional[str]:
        """Pull the first ``YYYY-MM-DD`` token from a finding rationale."""
        import re

        match = re.search(r"\d{4}-\d{2}-\d{2}", rationale or "")
        return match.group(0) if match else None

    def on_report(self, context: PluginContext) -> PluginHookResult:
        stats = context.observations.get(self.name, {}).get("stats", {})
        if not stats:
            return PluginHookResult("OK", {"markdown_lines": "- no latency statistics produced"})
        lines = [
            f"- Dated advisories analysed: **{stats['advisories_dated']}**",
            f"- Mean bulletin age: **{stats['bulletin_age_mean_days']} days** "
            f"(median {stats['bulletin_age_median_days']}, max {stats['bulletin_age_max_days']})",
            f"- Device patch level: `{stats['device_patch_level']}`",
        ]
        for subsystem, mean_days in stats["per_subsystem_mean_days"].items():
            lines.append(f"  - `{subsystem}`: mean {mean_days} days")
        return PluginHookResult("OK", {"markdown_lines": "\n".join(lines)})
