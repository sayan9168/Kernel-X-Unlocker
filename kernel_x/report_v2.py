"""
kernel_x.report_v2
==================

Automated Research Report Generator (v2)
=========================================

Professional, publication-ready research reports for Kernel-X audit sessions:

* **Markdown** — abstract, methodology, device fingerprint, risk heatmap
  (ASCII), findings register, per-finding rationale, simulated-scenario
  timeline, plugin contributions, remediation roadmap, integrity appendix.
* **HTML** — same content with embedded SVG charts (risk gauge, subsystem
  contribution bars, scenario timeline), print-friendly CSS and a
  one-click "Print → PDF" path from any browser.
* **PDF** — via ``weasyprint`` or ``wkhtmltopdf`` when installed on the
  research host; otherwise the HTML artifact is written and a hint is
  logged so the user can print-to-PDF manually.

Chart rendering is pure standard library (hand-written SVG) so the v2
generator works on Termux without numpy, matplotlib or weasyprint.

Every artifact keeps the v1 integrity model: canonical JSON body with an
embedded SHA-256 digest (``verify_artifact``) plus environment/hash
metadata for reproducibility.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .reporter import (
    AcademicReportGenerator,
    AuditSession,
    ETHICAL_DISCLAIMER,
    REPRODUCIBILITY_NOTE,
    _sha256,
    _utc_now,
)

logger = __import__("logging").getLogger("kernel_x.report_v2")

REPORT_SCHEMA_V2 = "kx-report/2.0"


def _esc(text: str) -> str:
    return html.escape(str(text), quote=True)


# --------------------------------------------------------------------------- #
# Pure-stdlib SVG charts                                                      #
# --------------------------------------------------------------------------- #

def _svg_header(width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="sans-serif">'
    )


def _svg_footer() -> str:
    return "</svg>"


def chart_gauge_svg(score: float, width: int = 420, height: int = 140) -> str:
    """Risk-score gauge (0..10) as an inline SVG fragment."""
    score = max(0.0, min(10.0, score))
    # Colour stops: green -> yellow -> red across the scale.
    def colour_at(frac: float) -> str:
        frac = max(0.0, min(1.0, frac))
        if frac < 0.5:
            t = frac * 2
            r = int(0x3f + (0xd2 - 0x3f) * t)
            g = int(0xb9 + (0x99 - 0xb9) * t)
            b = int(0x50 + (0x22 - 0x50) * t)
        else:
            t = (frac - 0.5) * 2
            r = int(0xd2 + (0xf8 - 0xd2) * t)
            g = int(0x99 + (0x51 - 0x99) * t)
            b = int(0x22 + (0x49 - 0x22) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    cx, cy, r = width * 0.5, height * 0.62, height * 0.30
    start_angle, end_angle = 200, 340  # degrees, semi-circle arc
    sweep = end_angle - start_angle
    frac = score / 10.0
    end_angle_arc = start_angle + sweep * frac

    def arc_point(angle_deg: float, radius: float):
        import math
        rad = math.radians(angle_deg)
        return cx + radius * __import__("math").cos(rad), cy - radius * __import__("math").sin(rad)

    import math
    x0, y0 = arc_point(start_angle, r)
    x1, y1 = arc_point(end_angle_arc, r)
    large_arc = 1 if sweep * frac > 180 else 0
    arc_d = (f"M {x0:.1f},{y0:.1f} A {r:.1f},{r:.1f} 0 {large_arc} 1 "
             f"{x1:.1f},{y1:.1f}")

    # tick labels at 0, 5, 10
    ticks = []
    for label, t in (("0", 0.0), ("5", 0.5), ("10", 1.0)):
        ang = start_angle + sweep * t
        tx, ty = arc_point(ang, r + 22)
        ticks.append(f'<text x="{tx:.1f}" y="{ty:.1f}" text-anchor="middle" '
                     f'font-size="11" fill="#8b98a8">{_esc(label)}</text>')

    needle_ang = start_angle + sweep * frac
    nx, ny = arc_point(needle_ang, r - 8)
    needle = (f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{nx:.1f}" y2="{ny:.1f}" '
              f'stroke="#161d27" stroke-width="3" marker-end="url(#needle-arrow)"/>')

    parts = [
        _svg_header(width, height),
        '<defs><linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">',
        '  <stop offset="0%" stop-color="#3fb950"/>',
        '  <stop offset="50%" stop-color="#d29922"/>',
        '  <stop offset="100%" stop-color="#f85149"/>',
        '</linearGradient>',
        '<marker id="needle-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" '
        'orient="auto"><polygon points="0,0 8,3 0,6" fill="#161d27"/></marker>',
        '</defs>',
        f'<path d="{arc_d}" fill="none" stroke="url(#gaugeGrad)" stroke-width="14" '
        f'stroke-linecap="round"/>',
        needle,
        f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="6" fill="#161d27"/>',
        *ticks,
        f'<text x="{cx:.1f}" y="{height * 0.86:.1f}" text-anchor="middle" font-size="22" '
        f'fill="#e6edf3" font-weight="bold">{score:.1f}</text>',
        f'<text x="{cx:.1f}" y="{height * 0.86 + 18:.1f}" text-anchor="middle" font-size="11" '
        f'fill="#8b98a8">/ 10.0</text>',
        _svg_footer(),
    ]
    return "\n".join(parts)


def chart_subsystem_bars_svg(
    subsystem_scores: Dict[str, float], width: int = 640, height: int = 260
) -> str:
    """Horizontal bar chart of subsystem contribution scores."""
    import math

    ordered = sorted(subsystem_scores.items(), key=lambda kv: kv[1], reverse=True)
    if not ordered:
        return f'<svg width="{width}" height="{height}"><text x="20" y="40" '
        f'fill="#8b98a8">no subsystem contributions</text></svg>'

    max_value = max(v for _, v in ordered) or 1.0
    bar_h = 22
    gap = 10
    top = 40
    left = 160
    right = width - 20

    parts = [_svg_header(width, height)]
    parts.append('<text x="20" y="24" fill="#e6edf3" font-size="14" font-weight="bold">'
                 'Subsystem exposure (contribution)</text>')
    parts.append('<text x="20" y="40" fill="#8b98a8" font-size="10">bar length ∝ contribution / 10</text>')
    for i, (name, value) in enumerate(ordered):
        y = top + i * (bar_h + gap)
        if y + bar_h > height:
            break
        frac = min(1.0, value / max_value)
        bar_w = (right - left) * frac
        colour = _gauge_colour(value / 10.0)
        parts.append(
            f'<text x="{left - 8}" y="{y + 16}" text-anchor="end" font-size="10" '
            f'fill="#cbd5e1" title="{_esc(name)}">{_esc(name)[:28]}</text>'
        )
        parts.append(
            f'<rect x="{left}" y="{y + 2}" width="{bar_w:.1f}" height="{bar_h - 4}" '
            f'fill="{colour}" rx="2"/>'
        )
        parts.append(
            f'<text x="{left + bar_w + 6}" y="{y + 16}" fill="#8b98a8" font-size="10">'
            f'{value:.2f}</text>'
        )
    parts.append(_svg_footer())
    return "\n".join(parts)


def _gauge_colour(frac: float) -> str:
    frac = max(0.0, min(1.0, frac))
    if frac < 0.5:
        t = frac * 2
        r = int(0x3f + (0xd2 - 0x3f) * t)
        g = int(0xb9 + (0x99 - 0xb9) * t)
        b = int(0x50 + (0x22 - 0x50) * t)
    else:
        t = (frac - 0.5) * 2
        r = int(0xd2 + (0xf8 - 0xd2) * t)
        g = int(0x99 + (0x51 - 0x99) * t)
        b = int(0x22 + (0x49 - 0x22) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def chart_timeline_svg(
    scenarios: Sequence[Any], width: int = 700, height: int = 300
) -> str:
    """Scenario outcome timeline as an inline SVG fragment."""
    parts = [_svg_header(width, height)]
    parts.append('<text x="20" y="24" fill="#e6edf3" font-size="14" font-weight="bold">'
                 'Simulated scenario timeline (dry-run)</text>')
    if not scenarios:
        parts.append('<text x="20" y="60" fill="#8b98a8">no scenarios executed</text>')
        parts.append(_svg_footer())
        return "\n".join(parts)

    row_h = 34
    top = 52
    left = 40
    for i, scenario in enumerate(scenarios):
        y = top + i * row_h
        if y > height - 10:
            break
        passed = bool(getattr(scenario, "passed", scenario.get("passed") if isinstance(scenario, dict) else False))
        name = getattr(scenario, "scenario", None) or (scenario.get("scenario") if isinstance(scenario, dict) else "scenario")
        colour = "#3fb950" if passed else "#f85149"
        parts.append(
            f'<rect x="{left}" y="{y}" width="{row_h - 6}" height="{row_h - 6}" '
            f'fill="{colour}" rx="3"/>'
        )
        parts.append(
            f'<text x="{left + (row_h - 6) / 2:.1f}" y="{y + (row_h - 6) / 2 + 4:.1f}" '
            f'text-anchor="middle" fill="#04121c" font-size="10" font-weight="bold">'
            f'{"P" if passed else "F"}</text>'
        )
        parts.append(
            f'<text x="{left + row_h + 10}" y="{y + 14}" fill="#e6edf3" font-size="12">'
            f'{_esc(str(name))[:60]}</text>'
        )
        status = "PASS" if passed else "FAIL"
        parts.append(
            f'<text x="{left + row_h + 10}" y="{y + 28}" fill="#8b98a8" font-size="10">'
            f'steps={len(getattr(scenario, "steps", scenario.get("steps", []) if isinstance(scenario, dict) else []))}  '
            f'status={status}</text>'
        )
    parts.append(_svg_footer())
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Report generator v2                                                         #
# --------------------------------------------------------------------------- #


class ProfessionalReportGenerator(AcademicReportGenerator):
    """Extends :class:`AcademicReportGenerator` with charts, timeline and PDF."""

    def __init__(self, output_dir: str = "reports", author_meta: Optional[Dict[str, str]] = None) -> None:
        super().__init__(output_dir=output_dir, author_meta=author_meta)

    # -- markdown v2 ----------------------------------------------------------

    def generate_markdown_v2(self, session: AuditSession) -> str:
        payload = self.build_payload(session)
        lines: List[str] = []
        lines += self._v2_header(session, payload)
        lines += self._v2_fingerprint(session)
        lines += self._v2_risk(session, payload)
        lines += self._v2_timeline(session)
        lines += self._v2_plugins(session)
        lines += self._v2_appendix(session, payload)
        return "\n".join(lines) + "\n"

    def _v2_header(self, session: AuditSession, payload: Dict[str, Any]) -> List[str]:
        env = payload["environment"]
        return [
            f"# {session.title}",
            "",
            f"**Session:** `{session.session_id}` · **Generated:** {payload['generated_at']} · "
            f"**Schema:** `{REPORT_SCHEMA_V2}`",
            "",
            f"**Authors:** {session.author} — {session.institution}",
            "",
            "---",
            "",
            "## Abstract",
            "",
            "This audit characterises the kernel-level security posture of the assessed "
            "build using static, unprivileged telemetry only: kernel/SoC fingerprinting, "
            "security-patch-level correlation, subsystem configuration inference and "
            "dry-run simulation of FBE / keystore / Gatekeeper boundary behaviour. "
            "Findings are correlation-based candidates derived from a curated, offline "
            "knowledge base of publicly documented advisories — they are **not** exploit "
            "confirmations and no live attack path was exercised.",
            "",
            "## 1. Methodology",
            "",
            "1. **Telemetry acquisition** — read-only collection of `/proc/version`, "
            "   `/proc/cpuinfo`, `/sys/devices/soc0/*`, `/proc/cmdline`, kernel config "
            "   (`/proc/config.gz` or `/boot/config-*`) and Android properties.",
            "2. **Surface correlation** — kernel series + subsystem configuration matched "
            "   against the offline CVE knowledge base; tri-state applicability "
            "   (present / absent / unverifiable).",
            "3. **Scoring** — `impact × reachability × exploit-maturity × applicability "
            "   × patch-decay`, complement-aggregated and mitigation-adjusted.",
            "4. **Dry-run modelling** — declarative scenarios exercise in-process keystore/"
            "   FBE state machines; only policy outcomes are recorded.",
            "5. **Reporting** — canonical JSON + Markdown/HTML with integrity digest.",
            "",
        ]

    def _v2_fingerprint(self, session: AuditSession) -> List[str]:
        fp = session.fingerprint
        if fp is None:
            return ["## 2. Device Fingerprint", "", "_No fingerprint captured._", ""]
        posture = fp.posture_summary
        rows = [
            ("Device", f"{fp.manufacturer} {fp.model} ({fp.device_name})"),
            ("Android / SDK", f"{fp.android_version or 'n/a'} / {fp.sdk_level or 'n/a'}"),
            ("Security patch level", f"{fp.security_patch_level or 'n/a'}"
             + (f" ({posture['patch_age_days']} days old)"
                if posture["patch_age_days"] is not None else "")),
            ("Kernel version", f"`{fp.kernel_version}` (series {fp.kernel_series[0]}.{fp.kernel_series[1]})"),
            ("Kernel flavour", fp.gki_variant),
            ("SoC", f"{fp.soc_vendor} — {fp.soc_codename} (soc_id={fp.soc_id}, hw={fp.hardware})"),
            ("Architecture", fp.architecture),
            ("Bootloader / AVB", f"{fp.bootloader_state} / {fp.avb_version}"
                                 f" (verifiedbootstate={fp.verified_boot_state}, "
                                 f"verity={fp.verity_mode})"),
            ("Storage encryption", f"{fp.fbe_encryption_type} — content `{fp.fbe_content_mode}`, "
                                   f"metadata `{fp.fbe_metadata_mode}`"),
            ("Keystore backend", f"{fp.keystore2_backend} (Weaver: {fp.weaver_backend})"),
            ("SELinux debug", "yes" if posture["sepolicy_debug"] else "no (enforcing assumptions hold)"),
            ("Kconfig visibility", fp.extra.get("kconfig_available", "no")),
        ]
        lines = ["## 2. Device Fingerprint", "", "| Attribute | Observed value |", "|---|---|"]
        lines += [f"| {name} | {value} |" for name, value in rows]
        lines.append("")
        return lines

    def _v2_risk(self, session: AuditSession, payload: Dict[str, Any]) -> List[str]:
        assessment = session.assessment
        if assessment is None:
            return ["## 3. Risk & Vulnerability Surface", "", "_No assessment attached._", ""]
        lines = [
            "## 3. Risk & Vulnerability Surface",
            "",
            f"**Normalized risk score:** `{assessment.risk_score}/10.0` → **{assessment.severity}**",
            "",
            f"Raw aggregate `{assessment.raw_score}` · mitigation net credit "
            f"`{assessment.metadata.get('mitigation_net_credit')}` · patch decay "
            f"`{assessment.metadata.get('patch_decay')}` "
            f"({assessment.metadata.get('patch_decay_note', '')})",
            "",
            "### 3.1 Subsystem exposure heatmap",
            "",
            "| Subsystem | Contribution | Bar |",
            "|---|---:|---|",
        ]
        ordered = sorted(assessment.subsystem_scores.items(), key=lambda kv: kv[1], reverse=True)
        for subsystem, value in ordered:
            bar = "#" * int(round(max(0.0, min(10.0, value)) / 10.0 * 20)) + \
                  "." * (20 - int(round(max(0.0, min(10.0, value)) / 10.0 * 20)))
            lines.append(f"| `{subsystem}` | {value:.2f} | `{bar}` |")
        lines += [
            "",
            "### 3.2 Findings register",
            "",
            "| CVE | Subsystem | Status | CVSS impact | Maturity | Contrib. | Confidence |",
            "|---|---|---|---:|---|---:|---:|",
        ]
        for finding in assessment.findings:
            lines.append(
                f"| [{finding.cve_id}]({finding.reference}) | `{finding.subsystem}` | "
                f"{finding.status} | {finding.cvss_base:.1f} | {finding.exploit_maturity} | "
                f"{finding.contribution:.2f} | {finding.confidence:.2f} |"
            )
        lines += ["", "### 3.3 Rationale per finding", ""]
        for finding in assessment.findings:
            lines += [
                f"- **{finding.cve_id} — {finding.title}**",
                f"  - Applicability: {finding.rationale}",
                f"  - Affected kernel range: `{finding.affected_range}` · "
                f"vector `{finding.cvss_vector}`",
                f"  - Remediation: {finding.remediation}",
            ]
        lines += ["", "### 3.4 Mitigation credit ledger", "", "| Factor | Credit |", "|---|---:|"]
        for factor, value in assessment.mitigations.items():
            lines.append(f"| {factor} | {value:+.2f} |")
        lines += ["", "## 4. Recommendations (defensive)", ""]
        for index, recommendation in enumerate(assessment.recommendations, start=1):
            lines.append(f"{index}. {recommendation}")
        lines.append("")
        return lines

    def _v2_timeline(self, session: AuditSession) -> List[str]:
        if not session.scenarios:
            return ["## 5. Simulated Boundary Behaviour (dry-run)", "",
                    "_No scenarios executed._", ""]
        lines = [
            "## 5. Simulated Boundary Behaviour (dry-run)",
            "",
            "All events originate from the in-process model; no hardware-backed service "
            "was contacted and no real credential verification was attempted.",
            "",
        ]
        for outcome in session.scenarios:
            status = "PASS" if outcome.passed else "FAIL"
            lines += [
                f"### Scenario `{outcome.scenario}` — **{status}** "
                f"({len(outcome.steps)} steps, {outcome.duration_s}s)",
                "",
                "| t (s) | Actor | Action | Outcome | Note |",
                "|---:|---|---|---|---|",
            ]
            for event in outcome.events:
                note = event["note"].replace("|", "\\|")
                lines.append(
                    f"| {event['t_offset']:.3f} | `{event['actor']}` | `{event['action']}` | "
                    f"{event['outcome']} | {note} |"
                )
            lines.append("")
            if outcome.notes:
                lines += ["Expectation mismatches:", ""]
                lines += [f"- {item}" for item in outcome.notes]
                lines.append("")
        return lines

    def _v2_plugins(self, session: AuditSession) -> List[str]:
        if not session.plugin_observations:
            return []
        lines = ["## 6. Plugin Contributions", ""]
        for plugin, observation in session.plugin_observations.items():
            if plugin.startswith("_"):
                continue
            lines.append(f"### `{plugin}`")
            lines.append("")
            if isinstance(observation, dict):
                for key, value in observation.items():
                    lines.append(f"- **{key}:** {value}")
            else:
                lines.append(f"```\n{observation}\n```")
            lines.append("")
        return lines

    def _v2_appendix(self, session: AuditSession, payload: Dict[str, Any]) -> List[str]:
        integrity = payload["integrity"]["canonical_body_sha256"]
        kb_digest = payload["environment"].get("knowledge_base_digest", "n/a")
        citations = self.generate_bibtex(session)
        lines = [
            "## Appendix A — Scoring Model",
            "",
            "```",
            "contribution_i = Impact_i × Reachability_i × Maturity_i × Applicability_i × PatchDecay",
            "Impact_i         = clamp(6.42 × ISCBase_i, 1, 10)      # CVSS 3.1 subscore approximation",
            "Reachability_i   = clamp(AV × AC × UI / 0.85, 0.15, 1)",
            "RiskScore        = clamp(10 × (1 − Π(1 − contribution_i / 10)) × (1 + ΣCredit), 0, 10)",
            "```",
            "",
            REPRODUCIBILITY_NOTE,
            "",
            "## Appendix B — Reproducibility & Integrity",
            "",
            f"- Schema: `{REPORT_SCHEMA_V2}`",
            f"- Environment SHA-256: `{payload['environment']['environment_sha256']}`",
            f"- Platform: {payload['environment']['os']} {payload['environment']['release']} "
            f"({payload['environment']['machine']}), Python {payload['environment']['python']}",
            f"- Toolkit git revision: `{payload['environment']['toolkit_git']}`",
            f"- Knowledge-base digest: `{kb_digest}`",
            f"- Canonical body SHA-256: `{integrity}`",
            f"- Session opened: {session.started_at} · report generated: {payload['generated_at']}",
            "",
            "Verify with: `sha256sum` over the canonical JSON body (see `verify_artifact`).",
            "",
            "## Appendix C — Citations (BibTeX)",
            "",
            "```bibtex",
            citations,
            "```",
            "",
            "---",
            "",
            ETHICAL_DISCLAIMER,
            "",
            f"*Generated by Kernel-X Research Toolkit — session `{session.session_id}`.*",
        ]
        return lines

    # -- HTML v2 with embedded SVG charts ------------------------------------

    def generate_html_v2(self, session: AuditSession) -> str:
        assessment = session.assessment
        fingerprint = session.fingerprint
        model = {
            "risk_score": assessment.risk_score if assessment else 0.0,
            "severity": assessment.severity if assessment else "N/A",
            "gauge_svg": chart_gauge_svg(assessment.risk_score) if assessment else "",
            "bars_svg": chart_subsystem_bars_svg(assessment.subsystem_scores) if assessment else "",
            "timeline_svg": chart_timeline_svg(session.scenarios),
        }
        rows = ""
        if fingerprint:
            posture = fingerprint.posture_summary
            rows = "\n".join(
                f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
                for k, v in [
                    ("Device", f"{fingerprint.manufacturer} {fingerprint.model}"),
                    ("Android / SDK", f"{fingerprint.android_version or 'n/a'} / {fingerprint.sdk_level or 'n/a'}"),
                    ("Patch level", f"{fingerprint.security_patch_level or 'n/a'}"
                                    + (f" ({posture['patch_age_days']}d old)"
                                       if posture['patch_age_days'] is not None else "")),
                    ("Kernel", f"{fingerprint.kernel_version} ({fingerprint.gki_variant})"),
                    ("SoC", f"{fingerprint.soc_vendor} {fingerprint.soc_codename}"),
                    ("Bootloader / AVB", f"{fingerprint.bootloader_state} / {fingerprint.avb_version}"),
                    ("FBE", f"{fingerprint.fbe_encryption_type} · {fingerprint.fbe_content_mode}"),
                    ("Keystore", fingerprint.keystore2_backend),
                ]
            )
        findings_rows = ""
        if assessment:
            for finding in assessment.findings:
                findings_rows += (
                    "<tr>"
                    f"<td>{_esc(finding.cve_id)}</td>"
                    f"<td>{_esc(finding.subsystem)}</td>"
                    f"<td>{_esc(finding.status)}</td>"
                    f"<td>{finding.cvss_base:.1f}</td>"
                    f"<td>{_esc(finding.exploit_maturity)}</td>"
                    f"<td>{finding.contribution:.2f}</td>"
                    f"<td>{finding.confidence:.2f}</td>"
                    f"<td>{_esc(finding.rationale[:120])}</td>"
                    "</tr>"
                )
        css = (
            "body{font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;max-width:980px;"
            "margin:2rem auto;padding:0 1rem;color:#111;background:#fff;line-height:1.5}"
            "h1{border-bottom:2px solid #0e7490;padding-bottom:6px}h2{border-bottom:1px solid #ddd;"
            "padding-bottom:4px}table{border-collapse:collapse;width:100%;margin:1rem 0}"
            "th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;text-align:left}"
            "tr:nth-child(even){background:#f7f9fb}.badge{display:inline-block;padding:2px 8px;"
            "border-radius:10px;font-size:12px;font-weight:700;color:#fff}"
            ".low{background:#3fb950}.high{background:#f85149}.med{background:#d29922}"
            "code{background:#f4f4f4;padding:1px 4px;border-radius:3px}"
            "pre{background:#f4f4f4;padding:12px;overflow:auto;border-radius:6px}"
            ".muted{color:#666;font-size:0.9em}svg{max-width:100%;height:auto;margin:1rem 0}"
            "@media print{body{background:#fff}a{color:#111}}"
        )
        sev = model["severity"]
        badge_class = "low" if sev in ("LOW", "INFORMATIONAL", "MODERATE") else ("high" if sev in ("HIGH", "CRITICAL") else "med")
        return (
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>Kernel-X Research Report — {session.session_id}</title>"
            f"<style>{css}</style></head><body>"
            f"<h1>Kernel-X Research Report</h1>"
            f"<p class='muted'>Session <code>{_esc(session.session_id)}</code> · "
            f"Generated {_utc_now()} · Schema {REPORT_SCHEMA_V2}</p>"
            f"<div class='badge {badge_class}'>Risk {model['risk_score']}/10 — {_esc(sev)}</div>"
            "<h2>Device Fingerprint</h2>"
            f"<table>{rows}</table>"
            "<h2>Risk Gauge</h2>"
            f"{model['gauge_svg']}"
            "<h2>Subsystem Exposure</h2>"
            f"{model['bars_svg']}"
            "<h2>Scenario Timeline</h2>"
            f"{model['timeline_svg']}"
            "<h2>Findings Register</h2>"
            f"<table><tr><th>CVE</th><th>Subsystem</th><th>Status</th><th>CVSS</th>"
            "<th>Maturity</th><th>Contrib.</th><th>Conf.</th><th>Rationale</th></tr>"
            f"{findings_rows}</table>"
            "<h2>Ethical Disclaimer</h2>"
            f"<div class='muted'><pre>{_esc(ETHICAL_DISCLAIMER)}</pre></div>"
            "<p class='muted'>Generated by Kernel-X Research Toolkit — "
            f"session <code>{_esc(session.session_id)}</code>.</p>"
            "</body></html>"
        )

    # -- export ---------------------------------------------------------------

    def export_v2(
        self,
        session: AuditSession,
        formats: Sequence[str] = ("md", "json", "html", "pdf"),
        basename: Optional[str] = None,
    ) -> Dict[str, str]:
        """Write the requested v2 artifacts; returns {format: absolute path}."""
        name = basename or f"kx-report-v2-{session.session_id}"
        written: Dict[str, str] = {}
        formats = [fmt.lower() for fmt in formats]

        if "json" in formats:
            path = os.path.join(self.output_dir, f"{name}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.build_payload(session), handle, indent=2, sort_keys=True, default=str)
            written["json"] = os.path.abspath(path)

        if "md" in formats or "markdown" in formats:
            path = os.path.join(self.output_dir, f"{name}.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.generate_markdown_v2(session))
            written["md"] = os.path.abspath(path)

        if "html" in formats:
            path = os.path.join(self.output_dir, f"{name}.html")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.generate_html_v2(session))
            written["html"] = os.path.abspath(path)

        if "pdf" in formats:
            pdf_path = self.try_pdf(name)
            if pdf_path:
                written["pdf"] = pdf_path
            else:
                logger.warning(
                    "no PDF engine (weasyprint/wkhtmltopdf) installed; HTML written "
                    "instead — use browser Print → Save as PDF for a PDF artifact"
                )

        logger.info("exported v2: %s", ", ".join(sorted(written)))
        return written


__all__ = [
    "ProfessionalReportGenerator",
    "REPORT_SCHEMA_V2",
    "chart_gauge_svg",
    "chart_subsystem_bars_svg",
    "chart_timeline_svg",
]
