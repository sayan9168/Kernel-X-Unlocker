"""
kernel_x.reporter
=================

Module 3 - Academic Reporting & Markdown/JSON Export.

``AcademicReportGenerator`` turns a session (device fingerprint, risk
assessment, simulation timelines, plugin observations) into publication-ready
artifacts:

* GitHub-flavoured **Markdown** with abstract, methodology, tables, ASCII
  heat-strip visualisation of the risk model, findings register, simulated
  behaviour timelines, remediation roadmap and reproducibility appendix;
* machine-readable **JSON** (schema-versioned, ``sort_keys`` for stable
  digests);
* optional **HTML** rendering (PDF-ready via any browser print pipeline or
  ``weasyprint``/``wkhtmltopdf`` if installed on the research host);
* automatically appended **ethical disclaimers**, timestamps, environmental
  hashes (toolkit build + knowledge-base digest + environment fingerprint) and
  **BibTeX** citation blocks.

Integrity model
---------------
Every report carries an SHA-256 over its canonical JSON body so that a
published figure can be re-derived from the archived artifact
(``verify_artifact``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .risk_engine import DeviceFingerprint, RiskAssessment
from .simulator import ScenarioOutcome

logger = logging.getLogger("kernel_x.reporter")

REPORT_SCHEMA_VERSION = "kx-report/1.0"

ETHICAL_DISCLAIMER = """\
## Ethical & Scope Disclaimer

This document was produced by **Kernel-X Research Toolkit**, an *observational*
security-analysis instrument intended for academic study, defensive hardening
and audit documentation. Its outputs are derived exclusively from static
telemetry, publicly published advisories and in-process simulations.

The toolkit is **not** an exploitation framework. It contains no exploit code,
performs no memory access (`/dev/mem`, `/dev/kmem`, ptrace) and issues no
commands against hardware-backed security services (KeyMint/keystore2,
Gatekeeper, Weaver). All "simulation" results describe *modelled* behaviour of
documented Android/Linux security boundaries; they do not constitute,
endorse, or assist unauthorised access to any device or account.

Research described here must comply with applicable law and institutional
policy (e.g., ACM/IEEE code of ethics, CFAA/EU Directive 2013/40/EU, and your
IRB/ethics-board approval). Only assess systems you own or have explicit,
written authorisation to test, and follow coordinated-disclosure timelines when
reporting real vulnerabilities. Findings herein are *correlation-based
candidates*; verify against vendor changelogs before disclosure or publication.
"""

REPRODUCIBILITY_NOTE = """\
Reports embed an environment hash and a knowledge-base digest. Re-running the
same toolkit build against the same fingerprint input reproduces byte-identical
canonical JSON (modulo wall-clock fields), enabling third-party replication of
the quantitative sections.
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Session container
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AuditSession:
    """Aggregates everything a report needs for one research run."""

    session_id: str
    started_at: str
    title: str = "Android Kernel Security Posture Assessment"
    author: str = "Security Architecture Research Group"
    institution: str = "Autonomous Systems Security Lab"
    fingerprint: Optional[DeviceFingerprint] = None
    assessment: Optional[RiskAssessment] = None
    scenarios: List[ScenarioOutcome] = field(default_factory=list)
    plugin_observations: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "title": self.title,
            "started_at": self.started_at,
            "risk_score": self.assessment.risk_score if self.assessment else None,
            "severity": self.assessment.severity if self.assessment else "N/A",
            "findings": len(self.assessment.findings) if self.assessment else 0,
            "scenarios_run": len(self.scenarios),
            "scenarios_passed": sum(1 for s in self.scenarios if s.passed),
        }


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------


class AcademicReportGenerator:
    """Formats an :class:`AuditSession` into Markdown / JSON / HTML artifacts."""

    BIBTEX_BASE_URL = "https://source.android.com/docs/security/bulletin"

    def __init__(self, output_dir: str = "reports", author_meta: Optional[Dict[str, str]] = None) -> None:
        self.output_dir = output_dir
        self.author_meta = author_meta or {}
        os.makedirs(self.output_dir, exist_ok=True)

    # -- environment -------------------------------------------------------

    def environment_hash(self) -> Dict[str, str]:
        """Stable identity of the analysis environment for reproducibility."""
        try:
            git_sha = subprocess.run(
                ["git", "-C", os.getcwd(), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=3, check=False,
            ).stdout.strip() or "n/a"
        except (OSError, subprocess.SubprocessError):
            git_sha = "n/a"

        material = "|".join(
            (
                platform.system(),
                platform.machine(),
                platform.release(),
                platform.python_version(),
                git_sha,
            )
        )
        return {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "toolkit_git": git_sha,
            "environment_sha256": _sha256(material),
        }

    @staticmethod
    def knowledge_base_digest(knowledge_base: Sequence[Any]) -> str:
        """Digest over CVE ids + version ranges of the mapped knowledge base."""
        lines = [
            f"{getattr(item, 'cve_id', '?')}|{getattr(item, 'affected_min', 0)}|{getattr(item, 'affected_max', 0)}"
            for item in knowledge_base
        ]
        return _sha256("\n".join(sorted(lines)))[:16]

    # -- canonical JSON ------------------------------------------------------

    def canonical_json(self, session: AuditSession) -> str:
        payload = self.build_payload(session)
        return json.dumps(payload, sort_keys=True, indent=2, default=str)

    def build_payload(self, session: AuditSession) -> Dict[str, Any]:
        fingerprint = session.fingerprint.as_dict() if session.fingerprint else {}
        assessment = session.assessment.as_dict() if session.assessment else {}
        payload: Dict[str, Any] = {
            "schema": REPORT_SCHEMA_VERSION,
            "generated_at": _utc_now(),
            "session": session.summary(),
            "metadata": {
                "title": session.title,
                "author": session.author or self.author_meta.get("author", ""),
                "institution": session.institution or self.author_meta.get("institution", ""),
                "toolkit": "Kernel-X Research Toolkit",
                "mode": "static-analysis + dry-run-simulation",
            },
            "environment": self.environment_hash(),
            "fingerprint": fingerprint,
            "risk_assessment": assessment,
            "simulation": [outcome.as_dict() for outcome in session.scenarios],
            "plugin_observations": session.plugin_observations,
            "notes": session.notes,
            "disclaimer": ETHICAL_DISCLAIMER,
        }
        body_for_digest = json.dumps(
            {k: payload[k] for k in ("fingerprint", "risk_assessment", "simulation")},
            sort_keys=True,
            default=str,
        )
        payload["integrity"] = {"canonical_body_sha256": _sha256(body_for_digest)}
        return payload

    # -- markdown ------------------------------------------------------------

    @staticmethod
    def _heat_strip(score: float, width: int = 20) -> str:
        filled = int(round(max(0.0, min(10.0, score)) / 10.0 * width))
        return "#" * filled + "." * (width - filled)

    def _md_header(self, session: AuditSession, payload: Dict[str, Any]) -> List[str]:
        env = payload["environment"]
        fp = session.fingerprint
        lines = [
            f"# {session.title}",
            "",
            f"**Session:** `{session.session_id}` · **Generated:** {payload['generated_at']} · "
            f"**Schema:** `{REPORT_SCHEMA_VERSION}`",
            "",
            f"**Authors:** {session.author} — {session.institution}",
            "",
            "---",
            "",
            "## Abstract",
            "",
        ]
        if fp and session.assessment:
            lines.append(
                f"This audit characterises the kernel-level security posture of a "
                f"**{fp.manufacturer} {fp.model}** running Android {fp.android_version or 'n/a'} "
                f"(SDK {fp.sdk_level or 'n/a'}) on a **{fp.soc_vendor} {fp.soc_codename}** SoC with "
                f"Linux kernel `{fp.kernel_version}` ({fp.gki_variant}). Static telemetry was mapped "
                f"against a curated knowledge base of {payload['risk_assessment'].get('metadata', {}).get('knowledge_base_size', 'N')} "
                f"publicly documented vulnerability surface areas, yielding a normalized risk score of "
                f"**{session.assessment.risk_score}/10.0 ({session.assessment.severity})**. "
                f"{len(session.scenarios)} dry-run scenario batteries were executed to model FBE, "
                f"keystore-policy and credential-verifier boundary behaviour. No live attack path was "
                f"exercised or attempted."
            )
        else:
            lines.append("No fingerprint/assessment data attached to this session.")
        lines += [
            "",
            "## 1. Methodology",
            "",
            "1. **Telemetry acquisition** — read-only collection of `/proc/version`, `/proc/cpuinfo`, "
            "`/sys/devices/soc0/*`, `/proc/cmdline`, kernel config (`/proc/config.gz` or `/boot/config-*`) "
            "and Android properties (`getprop` or injected lab dictionary).",
            "2. **Surface correlation** — kernel series + subsystem configuration matched against the "
            "local CVE knowledge base; tri-state applicability (present / absent / unverifiable).",
            "3. **Scoring** — `impact × reachability × exploit-maturity × applicability × patch-decay`, "
            "complement-aggregated and mitigation-adjusted (formula in Appendix A).",
            "4. **Dry-run modelling** — declarative scenarios exercise the in-process keystore/FBE/Gatekeeper "
            "state machines; only policy outcomes are recorded.",
            "5. **Reporting** — canonical JSON + Markdown export with integrity digest and citations.",
            "",
        ]
        return lines

    def _md_fingerprint(self, session: AuditSession) -> List[str]:
        fp = session.fingerprint
        if fp is None:
            return ["## 2. Device Fingerprint", "", "_No fingerprint captured._", ""]
        posture = fp.posture_summary
        rows = [
            ("Device", f"{fp.manufacturer} {fp.model} ({fp.device_name})"),
            ("Android / SDK", f"{fp.android_version or 'n/a'} / {fp.sdk_level or 'n/a'}"),
            ("Security patch level", f"{fp.security_patch_level or 'n/a'}"
             + (f" ({posture['patch_age_days']} days old)" if posture["patch_age_days"] is not None else "")),
            ("Kernel version", f"`{fp.kernel_version}` (series {fp.kernel_series[0]}.{fp.kernel_series[1]})"),
            ("Kernel flavour", fp.gki_variant),
            ("SoC", f"{fp.soc_vendor} — {fp.soc_codename} (soc_id={fp.soc_id}, hw={fp.hardware})"),
            ("Architecture", fp.architecture),
            ("Bootloader / AVB", f"{fp.bootloader_state} / {fp.avb_version} "
                                 f"(verifiedbootstate={fp.verified_boot_state}, verity={fp.verity_mode})"),
            ("Storage encryption", f"{fp.fbe_encryption_type} — content `{fp.fbe_content_mode}`, "
                                   f"metadata `{fp.fbe_metadata_mode}`"),
            ("FBE token model", fp.fileencryption_token),
            ("Keystore backend", f"{fp.keystore2_backend} (Weaver: {fp.weaver_backend})"),
            ("SELinux posture", "log/enforcing-relaxed detected" if posture["sepolicy_debug"]
                                else "enforcing assumptions hold (as far as observable)"),
            ("Kconfig visibility", fp.extra.get("kconfig_available", "no")),
            ("Build type", fp.extra.get("build_type", "n/a") or "n/a"),
        ]
        lines = ["## 2. Device Fingerprint", "", "| Attribute | Observed value |", "|---|---|"]
        lines += [f"| {name} | {value} |" for name, value in rows]
        lines.append("")
        return lines

    def _md_risk(self, session: AuditSession, payload: Dict[str, Any]) -> List[str]:
        assessment = session.assessment
        if assessment is None:
            return ["## 3. Vulnerability Surface & Risk", "", "_No assessment attached._", ""]

        lines = [
            "## 3. Vulnerability Surface & Risk",
            "",
            f"**Normalized risk score:** `{assessment.risk_score}/10.0` → **{assessment.severity}**",
            "",
            f"`[{self._heat_strip(assessment.risk_score)}]` 0 ──── 10",
            "",
            f"Raw aggregate `{assessment.raw_score}` · mitigation net credit "
            f"`{assessment.metadata.get('mitigation_net_credit')}` · patch decay "
            f"`{assessment.metadata.get('patch_decay')}` ({assessment.metadata.get('patch_decay_note', '')})",
            "",
            "### 3.1 Subsystem exposure heatmap",
            "",
            "| Subsystem | Contribution | Heat |",
            "|---|---:|---|",
        ]
        ordered = sorted(assessment.subsystem_scores.items(), key=lambda kv: kv[1], reverse=True)
        for subsystem, value in ordered:
            lines.append(f"| `{subsystem}` | {value:.2f} | `[{self._heat_strip(value, 12)}]` |")
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
                f"  - Affected kernel range: `{finding.affected_range}` · vector `{finding.cvss_vector}`",
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

    def _md_simulation(self, session: AuditSession) -> List[str]:
        if not session.scenarios:
            return ["## 5. Simulated Boundary Behaviour (dry-run)", "", "_No scenarios executed._", ""]
        lines = [
            "## 5. Simulated Boundary Behaviour (dry-run)",
            "",
            "All events below originate from the in-process model; no hardware-backed service was "
            "contacted and no real credential verification was attempted.",
            "",
        ]
        for outcome in session.scenarios:
            status = "PASS" if outcome.passed else "FAIL"
            lines += [
                f"### 5.x Scenario `{outcome.scenario}` — **{status}** "
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

    def _md_plugins(self, session: AuditSession) -> List[str]:
        if not session.plugin_observations:
            return []
        lines = ["## 6. Plugin Contributions", ""]
        for plugin, observation in session.plugin_observations.items():
            lines.append(f"### `{plugin}`")
            lines.append("")
            if isinstance(observation, dict):
                for key, value in observation.items():
                    lines.append(f"- **{key}:** {value}")
            else:
                lines.append(f"```\n{observation}\n```")
            lines.append("")
        return lines

    def _md_appendix(self, session: AuditSession, payload: Dict[str, Any]) -> List[str]:
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

    def generate_markdown(self, session: AuditSession) -> str:
        payload = self.build_payload(session)
        parts: List[str] = []
        parts += self._md_header(session, payload)
        parts += self._md_fingerprint(session)
        parts += self._md_risk(session, payload)
        parts += self._md_simulation(session)
        parts += self._md_plugins(session)
        parts += self._md_appendix(session, payload)
        return "\n".join(parts) + "\n"

    # -- citations -----------------------------------------------------------

    def generate_bibtex(self, session: AuditSession) -> str:
        """BibTeX block: used frameworks plus every cited advisory in findings."""
        entries: List[str] = []
        base = {
            "@misc{android-security-bulletin,": [
                "  title         = {Android Security Bulletin},",
                "  author        = {{Android Open Source Project}},",
                "  year          = {2025},",
                f"  howpublished = {{{self.BIBTEX_BASE_URL}}},",
                "  note          = {Monthly coordinated-disclosure advisories},",
                "}",
            ],
            "@misc{aosp-fbe,": [
                "  title         = {File-Based Encryption (FBE) architecture},",
                "  author        = {{Android Open Source Project}},",
                "  year          = {2024},",
                "  howpublished = {https://source.android.com/docs/security/features/encryption},",
                "}",
            ],
            "@misc{aosp-gki,": [
                "  title         = {Generic Kernel Image (GKI) architecture},",
                "  author        = {{Android Open Source Project}},",
                "  year          = {2024},",
                "  howpublished = {https://source.android.com/docs/core/architecture/kernel/generic-kernel-image},",
                "}",
            ],
            "@misc{keymint-spec,": [
                "  title         = {KeyMint (Keys through the Trustworthy Execution Environment) HAL specification},",
                "  author        = {{Android Open Source Project}},",
                "  year          = {2024},",
                "  howpublished = {https://developer.android.com/reference/android/hardware/security/keymint},",
                "}",
            ],
            "@article{cvss31,": [
                "  title  = {Common Vulnerability Scoring System v3.1 Specification},",
                "  author = {{FIRST.org}},",
                "  year   = {2019},",
                "  journal= {FIRST CV-SIG},",
                "  url    = {https://www.first.org/cvss/v3.1/specification-document},",
                "}",
            ],
            "@software{kernel-x-toolkit,": [
                f"  title   = {{{session.title or 'Kernel-X Research Toolkit'}}},",
                f"  author  = {{{session.author or 'Anonymous'}}},",
                f"  year    = {{{datetime.now(timezone.utc).year}}},",
                "  version = {2.0.0},",
                f"  note    = {{Session {session.session_id}; knowledge-base digest "
                f"{session.plugin_observations.get('_knowledge_base_digest', 'n/a')}}},",
                "}",
            ],
        }
        for key, body in base.items():
            entries.append(key + "\n" + "\n".join(body))

        if session.assessment:
            for finding in session.assessment.findings:
                cve_slug = finding.cve_id.lower().replace("-", "")
                year = finding.cve_id.split("-")[1] if "-" in finding.cve_id else "n/a"
                entries.append(
                    f"@misc{{{cve_slug},\n"
                    f"  title         = {{{finding.cve_id}: {finding.title}}},\n"
                    f"  author        = {{{finding.subsystem} maintainers / NVD}},\n"
                    f"  year          = {{{year}}},\n"
                    f"  howpublished = {{{finding.reference}}},\n"
                    f"  note          = {{CVSS vector {finding.cvss_vector}; mapped status {finding.status}}},\n"
                    f"}}"
                )
        return "\n\n".join(entries)

    # -- export --------------------------------------------------------------

    def export(
        self,
        session: AuditSession,
        formats: Sequence[str] = ("md", "json"),
        basename: Optional[str] = None,
    ) -> Dict[str, str]:
        """Write the requested artifacts; returns ``{format: absolute path}``."""
        name = basename or f"kx-report-{session.session_id}"
        written: Dict[str, str] = {}
        formats = [fmt.lower() for fmt in formats]

        payload = self.build_payload(session)
        if "json" in formats:
            path = os.path.join(self.output_dir, f"{name}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            written["json"] = os.path.abspath(path)

        if "md" in formats or "markdown" in formats:
            path = os.path.join(self.output_dir, f"{name}.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.generate_markdown(session))
            written["md"] = os.path.abspath(path)

        if "html" in formats:
            path = os.path.join(self.output_dir, f"{name}.html")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.render_html(self.generate_markdown(session)))
            written["html"] = os.path.abspath(path)

        if "pdf" in formats:
            pdf_path = self.try_pdf(name)
            if pdf_path:
                written["pdf"] = pdf_path
            else:
                logger.warning("no PDF engine available; exported HTML instead")
                written.update(self.export(session, ["html"], name))

        logger.info("exported %s", ", ".join(sorted(written)))
        return written

    def render_html(self, markdown_text: str) -> str:
        """Wrap Markdown in a print/PDF-ready HTML shell (best-effort tables)."""
        try:
            import markdown as md_lib  # optional dependency

            body = md_lib.markdown(markdown_text, extensions=["tables", "fenced_code"])
        except ImportError:
            escaped = (
                markdown_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            )
            body = f"<pre>{escaped}</pre>"
        style = (
            "body{font-family:'Segoe UI',Roboto,sans-serif;max-width:960px;margin:2rem auto;"
            "padding:0 1rem;color:#111;background:#fff;line-height:1.45}"
            "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;"
            "padding:6px 8px;font-size:13px;text-align:left}code{background:#f4f4f4;padding:1px 4px;"
            "border-radius:3px}pre{background:#f4f4f4;padding:12px;overflow:auto;border-radius:6px}"
            "h1,h2{border-bottom:1px solid #ddd;padding-bottom:4px}@media print{a{color:#111}}"
        )
        return (
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<title>Kernel-X Academic Security Report</title>"
            f"<style>{style}</style></head><body>{body}</body></html>"
        )

    def try_pdf(self, basename: str) -> Optional[str]:
        """Convert the exported HTML with an external engine, if installed."""
        html_path = os.path.join(self.output_dir, f"{basename}.html")
        pdf_path = os.path.join(self.output_dir, f"{basename}.pdf")
        for tool, args in (
            ("weasyprint", ["weasyprint", html_path, pdf_path]),
            ("wkhtmltopdf", ["wkhtmltopdf", html_path, pdf_path]),
        ):
            if shutil.which(tool):
                try:
                    completed = subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)
                    if completed.returncode == 0 and os.path.isfile(pdf_path):
                        return os.path.abspath(pdf_path)
                    logger.debug("%s failed: %s", tool, completed.stderr[:200])
                except (OSError, subprocess.SubprocessError) as exc:
                    logger.debug("%s invocation error: %s", tool, exc)
        return None

    # -- verification ----------------------------------------------------------

    @staticmethod
    def verify_artifact(json_path: str) -> bool:
        """Recompute the embedded integrity digest of an exported JSON report."""
        try:
            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("artifact unreadable: %s", exc)
            return False
        expected = payload.get("integrity", {}).get("canonical_body_sha256", "")
        body = json.dumps(
            {k: payload[k] for k in ("fingerprint", "risk_assessment", "simulation")},
            sort_keys=True,
            default=str,
        )
        actual = _sha256(body)
        match = bool(expected) and expected == actual
        logger.info("artifact verification %s: %s", os.path.basename(json_path), "OK" if match else "MISMATCH")
        return match


__all__ = [
    "AuditSession",
    "AcademicReportGenerator",
    "ETHICAL_DISCLAIMER",
    "REPRODUCIBILITY_NOTE",
    "REPORT_SCHEMA_VERSION",
]
