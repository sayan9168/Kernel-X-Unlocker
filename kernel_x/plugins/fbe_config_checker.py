"""Reference plugin: FBE configuration consistency checker.

Cross-validates the observed file-based-encryption posture against the
documented AOSP baseline for the device's SDK level: content policy
(``aes-256-xts`` + integrity), metadata encryption, direct-boot (DE) awareness
and keystore backend alignment. Findings are advisory *configuration review*
notes for an audit report - never remediation scripts or system writes.
"""

from __future__ import annotations

from typing import Any, Dict, List

from kernel_x.plugin_manager import BasePlugin, PluginContext, PluginHookResult


class FbeConfigChecker(BasePlugin):
    name = "fbe-config-checker"
    version = "1.1.0"
    description = "Reviews FBE/metadata/keystore configuration coherence against AOSP baselines."
    author = "Kernel-X core team"
    priority = 30
    capabilities = ("analysis", "audit")

    _MIN_SDK_METADATA_ENC = 30   # metadata encryption mandatory from Android 11
    _EXPECTED_CONTENT = "aes-256-xts"

    def on_scan(self, context: PluginContext) -> PluginHookResult:
        fingerprint = context.fingerprint
        if fingerprint is None:
            return PluginHookResult("SKIPPED", {}, "no fingerprint in context")

        checks: List[Dict[str, Any]] = []
        sdk = getattr(fingerprint, "sdk_level", 0) or 0
        content = (getattr(fingerprint, "fbe_content_mode", "") or "").lower()
        metadata = (getattr(fingerprint, "fbe_metadata_mode", "") or "").lower()
        crypto_type = (getattr(fingerprint, "fbe_encryption_type", "") or "").lower()

        checks.append(
            self._check(
                "content-policy",
                self._EXPECTED_CONTENT in content,
                f"fbe.content.mode='{content or 'unset'}'",
                "high",
                "Adopt aes-256-xts for CE/DE content policies per AOSP fstab defaults.",
            )
        )
        checks.append(
            self._check(
                "integrity-component",
                "integrity" in content or "cts" in content,
                "no AES-256-CTS/integrity component declared in content mode",
                "medium",
                "Include the integrity element (e.g. ':integrity:aes-256-cts').",
            )
        )
        if sdk >= self._MIN_SDK_METADATA_ENC:
            checks.append(
                self._check(
                    "metadata-encryption",
                    bool(metadata) and "aes-256-xts" in metadata,
                    f"fbe.metadata.mode='{metadata or 'unset'}' on SDK {sdk}",
                    "high",
                    "Metadata encryption is mandatory for new devices at SDK>=30.",
                )
            )
        else:
            checks.append(
                self._check(
                    "metadata-encryption",
                    True,
                    f"SDK {sdk} predates mandatory metadata encryption",
                    "info",
                    "",
                )
            )
        checks.append(
            self._check(
                "per-file-encryption",
                crypto_type in {"file", ""},
                f"ro.crypto.type='{crypto_type or 'unset'}' indicates legacy block/FDE profile",
                "high",
                "Android 11+ forbids FDE; migrate userdata to FBE profiles.",
            )
        )
        keystore_backend = (getattr(fingerprint, "keystore2_backend", "") or "").lower()
        checks.append(
            self._check(
                "keystore-alignment",
                not (sdk >= 31 and "keystore2" not in keystore_backend),
                f"SDK {sdk} expects keystore2 backend, observed '{keystore_backend}'",
                "medium",
                "Ensure KeyMint/keystore2 backs CE credential storage binding.",
            )
        )

        weights = {"high": 4.0, "medium": 2.0}
        failed = [c for c in checks if not c["passed"] and c["severity"] in weights]
        score = max(0.0, 10.0 - sum(weights[c["severity"]] for c in failed))
        data = {
            "checks_total": len(checks),
            "checks_failed": len(failed),
            "config_consistency_score": round(score, 1),
            "details": checks,
        }
        context.observations.setdefault(self.name, {})["fbe_review"] = data
        return PluginHookResult("OK", data, f"{len(failed)} FBE deviations flagged")

    @staticmethod
    def _check(name: str, passed: bool, observation: str, severity: str, guidance: str) -> Dict[str, Any]:
        return {
            "name": name,
            "passed": bool(passed),
            "observation": observation if not passed else "conforms to baseline",
            "severity": severity if not passed else "ok",
            "guidance": "" if passed else guidance,
        }

    def on_report(self, context: PluginContext) -> PluginHookResult:
        review = context.observations.get(self.name, {}).get("fbe_review", {})
        if not review:
            return PluginHookResult("OK", {"markdown_lines": "- FBE review did not run"})
        ok_mark = "PASS"
        warn_mark = "DEVIATION"
        lines = [
            f"- Storage-crypto consistency score: **{review['config_consistency_score']}/10** "
            f"({review['checks_failed']} of {review['checks_total']} checks deviating)"
        ]
        for detail in review["details"]:
            mark = ok_mark if detail["passed"] else f"{warn_mark} ({detail['severity']})"
            line = f"  - `{detail['name']}` [{mark}]"
            if not detail["passed"]:
                line += f" {detail['observation']} -> {detail['guidance']}"
            lines.append(line)
        return PluginHookResult("OK", {"markdown_lines": "\n".join(lines)})
