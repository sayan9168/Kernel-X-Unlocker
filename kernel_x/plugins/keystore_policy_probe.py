"""Reference plugin: keystore-policy model probe (dry-run only).

Uses the *in-process* :class:`KeystoreSimulator` from ``kernel_x.simulator`` to
probe how auth-bound key policy reacts to simulated FBE unlock states, then
records the observed transitions for the report. This never contacts a real
keystore/Gatekeeper service - it exercises the mock state machine exclusively.
"""

from __future__ import annotations

from typing import Any, Dict, List

from kernel_x.plugin_manager import BasePlugin, PluginContext, PluginHookResult
from kernel_x.simulator import (
    KeystoreSimulator,
    KeyAlgorithm,
    ScenarioRunner,
    ScenarioStep,
    SecurityLevel,
    StorageDomain,
)


class KeystorePolicyProbe(BasePlugin):
    name = "keystore-policy-probe"
    version = "1.0.0"
    description = "Dry-run probe of auth-bound keystore policy against simulated FBE states."
    author = "Kernel-X core team"
    priority = 60
    capabilities = ("simulation", "modeling")

    def on_simulate(self, context: PluginContext) -> PluginHookResult:
        simulator: KeystoreSimulator = context.simulator or KeystoreSimulator(
            seed=f"kx-probe-{context.session_id}"
        )
        steps: List[ScenarioStep] = [
            ScenarioStep("provision", ("provision_mock_credential", "u", "demo-pass")),
            ScenarioStep(
                "gen-auth-bound-CE-key",
                (
                    "generate_key", "probe_key", KeyAlgorithm.AES_GCM,
                    SecurityLevel.TRUSTED_ENVIRONMENT, True, 5_000, False, StorageDomain.CE,
                ),
            ),
            ScenarioStep("locked-access", ("begin_operation", "probe_key"),
                         expect_success=False),
            ScenarioStep("unlock", ("verify_lockscreen_credential", "demo-pass"),
                         expect_success=True),
            ScenarioStep("unlocked-access", ("begin_operation", "probe_key"),
                         expect_success=True),
            ScenarioStep("relock", ("lock_device",)),
            ScenarioStep("sealed-again", ("begin_operation", "probe_key"),
                         expect_success=False),
        ]
        runner = ScenarioRunner(simulator)
        outcome = runner.run_scenario("plugin-keystore-policy-probe", steps)
        context.scenarios.append(outcome)

        data: Dict[str, Any] = {
            "scenario_passed": outcome.passed,
            "steps": len(outcome.steps),
            "denied_steps": [
                step["step"] for step in outcome.steps if not step["result"]["success"]
            ],
            "granted_when_unlocked": any(
                s["step"] == "unlocked-access" and s["result"]["success"] for s in outcome.steps
            ),
            "timeline_length": len(outcome.events),
        }
        context.observations.setdefault(self.name, {})["probe"] = data
        return PluginHookResult("OK", data, "policy probe executed (simulation only)")

    def on_report(self, context: PluginContext) -> PluginHookResult:
        probe = context.observations.get(self.name, {}).get("probe", {})
        if not probe:
            return PluginHookResult("OK", {"markdown_lines": "- keystore probe did not run"})
        lines = [
            f"- Probe scenario passed: **{probe['scenario_passed']}** over {probe['steps']} steps",
            f"- Policy denials observed at: {', '.join(probe['denied_steps']) or 'none'}",
            f"- CE key usable while unlocked: **{probe['granted_when_unlocked']}**",
            "- Note: all operations were performed by the in-process mock; no hardware "
            "keymaster/KeyMint service was contacted.",
        ]
        return PluginHookResult("OK", {"markdown_lines": "\n".join(lines)})
