#!/usr/bin/env python3
"""Sample drop-in plugin for Kernel-X plugin marketplace smoke tests."""
from kernel_x.plugin_manager import BasePlugin, PluginContext, PluginHookResult


class SamplePlugin(BasePlugin):
    name = "sample-plugin"
    version = "1.0.0"
    description = "Sample marketplace plugin (smoke test fixture)"
    author = "Kernel-X QA"
    priority = 10
    capabilities = ("scan",)

    def on_initialize(self, context: PluginContext) -> PluginHookResult:
        context.observations.setdefault(self.name, {})["initialized"] = True
        return PluginHookResult("OK", {}, "sample plugin initialized")

    def on_scan(self, context: PluginContext) -> PluginHookResult:
        context.observations.setdefault(self.name, {})["scanned"] = True
        return PluginHookResult("OK", {}, "sample plugin scanned")

    def on_simulate(self, context: PluginContext) -> PluginHookResult:
        context.observations.setdefault(self.name, {})["simulated"] = True
        return PluginHookResult("OK", {}, "sample plugin simulated")

    def on_report(self, context: PluginContext) -> PluginHookResult:
        return PluginHookResult("OK", {"markdown_lines": "- sample plugin: OK"}, "sample report")
