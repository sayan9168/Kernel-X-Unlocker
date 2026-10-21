"""
Kernel-X Research Toolkit
=========================

A modular, **defensive** security-analysis and academic-audit framework for
studying Linux/Android (GKI + FBE) security architectures.

Scope & Ethics
--------------
This toolkit is an *observational* instrument. It performs:

* static telemetry mapping (kernel version / SoC / patch-level fingerprinting),
* configuration scanning against a curated knowledge base of publicly
  documented CVE surface areas,
* purely simulated ("dry-run") environment modeling of keystore / Gatekeeper /
  Weaver / FBE boundary conditions, and
* publication-ready academic report generation (Markdown / JSON).

It contains **no exploits, no payload injection, no credential-attack logic,
and no memory-access primitives**. Every simulation class operates exclusively
on in-process mock state; nothing is written to protected system paths and no
real hardware-backed service is contacted.

Modules
-------
- :mod:`kernel_x.risk_engine`     - fingerprinting + vulnerability-surface mapping
- :mod:`kernel_x.simulator`       - dry-run keystore & scenario simulation
- :mod:`kernel_x.reporter`        - Markdown/JSON academic reports
- :mod:`kernel_x.plugin_manager`  - extensible plugin framework
- :mod:`kernel_x.dashboard`       - local visualization dashboard (Flask)
"""

from __future__ import annotations

__version__ = "2.0.0"
__tool_name__ = "Kernel-X Research Toolkit"
__all__ = ["__version__", "__tool_name__", "TOOL_BANNER"]

TOOL_BANNER = (
    f"{__tool_name__} v{__version__} - Security Assessment & Academic Analysis Suite\n"
    "Mode: STATIC ANALYSIS / SIMULATION ONLY - defensive research use"
)
