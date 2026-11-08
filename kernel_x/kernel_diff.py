"""
kernel_x.kernel_diff
====================

GKI / Vendor Kernel Diff Analyzer
=================================

Compares two kernel builds (or two snapshots of the same build across an
update) and highlights *security-relevant* changes:

* kernel version string drift (series jump, GKI vs vendor suffix)
* kernel config additions / removals / flips, with security relevance
  flags (``CONFIG_DEVMEM``, ``CONFIG_KALLSYMS``, ``CONFIG_SECURITY_SELINUX``,
  ``CONFIG_LKDTM``, ``CONFIG_STAGING``, ``CONFIG_BPF_SYSCALL``, binder/ION
  flags, module signing, …)
* kernel symbol table additions / removals (from ``/proc/kallsyms`` or a
  ``System.map`` capture), flagging symbol classes that commonly aid
  post-exploitation (``commit_creds``, ``prepare_kernel_cred``,
  ``modprobe_path``, kprobe/ftrace helpers, …)
* CVE relevance: changed subsystems are correlated against the offline
  knowledge base so an analyst can see which documented advisories touch
  the changed surface.

Inputs are directory snapshots (no mounted kernel, no device access
required).  Each snapshot directory may contain::

    proc/version          # uname-style version string
    proc/config.gz        # or boot/config-<version>
    proc/cmdline          # boot cmdline
    proc/kallsyms         # optional symbol table
    System.map            # optional symbol table (root or boot/)

All reads are read-only.  Nothing is ever written to a kernel interface.
"""

from __future__ import annotations

import glob
import gzip
import hashlib
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .knowledge_base import DEFAULT_KNOWLEDGE_BASE, OfflineKnowledgeBase
from .risk_engine import _parse_series, _series_key

logger = logging.getLogger("kernel_x.kernel_diff")

#: Security-relevant kernel config symbols with a one-line research note.
SECURITY_CONFIG_NOTES: Dict[str, str] = {
    "DEVMEM": "/dev/mem interface - raw physical memory access (information disclosure / primitive exposure)",
    "KALLSYMS": "kernel symbol table exposed - aids symbol resolution for post-exploitation research",
    "KALLSYMS_ALL": "all symbols (including unexported) exposed - maximal symbol exposure",
    "KPROBES": "kprobes instrumentation - dynamic kernel probing surface",
    "FTRACE": "function tracing - tracing surface observable from userspace",
    "SECURITY_SELINUX": "SELinux mandatory access control - disabling weakens MAC posture",
    "SECURITY_APPARMOR": "AppArmor MAC - profile changes affect confinement surface",
    "LKDTM": "kernel crash test driver - debug-only, must be absent on production",
    "STAGING": "staging drivers - lower review bar, larger attack surface",
    "BPF_SYSCALL": "bpf() syscall - eBPF verifier surface",
    "BPF_JIT": "eBPF JIT compilation - JIT spraying relevance",
    "UNPRIVILEGED_BPF": "unprivileged eBPF - verifier reachable from unprivileged userspace",
    "MODULES": "loadable kernel modules - module loading attack surface",
    "MODULE_SIG_FORCE": "module signature enforcement - absent allows unsigned modules",
    "MODULE_FORCE_LOAD": "force module load - bypasses version/taint checks",
    "ANDROID_BINDER_IPC": "binder IPC driver - IPC attack surface",
    "ANDROID_BINDERFS": "binderfs mount surface",
    "ION": "legacy ION allocator - DMA-BUF/UAF history surface",
    "DMABUF_HEAPS": "dma-buf heaps - modern ION replacement surface",
    "XFRM": "IPsec transform framework - net-local attack surface",
    "NETFILTER": "netfilter/nftables - packet filtering surface",
    "TUN": "TUN/TAP driver - virtual network interface surface",
    "HIBERNATION": "hibernation/suspend image surface",
    "ACCESSIBILITY": "not a kernel config; reserved",
}

#: Symbol name prefixes/names whose appearance or disappearance is noteworthy.
SECURITY_SYMBOL_HINTS: Tuple[str, ...] = (
    "commit_creds",
    "prepare_kernel_cred",
    "modprobe_path",
    "usermodehelper",
    "call_usermodehelper",
    "seq_ops",
    "proc_fops",
    "kallsyms_lookup_name",
    "kprobe_",
    "kretprobe_",
    "ftrace_",
    "perf_",
    "bpf_",
    "kprobe",
    "kretprobe",
    "ftrace",
    "kgdb",
    "hw_breakpoint",
    " perf",
)


@dataclass(slots=True)
class KernelSnapshot:
    """Read-only description of one kernel build snapshot."""

    source_dir: str
    kernel_version: str = ""
    kernel_series: Tuple[int, int] = (0, 0)
    config: Dict[str, str] = field(default_factory=dict)
    cmdline: Dict[str, str] = field(default_factory=dict)
    symbols: Set[str] = field(default_factory=set)
    symbol_count: int = 0
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_dir": self.source_dir,
            "kernel_version": self.kernel_version,
            "kernel_series": list(self.kernel_series),
            "config": dict(self.config),
            "cmdline": dict(self.cmdline),
            "symbol_count": self.symbol_count,
            "captured_at": self.captured_at,
        }


@dataclass(slots=True)
class ConfigChange:
    name: str
    before: Optional[str]
    after: Optional[str]
    security_relevant: bool
    note: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SymbolChange:
    name: str
    change: str  # "added" | "removed"
    security_relevant: bool
    hint: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CVENote:
    cve_id: str
    subsystem: str
    title: str
    reason: str
    reference: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DiffReport:
    """Result of diffing two kernel snapshots."""

    before: KernelSnapshot
    after: KernelSnapshot
    version_changed: bool = False
    series_changed: bool = False
    config_changes: List[ConfigChange] = field(default_factory=list)
    symbol_changes: List[SymbolChange] = field(default_factory=list)
    cve_notes: List[CVENote] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "schema": "kx-kernel-diff/1.0",
            "before": self.before.as_dict(),
            "after": self.after.as_dict(),
            "version_changed": self.version_changed,
            "series_changed": self.series_changed,
            "config_changes": [c.as_dict() for c in self.config_changes],
            "symbol_changes": [s.as_dict() for s in self.symbol_changes],
            "cve_notes": [c.as_dict() for c in self.cve_notes],
            "summary": self.summary,
        }


def _read_text(path: str, limit: int = 4_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _load_config_from_dir(snapshot_dir: str) -> Dict[str, str]:
    """Parse kernel config from proc/config.gz or boot/config-*."""
    candidates: List[str] = []
    gz = os.path.join(snapshot_dir, "proc", "config.gz")
    if os.path.isfile(gz):
        candidates.append(("proc/config.gz", gz))
    candidates.extend(
        (os.path.basename(p), p)
        for p in sorted(glob.glob(os.path.join(snapshot_dir, "boot", "config-*")))
    )
    for label, path in candidates:
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                    text = handle.read(4_000_000)
            else:
                text = _read_text(path, limit=4_000_000)
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            logger.debug("config source %s unreadable: %s", path, exc)
            continue
        parsed: Dict[str, str] = {}
        enabled = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(\S+)$")
        disabled = re.compile(r"^# CONFIG_([A-Za-z0-9_]+) is not set$")
        for line in text.splitlines():
            line = line.strip()
            m = enabled.match(line)
            if m:
                parsed[m.group(1)] = m.group(2)
                continue
            m = disabled.match(line)
            if m:
                parsed[m.group(1)] = "n"
        if parsed:
            logger.info("loaded %d kconfig symbols from %s (%s)", len(parsed), path, label)
            return parsed
    return {}


def _load_symbols_from_dir(snapshot_dir: str) -> Set[str]:
    """Read symbol names from proc/kallsyms or System.map (best effort)."""
    symbols: Set[str] = set()
    candidates: List[str] = []
    k = os.path.join(snapshot_dir, "proc", "kallsyms")
    if os.path.isfile(k):
        candidates.append(k)
    candidates.extend(sorted(glob.glob(os.path.join(snapshot_dir, "System.map*"))))
    candidates.extend(sorted(glob.glob(os.path.join(snapshot_dir, "boot", "System.map*"))))
    for path in candidates:
        try:
            text = _read_text(path, limit=4_000_000)
        except OSError:
            continue
        # <address> <type> <name> [module]  --  kallsyms form
        # <address> <name>                       --  System.map form
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"^[0-9a-fA-F]+$", parts[0]):
                symbols.add(parts[2])
            elif len(parts) == 2 and re.match(r"^[0-9a-fA-F]+$", parts[0]):
                symbols.add(parts[1])
        if symbols:
            logger.info("loaded %d symbols from %s", len(symbols), path)
            break
    return symbols


def capture_snapshot(source_dir: str) -> KernelSnapshot:
    """Capture a read-only kernel snapshot from a directory tree."""
    source_dir = os.path.abspath(source_dir)
    version_path = os.path.join(source_dir, "proc", "version")
    version = _read_text(version_path).strip()
    match = re.search(r"Linux version (\S+)", version)
    kernel_version = match.group(1) if match else version
    snapshot = KernelSnapshot(
        source_dir=source_dir,
        kernel_version=kernel_version,
        kernel_series=_parse_series(kernel_version),
        config=_load_config_from_dir(source_dir),
        cmdline={},
        symbols=_load_symbols_from_dir(source_dir),
    )
    cmdline_path = os.path.join(source_dir, "proc", "cmdline")
    cmdline_text = _read_text(cmdline_path)
    for token in cmdline_text.split():
        key, sep, value = token.partition("=")
        snapshot.cmdline[key] = value if sep else "true"
    snapshot.symbol_count = len(snapshot.symbols)
    logger.info(
        "snapshot captured: %s (series %d.%d, config=%d, symbols=%d)",
        kernel_version,
        snapshot.kernel_series[0],
        snapshot.kernel_series[1],
        len(snapshot.config),
        snapshot.symbol_count,
    )
    return snapshot


def _symbol_security_hint(name: str) -> Tuple[bool, str]:
    low = name.lower()
    for hint in SECURITY_SYMBOL_HINTS:
        if hint.lower() in low:
            return True, f"symbol name matches '{hint}' pattern"
    return False, ""


class KernelDiffAnalyzer:
    """Diffs two :class:`KernelSnapshot` objects into a :class:`DiffReport`."""

    def __init__(
        self,
        knowledge_base: Optional[OfflineKnowledgeBase] = None,
    ) -> None:
        self.kb = knowledge_base or DEFAULT_KNOWLEDGE_BASE

    def diff(
        self,
        before: KernelSnapshot,
        after: KernelSnapshot,
    ) -> DiffReport:
        report = DiffReport(before=before, after=after)

        report.version_changed = before.kernel_version != after.kernel_version
        report.series_changed = before.kernel_series != after.kernel_series

        # --- config diff ----------------------------------------------------
        before_keys = set(before.config)
        after_keys = set(after.config)
        all_keys = before_keys | after_keys
        for name in sorted(all_keys):
            b_val = before.config.get(name)
            a_val = after.config.get(name)
            if b_val == a_val:
                continue
            relevant = name in SECURITY_CONFIG_NOTES
            note = SECURITY_CONFIG_NOTES.get(name, "config value changed")
            report.config_changes.append(
                ConfigChange(
                    name=name,
                    before=b_val,
                    after=a_val,
                    security_relevant=relevant,
                    note=note,
                )
            )
        report.config_changes.sort(
            key=lambda c: (not c.security_relevant, c.name)
        )

        # --- symbol diff ----------------------------------------------------
        added = after.symbols - before.symbols
        removed = before.symbols - after.symbols
        for name in sorted(added):
            relevant, hint = _symbol_security_hint(name)
            report.symbol_changes.append(
                SymbolChange(name=name, change="added", security_relevant=relevant, hint=hint)
            )
        for name in sorted(removed):
            relevant, hint = _symbol_security_hint(name)
            report.symbol_changes.append(
                SymbolChange(name=name, change="removed", security_relevant=relevant, hint=hint)
            )
        report.symbol_changes.sort(
            key=lambda s: (not s.security_relevant, s.change, s.name)
        )

        # --- CVE relevance for changed subsystems --------------------------
        affected_subsystems: Set[str] = set()
        for change in report.config_changes:
            if not change.security_relevant:
                continue
            mapping = {
                "DEVMEM": "core-mm-mem",
                "KALLSYMS": "core-symbols",
                "SECURITY_SELINUX": "core-mac-selinux",
                "SECURITY_APPARMOR": "core-mac-apparmor",
                "LKDTM": "core-debug-lkdtm",
                "STAGING": "core-staging",
                "BPF_SYSCALL": "ebpf-verifier",
                "BPF_JIT": "ebpf-verifier",
                "UNPRIVILEGED_BPF": "ebpf-verifier",
                "MODULES": "core-modules",
                "MODULE_SIG_FORCE": "core-modules",
                "MODULE_FORCE_LOAD": "core-modules",
                "ANDROID_BINDER_IPC": "binder-ipc",
                "ANDROID_BINDERFS": "binder-ipc",
                "ION": "ion-dmabuf",
                "DMABUF_HEAPS": "ion-dmabuf",
                "XFRM": "core-net-route",
                "NETFILTER": "core-net-filter",
                "TUN": "core-net-tun",
            }
            subsystem = mapping.get(change.name)
            if subsystem:
                affected_subsystems.add(subsystem)

        if affected_subsystems:
            series = after.kernel_series
            for subsystem in sorted(affected_subsystems):
                for entry in self.kb.by_subsystem(subsystem):
                    if entry.covers_series(series):
                        report.cve_notes.append(
                            CVENote(
                                cve_id=entry.cve_id,
                                subsystem=entry.subsystem,
                                title=entry.title,
                                reason=f"kernel config surface '{subsystem}' changed between builds; "
                                       f"series {series[0]}.{series[1]} is within the documented "
                                       f"affected range {entry.affected_range}",
                                reference=entry.reference,
                            )
                        )
        # dedupe CVE notes
        seen: Set[str] = set()
        deduped: List[CVENote] = []
        for note in report.cve_notes:
            key = (note.cve_id, note.subsystem)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(note)
        report.cve_notes = deduped

        # --- summary --------------------------------------------------------
        security_config = [c for c in report.config_changes if c.security_relevant]
        security_symbols = [s for s in report.symbol_changes if s.security_relevant]
        report.summary = {
            "config_changes_total": len(report.config_changes),
            "config_changes_security_relevant": len(security_config),
            "symbol_changes_total": len(report.symbol_changes),
            "symbol_changes_security_relevant": len(security_symbols),
            "cve_notes": len(report.cve_notes),
            "version_changed": report.version_changed,
            "series_changed": report.series_changed,
            "risk_direction": _risk_direction(security_config, security_symbols),
        }
        return report


def _risk_direction(config_changes: List[ConfigChange],
                    symbol_changes: List[SymbolChange]) -> str:
    if not config_changes and not symbol_changes:
        return "unchanged"
    signals = 0
    for c in config_changes:
        if c.name in {"DEVMEM", "KALLSYMS_ALL", "LKDTM",
                      "MODULE_FORCE_LOAD", "CONFIG_SECURITY_SELINUX"}:
            signals += 1
    for s in symbol_changes:
        if s.change == "added" and s.security_relevant:
            signals += 1
    if signals >= 3:
        return "increased_attack_surface"
    if signals >= 1:
        return "notable_change"
    return "minor_change"


# --------------------------------------------------------------------------- #
# Report rendering                                                            #
# --------------------------------------------------------------------------- #


def render_markdown(report: DiffReport) -> str:
    lines: List[str] = [
        "# Kernel Diff Report",
        "",
        f"**Schema:** `kx-kernel-diff/1.0`  ·  **Generated:** {report.generated_at}",
        "",
        "## Summary",
        "",
        "| Field | Before | After |",
        "|---|---|---|",
        f"| Kernel version | `{report.before.kernel_version or 'n/a'}` | `{report.after.kernel_version or 'n/a'}` |",
        f"| Kernel series | {report.before.kernel_series[0]}.{report.before.kernel_series[1]} | "
        f"{report.after.kernel_series[0]}.{report.after.kernel_series[1]} |",
        f"| Config symbols | {len(report.before.config)} | {len(report.after.config)} |",
        f"| Kernel symbols | {report.before.symbol_count} | {report.after.symbol_count} |",
        "",
        f"- Version changed: **{report.version_changed}**",
        f"- Series changed: **{report.series_changed}**",
        f"- Config changes: {report.summary['config_changes_total']} "
        f"({report.summary['config_changes_security_relevant']} security-relevant)",
        f"- Symbol changes: {report.summary['symbol_changes_total']} "
        f"({report.summary['symbol_changes_security_relevant']} security-relevant)",
        f"- CVE-relevant notes: {report.summary['cve_notes']}",
        f"- Risk direction: **{report.summary['risk_direction']}**",
        "",
    ]

    sec_config = [c for c in report.config_changes if c.security_relevant]
    other_config = [c for c in report.config_changes if not c.security_relevant]
    if sec_config:
        lines += ["## 1. Security-Relevant Config Changes", ""]
        lines += ["| Config | Before | After | Note |", "|---|---|---|---|"]
        for c in sec_config:
            lines.append(
                f"| `{c.name}` | `{c.before or 'unset'}` | `{c.after or 'unset'}` | {c.note} |"
            )
        lines += [""]
    if other_config:
        lines += ["### 1.1 Other config changes", ""]
        for c in other_config[:30]:
            lines.append(
                f"- `{c.name}`: `{c.before or 'unset'}` → `{c.after or 'unset'}` ({c.note})"
            )
        if len(other_config) > 30:
            lines.append(f"- … and {len(other_config) - 30} more")
        lines += [""]

    sec_symbols = [s for s in report.symbol_changes if s.security_relevant]
    other_symbols = [s for s in report.symbol_changes if not s.security_relevant]
    if sec_symbols:
        lines += ["## 2. Security-Relevant Symbol Changes", ""]
        lines += ["| Symbol | Change | Hint |", "|---|---|---|"]
        for s in sec_symbols:
            lines.append(f"| `{s.name}` | {s.change} | {s.hint} |")
        lines += [""]
    if other_symbols:
        lines += [f"### 2.1 Other symbol changes ({len(other_symbols)})", ""]
        for s in other_symbols[:20]:
            lines.append(f"- `{s.name}` ({s.change})")
        if len(other_symbols) > 20:
            lines.append(f"- … and {len(other_symbols) - 20} more")
        lines += [""]

    if report.cve_notes:
        lines += ["## 3. CVE Relevance (changed subsystems)", ""]
        lines += ["| CVE | Subsystem | Title | Reference |", "|---|---|---|---|"]
        for note in report.cve_notes:
            lines.append(
                f"| [{note.cve_id}]({note.reference}) | `{note.subsystem}` | "
                f"{note.title} | {note.reference} |"
            )
        lines += [""]

    lines += [
        "## Methodology & Scope",
        "",
        "This diff compares static, read-only captures of kernel build artifacts "
        "(version string, kconfig, symbol table).  It does **not** inspect a live "
        "kernel, does not open `/dev/mem` or `/dev/kcore`, and does not determine "
        "whether any specific vulnerability is exploitable.  CVE notes are "
        "correlation hints: a changed config puts a documented advisory's "
        "affected-subsystem surface in scope for manual verification against the "
        "vendor changelog.",
        "",
        "---",
        "",
        "*Generated by Kernel-X GKI / Vendor Kernel Diff Analyzer (educational, "
        "read-only).*",
    ]
    return "\n".join(lines) + "\n"


def render_json(report: DiffReport) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True, default=str)


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="GKI / Vendor Kernel Diff Analyzer (read-only, educational)"
    )
    parser.add_argument("before", help="snapshot directory for the earlier build")
    parser.add_argument("after", help="snapshot directory for the later build")
    parser.add_argument("--out", default=None, help="write Markdown report to this path")
    parser.add_argument("--json-out", default=None, help="write JSON report to this path")
    parser.add_argument("--kb", default=None, help="override knowledge base bundle path")
    args = parser.parse_args(argv)

    if args.kb:
        kb = OfflineKnowledgeBase(bundle_path=args.kb)
    else:
        kb = DEFAULT_KNOWLEDGE_BASE

    before = capture_snapshot(args.before)
    after = capture_snapshot(args.after)
    report = KernelDiffAnalyzer(knowledge_base=kb).diff(before, after)

    md = render_markdown(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(md)
        print(f"Markdown report written to {args.out}")
    else:
        print(md)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(render_json(report))
        print(f"JSON report written to {args.json_out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
