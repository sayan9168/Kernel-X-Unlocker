#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel_x.selinux_flow
=====================

SELinux context-flow read-only analyzer
=======================================

This module inspects SELinux state **without touching any device**:

  * Reads ``/sys/fs/selinux`` (enforce mode, policy version, commit id) and
    the context files exposed there (``file_contexts``, ``genfs_contexts``,
    ``property_contexts`` ...), strictly read-only.
  * Maps a list of filesystem paths to their effective SELinux type using
    longest-regex-prefix matching (same semantics as libsematch).
  * Optionally parses a caller-provided domain-transition text file
    (``source target executable`` per line) and builds a flow graph, then
    reports reachable domains and over-broad transitions (e.g. a shell-like
    domain reaching media domains).
  * Emits JSON-safe findings with an informational severity rating.

No policy is ever modified, loaded, or enforced by this code. On hosts without
SELinux sysfs (most desktops) the analyzer degrades gracefully and reports
``selinux_available: false``.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("kernel_x.selinux_flow")

_CONTEXT_RE = re.compile(r"^([^:]+):([^:]+):([^:]+)(?::([^:]+))?$")
# file_context line: "<path regex> <context>"
_FILE_CONTEXT_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s*$")
_TRANSITION_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s*$")

_SELINUX_SYSFS = "/sys/fs/selinux"
_SELINUX_CONTEXT_DIR = os.path.join(_SELINUX_SYSFS, "context")


@dataclass(slots=True)
class PathContext:
    path: str
    matched_regex: Optional[str]
    context: Optional[str]  # "user:role:type:range" or None
    type: Optional[str]     # third field of context


@dataclass(slots=True)
class Finding:
    severity: str   # informational | advisory
    title: str
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"severity": self.severity, "title": self.title,
                "detail": self.detail}


# --------------------------------------------------------------------------- #
# Analyzer                                                                    #
# --------------------------------------------------------------------------- #


class SelinuxFlowAnalyzer:
    """Read-only SELinux context and flow inspector."""

    def __init__(self, sysfs_dir: str = _SELINUX_SYSFS) -> None:
        self.sysfs_dir = sysfs_dir
        self.available = False
        self.enforce: Optional[int] = None
        self.policy_version: Optional[int] = None
        self.commit: Optional[str] = None
        self.file_contexts: List[Tuple[str, str]] = []  # (regex, context)
        self.genfs_contexts: List[Tuple[str, str]] = []
        self.property_contexts: List[Tuple[str, str]] = []
        self._load_sysfs()

    # -- sysfs (read only) ----------------------------------------------------

    def _read_sysfs_file(self, name: str) -> Optional[str]:
        path = os.path.join(self.sysfs_dir, name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()
        except OSError:
            return None

    def _load_sysfs(self) -> None:
        if not os.path.isdir(self.sysfs_dir):
            logger.info("SELinux sysfs not present at %s", self.sysfs_dir)
            return
        enforce = self._read_sysfs_file("enforce")
        if enforce is not None:
            try:
                self.enforce = int(enforce)
            except ValueError:
                self.enforce = None
        pv = self._read_sysfs_file("policyvers")
        if pv is not None:
            try:
                self.policy_version = int(pv)
            except ValueError:
                self.policy_version = None
        self.commit = self._read_sysfs_file("commit")
        self.available = True

        ctx_dir = _SELINUX_CONTEXT_DIR if self.sysfs_dir == _SELINUX_SYSFS \
            else os.path.join(self.sysfs_dir, "context")
        if os.path.isdir(ctx_dir):
            for fname in ("file_contexts", "genfs_contexts",
                          "property_contexts"):
                self._load_context_file(os.path.join(ctx_dir, fname),
                                        getattr(self, fname))

    def _load_context_file(self, path: str, sink: List[Tuple[str, str]]) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _FILE_CONTEXT_LINE_RE.match(line)
            if not m:
                continue
            regex, context = m.group(1), m.group(2)
            if _CONTEXT_RE.match(context):
                sink.append((regex, context))

    # -- context resolution ---------------------------------------------------

    def resolve(self, path: str) -> PathContext:
        """Best (longest-regex) match for *path* among loaded file contexts."""
        best: Optional[Tuple[int, str, str]] = None  # (length, regex, ctx)
        for regex, context in self.file_contexts:
            try:
                if re.match(regex, path):
                    if best is None or len(regex) > best[0]:
                        best = (len(regex), regex, context)
            except re.error:
                continue
        if best is None:
            return PathContext(path, None, None, None)
        _, regex, context = best
        parts = context.split(":")
        return PathContext(path, regex, context, parts[2] if len(parts) > 2
                           else None)

    def resolve_many(self, paths: List[str]) -> List[PathContext]:
        return [self.resolve(p) for p in paths]

    # -- transition graph (optional, caller-provided) ------------------------

    def load_transitions(self, path: str) -> int:
        """
        Read an optional, caller-provided transition description file.
        Format: ``source_domain target_domain executable`` per line.
        Returns number of edges loaded. Read-only file access.
        """
        edges: List[Tuple[str, str, str]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("cannot read transitions file %s: %s", path, exc)
            return 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _TRANSITION_LINE_RE.match(line)
            if m:
                edges.append((m.group(1), m.group(2), m.group(3)))
        self._edges = edges
        return len(edges)

    def _graph(self) -> Dict[str, Set[str]]:
        graph: Dict[str, Set[str]] = {}
        for src, dst, _exe in getattr(self, "_edges", []):
            graph.setdefault(src, set()).add(dst)
        return graph

    def flow_report(self) -> Dict[str, Any]:
        graph = self._graph()
        reachable: Dict[str, Set[str]] = {}
        for src in graph:
            seen: Set[str] = set()
            stack = list(graph.get(src, ()))
            while stack:
                node = stack.pop()
                if node in seen:
                    continue
                seen.add(node)
                stack.extend(graph.get(node, ()))
            reachable[src] = seen

        findings: List[Finding] = []
        # Over-broad domains: shell/adb-ish domains reaching media/data domains.
        sensitive_targets = {
            "mediadata", "mediaserver", "mediashell", "platform_app",
            "system_app", "recovery", "rootfs", "shell_data",
        }
        for src, targets in sorted(reachable.items()):
            for t in sorted(targets):
                if t in sensitive_targets and src not in sensitive_targets:
                    findings.append(Finding(
                        "advisory",
                        f"flow {src} -> {t}",
                        f"domain {src} can transitively reach domain {t} "
                        "via domain transitions"))
        if self.enforce == 0:
            findings.append(Finding(
                "informational", "SELinux enforcing disabled",
                "enforce == 0: policy is permissive on this device"))
        if self.enforce is None and self.available:
            findings.append(Finding(
                "informational", "enforce file unreadable",
                "SELinux sysfs present but enforce status could not be read"))

        return {
            "available": self.available,
            "enforce": self.enforce,
            "enforce_mode": {0: "permissive", 1: "enforcing",
                             2: "compat"}.get(self.enforce, "unknown"),
            "policy_version": self.policy_version,
            "commit": self.commit,
            "context_rules": len(self.file_contexts),
            "genfs_rules": len(self.genfs_contexts),
            "property_rules": len(self.property_contexts),
            "transition_edges": len(getattr(self, "_edges", [])),
            "domains_with_flows": len(reachable),
            "findings": [f.as_dict() for f in findings],
        }

    # -- full report ----------------------------------------------------------

    def report(self, paths: List[str],
               transitions_path: Optional[str] = None
               ) -> Dict[str, Any]:
        if transitions_path:
            self.load_transitions(transitions_path)
        mappings = [asdict(pc) for pc in self.resolve_many(paths)]
        flow = self.flow_report()
        return {
            "schema": "kx-selinux-flow/1.0",
            "generated_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"),
            "selinux": flow,
            "path_mappings": mappings,
        }


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description="Read-only SELinux context-flow analyzer")
    ap.add_argument("--sysfs", default=_SELINUX_SYSFS,
                    help="SELinux sysfs directory to inspect (read-only)")
    ap.add_argument("--path", action="append", default=[],
                    help="path to resolve (repeatable)")
    ap.add_argument("--transitions", metavar="PATH",
                    help="optional domain-transition edge file (read-only)")
    ap.add_argument("--out", metavar="PATH",
                    help="write JSON report to this path")
    args = ap.parse_args(argv)

    analyzer = SelinuxFlowAnalyzer(sysfs_dir=args.sysfs)
    report = analyzer.report(args.path, args.transitions)
    print(json.dumps(report, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
