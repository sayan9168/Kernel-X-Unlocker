#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel_x.multi_device
=====================

Multi-device parallel analysis (read-only)
==========================================

Runs the same read-only analyzer across many device snapshot directories in
parallel (thread pool), isolating per-device failures so one bad snapshot
never aborts the whole session.

Design constraints:

  * Analyzers are plain callables ``analyzer(device_id, snapshot_dir)`` that
    return JSON-safe dicts. The runner passes paths only; analyzers must open
    files read-only (no /dev/mem, no ptrace, no device ioctls).
  * Every device result is captured separately: exceptions become structured
    error entries instead of crashing the pool.
  * Output is a JSON-safe :class:`MultiSessionReport` suitable for the
    dashboard/reporter.

Use case example: feed each device's captured proc/config/kallsyms snapshots
to :mod:`kernel_x.kernel_diff` diffing against a reference build, or run the
compatibility analyzer across a fleet of lab devices.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("kernel_x.multi_device")

# A built-in, trivially read-only analyzer: SHA-256 of every file in a
# snapshot directory (a "snapshot fingerprint", useful for diff sessions).
SNAPSHOT_ANALYZER = "snapshot_hash"


@dataclass(slots=True)
class DeviceSpec:
    device_id: str
    snapshot_dir: str
    tags: List[str] = field(default_factory=list)


@dataclass(slots=True)
class DeviceResult:
    device_id: str
    ok: bool
    analyzer: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MultiSessionReport:
    schema: str = "kx-multi-device/1.0"
    generated_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(
            timespec="seconds"))
    devices: int = 0
    max_workers: int = 0
    succeeded: int = 0
    failed: int = 0
    results: List[DeviceResult] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "generated_utc": self.generated_utc,
            "devices": self.devices,
            "max_workers": self.max_workers,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "results": [r.as_dict() for r in self.results],
        }


def _default_analyzer(device_id: str,
                      snapshot_dir: str) -> Dict[str, Any]:
    """Built-in snapshot fingerprint: hash every file read-only."""
    if not os.path.isdir(snapshot_dir):
        raise FileNotFoundError(f"snapshot dir missing: {snapshot_dir}")
    files: List[Dict[str, str]] = []
    for root, _dirs, names in os.walk(snapshot_dir):
        for name in sorted(names):
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                size = os.path.getsize(path)
            except OSError as exc:
                digest = f"ERROR: {exc}"
                size = -1
            files.append({"path": os.path.relpath(path, snapshot_dir),
                          "sha256": digest, "size_bytes": str(size)})
    files.sort(key=lambda f: f["path"])
    return {"file_count": len(files), "files": files}


class MultiDeviceRunner:
    """Execute one analyzer across many device snapshots in parallel."""

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max(1, max_workers)

    # -- execution -----------------------------------------------------------

    def run_all(self,
                devices: List[DeviceSpec],
                analyzer: Callable[[str, str], Dict[str, Any]]
                ) -> MultiSessionReport:
        report = MultiSessionReport(
            devices=len(devices), max_workers=self.max_workers)
        if not devices:
            return report

        def task(spec: DeviceSpec) -> DeviceResult:
            import time
            start = datetime.now(timezone.utc)
            try:
                result = analyzer(spec.device_id, spec.snapshot_dir)
                if not isinstance(result, dict):
                    raise TypeError("analyzer must return a dict")
                end = datetime.now(timezone.utc)
                return DeviceResult(
                    spec.device_id, True, "callable", result=result,
                    error=None,
                    duration_ms=(end - start).total_seconds() * 1000.0)
            except Exception as exc:  # isolate per device
                end = datetime.now(timezone.utc)
                logger.warning("device %s failed: %s", spec.device_id, exc)
                return DeviceResult(
                    spec.device_id, False, "callable",
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=(end - start).total_seconds() * 1000.0)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(task, s): s.device_id for s in devices}
            for fut in as_completed(futures):
                res = fut.result()
                report.results.append(res)
                if res.ok:
                    report.succeeded += 1
                else:
                    report.failed += 1

        report.results.sort(key=lambda r: r.device_id)
        return report

    def run_builtin(self,
                    devices: List[DeviceSpec],
                    analyzer: str = SNAPSHOT_ANALYZER
                    ) -> MultiSessionReport:
        if analyzer == SNAPSHOT_ANALYZER:
            return self.run_all(devices, _default_analyzer)
        raise ValueError(f"unknown built-in analyzer: {analyzer}")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def parse_device_specs(specs: List[str]) -> List[DeviceSpec]:
    """Parse ``id:path`` strings into DeviceSpecs (tags after '@' optional)."""
    out: List[DeviceSpec] = []
    for spec in specs:
        tags: List[str] = []
        if "@" in spec:
            spec, tag_part = spec.rsplit("@", 1)
            tags = [t.strip() for t in tag_part.split(",") if t.strip()]
        if ":" not in spec:
            raise ValueError(f"invalid device spec '{spec}' (use id:path)")
        device_id, path = spec.split(":", 1)
        out.append(DeviceSpec(device_id=device_id.strip(),
                              snapshot_dir=path.strip(), tags=tags))
    return out


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description="Parallel read-only analysis across device snapshots")
    ap.add_argument("--device", action="append", default=[],
                    help="device spec 'id:path' (repeatable; '@tags' optional)")
    ap.add_argument("--analyzer", default=SNAPSHOT_ANALYZER,
                    help=f"analyzer name (built-in: {SNAPSHOT_ANALYZER})")
    ap.add_argument("--max-workers", type=int, default=4)
    ap.add_argument("--out", metavar="PATH",
                    help="write JSON report to this path")
    args = ap.parse_args(argv)

    try:
        devices = parse_device_specs(args.device)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    runner = MultiDeviceRunner(max_workers=args.max_workers)
    report = runner.run_builtin(devices, args.analyzer)
    print(json.dumps(report.as_dict(), indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report.as_dict(), fh, indent=2)
        print(f"[+] report written to {args.out}")
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
