#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
memory_scanner_advanced.py
==========================

Educational **read-only** memory-forensics module for the Kernel-X Research
Toolkit.  It is designed to run inside a controlled laboratory on devices you
own, for studying how Android security services (``gatekeeperd``,
``keystore2``, ``vold``) lay out their anonymous mappings in RAM.

Safety contract (enforced by design)
------------------------------------
* READ-ONLY.  The module never opens any file descriptor with write intent and
  contains no code path that could modify target-process memory.
* Every read is wrapped in exception handling; a faulted /proc/<pid>/mem read
  raises ``ProcessLookupError``/``PermissionError`` which we catch and report -
  the target process is *never* signalled, attached-to with ptrace, or killed.
* A byte-scan budget and per-region cap prevent runaway CPU/IO that could
  destabilise the lab host.
* On production Android, SELinux blocks cross-domain reads of gatekeeperd /
  keystore2 memory.  That denial is itself an interesting forensic observation
  and is reported as such instead of being "worked around".
* Findings are *structural indicators only* (region sizes, entropy profiles,
  signature matches against well-known key-schedule magic numbers).  The
  module deliberately does NOT dump, export, reconstruct or print raw bytes
  that could constitute key material.

JSON output
-----------
``scan_memory_patterns(target_pid)`` returns a plain ``dict``; call
``json.dumps(result)`` or use ``--json-out`` on the CLI to feed the dashboard.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import platform
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover - lab hosts without psutil
    psutil = None  # type: ignore
    PSUTIL_AVAILABLE = False

logger = logging.getLogger("kernel_x.memory_scanner")

TOOL_VERSION = "2.1.0"
TARGET_PROCESSES = ("gatekeeperd", "keystore2", "vold")

# Default hard limits - keep the scanner gentle on lab hardware.
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024      # 64 MiB scanned per process
DEFAULT_MAX_REGION_BYTES = 8 * 1024 * 1024      # 8 MiB per single mapping
CHUNK_SIZE = 64 * 1024                          # read granularity
OVERLAP = 512                                   # overlap so signatures that
                                                  # straddle a chunk boundary
                                                  # are not missed


# ---------------------------------------------------------------------------
# Known structural signatures (PUBLIC documentation values, not secrets)
# ---------------------------------------------------------------------------
# These magic constants come from the *publicly documented* AOSP key-storage
# formats.  They let a researcher confirm where a keyring lives in a memory
# map during an exercise on a disposable lab image.  Matching one tells you
# "a metadata header exists here"; it never yields usable key material.
@dataclass(frozen=True)
class Signature:
    name: str
    description: str
    pattern: bytes
    offset: int = 0          # fixed offset within the structure, -1 = anywhere
    severity_hint: str = "info"


KNOWN_SIGNATURES: Tuple[Signature, ...] = (
    Signature(
        name="ks_keyblob_magic",
        description="KeyMint/Keystore key-blob header magic 0x4B4B4201 "
                    "(AOSP KeyBlobHeader, public constant)",
        pattern=bytes.fromhex("014b4b4b"),   # little-endian 0x4B4B4B01
        offset=-1,
        severity_hint="low",
    ),
    Signature(
        name="fbe_keymaster_blob_tag",
        description="FBE 'km' master-key blob tag used by vold system "
                    "encryption metadata (public AOSP format)",
        pattern=b"km\x00\x00",
        offset=0,
        severity_hint="low",
    ),
    Signature(
        name="fbe_dm_default_key",
        description="Legacy dm-default-key placeholder string from FBE "
                    "adoption docs (indicates inline-encryption config)",
        pattern=b"dm-default-key",
        offset=-1,
        severity_hint="info",
    ),
    Signature(
        name="gatekeeper_msg_header",
        description="Gatekeeper message header word GK_MSG_HEADER_MAGIC "
                    "(0x474b4d48, public hardware-gatekeeper interface)",
        pattern=bytes.fromhex("484d4b47"),
        offset=-1,
        severity_hint="info",
    ),
)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class RegionInfo:
    addr_start: int
    addr_end: int
    readable: bool
    writable: bool
    executable: bool
    path: str
    size: int

    @property
    def anon(self) -> bool:
        return self.path.startswith("[") or self.path == ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "addr_start": f"0x{self.addr_start:x}",
            "addr_end": f"0x{self.addr_end:x}",
            "size_bytes": self.size,
            "perms": "".join([
                "r" if self.readable else "-",
                "w" if self.writable else "-",
                "x" if self.executable else "-",
            ]),
            "path": self.path or "[anon]",
            "anonymous": self.anon,
        }


@dataclass
class ScanResult:
    pid: int
    process_name: str
    status: str = "ok"                 # ok | denied | error | skipped
    error: Optional[str] = None
    regions_total: int = 0
    regions_scanned: int = 0
    bytes_scanned: int = 0
    truncated: bool = False
    high_entropy_regions: List[Dict[str, Any]] = field(default_factory=list)
    signature_hits: List[Dict[str, Any]] = field(default_factory=list)
    region_map: List[Dict[str, Any]] = field(default_factory=list)
    started_utc: str = ""
    finished_utc: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "status": self.status,
            "error": self.error,
            "regions_total": self.regions_total,
            "regions_scanned": self.regions_scanned,
            "bytes_scanned": self.bytes_scanned,
            "truncated_by_budget": self.truncated,
            "high_entropy_regions": self.high_entropy_regions,
            "signature_hits": self.signature_hits,
            "region_map": self.region_map,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Normalised Shannon entropy in [0, 1]. Cheap and dependency-free."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return ent / 8.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_android() -> bool:
    rel = platform.release().lower()
    machine = platform.machine().lower()
    return "android" in rel or machine in ("arm64", "aarch64") and \
        os.path.exists("/system/bin")


def get_platform_notes() -> Dict[str, Any]:
    """Platform-specific context that affects what a safe scan can observe."""
    notes: Dict[str, Any] = {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "psutil_available": PSUTIL_AVAILABLE,
        "euid": os.geteuid() if hasattr(os, "geteuid") else -1,
    }
    if is_android():
        notes["platform"] = "android"
        notes["ptrace_scope_note"] = (
            "Android SELinux domains (plat_sepolicy) deny cross-domain "
            "ptrace/mem reads of gatekeeperd & keystore2 even for root in "
            "enforcing mode; denials surface as EPERM and are reported."
        )
    elif notes["os"] == "Linux":
        notes["platform"] = "linux"
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r",
                      encoding="utf-8") as fh:
                notes["yama_ptrace_scope"] = fh.read().strip()
        except OSError:
            notes["yama_ptrace_scope"] = "n/a"
    else:
        notes["platform"] = notes["os"].lower()
    return notes


def find_target_pids(names: Iterable[str] = TARGET_PROCESSES) -> List[Tuple[int, str]]:
    """Locate candidate security-service PIDs using psutil when available."""
    found: List[Tuple[int, int, str]] = []
    wanted = tuple(n.lower() for n in names)
    try:
        if PSUTIL_AVAILABLE:
            for proc in psutil.process_iter(["pid", "name", "username",
                                            "create_time"]):
                try:
                    nm = (proc.info["name"] or "").lower()
                    if any(w in nm for w in wanted):
                        found.append((proc.info["pid"],
                                      proc.info["create_time"], nm))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        else:  # fallback: walk /proc without psutil
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/comm", "r",
                              encoding="utf-8", errors="replace") as fh:
                        nm = fh.read().strip().lower()
                    if any(w in nm for w in wanted):
                        st = os.stat(f"/proc/{entry}")
                        found.append((int(entry), st.st_mtime, nm))
                except OSError:
                    continue
    except OSError as exc:  # /proc missing (non-Linux) - nothing to find
        logger.warning("process enumeration unavailable: %s", exc)
    # de-dup, prefer newest instance
    dedup = {pid: (pid, ct, nm) for pid, ct, nm in found}
    ordered = sorted(dedup.values(), key=lambda t: t[1], reverse=True)
    return [(pid, nm) for pid, _ct, nm in ordered]


# ---------------------------------------------------------------------------
# Core scanning logic (READ-ONLY)
# ---------------------------------------------------------------------------

_MAPS_LINE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+([r\-])([w\-])([x\-])([p\-])\s+"
    r"[0-9a-f]+:[0-9a-f]+\s+\d+(?:\s+(.*))?$"
)


def _enumerate_regions(pid: int) -> List[RegionInfo]:
    """Parse /proc/<pid>/maps into RegionInfo records (metadata only)."""
    regions: List[RegionInfo] = []
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _MAPS_LINE.match(line.strip())
                if not m:
                    continue
                start, end = int(m.group(1), 16), int(m.group(2), 16)
                regions.append(RegionInfo(
                    addr_start=start,
                    addr_end=end,
                    readable=m.group(3) == "r",
                    writable=m.group(4) == "w",
                    executable=m.group(5) == "x",
                    path=(m.group(7) or "").strip(),
                    size=end - start,
                ))
    except FileNotFoundError:
        raise ProcessLookupError(f"pid {pid} has no {maps_path}")
    except PermissionError as exc:
        raise PermissionError(
            f"cannot read {maps_path}: {exc} "
            "(SELinux denial or Yama ptrace_scope on target)") from exc
    return regions


def _safe_read_mem(fd: int, addr: int, length: int) -> Optional[bytes]:
    """Read `length` bytes at `addr`; return None on any kernel-level fault."""
    try:
        os.lseek(fd, addr, os.SEEK_SET)
        data = os.read(fd, length)
        return data if data else None
    except (OSError, ValueError, OverflowError) as exc:
        logger.debug("read fault @0x%x (%s) - skipping range safely",
                     addr, exc.__class__.__name__)
        return None


def _scan_region(fd: int, region: RegionInfo, budget_left: int,
                 result: ScanResult) -> int:
    """Scan one readable region. Returns bytes consumed from the budget."""
    consume = min(region.size, DEFAULT_MAX_REGION_BYTES, max(budget_left, 0))
    if consume <= 0:
        return 0

    entropy_samples: List[float] = []
    consumed = 0
    addr = region.addr_start
    end = region.addr_start + consume
    while addr < end:
        want = min(CHUNK_SIZE, end - addr)
        data = _safe_read_mem(fd, addr, want + (OVERLAP if addr + want < end else 0))
        if data is None:
            break  # unmapped/faulted page - stop this region, stay safe
        consumed += len(data)

        entropy_samples.append(shannon_entropy(data))
        _check_signatures(region, addr, data, result)

        addr += want

    result.bytes_scanned += consumed
    # Anonymous rw mappings with sustained high entropy are the classic
    # forensic indicator of buffers holding random/key-like material.
    if (region.anon and region.writable and not region.executable
            and entropy_samples
            and sum(entropy_samples) / len(entropy_samples) > 0.85):
        result.high_entropy_regions.append({
            "addr_start": f"0x{region.addr_start:x}",
            "addr_end": f"0x{region.addr_end:x}",
            "size_bytes": region.size,
            "mean_entropy": round(sum(entropy_samples) / len(entropy_samples), 4),
            "note": ("High-entropy anonymous writable mapping. Structural "
                     "indicator only; content was NOT exported."),
        })
    return consumed


def _check_signatures(region: RegionInfo, chunk_addr: int, data: bytes,
                      result: ScanResult) -> None:
    for sig in KNOWN_SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig.pattern, start)
            if idx < 0:
                break
            if sig.offset >= 0 and idx != sig.offset:
                start = idx + 1
                continue
            hit_addr = chunk_addr + idx
            # de-duplicate hits inside the same region
            if not any(h["address"] == f"0x{hit_addr:x}" and
                       h["signature"] == sig.name for h in result.signature_hits):
                result.signature_hits.append({
                    "signature": sig.name,
                    "description": sig.description,
                    "address": f"0x{hit_addr:x}",
                    "region": region.path or "[anon]",
                    "severity_hint": sig.severity_hint,
                    "note": "Public-format header match; no key material "
                            "extracted or displayed.",
                })
            start = idx + 1


def scan_memory_patterns(target_pid: int,
                         process_name: Optional[str] = None,
                         max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES) -> Dict[str, Any]:
    """
    Read-only forensic sweep of one process's memory map.

    Searches readable mappings for the *public* structural signatures above
    and flags high-entropy anonymous regions. Never writes, injects, signals
    or attaches to the target. All failure modes degrade gracefully into the
    returned JSON-safe dict.

    :param target_pid: PID of a process owned by the lab operator.
    :returns: JSON-serialisable scan report.
    """
    result = ScanResult(
        pid=int(target_pid),
        process_name=process_name or f"pid-{target_pid}",
        started_utc=_now_iso(),
    )
    mem_path = f"/proc/{target_pid}/mem"

    try:
        regions = _enumerate_regions(int(target_pid))
    except ProcessLookupError as exc:
        result.status, result.error = "error", str(exc)
        result.finished_utc = _now_iso()
        return result.to_dict()
    except PermissionError as exc:
        result.status, result.error = "denied", str(exc)
        result.finished_utc = _now_iso()
        return result.to_dict()
    except Exception as exc:  # defensive: never propagate unexpected faults
        logger.exception("unexpected failure enumerating regions")
        result.status, result.error = "error", f"{type(exc).__name__}: {exc}"
        result.finished_utc = _now_iso()
        return result.to_dict()

    result.regions_total = len(regions)
    result.region_map = [r.to_dict() for r in regions][:200]  # bounded output

    readable = [r for r in regions if r.readable]
    fd = -1
    try:
        # O_RDONLY is critical: the kernel will refuse anything else for
        # /proc/pid/mem, guaranteeing this tool cannot write by construction.
        fd = os.open(mem_path, os.O_RDONLY)
    except FileNotFoundError:
        result.status, result.error = "error", f"{mem_path} missing (unsupported OS?)"
    except PermissionError as exc:
        result.status, result.error = "denied", (
            f"cannot open {mem_path}: {exc}. On Android this is an expected "
            "SELinux denial for gatekeeperd/keystore2 in enforcing mode.")
    except OSError as exc:
        result.status, result.error = "error", f"open failed: {exc}"

    budget = max_total_bytes
    if fd >= 0:
        try:
            for region in readable:
                if budget <= 0:
                    result.truncated = True
                    break
                used = _scan_region(fd, region, budget, result)
                budget -= used
                result.regions_scanned += 1
        except Exception as exc:  # final safety net around the hot loop
            logger.exception("scan aborted; returning partial results")
            result.error = f"partial scan, aborted with {type(exc).__name__}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    result.finished_utc = _now_iso()
    return result.to_dict()


def scan_all_targets(max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES) -> Dict[str, Any]:
    """Convenience sweep over every discovered gatekeeperd/keystore2/vold PID."""
    report: Dict[str, Any] = {
        "tool": "memory_scanner_advanced",
        "version": TOOL_VERSION,
        "mode": "read-only-forensic",
        "generated_utc": _now_iso(),
        "platform": get_platform_notes(),
        "targets": [],
        "summary": {"scanned": 0, "denied": 0, "errors": 0,
                    "signature_hits": 0, "high_entropy_regions": 0},
    }
    targets = find_target_pids()
    if not targets:
        report["note"] = ("No gatekeeperd/keystore2/vold processes found - "
                          "expected on non-Android lab hosts. Run against a "
                          "permitted local test process instead.")
    for pid, name in targets:
        res = scan_memory_patterns(pid, name, max_total_bytes)
        report["targets"].append(res)
        s = report["summary"]
        if res["status"] == "ok":
            s["scanned"] += 1
        elif res["status"] == "denied":
            s["denied"] += 1
        else:
            s["errors"] += 1
        s["signature_hits"] += len(res["signature_hits"])
        s["high_entropy_regions"] += len(res["high_entropy_regions"])
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only educational memory forensics scanner "
                    "(lab use on owned devices only).")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--pid", type=int, help="scan a single specific PID")
    group.add_argument("--all", action="store_true",
                       help="auto-discover gatekeeperd/keystore2/vold PIDs")
    parser.add_argument("--json-out", metavar="FILE",
                        help="write the JSON report to FILE")
    parser.add_argument("--budget-mib", type=int, default=64,
                        help="max MiB to scan per process (default 64)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.budget_mib <= 0 or args.budget_mib > 512:
        print("[!] Budget must be between 1 and 512 MiB - refusing to run "
              "with unsafe parameters.", file=sys.stderr)
        return 2

    budget = args.budget_mib * 1024 * 1024
    if args.pid is not None:
        report: Dict[str, Any] = {
            "tool": "memory_scanner_advanced",
            "version": TOOL_VERSION,
            "mode": "read-only-forensic",
            "generated_utc": _now_iso(),
            "platform": get_platform_notes(),
            "targets": [scan_memory_patterns(args.pid,
                                             max_total_bytes=budget)],
        }
    else:
        report = scan_all_targets(max_total_bytes=budget)

    text = json.dumps(report, indent=2)
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print(f"[+] JSON report written to {args.json_out}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)
            return 1
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
