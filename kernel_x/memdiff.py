#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel_x.memdiff
================

Read-only memory-dump comparison (defensive forensics aid)
==========================================================

This module compares two *memory dump files* that a researcher already holds
(e.g. captured from authorized lab VMs or emergency-dump files). It never
touches live kernel memory: no /dev/mem, /dev/kmem, /proc/kcore, ptrace, or
any device interface is accessed.

Outputs (all JSON-safe):

  * page-level change set: 4 KiB pages hashed with SHA-256; pages present in
    only one dump, pages that changed, and identical pages,
  * byte-frequency profile distance (L1 over 256 buckets),
  * Shannon-entropy distribution per dump (to spot packed/encrypted regions),
  * printable-string set diff (strings appearing in only one dump),
  * a compact JSON report plus an optional Markdown rendering.

This is a diffing/auditing primitive, not a vulnerability scanner: no
signatures, no exploitation, no credential extraction.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("kernel_x.memdiff")

PAGE_SIZE = 4096
_PRINTABLE = set(bytes(range(0x20, 0x7f)).decode("ascii") + "\t\n\r")
_STRING_MIN_LEN = 6


@dataclass(slots=True)
class PageStat:
    index: int
    offset: int
    sha256: str
    entropy: float
    size: int

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DiffReport:
    path_a: str
    path_b: str
    size_a: int
    size_b: int
    pages_a: int
    pages_b: int
    pages_identical: int
    pages_changed: int
    pages_only_a: int
    pages_only_b: int
    changed_pages: List[PageStat] = field(default_factory=list)
    only_a_pages: List[PageStat] = field(default_factory=list)
    only_b_pages: List[PageStat] = field(default_factory=list)
    entropy_a: List[float] = field(default_factory=list)
    entropy_b: List[float] = field(default_factory=list)
    strings_only_a: List[str] = field(default_factory=list)
    strings_only_b: List[str] = field(default_factory=list)
    strings_common: int = 0
    byte_profile_distance: float = 0.0
    generated_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(
            timespec="seconds"))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path_a": self.path_a,
            "path_b": self.path_b,
            "size_a": self.size_a,
            "size_b": self.size_b,
            "pages_a": self.pages_a,
            "pages_b": self.pages_b,
            "pages_identical": self.pages_identical,
            "pages_changed": self.pages_changed,
            "pages_only_a": self.pages_only_a,
            "pages_only_b": self.pages_only_b,
            "changed_pages": [p.as_dict() for p in self.changed_pages],
            "only_a_pages": [p.as_dict() for p in self.only_a_pages],
            "only_b_pages": [p.as_dict() for p in self.only_b_pages],
            "entropy_a": self.entropy_a,
            "entropy_b": self.entropy_b,
            "strings_only_a": self.strings_only_a,
            "strings_only_b": self.strings_only_b,
            "strings_common": self.strings_common,
            "byte_profile_distance": self.byte_profile_distance,
            "generated_utc": self.generated_utc,
        }


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = uniform constant, 8 = max)."""
    if not data:
        return 0.0
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _byte_profile(data: bytes) -> List[int]:
    prof = [0] * 256
    for b in data:
        prof[b] += 1
    n = len(data) or 1
    return [c / n for c in prof]


def _l1_distance(a: List[float], b: List[float]) -> float:
    return sum(abs(x - y) for x, y in zip(a, b))


def _strings(data: bytes, min_len: int = _STRING_MIN_LEN) -> Set[str]:
    out: Set[str] = set()
    current: List[str] = []
    for b in data:
        ch = chr(b)
        if ch in _PRINTABLE:
            current.append(ch)
        else:
            if len(current) >= min_len:
                out.add("".join(current))
            current = []
    if len(current) >= min_len:
        out.add("".join(current))
    return out


def _read_pages(path: str) -> Tuple[int, Dict[str, PageStat], List[float]]:
    """Read *path* once; return (size, {sha256: PageStat}, entropy per page)."""
    pages: Dict[str, PageStat] = {}
    entropies: List[float] = []
    size = 0
    index = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(PAGE_SIZE)
            if not chunk:
                break
            offset = index * PAGE_SIZE
            size += len(chunk)
            digest = _sha256(chunk)
            ent = _entropy(chunk)
            entropies.append(ent)
            # First occurrence wins; later identical pages share the digest.
            pages.setdefault(digest, PageStat(index, offset, digest, ent,
                                              len(chunk)))
            index += 1
    return size, pages, entropies


# --------------------------------------------------------------------------- #
# Analyzer                                                                    #
# --------------------------------------------------------------------------- #

class MemoryDumpDiff:
    """Compare two dump files without touching any live memory interface."""

    def __init__(self, max_strings: int = 200) -> None:
        self.max_strings = max_strings

    def diff(self, path_a: str, path_b: str) -> DiffReport:
        size_a, pages_a, ent_a = _read_pages(path_a)
        size_b, pages_b, ent_b = _read_pages(path_b)

        digest_a = set(pages_a)
        digest_b = set(pages_b)
        common = digest_a & digest_b

        changed_pages: List[PageStat] = []
        # Same offset, different digest -> content changed at that offset.
        offset_a: Dict[int, PageStat] = {}
        offset_b: Dict[int, PageStat] = {}
        for ps in pages_a.values():
            offset_a[ps.index] = ps
        for ps in pages_b.values():
            offset_b[ps.index] = ps
        for idx in sorted(set(offset_a) & set(offset_b)):
            pa, pb = offset_a[idx], offset_b[idx]
            if pa.sha256 != pb.sha256:
                changed_pages.append(PageStat(
                    idx, pa.offset, pb.sha256, pb.entropy, pb.size))

        report = DiffReport(
            path_a=os.path.abspath(path_a),
            path_b=os.path.abspath(path_b),
            size_a=size_a,
            size_b=size_b,
            pages_a=(size_a + PAGE_SIZE - 1) // PAGE_SIZE,
            pages_b=(size_b + PAGE_SIZE - 1) // PAGE_SIZE,
            pages_identical=len(common),
            pages_changed=len(changed_pages),
            pages_only_a=len(digest_a - digest_b),
            pages_only_b=len(digest_b - digest_a),
            changed_pages=[pages_b[p.sha256] for p in changed_pages
                           if p.sha256 in pages_b][:50],
            only_a_pages=list({ps.sha256: ps for ps in pages_a.values()
                               if ps.sha256 not in common}.values())[:50],
            only_b_pages=list({ps.sha256: ps for ps in pages_b.values()
                               if ps.sha256 not in common}.values())[:50],
            entropy_a=ent_a,
            entropy_b=ent_b,
            byte_profile_distance=_l1_distance(
                _byte_profile(_read_whole(path_a)),
                _byte_profile(_read_whole(path_b))),
        )
        strings_a = _strings(_read_whole(path_a))
        strings_b = _strings(_read_whole(path_b))
        common_strings = strings_a & strings_b
        report.strings_only_a = sorted(strings_a - strings_b)[: self.max_strings]
        report.strings_only_b = sorted(strings_b - strings_a)[: self.max_strings]
        report.strings_common = len(common_strings)
        return report

    def render_markdown(self, report: DiffReport) -> str:
        lines = [
            "# Memory Dump Diff Report",
            "",
            f"- Schema: `kx-memdiff/1.0`",
            f"- Generated: {report.generated_utc}",
            f"- Dump A: `{report.path_a}` ({report.size_a} bytes)",
            f"- Dump B: `{report.path_b}` ({report.size_b} bytes)",
            "",
            "## Page-level comparison (4 KiB pages, SHA-256)",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Pages in A | {report.pages_a} |",
            f"| Pages in B | {report.pages_b} |",
            f"| Identical pages | {report.pages_identical} |",
            f"| Changed pages (same offset) | {report.pages_changed} |",
            f"| Pages only in A | {report.pages_only_a} |",
            f"| Pages only in B | {report.pages_only_b} |",
            "",
            "## Byte-profile distance (L1 over 256 buckets)",
            "",
            f"- Distance: {report.byte_profile_distance:.4f} "
            "(0 = identical byte distribution)",
            "",
            "## Entropy (bits/byte, per page)",
            "",
            f"- Dump A: min={min(report.entropy_a):.2f} "
            f"max={max(report.entropy_a):.2f} "
            f"mean={sum(report.entropy_a)/len(report.entropy_a):.2f}" if report.entropy_a else "- Dump A: n/a",
            f"- Dump B: min={min(report.entropy_b):.2f} "
            f"max={max(report.entropy_b):.2f} "
            f"mean={sum(report.entropy_b)/len(report.entropy_b):.2f}" if report.entropy_b else "- Dump B: n/a",
            "",
            "## Printable-string diff",
            "",
            f"- Strings common to both: {report.strings_common}",
            f"- Strings only in A (showing {len(report.strings_only_a)}):",
        ]
        for s in report.strings_only_a:
            lines.append(f"  - `{s}`")
        lines.append(f"- Strings only in B (showing {len(report.strings_only_b)}):")
        for s in report.strings_only_b:
            lines.append(f"  - `{s}`")
        lines.append("")
        lines.append("> All data derived from the provided dump files only. "
                     "No live memory interface was accessed.")
        return "\n".join(lines)


# small helper used by diff() for whole-file profiles/strings


def _read_whole(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(
        description="Read-only memory dump diff")
    ap.add_argument("dump_a")
    ap.add_argument("dump_b")
    ap.add_argument("--out", metavar="PATH",
                    help="write JSON report to this path")
    ap.add_argument("--markdown-out", metavar="PATH",
                    help="write Markdown report to this path")
    args = ap.parse_args(argv)

    diff = MemoryDumpDiff()
    report = diff.diff(args.dump_a, args.dump_b)
    print(json.dumps(report.as_dict(), indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report.as_dict(), fh, indent=2)
    if args.markdown_out:
        with open(args.markdown_out, "w", encoding="utf-8") as fh:
            fh.write(diff.render_markdown(report))
        print(f"[+] markdown report written to {args.markdown_out}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
