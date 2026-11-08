#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel_x.avb_inspector
======================

Android Verified Boot (AVB) / dm-verity read-only posture inspector
===================================================================

Inspects an *image file provided by the researcher* (boot.img, vbmeta.img,
system.img ...) for AVB structures — strictly read-only, no device contact,
no bootloader interaction:

  * AVB footer: located in the last 4096 bytes of the image; parses magic,
    version, image/vbmeta sizes, digest algorithm, salt, public-key digest
    and vbmeta digest (all bounds-checked).
  * dm-verity heuristic: scans the image head for verity-related markers
    and reports presence as *heuristic only*.
  * Posture findings are informational: algorithm strength, whether a vbmeta
    structure is referenced, etc.

This is an evidence-collection primitive for forensic/research reports. It
never flashes, never unlocks a bootloader, and never extracts keys from a
device — it only reads bytes from a file path the caller supplies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kernel_x.avb_inspector")

AVB_MAGIC = b"AVB0\0\0\0\0"
FOOTER_SIZE = 4096
# Offsets inside struct AvbFooter (little-endian)
_FOOTER_FIELDS = (
    ("version_major", 8, "<I"),
    ("version_minor", 12, "<I"),
    ("image_size", 16, "<I"),
    ("vbmeta_size", 20, "<I"),
    ("vbmeta_offset", 24, "<I"),
    ("algorithm_offset", 28, "<I"),
    ("algorithm_length", 32, "<I"),
    ("salt_offset", 36, "<Q"),
    ("salt_length", 44, "<Q"),
    ("auxiliary_offset", 52, "<Q"),
    ("auxiliary_length", 60, "<Q"),
    ("signature_offset", 68, "<Q"),
    ("signature_length", 76, "<Q"),
)

# dm-verity markers (heuristic scan, not a verified parse)
_DM_VERITY_MARKERS = (b"DMVERITY", b"dm-verity", b"verity",
                      b"ROOT_DEVICE", b"verity_mode")


@dataclass(slots=True)
class Finding:
    severity: str   # informational | advisory
    title: str
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"severity": self.severity, "title": self.title,
                "detail": self.detail}


@dataclass(slots=True)
class AvbReport:
    schema: str = "kx-avb/1.0"
    generated_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(
            timespec="seconds"))
    image: str = ""
    image_size: int = 0
    footer_present: bool = False
    footer_offset: Optional[int] = None
    version: Optional[str] = None
    algorithm: Optional[str] = None
    vbmeta_size: Optional[int] = None
    vbmeta_offset: Optional[int] = None
    salt_length: Optional[int] = None
    signature_length: Optional[int] = None
    pubkey_digest: Optional[str] = None
    vbmeta_digest: Optional[str] = None
    dm_verity_heuristic: bool = False
    findings: List[Finding] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "generated_utc": self.generated_utc,
            "image": self.image,
            "image_size": self.image_size,
            "footer_present": self.footer_present,
            "footer_offset": self.footer_offset,
            "version": self.version,
            "algorithm": self.algorithm,
            "vbmeta_size": self.vbmeta_size,
            "vbmeta_offset": self.vbmeta_offset,
            "salt_length": self.salt_length,
            "signature_length": self.signature_length,
            "pubkey_digest": self.pubkey_digest,
            "vbmeta_digest": self.vbmeta_digest,
            "dm_verity_heuristic": self.dm_verity_heuristic,
            "findings": [f.as_dict() for f in self.findings],
        }


class AvbInspector:
    """Read-only AVB/dm-verity inspector over a single image file."""

    def __init__(self, image_path: str) -> None:
        self.image_path = os.path.abspath(image_path)

    def _read_at(self, fh, offset: int, length: int) -> bytes:
        fh.seek(offset)
        return fh.read(length)

    def inspect(self) -> AvbReport:
        size = os.path.getsize(self.image_path)
        report = AvbReport(image=self.image_path, image_size=size)

        # --- heuristic dm-verity scan of the image head -------------------
        scan_len = min(size, 64 * 1024)
        with open(self.image_path, "rb") as fh:
            head = fh.read(scan_len)
        hits = [m.decode() for m in _DM_VERITY_MARKERS if m in head]
        if hits:
            report.dm_verity_heuristic = True
            report.findings.append(Finding(
                "informational", "dm-verity markers detected (heuristic)",
                f"markers in first {scan_len} bytes: {', '.join(hits)} "
                "(heuristic scan only — not a verified parse)"))

        # --- AVB footer (last 4096 bytes) ----------------------------------
        if size < FOOTER_SIZE:
            report.findings.append(Finding(
                "informational", "image smaller than AVB footer",
                f"{size} bytes < {FOOTER_SIZE}; no footer possible"))
            return report

        footer_offset = size - FOOTER_SIZE
        with open(self.image_path, "rb") as fh:
            footer = self._read_at(fh, footer_offset, FOOTER_SIZE)

        if footer[:8] != AVB_MAGIC:
            report.findings.append(Finding(
                "informational", "no AVB footer magic",
                f"last {FOOTER_SIZE} bytes do not start with the AVB0 "
                "magic — not an AVB-signed image (or footer stripped)"))
            return report

        report.footer_present = True
        report.footer_offset = footer_offset
        parsed: Dict[str, Any] = {}
        for name, off, fmt in _FOOTER_FIELDS:
            try:
                parsed[name] = struct.unpack_from(fmt, footer, off)[0]
            except struct.error:
                continue
        report.version = f"{parsed.get('version_major', '?')}.{parsed.get('version_minor', '?')}"
        report.vbmeta_size = parsed.get("vbmeta_size")
        report.vbmeta_offset = parsed.get("vbmeta_offset")
        report.salt_length = parsed.get("salt_length")
        report.signature_length = parsed.get("signature_length")

        # algorithm string
        a_off = parsed.get("algorithm_offset", 0)
        a_len = parsed.get("algorithm_length", 0)
        if 0 < a_len <= 128 and a_off + a_len <= FOOTER_SIZE:
            try:
                report.algorithm = footer[a_off:a_off + a_len].decode(
                    "ascii").rstrip("\0")
            except UnicodeDecodeError:
                report.algorithm = None

        # digests
        if len(footer) >= 148:
            report.pubkey_digest = footer[84:116].hex()
            report.vbmeta_digest = footer[116:148].hex()

        if report.algorithm:
            report.findings.append(Finding(
                "informational", "AVB digest algorithm",
                f"algorithm={report.algorithm}"))
        if report.vbmeta_size:
            report.findings.append(Finding(
                "informational", "vbmeta structure referenced",
                f"size={report.vbmeta_size} offset={report.vbmeta_offset}"))
        if not report.algorithm:
            report.findings.append(Finding(
                "advisory", "no digest algorithm in footer",
                "AVB footer present but algorithm string missing or "
                "out of bounds"))
        return report

    def render_markdown(self, report: AvbReport) -> str:
        lines = [
            "# AVB / dm-verity Posture Report",
            "",
            f"- Schema: `{report.schema}`  ·  Generated: {report.generated_utc}",
            f"- Image: `{report.image}` ({report.image_size} bytes)",
            "",
            "## AVB footer",
            "",
            f"- Footer present: **{report.footer_present}**",
        ]
        if report.footer_present:
            lines += [
                f"- Footer offset: {report.footer_offset}",
                f"- AVB version: {report.version}",
                f"- Digest algorithm: {report.algorithm or 'n/a'}",
                f"- vbmeta size: {report.vbmeta_size}",
                f"- vbmeta offset: {report.vbmeta_offset}",
                f"- salt length: {report.salt_length}",
                f"- signature length: {report.signature_length}",
                f"- public key digest: {report.pubkey_digest}",
                f"- vbmeta digest: {report.vbmeta_digest}",
            ]
        lines += [
            "",
            "## dm-verity heuristic",
            "",
            f"- Markers detected: **{report.dm_verity_heuristic}** "
            "(heuristic scan of image head only)",
            "",
            "## Findings",
        ]
        for fnd in report.findings:
            lines.append(f"- [{fnd.severity}] {fnd.title}: {fnd.detail}")
        lines += [
            "",
            "> All data derived from the provided image file only. No device was "
            "contacted and no bootloader state was modified.",
        ]
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description="Read-only AVB/dm-verity image inspector")
    ap.add_argument("image", help="image file to inspect (read-only)")
    ap.add_argument("--out", metavar="PATH",
                    help="write JSON report to this path")
    ap.add_argument("--markdown-out", metavar="PATH",
                    help="write Markdown report to this path")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.image):
        print(f"error: not a file: {args.image}", file=sys.stderr)
        return 2

    inspector = AvbInspector(args.image)
    report = inspector.inspect()
    print(json.dumps(report.as_dict(), indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report.as_dict(), fh, indent=2)
    if args.markdown_out:
        with open(args.markdown_out, "w", encoding="utf-8") as fh:
            fh.write(inspector.render_markdown(report))
        print(f"[+] markdown report written to {args.markdown_out}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
