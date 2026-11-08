#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel_x.offset_db
==================

Read-only kernel symbol offset database (lab samples only)
===========================================================

Maintains a small JSON database of *illustrative* symbol offsets captured
from authorized lab builds:

    {
      "kernel_series": "5.15",
      "build_id": "lab-sample-0001",
      "symbol": "prepare_kernel_cred",
      "offset": 0x123450,
      "source": "lab System.map (illustrative sample only)",
      "note": "not from any production device",
    }

Uses:

  * ``lookup(series, symbol)`` — all matching entries for a kernel series,
  * ``relocated_address(base_address, offset)`` — KASLR-aware relocation
    math (runtime base + link-time offset), used together with
    :mod:`kernel_x.symbol_resolver` when the live table is masked by
    kptr_restrict,
  * database integrity: every file rewrite is SHA-256 digested.

This database ships with clearly-labeled *samples only* — nothing here was
taken from a production device, and no offsets are ever exfiltrated from a
real device by this code.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kernel_x.offset_db")

DEFAULT_DB_PATH = os.path.join("data", "offsets.json")
SCHEMA = "kx-offset-db/1.0"

# Illustrative lab entries ONLY. Every entry is marked as a sample; none
# describe a production shipping build.
SAMPLE_ENTRIES: List[Dict[str, Any]] = [
    {
        "kernel_series": "5.15",
        "build_id": "lab-sample-gki-5.15-0001",
        "symbol": "prepare_kernel_cred",
        "offset": 0x14A050,
        "source": "lab System.map (illustrative sample)",
        "note": "sample offset; do not use for production devices",
    },
    {
        "kernel_series": "5.15",
        "build_id": "lab-sample-gki-5.15-0001",
        "symbol": "commit_creds",
        "offset": 0x14B310,
        "source": "lab System.map (illustrative sample)",
        "note": "sample offset; do not use for production devices",
    },
    {
        "kernel_series": "5.10",
        "build_id": "lab-sample-vendor-5.10-0002",
        "symbol": "modprobe_path",
        "offset": 0x0C4120,
        "source": "lab System.map (illustrative sample)",
        "note": "sample offset; do not use for production devices",
    },
    {
        "kernel_series": "6.1",
        "build_id": "lab-sample-gki-6.1-0003",
        "symbol": "prepare_kernel_cred",
        "offset": 0x1E20A0,
        "source": "lab System.map (illustrative sample)",
        "note": "sample offset; do not use for production devices",
    },
]


@dataclass(slots=True)
class OffsetEntry:
    kernel_series: str
    build_id: str
    symbol: str
    offset: int
    source: str
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["offset"] = hex(self.offset)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OffsetEntry":
        return cls(
            kernel_series=data["kernel_series"],
            build_id=data["build_id"],
            symbol=data["symbol"],
            offset=int(data["offset"], 16) if isinstance(data["offset"], str)
            else int(data["offset"]),
            source=data.get("source", ""),
            note=data.get("note", ""),
        )


# --------------------------------------------------------------------------- #
# Database                                                                    #
# --------------------------------------------------------------------------- #

class OffsetDatabase:
    """In-memory symbol-offset database with JSON persistence."""

    def __init__(self, entries: Optional[List[OffsetEntry]] = None) -> None:
        self.entries: List[OffsetEntry] = list(entries or [])
        self._digest: Optional[str] = None

    @classmethod
    def load(cls, path: str = DEFAULT_DB_PATH) -> "OffsetDatabase":
        if not os.path.exists(path):
            logger.info("offset db %s not found; shipping samples only", path)
            return cls([OffsetEntry.from_dict(e) for e in SAMPLE_ENTRIES])
        try:
            with open(path, "r", encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("cannot read offset db %s: %s", path, exc)
            return cls([OffsetEntry.from_dict(e) for e in SAMPLE_ENTRIES])
        entries = [OffsetEntry.from_dict(e) for e in blob.get("entries", [])]
        db = cls(entries)
        db._digest = blob.get("digest")
        return db

    def save(self, path: str = DEFAULT_DB_PATH) -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = {
            "schema": SCHEMA,
            "generated_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"),
            "entries": [e.as_dict() for e in self.entries],
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()).hexdigest()
        payload["digest"] = digest
        self._digest = digest
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
        return digest

    def verify(self, path: str = DEFAULT_DB_PATH) -> bool:
        """Recompute digest and compare with the stored one."""
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return False
        stored = blob.get("digest")
        if not stored:
            return False
        check = {k: v for k, v in blob.items() if k != "digest"}
        digest = hashlib.sha256(
            json.dumps(check, sort_keys=True).encode()).hexdigest()
        return digest == stored

    def lookup(self, kernel_series: str,
               symbol: str) -> List[OffsetEntry]:
        series = kernel_series.strip()
        return [e for e in self.entries
                if e.kernel_series == series and e.symbol == symbol]

    def add_entry(self, entry: OffsetEntry) -> None:
        self.entries.append(entry)
        self._digest = None  # invalidate until next save

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "entries": [e.as_dict() for e in self.entries],
            "digest": self._digest,
        }


# --------------------------------------------------------------------------- #
# Relocation helper (used with symbol_resolver)                               #
# --------------------------------------------------------------------------- #

def relocated_address(base_address: int, offset: int) -> int:
    """Runtime address = KASLR base + link-time offset (pure math)."""
    return base_address + offset


def estimate_with_db(resolver, db: OffsetDatabase, symbol: str,
                     base_address: int,
                     kernel_series: str = "5.15",
                     acknowledge_lab_mode: bool = False
                     ) -> Dict[str, Any]:
    """
    Try to locate *symbol* using the live kallsyms table via *resolver*,
    falling back to ``base_address + offset`` from the offset DB when the
    symbol is masked (kptr_restrict). Result is always labeled as an
    *estimate* when it comes from the database.
    """
    result = resolver.resolve(symbol,
                              acknowledge_lab_mode=acknowledge_lab_mode)
    if result.found and result.address is not None:
        return {
            "symbol": symbol,
            "address": hex(result.address),
            "source": "live kallsyms",
            "estimate": False,
        }
    matches = db.lookup(kernel_series, symbol)
    if matches and base_address is not None:
        entry = matches[0]
        addr = relocated_address(base_address, entry.offset)
        return {
            "symbol": symbol,
            "address": hex(addr),
            "source": f"offset-db estimate ({entry.build_id})",
            "estimate": True,
            "offset": hex(entry.offset),
            "base": hex(base_address),
            "note": ("database entry is an illustrative lab sample — "
                     "not a production measurement"),
        }
    return {
        "symbol": symbol,
        "address": None,
        "source": "unavailable",
        "error": result.error or "no offset-db entry",
        "estimate": False,
    }


def _series_of(resolver) -> str:  # retained for backward compatibility
    import platform
    release = platform.release()
    parts = release.split(".")[:2]
    return ".".join(parts) if len(parts) == 2 else "5.15"


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description="Read-only kernel symbol offset database")
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    ap.add_argument("--lookup", metavar="SERIES:SYMBOL",
                    help="lookup entries, e.g. 5.15:commit_creds")
    ap.add_argument("--relocated-base", type=lambda x: int(x, 16),
                    metavar="ADDR", help="KASLR base for relocation math")
    ap.add_argument("--symbol", metavar="SYMBOL",
                    help="symbol to estimate with --relocated-base")
    ap.add_argument("--series", default="5.15",
                    help="kernel series for offset-db lookup (default: 5.15)")
    ap.add_argument("--verify", action="store_true",
                    help="verify database digest integrity")
    ap.add_argument("--init-samples", action="store_true",
                    help="write sample entries to --db")
    args = ap.parse_args(argv)

    db = OffsetDatabase.load(args.db)

    if args.init_samples:
        digest = db.save(args.db)
        print(f"sample db written to {args.db} (digest {digest[:12]}...)")

    if args.lookup:
        series, _, symbol = args.lookup.partition(":")
        matches = db.lookup(series, symbol)
        print(json.dumps([e.as_dict() for e in matches], indent=2))

    if args.verify:
        print("digest valid:", db.verify(args.db))

    if args.symbol is not None and args.relocated_base is not None:
        from symbol_resolver import SymbolResolver
        resolver = SymbolResolver()
        print(json.dumps(
            estimate_with_db(resolver, db, args.symbol,
                             args.relocated_base,
                             kernel_series=args.series), indent=2))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
