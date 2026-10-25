#!/usr/bin/env python3
"""
symbol_resolver.py — KASLR-aware kernel symbol resolver (READ-ONLY)
====================================================================

PURPOSE (educational / authorized lab research only)
----------------------------------------------------
Modern Linux/Android kernels randomize the base address of the kernel image
on every boot (KASLR).  Hard-coding symbol addresses therefore breaks across
reboots.  However, the kernel *itself* publishes the fully-relocated symbol
table through ``/proc/kallsyms``:

    <address> <type> <name> [<module>]

Because the kernel performs the relocation when generating this file, simply
parsing it yields post-KASLR ("dynamic") addresses without ever having to
guess or brute-force the slide.  This module demonstrates that resolution
process in a strictly PASSIVE way:

  * It only READS /proc/kallsyms (or an offline capture of it).
  * It NEVER writes to /dev/mem, /proc/kcore, /sys/kernel/... , and it never
    attaches a debugger.  Address resolution alone is a legitimate forensic /
    research primitive (used by crash dump analysis, eBPF tooling, perf, etc.).
  * On production Android devices ``kptr_restrict=2`` masks all addresses to
    zero for unprivileged readers; this module detects that condition and
    reports it instead of attempting any circumvention.

TYPICAL RESEARCH USES
---------------------
1. Verifying that a target device exposes (or hides) kernel symbols, which is
   itself a security-posture finding (leaked KASLR base == information
   disclosure vulnerability worth reporting to the vendor).
2. Offline analysis of kallsyms captures pulled from authorized lab images.
3. Deriving the KASLR slide when combined with a known-good System.map
   (classic academic exercise; useful for understanding why kptr_restrict
   exists).

SAFETY POLICY
-------------
* Read-only by construction: the only privileged path touched is opening
  /proc/kallsyms in mode "r".
* Graceful degradation: PermissionError / FileNotFoundError never raise out
  of the public API; they are returned as structured ``ResolutionResult``
  objects so calling code (and the evidence logger) can record them.
* Optional allow-list guard (:meth:`SymbolResolver.guard`) refuses to resolve
  names flagged as "weaponization" targets unless the caller explicitly
  acknowledges LAB MODE.  This keeps the tool honest: it is for measuring
  exposure, not for scripting attacks.

COMPATIBILITY
-------------
Arch Linux (desktop/laptop kernels) and Termux (Android).  Pure standard
library; works on Python >= 3.8.  No root required (root required only for
non-zero addresses on Android, due to kptr_restrict).

EXAMPLE
-------
    from symbol_resolver import SymbolResolver
    r = SymbolResolver()
    res = r.resolve("gatekeeper_verify")           # demo name; real kernels
    if res.found:                                  # rarely export such a
        print(hex(res.address))                    # userspace-named symbol)
    print(r.kaslr_summary())
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("kernelx.symbol_resolver")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROC_KALLSYMS = "/proc/kallsyms"

# Default location for OFFLINE captures taken from authorized lab images.
# Keeping this separate from the live path makes the read-only story clear.
DEFAULT_OFFLINE_DIR = os.environ.get(
    "KERNELX_KALLSYMS_DIR",
    os.path.join(os.path.expanduser("~"), ".kernel_x", "captures"),
)

# Line format: "ffffffff81a2b3c0 T some_function_name [module]"
_LINE_RE = re.compile(
    r"^(?P<addr>[0-9a-fA-F]+)\s+(?P<type>\S)\s+(?P<name>[^\s\[]+)"
    r"(?:\s+\[(?P<module>[^\]]+)\])?\s*$"
)

# Symbol names that indicate the caller may be moving from *measurement*
# toward *exploitation*.  Resolution is still possible but requires an
# explicit acknowledgement flag (see `guard()`).
WEAPONIZATION_HINTS: Tuple[str, ...] = (
    "commit_creds",
    "prepare_kernel_cred",
    "override_creds",
    "set_memory_ro",
    "set_memory_rw",
    "text_poke",
    "stop_machine",
)


def _is_android() -> bool:
    """Heuristic: is this a Termux / Android environment?"""
    return (
        "com.termux" in os.environ.get("PREFIX", "")
        or os.path.exists("/system/build.prop")
        or "android" in os.uname().release.lower()
    )


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class KernelSymbol:
    """One parsed entry of /proc/kallsyms."""
    address: int          # raw value as published (0 == masked by kptr_restrict)
    sym_type: str         # T/t D/d R/r B/b W/w U S/s ... (upper == global)
    name: str
    module: Optional[str] = None    # e.g. "gatekeeper" for loadable modules

    @property
    def masked(self) -> bool:
        """True when kptr_restrict has zeroed the address."""
        return self.address == 0

    @property
    def is_text(self) -> bool:
        return self.sym_type in ("T", "t")


@dataclass
class ResolutionResult:
    """Structured outcome of a resolve() call — never raises for I/O errors."""
    query: str
    found: bool = False
    address: Optional[int] = None
    symbol: Optional[KernelSymbol] = None
    error: Optional[str] = None       # human-readable failure reason
    source: str = PROC_KALLSYMS
    candidates: List[KernelSymbol] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.error:
            return f"[{self.query}] ERROR: {self.error}"
        if not self.found:
            return f"[{self.query}] not found ({len(self.candidates)} fuzzy hits)"
        return f"[{self.query}] -> 0x{self.address:016x} ({self.symbol.sym_type})"


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

class SymbolResolver:
    """
    Parse /proc/kallsyms (live or captured) and resolve symbol names to
    post-KASLR addresses.  All public methods are non-throwing for the
    common permission/not-found cases; inspect ``ResolutionResult.error``.
    """

    def __init__(self, source_path: str = PROC_KALLSYMS,
                 offline_dir: str = DEFAULT_OFFLINE_DIR) -> None:
        self.source_path = source_path
        self.offline_dir = offline_dir
        self._symbols: Dict[str, KernelSymbol] = {}
        self._loaded = False
        self._load_error: Optional[str] = None
        self._base_lowest_text: Optional[int] = None

    # -- loading ------------------------------------------------------------

    def load(self) -> Optional[str]:
        """
        Read and parse the symbol table once (lazy caching).

        Returns ``None`` on success, or a string describing why the table
        could not be read.  Permission denied is EXPECTED on unprivileged
        Android and is handled gracefully (we then fall back to any offline
        capture the researcher placed in ``offline_dir``).
        """
        if self._loaded:
            return self._load_error

        try:
            text = self._read_live()
            source = self.source_path
        except PermissionError:
            logger.warning("Permission denied reading %s (expected on "
                           "unprivileged Android). Trying offline capture.",
                           self.source_path)
            text, source = self._read_offline()
            if text is None:
                self._load_error = (
                    "EACCES: cannot read /proc/kallsyms and no offline "
                    "capture found. On Termux without root this is normal; "
                    "place a 'kallsyms' file captured from an authorized lab "
                    f"image into {self.offline_dir}/."
                )
                self._loaded = True
                return self._load_error
        except FileNotFoundError:
            self._load_error = f"{self.source_path} does not exist (not Linux?)"
            self._loaded = True
            return self._load_error
        except OSError as exc:                       # EIO, ENODEV, ...
            self._load_error = f"OS error while reading kallsyms: {exc}"
            self._loaded = True
            return self._load_error

        self._parse(text, source)
        self._loaded = True
        return None

    def _read_live(self) -> str:
        """Open the live procfs file strictly read-only."""
        with open(self.source_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def _read_offline(self) -> Tuple[Optional[str], Optional[str]]:
        """Find newest '<anything>/kallsyms*' capture inside offline_dir."""
        try:
            entries = sorted(
                (os.path.join(self.offline_dir, n)
                 for n in os.listdir(self.offline_dir)
                 if "kallsyms" in n),
                key=os.path.getmtime,
                reverse=True,
            )
        except OSError:
            return None, None
        for path in entries:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    logger.info("Using offline kallsyms capture: %s", path)
                    return fh.read(), path
            except OSError:
                continue
        return None, None

    def _parse(self, text: str, source: str) -> None:
        """Parse kallsyms lines; duplicates resolved first-wins + candidate list."""
        count = skipped = 0
        for line in text.splitlines():
            m = _LINE_RE.match(line)
            if not m:
                skipped += 1
                continue
            sym = KernelSymbol(
                address=int(m.group("addr"), 16),
                sym_type=m.group("type"),
                name=m.group("name"),
                module=m.group("module"),
            )
            # Modules can legitimately export duplicate names; keep the first
            # exact match but remember everything for fuzzy queries.
            self._symbols.setdefault(sym.name, sym)
            self._by_name_all.setdefault(sym.name, []).append(sym)
            count += 1
        self._source = source
        logger.info("Parsed %d symbols (%d malformed lines skipped) from %s",
                    count, skipped, source)

    # `_by_name_all` must exist before _parse touches it:
    @property
    def _by_name_all(self) -> Dict[str, List[KernelSymbol]]:
        try:
            return self.__dict__["_by_name_all"]
        except KeyError:
            self.__dict__["_by_name_all"] = {}
            return self.__dict__["_by_name_all"]

    # -- querying -----------------------------------------------------------

    def resolve(self, name: str, acknowledge_lab_mode: bool = False) -> ResolutionResult:
        """
        Exact-match resolution of ``name``.

        ``acknowledge_lab_mode`` gates weaponization-adjacent symbols
        (e.g. commit_creds).  A researcher analysing a CTF kernel image sets
        it to True deliberately; scripts that hit it by accident get blocked,
        which prevents silent drift from measurement to exploitation.
        """
        err = self.load()
        if err:
            return ResolutionResult(query=name, error=err, source=self.source_path)

        if self._is_weaponization_hint(name) and not acknowledge_lab_mode:
            return ResolutionResult(
                query=name,
                error=("BLOCKED: '%s' is a sensitive symbol class. Pass "
                       "acknowledge_lab_mode=True only inside an authorized "
                       "lab exercise." % name),
            )

        sym = self._symbols.get(name)
        if sym is None:
            return ResolutionResult(
                query=name,
                candidates=self._fuzzy_candidates(name),
                error=None,
            )

        result = ResolutionResult(query=name, symbol=sym, source=self._source)
        if sym.masked:
            # File readable but addresses zeroed => kptr_restrict active.
            result.found = True
            result.address = None
            result.error = ("Address masked by kptr_restrict (all symbols "
                            "read as 0). KASLR base is NOT leaked on this "
                            "device — that is a positive security finding.")
        else:
            result.found = True
            result.address = sym.address
        return result

    def resolve_many(self, names: List[str], **kw) -> Dict[str, ResolutionResult]:
        return {n: self.resolve(n, **kw) for n in names}

    def search(self, pattern: str, limit: int = 50) -> List[KernelSymbol]:
        """Regex search over symbol names (read-only listing)."""
        if self.load():
            return []
        rx = re.compile(pattern)
        out = [s for n, s in self._symbols.items() if rx.search(n)]
        return out[:limit]

    def module_symbols(self, module: str) -> List[KernelSymbol]:
        """All symbols belonging to a loadable module (e.g. 'gatekeeper')."""
        if self.load():
            return []
        return [s for lst in self._by_name_all.values()
                for s in lst if s.module == module]

    # -- indexed lookup (ADVANCED) ---------------------------------------------

    def _ensure_index(self) -> None:
        """
        Build a name-sorted index ONCE so repeated exact lookups are O(log n)
        instead of hashing a freshly parsed dict every call.  /proc/kallsyms
        on Android kernels commonly holds 100k+ symbols; Termux devices have
        little RAM/CPU to spare, so the binary-search path matters when a
        harness resolves thousands of names per session.
        """
        if self.load():
            return
        if "_sorted_names" not in self.__dict__:
            self.__dict__["_sorted_names"] = sorted(self._symbols.keys())
            self.__dict__["_index_built"] = True

    def resolve_indexed(self, name: str,
                        acknowledge_lab_mode: bool = False) -> ResolutionResult:
        """
        Same semantics as resolve(), but served through the sorted index via
        bisect (O(log n)).  Demonstrates the classic 'build-once, query-many'
        pattern used by real symbolizers (perf, crash).
        """
        import bisect
        self._ensure_index()
        names: List[str] = self.__dict__.get("_sorted_names", [])
        i = bisect.bisect_left(names, name)
        if i < len(names) and names[i] == name:
            # Delegate to the guarded path so lab-mode gating & masking
            # semantics stay identical between both APIs.
            return self.resolve(name, acknowledge_lab_mode)
        return ResolutionResult(query=name, error=None,
                                source=getattr(self, "_source", self.source_path))

    def stats(self) -> Dict[str, int]:
        """Quick census of the loaded table (type histogram), for reports."""
        if self.load():
            return {}
        hist: Dict[str, int] = {}
        for s in self._symbols.values():
            hist[s.sym_type] = hist.get(s.sym_type, 0) + 1
        hist["total"] = len(self._symbols)
        return hist

    def _fuzzy_candidates(self, name: str) -> List[KernelSymbol]:
        """Substring candidates help when the exact spelling differs."""
        needle = name.lower()
        return [s for n, s in self._symbols.items() if needle in n.lower()][:20]

    @staticmethod
    def _is_weaponization_hint(name: str) -> bool:
        return any(h in name for h in WEAPONIZATION_HINTS)

    # -- KASLR posture ------------------------------------------------------

    def kaslr_summary(self) -> Dict[str, object]:
        """
        Summarise whether kernel addresses are exposed.

        * all_masked  -> kptr_restrict effective (good posture).
        * leak_slide  -> lowest executable text address; on x86_64 the gap to
          the compile-time System.map base reveals the KASLR slide (this is
          exactly the information disclosure vendors patch with kptr_restrict).
        """
        err = self.load()
        summary: Dict[str, object] = {"available": err is None}
        if err:
            summary["error"] = err
            return summary

        text_syms = [s for s in self._symbols.values() if s.is_text]
        masked = sum(1 for s in text_syms if s.masked)
        summary.update({
            "total_symbols": len(self._symbols),
            "text_symbols": len(text_syms),
            "masked_count": masked,
            "addresses_exposed": masked < max(len(text_syms) - 1, 1),
            "environment": "android/termux" if _is_android() else "linux",
        })
        visible = [s.address for s in text_syms if not s.masked]
        if visible:
            summary["lowest_visible_text_addr"] = hex(min(visible))
        return summary

    # -- KASLR slide derivation (ADVANCED, educational) -------------------------

    def load_system_map(self, path: str) -> int:
        """
        Load a compile-time System.map (same kallsyms line format, but with
        LINK-TIME addresses).  Diffing it against the live table reveals the
        per-boot KASLR slide — the exact information that kptr_restrict is
        designed to protect.  Legitimate forensic use: validating crash dumps
        and teaching why symbol exposure matters.  Read-only file access.
        Returns the number of entries loaded.
        """
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("cannot read System.map %s: %s", path, exc)
            return 0
        n = 0
        self._system_map: Dict[str, int] = {}
        for line in text.splitlines():
            m = _LINE_RE.match(line)
            if m:
                self._system_map.setdefault(m.group("name"),
                                            int(m.group("addr"), 16))
                n += 1
        return n

    def kaslr_slide(self, sample: int = 32) -> Optional[int]:
        """
        Estimate the runtime KASLR slide: median of
        (live address - link-time address) over symbols present in BOTH the
        live kallsyms table and a previously-loaded System.map.  A single
        outlier module cannot skew the median; if the estimates disagree by
        more than one page, we return None (slide is not uniform — e.g. mixed
        modules) instead of reporting a wrong number.
        Requires non-masked addresses; returns None on hardened kernels
        (that failure IS the good-security outcome).
        """
        smap = getattr(self, "_system_map", None)
        if not smap or self.load():
            return None
        deltas: List[int] = []
        for name, link_addr in list(smap.items())[:sample * 4]:
            sym = self._symbols.get(name)
            if sym and not sym.masked and sym.is_text:
                deltas.append(sym.address - link_addr)
                if len(deltas) >= sample:
                    break
        if len(deltas) < 5:
            return None
        deltas.sort()
        slide = deltas[len(deltas) // 2]
        tol = 0x1000                              # one page
        if any(abs(d - slide) > tol for d in deltas):
            logger.warning("non-uniform deltas; refusing to guess a slide")
            return None
        return slide

    def write_report(self, path: str) -> str:
        """Dump a small plain-text posture report (for the evidence logger)."""
        s = self.kaslr_summary()
        lines = ["# kernel symbol exposure report",
                 f"source: {getattr(self, '_source', self.source_path)}"]
        for k, v in s.items():
            lines.append(f"{k}: {v}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("symbols", nargs="*",
                    help="symbol names to resolve (e.g. gatekeeper_verify)")
    ap.add_argument("--search", metavar="REGEX",
                    help="regex-search symbol names instead")
    ap.add_argument("--source", default=PROC_KALLSYMS,
                    help="path to a live or captured kallsyms file")
    ap.add_argument("--system-map", metavar="PATH",
                    help="link-time System.map; enables KASLR slide derivation")
    ap.add_argument("--stats", action="store_true",
                    help="print symbol-type census of the loaded table")
    ap.add_argument("--lab-mode", action="store_true",
                    help="acknowledge resolution of sensitive symbol classes")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.ERROR if args.quiet else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    r = SymbolResolver(source_path=args.source)
    err = r.load()
    if err:
        print(f"NOTE: {err}")

    print("KASLR posture:", r.kaslr_summary())

    if args.stats:
        print("Symbol census:", r.stats())

    if args.system_map:
        n = r.load_system_map(args.system_map)
        print(f"System.map entries loaded: {n}")
        slide = r.kaslr_slide()
        print("KASLR slide:", hex(slide) if slide is not None
              else "not derivable (masked or non-uniform — expected on "
                   "hardened kernels)")

    if args.search:
        for sym in r.search(args.search):
            flag = " (masked)" if sym.masked else ""
            print(f"0x{sym.address:016x} {sym.sym_type} {sym.name}{flag}")
        return 0

    for name in args.symbols:
        res = r.resolve(name, acknowledge_lab_mode=args.lab_mode)
        print(res)
        for c in res.candidates:
            print(f"    candidate: {c.name} ({c.sym_type})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
