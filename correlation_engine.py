#!/usr/bin/env python3
"""
correlation_engine.py — cross-device vulnerability correlation (SQLite)
=======================================================================

PURPOSE (educational / authorized lab research only)
----------------------------------------------------
When a lab fleet contains many Android devices (different AOSP versions,
SoC vendors, patch levels), individual findings become *patterns* once you
can query them jointly.  This module provides:

  * A normalized SQLite schema:
      devices(device_id, android_version, soc_vendor, soc_model, kernel, ...)
      vulns(cve_id, title, severity, cvss, component, ...)
      findings(id, device_id, vuln_id, evidence_ref, observed_on, notes)
      ^-- evidence_ref is the Merkle leaf/root hex from evidence_logger.py,
          so every DB row is cryptographically tied to the forensic log.
  * Safe ingestion API (`add_device`, `add_vuln`, `add_finding`) using
    parameterized statements ONLY (no string interpolation => no SQL
    injection in our own tooling).
  * A pattern-correlation query system:
      - common_vulns_across_versions(): which CVEs recur across N+ Android
        releases (candidate systemic/root-cause issues)?
      - vulns_by_soc(): per-SoC-vendor concentration (driver/HAL clusters)?
      - fingerprint_matches(): identical finding fingerprints on different
        devices/versions => same underlying bug, dedupe + escalate.
      - pivot(sql_name, params): a small whitelist of vetted read-only
        queries instead of raw user SQL (defense in depth).
  * Export helpers (CSV/JSON) for feeding dashboards or reports.

SAFETY POLICY
-------------
* The engine never touches the network and never opens device files; it is
  pure local data analysis over observations *you* insert.
* PRAGMAs enforce journal_mode=WAL + foreign keys; opening an existing DB
  read-only is supported (`CorrelationEngine(path, readonly=True)` via
  `file:...?mode=ro` URI) so auditors can inspect without mutating evidence.
* Query whitelist rejects anything that isn't a SELECT.

COMPATIBILITY
-------------
Arch Linux & Termux (`pkg install python` ships sqlite3 in the stdlib).
Python >= 3.8.

EXAMPLE
-------
    from correlation_engine import CorrelationEngine
    db = CorrelationEngine("lab.db")
    db.add_device("pixel6a", "13", "Google", "Tensor G2")
    db.add_vuln("CVE-2024-0001", "gatekeeper TOCTOU", "high", 7.8, "gatekeeper")
    db.add_finding("pixel6a", "CVE-2024-0001", evidence_ref="ab12...")
    print(db.common_vulns_across_versions(min_versions=2))
"""

from __future__ import annotations

import csv
import os
import io
import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger("kernelx.correlation")

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices(
    device_id       TEXT PRIMARY KEY,
    android_version TEXT NOT NULL,
    soc_vendor      TEXT,
    soc_model       TEXT,
    kernel_release  TEXT,
    patch_level     TEXT,
    labels          TEXT DEFAULT '[]',          -- JSON array
    first_seen      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulns(
    cve_id     TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    severity   TEXT CHECK(severity IN ('low','medium','high','critical')),
    cvss       REAL,
    component  TEXT,                            -- gatekeeper/keystore/kernel/...
    url        TEXT,
    notes      TEXT
);

CREATE TABLE IF NOT EXISTS findings(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL REFERENCES vulns(cve_id)     ON DELETE CASCADE,
    evidence_ref TEXT,                           -- merkle leaf/root hex
    fingerprint  TEXT,                           -- normalized pattern key
    observed_on  TEXT NOT NULL,
    notes        TEXT,
    UNIQUE(device_id, cve_id, evidence_ref)
);

CREATE INDEX IF NOT EXISTS idx_findings_cve     ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_dev     ON findings(device_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp      ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_devices_version  ON devices(android_version);
"""

# ---------------------------------------------------------------------------
# Vetted read-only query library (whitelist > raw SQL)
# ---------------------------------------------------------------------------

QUERIES: Dict[str, str] = {
    # CVEs seen on devices spanning >= :min_versions distinct Android releases
    "common_vulns_across_versions": """
        SELECT v.cve_id, v.title, v.severity,
               COUNT(DISTINCT d.android_version) AS n_versions,
               GROUP_CONCAT(DISTINCT d.android_version) AS versions,
               COUNT(*) AS n_findings
        FROM findings f
        JOIN devices d  ON d.device_id = f.device_id
        JOIN vulns    v ON v.cve_id    = f.cve_id
        GROUP BY v.cve_id
        HAVING n_versions >= :min_versions
        ORDER BY n_versions DESC, n_findings DESC;
    """,
    # Per-SoC-vendor concentration of findings
    "vulns_by_soc": """
        SELECT d.soc_vendor,
               COUNT(DISTINCT f.cve_id) AS distinct_cves,
               COUNT(*)                 AS total_findings
        FROM findings f
        JOIN devices d ON d.device_id = f.device_id
        WHERE d.soc_vendor IS NOT NULL
        GROUP BY d.soc_vendor
        ORDER BY total_findings DESC;
    """,
    # Same fingerprint on more than one device => likely one systemic bug
    "fingerprint_matches": """
        SELECT f.fingerprint,
               COUNT(DISTINCT f.device_id) AS devices,
               GROUP_CONCAT(DISTINCT d.android_version) AS versions,
               GROUP_CONCAT(DISTINCT d.soc_vendor)      AS socs,
               MIN(f.cve_id) AS example_cve
        FROM findings f
        JOIN devices d ON d.device_id = f.device_id
        WHERE f.fingerprint IS NOT NULL
        GROUP BY f.fingerprint
        HAVING devices > 1
        ORDER BY devices DESC;
    """,
    # Component hot-spots (gatekeeper vs keystore vs kernel ...)
    "component_hotspots": """
        SELECT v.component, COUNT(*) AS findings,
               SUM(CASE WHEN v.severity='critical' THEN 1 ELSE 0 END) AS criticals
        FROM findings f JOIN vulns v ON v.cve_id = f.cve_id
        GROUP BY v.component ORDER BY findings DESC;
    """,
    # Everything observed about one device (audit view)
    "device_profile": """
        SELECT v.cve_id, v.title, v.severity, f.evidence_ref, f.observed_on
        FROM findings f JOIN vulns v ON v.cve_id = f.cve_id
        WHERE f.device_id = :device_id ORDER BY v.cvss DESC;
    """,
    # ADVANCED: kernel-version clustering — same CVE across distinct kernel
    # releases hints at a long-lived upstream defect vs a vendor backport gap.
    "kernel_version_clusters": """
        SELECT f.cve_id, v.title, v.severity,
               COUNT(DISTINCT d.kernel_release) AS n_kernels,
               GROUP_CONCAT(DISTINCT d.kernel_release) AS kernels
        FROM findings f
        JOIN devices d ON d.device_id = f.device_id
        JOIN vulns   v ON v.cve_id    = f.cve_id
        WHERE d.kernel_release IS NOT NULL
        GROUP BY f.cve_id
        HAVING n_kernels >= :min_kernels
        ORDER BY n_kernels DESC;
    """,
}


@dataclass
class FindingRow:
    device_id: str
    cve_id: str
    evidence_ref: Optional[str]
    fingerprint: Optional[str]
    observed_on: str
    notes: Optional[str] = None


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_fingerprint(component: str, soc_vendor: str, symptom: str) -> str:
    """
    Normalize the fields that identify *the same bug shape* across devices.
    Lower-cased, whitespace-collapsed: 'Gatekeeper  TOCTOU ' == 'gatekeeper toctou'.
    """
    norm = lambda s: " ".join(str(s).lower().split())
    return f"{norm(component)}|{norm(soc_vendor)}|{norm(symptom)}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """SQLite-backed multi-device vulnerability store + pattern queries."""

    def __init__(self, db_path: str, readonly: bool = False) -> None:
        self.db_path = db_path
        if readonly:
            # URI mode=ro guarantees we cannot create/modify the database —
            # ideal when another analyst's evidence DB must stay pristine.
            uri = f"file:{db_path}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True)
        else:
            self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        if not readonly:
            self._conn.execute("PRAGMA journal_mode = WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        try:
            cur.executescript(_SCHEMA)
        except sqlite3.OperationalError:
            if not self._readonly():
                raise
            return                       # ro DB with missing schema: tolerate
        cur.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),))
        self._conn.commit()

    def _readonly(self) -> bool:
        row = self._conn.execute("PRAGMA query_only").fetchone()
        return bool(row and row[0])

    @contextmanager
    def _tx(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # -- ingestion ------------------------------------------------------------

    def add_device(self, device_id: str, android_version: str,
                   soc_vendor: Optional[str] = None,
                   soc_model: Optional[str] = None,
                   kernel_release: Optional[str] = None,
                   patch_level: Optional[str] = None,
                   labels: Optional[Sequence[str]] = None) -> None:
        with self._tx() as c:
            c.execute("""
                INSERT INTO devices(device_id, android_version, soc_vendor,
                                    soc_model, kernel_release, patch_level,
                                    labels, first_seen)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(device_id) DO UPDATE SET
                    android_version=excluded.android_version,
                    soc_vendor=COALESCE(excluded.soc_vendor, soc_vendor),
                    soc_model=COALESCE(excluded.soc_model, soc_model),
                    kernel_release=COALESCE(excluded.kernel_release, kernel_release),
                    patch_level=COALESCE(excluded.patch_level, patch_level),
                    labels=excluded.labels;
            """, (device_id, android_version, soc_vendor, soc_model,
                  kernel_release, patch_level,
                  json.dumps(sorted(set(labels or []))), _utcnow()))

    def add_vuln(self, cve_id: str, title: str,
                 severity: str = "medium", cvss: Optional[float] = None,
                 component: Optional[str] = None, url: Optional[str] = None,
                 notes: Optional[str] = None) -> None:
        sev = severity.lower()
        if sev not in ("low", "medium", "high", "critical"):
            raise ValueError(f"invalid severity '{severity}'")
        with self._tx() as c:
            c.execute("""
                INSERT INTO vulns(cve_id, title, severity, cvss, component,
                                  url, notes)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    title=excluded.title, severity=excluded.severity,
                    cvss=excluded.cvss, component=excluded.component;
            """, (cve_id, title, sev, cvss, component, url, notes))

    def add_finding(self, device_id: str, cve_id: str,
                    evidence_ref: Optional[str] = None,
                    fingerprint: Optional[str] = None,
                    notes: Optional[str] = None) -> int:
        """Link a device to a vuln. FK constraints require the rows exist."""
        with self._tx() as c:
            cur = c.execute("""
                INSERT INTO findings(device_id, cve_id, evidence_ref,
                                     fingerprint, observed_on, notes)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(device_id, cve_id, evidence_ref) DO NOTHING;
            """, (device_id, cve_id, evidence_ref, fingerprint,
                  _utcnow(), notes))
            return cur.lastrowid or -1

    def bulk_ingest(self, records: Iterable[Dict[str, Any]]) -> int:
        """
        Ingest analyzer output dicts, e.g. from symbol_resolver/selinux runs:
            {"device": {...}, "vuln": {...}, "findings": [{...}]}
        Returns number of findings inserted.
        """
        n = 0
        for rec in records:
            if "device" in rec:
                self.add_device(**rec["device"])
            if "vuln" in rec:
                self.add_vuln(**rec["vuln"])
            for f in rec.get("findings", []):
                self.add_finding(**f)
                n += 1
        return n

    # -- querying ---------------------------------------------------------------

    def run_query(self, name: str, **params) -> List[Dict[str, Any]]:
        """Execute a WHITELISTED named query (never arbitrary SQL)."""
        sql = QUERIES.get(name)
        if sql is None:
            raise KeyError(f"unknown query '{name}'; available: "
                           f"{sorted(QUERIES)}")
        # Belt & braces: whitelisted SQL must start with SELECT.
        if not sql.strip().upper().startswith("SELECT"):
            raise RuntimeError("internal error: non-SELECT in whitelist")
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def common_vulns_across_versions(self, min_versions: int = 2
                                     ) -> List[Dict[str, Any]]:
        """Systemic candidates: CVEs present on >= min_versions Android releases."""
        return self.run_query("common_vulns_across_versions",
                              min_versions=min_versions)

    def vulns_by_soc(self) -> List[Dict[str, Any]]:
        return self.run_query("vulns_by_soc")

    def fingerprint_matches(self) -> List[Dict[str, Any]]:
        """Cross-device duplicates by normalized fingerprint."""
        return self.run_query("fingerprint_matches")

    def component_hotspots(self) -> List[Dict[str, Any]]:
        return self.run_query("component_hotspots")

    def kernel_version_clusters(self, min_kernels: int = 2
                                ) -> List[Dict[str, Any]]:
        """CVEs observed across >= min_kernels distinct kernel releases."""
        return self.run_query("kernel_version_clusters",
                              min_kernels=min_kernels)

    def device_profile(self, device_id: str) -> List[Dict[str, Any]]:
        return self.run_query("device_profile", device_id=device_id)

    def stats(self) -> Dict[str, int]:
        q = lambda t: self._conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        return {"devices": q("devices"), "vulns": q("vulns"),
                "findings": q("findings")}

    # -- export -----------------------------------------------------------------

    def export_json(self, path: str) -> str:
        tables = {}
        for t in ("devices", "vulns", "findings"):
            tables[t] = [dict(r) for r in
                         self._conn.execute(f"SELECT * FROM {t}").fetchall()]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(tables, fh, indent=2, default=str)
        return path

    def export_csv(self, table: str, fh: "io.TextIOBase") -> None:
        if table not in ("devices", "vulns", "findings"):
            raise ValueError("unknown table")
        rows = self._conn.execute(f"SELECT * FROM {table}").fetchall()
        if not rows:
            return
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        for r in rows:
            w.writerow(dict(r))

    def close(self) -> None:
        self._conn.close()

    # -- evidence anchoring (ADVANCED, cross-module integration) ----------------

    def anchor_evidence_log(self, log_path: str) -> Dict[str, Any]:
        """
        Import the CURRENT Merkle root of an evidence_logger JSONL file as a
        single 'audit' finding, so database consumers can verify that the
        forensic trail backing these rows has not been tampered with since
        ingestion.

        Uses ONLY public APIs (EvidenceLogger.verify_integrity/root_hex);
        the optional import is guarded so this module keeps working on
        minimal installs without evidence_logger.py present.  The DB row's
        evidence_ref stores '<log name>:root:<hex>' — verifiable offline by
        re-running `python evidence_logger.py --log <path> --verify`.
        """
        try:
            from evidence_logger import EvidenceLogger, IntegrityError
        except ImportError:
            return {"status": "SKIPPED",
                    "error": "evidence_logger module not importable"}
        logger_obj = EvidenceLogger(log_path)
        try:
            ok = logger_obj.verify_integrity()
            status = "PASS" if ok else "FAIL"
        except IntegrityError as exc:
            # A failed verification is itself critical forensic information:
            # record it, do not hide it.
            status = f"FAIL: {exc}"
        root = logger_obj.root_hex()
        ref = f"{os.path.basename(log_path)}:root:{root}"
        now = _utcnow().replace(":", "").replace("-", "")[:15]
        dev = f"lab-audit-{now}"
        self.add_device(device_id=dev, android_version="n/a",
                        labels=["audit"])
        self.add_vuln(cve_id=f"AUDIT-{root[:12] or 'empty'}",
                      title=f"Evidence-log integrity anchor: {status}",
                      # severity CHECK allows low/medium/high/critical only;
                      # a broken trail is critical, a healthy one is 'low'
                      # (informational) — recorded honestly either way.
                      severity="low" if status == "PASS" else "critical",
                      component="evidence_logger")
        self.add_finding(device_id=dev, cve_id=f"AUDIT-{root[:12] or 'empty'}",
                         evidence_ref=ref, notes=status)
        return {"status": status, "root": root, "device_id": dev}

    def __enter__(self) -> "CorrelationEngine":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Demo dataset + CLI
# ---------------------------------------------------------------------------

def _seed_demo(db: CorrelationEngine) -> None:
    """Synthetic lab-fleet data (no real device identifiers)."""
    demo_devices = [
        ("lab-pix-6a",  "13", "Google",   "Tensor G2",   "5.10", "2023-11"),
        ("lab-pix-7",   "14", "Google",   "Tensor G3",   "5.10", "2024-03"),
        ("lab-smi-s22", "13", "Samsung",  "Exynos 2200", "5.10", "2023-09"),
        ("lab-one-9",   "13", "Qualcomm", "SD 888",      "5.4",  "2023-06"),
        ("lab-moto-e",  "12", "Qualcomm", "SD 662",      "5.4",  "2023-02"),
    ]
    demo_vulns = [
        ("CVE-2024-0001", "Gatekeeper TOCTOU on verify response", "high",
         7.8, "gatekeeper"),
        ("CVE-2024-0002", "Keymaster HAL integer overflow", "critical",
         9.1, "keystore"),
        ("CVE-2024-0003", "kallsyms address leak (kptr_restrict=0)", "medium",
         5.5, "kernel"),
        ("CVE-2024-0004", "Timing side-channel in PIN compare", "medium",
         6.2, "gatekeeper"),
    ]
    demo_findings = [
        ("lab-pix-6a",  "CVE-2024-0001", "aa11", "gatekeeper|google|toctou"),
        ("lab-pix-7",   "CVE-2024-0001", "bb22", "gatekeeper|google|toctou"),
        ("lab-smi-s22", "CVE-2024-0001", "cc33", "gatekeeper|samsung|toctou"),
        ("lab-one-9",   "CVE-2024-0002", "dd44", "keystore|qualcomm|overflow"),
        ("lab-moto-e",  "CVE-2024-0002", "ee55", "keystore|qualcomm|overflow"),
        ("lab-pix-6a",  "CVE-2024-0003", "ff66", "kernel|google|kallsyms-leak"),
        ("lab-one-9",   "CVE-2024-0003", "gg77", "kernel|qualcomm|kallsyms-leak"),
        ("lab-moto-e",  "CVE-2024-0003", "hh88", "kernel|qualcomm|kallsyms-leak"),
        ("lab-pix-7",   "CVE-2024-0004", "ii99", "gatekeeper|google|timing"),
    ]
    for d in demo_devices:
        db.add_device(*d)
    for v in demo_vulns:
        db.add_vuln(*v)
    for dev, cve, ref, fp in demo_findings:
        db.add_finding(dev, cve, evidence_ref=ref, fingerprint=fp)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default="lab_correlation.db")
    ap.add_argument("--demo", action="store_true",
                    help="seed synthetic lab-fleet data then report")
    ap.add_argument("--query", choices=sorted(QUERIES) + ["verify_evidence_log"],
                    help="run one whitelisted query")
    ap.add_argument("--min-versions", type=int, default=2)
    ap.add_argument("--min-kernels", type=int, default=2,
                    help="threshold for kernel_version_clusters query")
    ap.add_argument("--device", help="device_id for device_profile query")
    ap.add_argument("--evidence-log", metavar="PATH",
                    help="JSONL log path for --query verify_evidence_log")
    ap.add_argument("--export-json", metavar="PATH")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO)

    db = CorrelationEngine(args.db)
    if args.demo:
        _seed_demo(db)
        logger.info("seeded demo fleet: %s", db.stats())

    if args.query == "verify_evidence_log":
        # ADVANCED cross-module integration: anchor the evidence_logger
        # Merkle root inside this DB and print the verdict.
        if not args.evidence_log:
            ap.error("--query verify_evidence_log needs --evidence-log PATH")
        print(json.dumps(db.anchor_evidence_log(args.evidence_log), indent=2))
    elif args.query:
        params: Dict[str, Any] = {}
        if args.query == "common_vulns_across_versions":
            params["min_versions"] = args.min_versions
        if args.query == "kernel_version_clusters":
            params["min_kernels"] = args.min_kernels
        if args.query == "device_profile":
            params["device_id"] = args.device or "*"
        for row in db.run_query(args.query, **params):
            print(json.dumps(row, default=str))
    elif args.demo:
        print("\n== systemic candidates (>=2 Android versions) ==")
        for r in db.common_vulns_across_versions(args.min_versions):
            print(f"  {r['cve_id']:16} x{r['n_versions']} versions "
                  f"[{r['versions']}] ({r['severity']}) {r['title']}")
        print("\n== kernel-release clusters (>=2 kernels) ==")
        for r in db.kernel_version_clusters(args.min_kernels):
            print(f"  {r['cve_id']:16} x{r['n_kernels']} kernels "
                  f"[{r['kernels']}] ({r['severity']}) {r['title']}")
        print("\n== SoC concentration ==")
        for r in db.vulns_by_soc():
            print(f"  {r['soc_vendor']:10} cves={r['distinct_cves']} "
                  f"findings={r['total_findings']}")
        print("\n== cross-device fingerprint matches ==")
        for r in db.fingerprint_matches():
            print(f"  {r['fingerprint']:40} devices={r['devices']} "
                  f"socs=[{r['socs']}]")
        print("\n== component hotspots ==")
        for r in db.component_hotspots():
            print(f"  {r['component']:12} findings={r['findings']} "
                  f"criticals={r['criticals']}")

    if args.export_json:
        print("exported:", db.export_json(args.export_json))

    db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
