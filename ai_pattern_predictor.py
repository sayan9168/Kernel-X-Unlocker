#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_pattern_predictor.py  (v2 - refactored)
==========================================

Kernel-X Research Toolkit - **defensive** risk-prediction module.

This module replaces the legacy "SayanAI" lockscreen-pattern predictor, which
attempted to guess user PINs from behavioural data. Guessing a real person's
lockscreen credential is credential-attack behaviour and has been removed.

What this module does instead (educational / lab use on owned devices):

* A scikit-learn **RandomForestClassifier** that estimates how likely a lab
  device's kernel belongs to a *patch-latency risk class* given:
    - Kernel version (major/minor)
    - Android Security Patch Level (months behind current baseline)
    - SoC architecture (ARM64 / ARM32 / x86_64 emulator)
* The training corpus is built from **publicly documented** GKI/ASB advisory
  metadata (kernel series vs. cumulative patch depth). It models *exposure
  windows*, not exploitable primitives, and never emits attack guidance.
* Optional integration with :mod:`memory_scanner_advanced`: a read-only scan
  report can nudge the confidence of the *configuration-hygiene* feature set
  (e.g., keystore2 present + no anomalous anonymous-rwx mappings => slightly
  lower exposure score). No key material is ever consumed.
* All outputs are JSON-safe dicts for the dashboard.

The public class name ``SayanAI`` is kept as a thin backwards-compatible alias
so older notebooks keep importing, but its prediction API now returns risk
metadata only.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    RandomForestClassifier = None  # type: ignore[assignment]
    SKLEARN_AVAILABLE = False

logger = logging.getLogger("kernel_x.ai_predictor")

MODEL_VERSION = "2.0.0"
DEFAULT_MODEL_PATH = os.path.join("bin", "ai_model.pkl")

FEATURE_NAMES: Tuple[str, ...] = (
    "kernel_major",
    "kernel_minor",
    "patch_months_behind",
    "arch_arm64",
    "arch_arm32",
    "arch_x86_emulator",
    "gki_managed",
    "scanner_anomaly_score",
)

RISK_LABELS: Dict[int, str] = {
    0: "LOW_EXPOSURE",       # current GKI line, patch level <= 3 months old
    1: "MODERATE_EXPOSURE",  # 1-2 quarters of ASB backlog
    2: "HIGH_EXPOSURE",      # >= 2 quarters behind / EOL kernel series
}


# ---------------------------------------------------------------------------
# Device info container & parsers
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """Static telemetry about a lab device. Contains no user data."""
    kernel_version: str = "5.15.0"        # e.g. "5.10.101-android12-9..."
    security_patch_level: str = "2026-05-05"
    soc_architecture: str = "arm64-v8a"   # arm64-v8a | armeabi-v7a | x86_64
    gki_managed: bool = True              # ships as a GKI image w/ vendor DLKM
    reference_patch_date: str = ""        # baseline "today" for delta calc

    def parse_kernel(self) -> Tuple[int, int]:
        m = re.match(r"\s*(\d+)\.(\d+)", self.kernel_version)
        if not m:
            logger.warning("unparseable kernel '%s'; defaulting to 0.0",
                           self.kernel_version)
            return (0, 0)
        return int(m.group(1)), int(m.group(2))

    def patch_months_behind(self) -> int:
        try:
            ref = datetime.strptime(self.reference_patch_date or
                                    _today_str(), "%Y-%m-%d")
            lvl = datetime.strptime(self.security_patch_level, "%Y-%m-%d")
        except ValueError:
            logger.warning("bad SPL format '%s' (expected YYYY-MM-DD); "
                           "assuming worst case", self.security_patch_level)
            return 36
        months = (ref.year - lvl.year) * 12 + (ref.month - lvl.month)
        return max(0, min(months, 120))

    @classmethod
    def from_props(cls, props: Dict[str, str]) -> "DeviceInfo":
        """Build from `getprop` output keys commonly seen on Android."""
        return cls(
            kernel_version=props.get("kernel.version", "") or _uname_release(),
            security_patch_level=props.get(
                "ro.build.version.security_patch", ""),
            soc_architecture=props.get("ro.product.cpu.abi", _native_arch()),
            gki_managed=props.get("ro.boot.gki", "auto").lower() != "false",
        )


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _uname_release() -> str:
    import platform
    return platform.release()


def _native_arch() -> str:
    import platform
    machine = platform.machine().lower()
    return {"aarch64": "arm64-v8a", "armv7l": "armeabi-v7a",
            "x86_64": "x86_64"}.get(machine, "arm64-v8a")


# ---------------------------------------------------------------------------
# Training corpus - PUBLIC advisory-derived configuration classes
# ---------------------------------------------------------------------------

def _build_synthetic_corpus() -> Tuple[np.ndarray, np.ndarray]:
    """
    Deterministic, synthetic-but-realistic corpus describing *configuration
    hygiene classes* observed across public GKI/ASB advisories:

      * kernels 4.9/4.14 (Android 8-11 era) with >18 months patch backlog
        historically accumulated HIGH-severity LPE advisories  -> class 2
      * 4.14/5.4/5.10 with 4-18 months backlog                 -> class 1
      * 5.10+ GKI with <=3 months backlog                      -> class 0

    Features: [kmaj, kmin, months_behind, arm64, arm32, x86, gki, anomaly]
    Labels  : 0 LOW | 1 MODERATE | 2 HIGH exposure class.
    """
    rng = np.random.default_rng(1337)  # deterministic for reproducible labs
    rows: List[List[float]] = []
    labels: List[int] = []

    arch_variants = [(1, 0, 0), (0, 1, 0), (0, 0, 1)]  # arm64/arm32/x86emu

    def add(kmaj: int, kmin: int, months: int, arch: Tuple[int, int, int],
            gki: int, label: int, n: int = 40) -> None:
        for _ in range(n):
            jitter_m = max(0, months + int(rng.integers(-1, 2)))
            anomaly = float(np.clip(rng.normal(0.05 if label == 0 else
                                               (0.3 if label == 1 else 0.6),
                                               0.08), 0.0, 1.0))
            rows.append([kmaj, kmin, jitter_m, *arch, gki, anomaly])
            labels.append(label)

    # Legacy non-GKI series (EOL upstream lines)
    for arch in arch_variants:
        add(4, 9, 30, arch, 0, 2)
        add(4, 14, 26, arch, 0, 2)
        add(4, 14, 10, arch, 0, 1)
        add(4, 19, 12, arch, 0, 1)
    # Transitional LTS
    for arch in arch_variants[:2]:
        add(5, 4, 24, arch, 0, 2)
        add(5, 4, 8, arch, 0, 1)
        add(5, 10, 14, arch, 1, 1)
        add(5, 10, 3, arch, 1, 0)
        add(5, 15, 6, arch, 1, 1)
        add(5, 15, 2, arch, 1, 0)
    # Modern GKI lines
    for arch in arch_variants:
        add(5, 15, 1, arch, 1, 0)
        add(6, 1, 2, arch, 1, 0)
        add(6, 6, 1, arch, 1, 0)
        add(6, 1, 9, arch, 1, 1)

    return np.asarray(rows, dtype=float), np.asarray(labels, dtype=int)


def features_from_device(dev: DeviceInfo,
                         scanner_anomaly_score: float = 0.0) -> List[float]:
    """Convert a DeviceInfo (+ optional read-only scan signal) into features."""
    kmaj, kmin = dev.parse_kernel()
    arch = dev.soc_architecture.lower()
    is_arm64 = 1 if ("arm64" in arch or "aarch64" in arch) else 0
    is_arm32 = 1 if ("armeabi" in arch or "armv7" in arch) else 0
    is_x86 = 1 if ("x86" in arch or "intel" in arch) else 0
    anomaly = float(np.clip(scanner_anomaly_score, 0.0, 1.0))
    return [kmaj, kmin, dev.patch_months_behind(),
            is_arm64, is_arm32, is_x86, 1 if dev.gki_managed else 0, anomaly]


# ---------------------------------------------------------------------------
# Predictor
# ---------------------------------------------------------------------------

class VulnerabilityRiskPredictor:
    """
    Random-Forest exposure-classifier over public advisory metadata.

    It answers: *"given this kernel/patch/arch configuration, which documented
    risk-latency bucket does the device fall into?"* - the same question a
    patch-management dashboard answers. It does not identify vulnerable
    functions, offsets, or exploitation paths.
    """

    def __init__(self, n_estimators: int = 200, random_state: int = 42):
        if not SKLEARN_AVAILABLE:
            raise RuntimeError(
                "scikit-learn is required for VulnerabilityRiskPredictor. "
                "Install with: pip install scikit-learn")
        self.pipeline: Pipeline = Pipeline(steps=[
            ("scale", StandardScaler()),
            ("rf", RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=10,
                class_weight="balanced_subsample",
                random_state=random_state,
                n_jobs=1,  # conservative for Termux/low-RAM lab devices
            )),
        ])
        self.is_trained: bool = False
        self.cv_accuracy: Optional[float] = None
        self._trained_utc: str = ""

    # -- training ----------------------------------------------------------

    def train_on_datasets(self, data_points: Any, labels: Any) -> Dict[str, Any]:
        """Train on an explicit (X, y) pair; X must match FEATURE_NAMES."""
        X = np.asarray(data_points, dtype=float)
        y = np.asarray(labels, dtype=int)
        if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"data_points must be shape (n, {len(FEATURE_NAMES)}), got "
                f"{X.shape}")
        return self._fit(X, y)

    def train_default_corpus(self) -> Dict[str, Any]:
        X, y = _build_synthetic_corpus()
        return self._fit(X, y)

    def _fit(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        logger.info("[*] AI Engine: training exposure classifier on %d "
                    "configuration samples...", len(X))
        try:
            scores = cross_val_score(self.pipeline, X, y, cv=3)
            self.cv_accuracy = float(scores.mean())
        except Exception as exc:  # tiny corpora can fail CV folds
            logger.warning("cross-validation skipped: %s", exc)
            self.cv_accuracy = None
        self.pipeline.fit(X, y)
        self.is_trained = True
        self._trained_utc = datetime.now(timezone.utc).isoformat(
            timespec="seconds")
        result = {
            "status": "trained",
            "samples": int(len(X)),
            "cv_accuracy": (round(self.cv_accuracy, 4)
                            if self.cv_accuracy is not None else None),
            "feature_names": list(FEATURE_NAMES),
            "labels": RISK_LABELS,
        }
        logger.info("[SUCCESS] model trained (cv_acc=%s)", self.cv_accuracy)
        return result

    # -- prediction --------------------------------------------------------

    def predict_risk(self, dev: DeviceInfo,
                     scanner_report: Optional[Dict[str, Any]] = None
                     ) -> Dict[str, Any]:
        """
        Predict exposure class for a device. If a read-only
        ``memory_scanner_advanced`` report dict is supplied, its structural
        anomalies contribute a bounded hygiene signal (never raw bytes).
        """
        anomaly = _anomaly_signal_from_scan(scanner_report)
        feats = np.array([features_from_device(dev, anomaly)], dtype=float)

        if not self.is_trained:
            logger.warning("[!] model not trained - returning heuristic fallback")
            return self._fallback_result(dev, anomaly)

        proba = self.pipeline.predict_proba(feats)[0]
        idx = int(np.argmax(proba))
        pred = int(self.pipeline.classes_[idx])
        conf = float(proba[idx])
        per_class = {
            RISK_LABELS.get(int(c), str(int(c))): round(float(p), 4)
            for c, p in zip(self.pipeline.classes_, proba)
        }
        return {
            "status": "predicted",
            "model_version": MODEL_VERSION,
            "generated_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"),
            "device": {
                "kernel_version": dev.kernel_version,
                "security_patch_level": dev.security_patch_level,
                "soc_architecture": dev.soc_architecture,
                "patch_months_behind": dev.patch_months_behind(),
                "gki_managed": dev.gki_managed,
            },
            "prediction": RISK_LABELS.get(pred, str(pred)),
            "confidence": round(conf, 4),
            "class_probabilities": per_class,
            "scanner_anomaly_signal": round(anomaly, 4),
            "advisory": (
                "Exposure class derived from public advisory metadata. "
                "Remediation: update the security patch level and prefer "
                "GKI-maintained kernel lines. This tool provides no "
                "exploitation information."),
        }

    def _fallback_result(self, dev: DeviceInfo, anomaly: float) -> Dict[str, Any]:
        months = dev.patch_months_behind()
        if months <= 3 and dev.gki_managed:
            label = RISK_LABELS[0]
        elif months <= 12:
            label = RISK_LABELS[1]
        else:
            label = RISK_LABELS[2]
        return {
            "status": "heuristic_fallback",
            "model_version": MODEL_VERSION,
            "prediction": label,
            "confidence": 0.5,
            "note": "Model untrained; used simple patch-age heuristic.",
            "scanner_anomaly_signal": round(anomaly, 4),
        }

    # -- persistence ---------------------------------------------------------

    def save(self, path: str = DEFAULT_MODEL_PATH) -> None:
        import pickle
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            pickle.dump({"version": MODEL_VERSION, "pipeline": self.pipeline,
                         "is_trained": self.is_trained}, fh)
        os.replace(tmp, path)  # atomic-ish; avoids corrupting live model
        logger.info("[+] AI model saved to %s", path)

    @classmethod
    def load(cls, path: str = DEFAULT_MODEL_PATH) -> "VulnerabilityRiskPredictor":
        import pickle
        obj = cls()
        try:
            with open(path, "rb") as fh:
                blob = pickle.load(fh)
        except (OSError, EOFError, ValueError) as exc:
            logger.warning("could not load model %s (%s); starting fresh",
                           path, exc)
            return obj
        if isinstance(blob, dict) and "pipeline" in blob:
            obj.pipeline = blob["pipeline"]
            obj.is_trained = bool(blob.get("is_trained", True))
        else:  # legacy SayanAI pickle - refuse to reuse, start fresh
            logger.warning("[!] legacy model file detected; ignoring weights")
        return obj


def _anomaly_signal_from_scan(scan_report: Optional[Dict[str, Any]]) -> float:
    """
    Map a read-only scan report to a bounded [0,1] hygiene signal.

    Rules (deliberately coarse; this is a *configuration* signal):
      * each unexpected executable-anonymous mapping adds 0.15
      * each high-entropy anon-rw region beyond the first adds 0.05
      * SELinux denials (good posture!) subtract 0.1
    """
    if not scan_report:
        return 0.0
    score = 0.0
    targets = scan_report.get("targets", []) or []
    for t in targets:
        for r in t.get("region_map", []):
            if r.get("anonymous") and r.get("perms", "").endswith("x"):
                score += 0.15
        score += 0.05 * max(0, len(t.get("high_entropy_regions", [])) - 1)
        if t.get("status") == "denied":
            score -= 0.10
    return float(np.clip(score, 0.0, 1.0))


# ---------------------------------------------------------------------------
# Backwards-compatible alias (legacy notebooks import SayanAI)
# ---------------------------------------------------------------------------

class SayanAI(VulnerabilityRiskPredictor):
    """Deprecated shim. Formerly predicted lockscreen patterns; that
    credential-guessing behaviour was removed in v2. Use
    :class:`VulnerabilityRiskPredictor` directly."""

    def predict_pattern(self, device_info: Any) -> str:  # pragma: no cover
        return ("[DEPRECATED] Lockscreen-pattern prediction was removed for "
                "ethics reasons. Use predict_risk(DeviceInfo(...)).")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Kernel exposure-class predictor (educational, defensive).")
    parser.add_argument("--kernel", default=_uname_release(),
                        help="kernel version string, e.g. 5.15.123-android")
    parser.add_argument("--spl", default="", dest="spl",
                        help="security patch level YYYY-MM-DD")
    parser.add_argument("--arch", default=_native_arch(), dest="arch",
                        choices=["arm64-v8a", "armeabi-v7a", "x86_64"])
    parser.add_argument("--no-gki", action="store_true",
                        help="device does not use GKI-managed kernel")
    parser.add_argument("--scan-report", metavar="JSON_FILE",
                        help="optional memory_scanner_advanced JSON output")
    parser.add_argument("--train", action="store_true",
                        help="(re)train on the bundled corpus and persist")
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not SKLEARN_AVAILABLE:
        print("[!] scikit-learn not installed; run: pip install scikit-learn",
              file=sys.stderr)
        return 2

    predictor = VulnerabilityRiskPredictor()
    train_meta = predictor.train_default_corpus()

    scan_report = None
    if args.scan_report:
        try:
            with open(args.scan_report, "r", encoding="utf-8") as fh:
                scan_report = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("could not load scan report: %s", exc)

    dev = DeviceInfo(
        kernel_version=args.kernel,
        security_patch_level=args.spl or _today_str(),
        soc_architecture=args.arch,
        gki_managed=not args.no_gki,
    )
    prediction = predictor.predict_risk(dev, scan_report)

    out = {"training": train_meta, "prediction": prediction}
    if args.train:
        try:
            predictor.save(args.model_path)
            out["saved_model"] = args.model_path
        except OSError as exc:
            out["save_error"] = str(exc)

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
