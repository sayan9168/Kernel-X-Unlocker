"""
kernel_x.risk_engine
====================

Module 1 - Analysis & Risk Engine.

Responsibilities
----------------
1. ``DeviceFingerprinter``
   Reads *local, unprivileged* system telemetry (``/proc/version``,
   ``/proc/cpuinfo``, ``/sys/devices/soc0/*``, ``/proc/cmdline``,
   ``/boot/config-*`` / ``/proc/config.gz``) and optionally Android system
   properties (via ``getprop`` when present, or an injected mock property
   dictionary in lab/emulator mode) to derive a structured device/kernel
   fingerprint: kernel version series, SoC identification, security-patch
   level, FBE/GKI configuration indicators and observable hardening posture.

2. ``VulnerabilitySurfaceMapper``
   Maps the derived fingerprint against a curated, local knowledge base of
   publicly documented kernel/driver CVE surface areas (eBPF verifier,
   ION/DMA-BUF allocator, binder driver, Dirty Pipe, Dirty COW, ashmem ...)
   and computes a normalized risk score in ``[0.0, 10.0]`` using a
   CVSS-3.1-style impact model with exploit-maturity weighting, patch-level
   recency decay and mitigation credit.

Defensive guarantees
--------------------
* Only world-readable pseudo-files are touched. The toolkit never opens
  ``/dev/mem`` / ``/dev/kmem``, never writes outside its own report directory
  and performs no process-memory access of any kind.
* The knowledge base is purely descriptive (affected version ranges +
  remediation guidance). It deliberately contains **no** exploitation
  material, PoC code or payload logic.
"""

from __future__ import annotations

import glob
import gzip
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("kernel_x.risk_engine")

# ---------------------------------------------------------------------------
# Constants / small helpers
# ---------------------------------------------------------------------------

#: Subsystems whose presence is inferred from the kernel config and which
#: materially change the attack-surface profile of an Android/Linux build.
TRACKED_CONFIG_KEYS: Tuple[str, ...] = (
    "CONFIG_ANDROID_BINDER_IPC",
    "CONFIG_ANDROID_BINDERFS",
    "CONFIG_ASHMEM",
    "CONFIG_ION",
    "CONFIG_DMABUF_HEAPS",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_CGROUPS",
    "CONFIG_SECURITY_SELINUX",
    "CONFIG_SECURITY_APPARMOR",
    "CONFIG_LKDTM",
    "CONFIG_TUN",
    "CONFIG_XFRM",
    "CONFIG_NETFILTER",
    "CONFIG_NFC",
    "CONFIG_USB_GADGET",
    "CONFIG_KALLSYMS",
    "CONFIG_DEVMEM",
    "CONFIG_STAGING",
)

#: Boot-time hardening flags we look for on ``/proc/cmdline``.
HARDENING_CMDLINE_FLAGS: Tuple[str, ...] = (
    "androidboot.verifiedbootstate",
    "androidboot.vbmeta.device_state",
    "androidboot.veritymode",
    "androidboot.flash.locked",
)

_SEVERITY_BANDS: Tuple[Tuple[float, str], ...] = (
    (0.0, "INFORMATIONAL"),
    (1.0, "LOW"),
    (3.0, "MODERATE"),
    (5.0, "ELEVATED"),
    (7.0, "HIGH"),
    (9.0, "CRITICAL"),
)

_PATCH_RECENCY_CEILING_DAYS = 1095  # 3 years -> fully stale


def _read_text(path: str, limit: int = 262_144) -> str:
    """Read a (pseudo-)file defensively; return ``""`` on any failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError as exc:  # missing / permission denied / not a file
        logger.debug("telemetry read skipped for %s: %s", path, exc)
        return ""


def _parse_series(version: str) -> Tuple[int, int]:
    """Extract ``(major, minor)`` from strings like ``5.10.134-abc``."""
    match = re.match(r"^\s*(\d+)\.(\d+)", version or "")
    if not match:
        return (0, 0)
    return (int(match.group(1)), int(match.group(2)))


def _series_key(series: Tuple[int, int]) -> float:
    """Monotonic numeric key for a kernel series (used for range checks)."""
    major, minor = series
    return major * 1000.0 + minor


def severity_band(score: float) -> str:
    """Map a numeric risk score onto a qualitative severity band."""
    label = _SEVERITY_BANDS[0][1]
    for threshold, name in _SEVERITY_BANDS:
        if score >= threshold:
            label = name
    return label


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class KernelTelemetry:
    """Raw low-level observations collected from the audit host."""

    proc_version: str = ""
    uname_release: str = ""
    arch: str = ""
    hostname: str = ""
    cpu_model: str = "unknown"
    cpu_implementer: str = "unknown"
    cpu_part: str = "unknown"
    soc_id: str = "unknown"
    soc_family: str = "unknown"
    l1_config_present: bool = False
    config_options: Dict[str, str] = field(default_factory=dict)
    cmdline_flags: Dict[str, str] = field(default_factory=dict)
    source: str = "live-host"
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeviceFingerprint:
    """Normalized identity of the audited device / kernel build."""

    device_name: str = "Unknown Device"
    manufacturer: str = "Unknown"
    model: str = "unknown-model"
    product: str = "unknown-product"
    android_version: str = ""
    sdk_level: int = 0
    security_patch_level: str = ""
    build_fingerprint: str = ""
    vendor: str = ""
    hardware: str = "unknown"
    architecture: str = "unknown"

    bootloader_state: str = "unknown"
    avb_version: str = "unknown"
    verified_boot_state: str = "unknown"
    verity_mode: str = "unknown"
    sepolicy_debug: bool = False
    developer_options_enabled: Optional[bool] = None

    kernel_version: str = ""
    kernel_series: Tuple[int, int] = (0, 0)
    gki_variant: str = "non-GKI / vendor kernel"
    kernel_build_host: str = "unknown"

    soc_vendor: str = "unknown"
    soc_codename: str = "unknown"
    soc_id: str = "unknown"

    fbe_encryption_type: str = "file"
    fbe_content_mode: str = "aes-256-xts:integrity:aes-256-cts"
    fbe_metadata_mode: str = "aes-256-xts"
    fileencryption_token: str = "none"
    keystore2_backend: str = "unspecified"
    weaver_backend: str = "unspecified"
    gatekeeper_tee_timeout_ms: int = 0

    config_options: Dict[str, str] = field(default_factory=dict)
    hardening_flags: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["kernel_series"] = list(self.kernel_series)
        return data

    @property
    def patch_age_days(self) -> Optional[int]:
        """Age of the declared security-patch level in days (None if unknown)."""
        return parse_patch_age_days(self.security_patch_level)

    def _is_weak_fbe_profile(self) -> bool:
        content = self.fbe_content_mode.lower()
        if not content:
            return True
        return "aes-256-xts" not in content

    @property
    def posture_summary(self) -> Dict[str, Any]:
        """Compact hardening-posture digest used by the mapper and reporter."""
        age = self.patch_age_days
        locked = self.bootloader_state.lower() in {"locked", "green"}
        return {
            "patch_age_days": age,
            "patch_stale": bool(age is not None and age > 180),
            "bootloader_unlocked": self.bootloader_state.lower()
            in {"unlocking", "unlocked", "orange"},
            "verified_boot_ok": self.verified_boot_state.lower() in {"green", "locked"} or locked,
            "sepolicy_debug": self.sepolicy_debug,
            "fde_legacy": self.fbe_encryption_type.lower() in {"", "none", "block", "fde"},
            "weak_fbe_profile": self._is_weak_fbe_profile(),
            "keystore_software": self.keystore2_backend.lower()
            in {"software", "default", "unspecified"},
            "gki": self.gki_variant.startswith("GKI"),
            "kconfig_available": self.extra.get("kconfig_available", "no") == "yes",
        }


@dataclass(slots=True)
class SurfaceFinding:
    """One mapped vulnerability-surface observation for the audited build."""

    cve_id: str
    subsystem: str
    title: str
    cvss_vector: str
    cvss_base: float
    exploit_maturity: str
    affected_range: str
    status: str  # EXPOSED-CANDIDATE | LIKELY-PATCHED | UNVERIFIED
    confidence: float
    contribution: float
    rationale: str
    remediation: str
    reference: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RiskAssessment:
    """Aggregate output of the analysis & risk engine."""

    fingerprint_hash: str
    raw_score: float
    risk_score: float
    severity: str
    subsystem_scores: Dict[str, float]
    findings: List[SurfaceFinding]
    mitigations: Dict[str, float]
    recommendations: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.as_dict() for finding in self.findings]
        return data


# ---------------------------------------------------------------------------
# Patch-level / CVSS utilities
# ---------------------------------------------------------------------------


def parse_patch_age_days(patch_level: str, now: Optional[datetime] = None) -> Optional[int]:
    """Return the age (in days) of a ``YYYY-MM-DD`` security-patch string."""
    if not patch_level:
        return None
    candidate = patch_level.strip().split()[0]
    try:
        parsed = datetime.strptime(candidate, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        logger.debug("unparsable security patch level: %r", patch_level)
        return None
    reference = now or datetime.now(timezone.utc)
    return max(0, (reference - parsed).days)


_CVSS_METRICS: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.70, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_EXPLOIT_MATURITY_WEIGHT: Dict[str, float] = {
    "functional": 1.00,
    "poc": 0.85,
    "weaponized-in-wild": 0.95,
    "theoretical": 0.55,
    "unknown": 0.65,
}


def parse_cvss_vector(vector: str) -> Dict[str, float]:
    """Parse a CVSS 3.1 vector into the metric values needed by the model.

    Supports the ``CVSS:3.1/AV:N/AC:L/...`` form. Unknown tokens are ignored
    (and logged) rather than raising, so a partially malformed knowledge-base
    entry degrades gracefully instead of aborting the scan.
    """
    weights: Dict[str, float] = {}
    body = vector.split(":", 1)[1] if vector.upper().startswith("CVSS:") else vector
    for token in body.split("/"):
        if not token or token.upper().startswith("CVSS"):
            continue
        if ":" not in token:
            logger.debug("ignoring malformed CVSS token %r", token)
            continue
        metric, _, value = token.partition(":")
        table = _CVSS_METRICS.get(metric.upper())
        if table is None:
            logger.debug("ignoring unsupported CVSS metric %r", metric)
            continue
        parsed = table.get(value.upper())
        if parsed is None:
            logger.debug("unknown value %r for CVSS metric %r", value, metric)
            continue
        weights[metric.upper()] = parsed
    return weights


# ---------------------------------------------------------------------------
# Vulnerability-surface knowledge base
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SurfaceEntry:
    """A curated, descriptive knowledge-base record (no exploitation data)."""

    cve_id: str
    subsystem: str
    title: str
    cvss_vector: str
    exploit_maturity: str
    affected_min: float
    affected_max: float
    required_configs: Tuple[str, ...]
    excluded_configs: Tuple[str, ...]
    requires_binder: bool
    requires_ion: bool
    requires_ebpf: bool
    patch_exempt_before: str  # bulletin date that resolved the advisory
    remediation: str
    reference: str

    @staticmethod
    def _fmt(value: float) -> str:
        return f"{int(value // 1000)}.{int(value % 1000)}"

    @property
    def affected_range(self) -> str:
        return f"{self._fmt(self.affected_min)} .. {self._fmt(self.affected_max)}"


def _entry(**kwargs: Any) -> SurfaceEntry:
    defaults: Dict[str, Any] = dict(
        cve_id="N/A",
        subsystem="generic",
        title="unspecified surface",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:L/I:L/A:N",
        exploit_maturity="unknown",
        affected_min=0.0,
        affected_max=99_000.0,
        required_configs=(),
        excluded_configs=(),
        requires_binder=False,
        requires_ion=False,
        requires_ebpf=False,
        patch_exempt_before="",
        remediation="Update to the current Android Security Bulletin level.",
        reference="https://source.android.com/docs/security/bulletin",
    )
    defaults.update(kwargs)
    return SurfaceEntry(**defaults)


#: Curated knowledge base of publicly documented kernel / driver surface areas.
#: Values are *descriptive only*: version ranges, affected subsystems and
#: remediation guidance sourced from public advisories.
DEFAULT_SURFACE_KNOWLEDGE_BASE: Tuple[SurfaceEntry, ...] = (
    _entry(
        cve_id="CVE-2022-0847",
        subsystem="core-mm-pipe",
        title="Dirty Pipe - pipe buffer flag corruption enables overwrite of cached files",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="weaponized-in-wild",
        affected_min=_series_key((5, 8)),
        affected_max=_series_key((5, 16)) + 13.0,
        patch_exempt_before="2022-03-05",
        remediation="Update the kernel to >= 5.10.102 / 5.15.25 / 5.16.11 and apply the "
        "2022-03 Android Security Bulletin; deploy GKI 5.10 LTS builds.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
    ),
    _entry(
        cve_id="CVE-2016-5195",
        subsystem="core-mm",
        title="Dirty COW - race condition in copy-on-write handling of private read-only mappings",
        cvss_vector="CVSS:3.1/AV:L/AC:H/UI:N/S:U/C:N/I:H/A:N",
        exploit_maturity="weaponized-in-wild",
        affected_min=_series_key((0, 0)),
        affected_max=_series_key((4, 9)) + 20.0,
        patch_exempt_before="2017-01-05",
        remediation="Apply the 2017-01 bulletin / upgrade off the 4.9 vendor series.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
    ),
    _entry(
        cve_id="CVE-2017-0405",
        subsystem="binder-ipc",
        title="Binder transaction-failure cleanup leaks kernel pointers to userspace (info leak)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:L/I:N/A:N",
        exploit_maturity="poc",
        affected_min=_series_key((3, 0)),
        affected_max=_series_key((4, 9)) + 90.0,
        requires_binder=True,
        patch_exempt_before="2017-06-05",
        remediation="Disable binder user debug surfaces and update to >= 2017-06 patch level.",
        reference="https://source.android.com/docs/security/bulletin/2017-06-01",
    ),
    _entry(
        cve_id="CVE-2019-2215",
        subsystem="binder-ipc",
        title="Binder use-after-free via freed transaction buffers in /dev/binder context manager",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="weaponized-in-wild",
        affected_min=_series_key((4, 0)),
        affected_max=_series_key((4, 14)) + 90.0,
        requires_binder=True,
        patch_exempt_before="2019-09-05",
        remediation="Update to >= 2019-09 bulletin; prefer GKI 5.4+ where binderfs isolation applies.",
        reference="https://source.android.com/docs/security/bulletin/2019-09-01",
    ),
    _entry(
        cve_id="CVE-2020-0030",
        subsystem="binder-ipc",
        title="Binder out-of-bounds write in iovec copy path (arbitrary write primitive class)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 4)),
        affected_max=_series_key((4, 19)) + 0.0,
        requires_binder=True,
        patch_exempt_before="2020-03-05",
        remediation="Apply >= 2020-03 bulletin; enable KASAN in lab builds to detect regressions.",
        reference="https://source.android.com/docs/security/bulletin/2020-03-01",
    ),
    _entry(
        cve_id="CVE-2019-2025",
        subsystem="ion-dmabuf",
        title="ION improper release of unmapped pages allows DMA-BUF reuse after free (UAF class)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="weaponized-in-wild",
        affected_min=_series_key((4, 0)),
        affected_max=_series_key((5, 4)) + 200.0,
        requires_ion=True,
        excluded_configs=("CONFIG_DMABUF_HEAPS",),
        patch_exempt_before="2020-09-05",
        remediation="Migrate from legacy ION to the dma-buf heaps framework (>= 5.4) and apply "
        "the 2020-09 bulletin.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2019-2025",
    ),
    _entry(
        cve_id="CVE-2020-10721",
        subsystem="ion-dmabuf",
        title="Missing check in ARM dmabuf/ION mmap handling permits cache-attribute mismatch",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:N/I:L/A:L",
        exploit_maturity="theoretical",
        affected_min=_series_key((4, 0)),
        affected_max=_series_key((5, 7)) + 0.0,
        requires_ion=True,
        patch_exempt_before="2020-12-05",
        remediation="Update the ARM SoC BSP; restrict dmabuf heap access via SELinux genfs labels.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-10721",
    ),
    _entry(
        cve_id="CVE-2020-28915",
        subsystem="ebpf-verifier",
        title="eBPF verifier pointer-arithmetic misclassification for truncated arithmetic offsets",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((5, 3)),
        affected_max=_series_key((5, 9)) + 220.0,
        requires_ebpf=True,
        patch_exempt_before="2021-01-05",
        remediation="Update to >= 5.10.x LTS; keep unprivileged BPF disabled on GKI builds.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-28915",
    ),
    _entry(
        cve_id="CVE-2021-3489",
        subsystem="ebpf-verifier",
        title="eBPF signed-divide register-bound miscomputation permits out-of-bounds map access",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 14)),
        affected_max=_series_key((5, 12)) + 40.0,
        requires_ebpf=True,
        patch_exempt_before="2021-09-05",
        remediation="Update to >= 5.12.4 / apply 2021-09 bulletin; disable unprivileged BPF where unused.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-3489",
    ),
    _entry(
        cve_id="CVE-2022-2588",
        subsystem="core-net-route",
        title="Classic eBPF route-key use-after-free in xfrm garbage collection (netns-local)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 4)),
        affected_max=_series_key((5, 18)) + 20.0,
        required_configs=("CONFIG_XFRM",),
        patch_exempt_before="2022-08-05",
        remediation="Update to >= 5.18.19 / apply the 2022-08 bulletin; namespace xfrm exposure.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-2588",
    ),
    _entry(
        cve_id="CVE-2022-2586",
        subsystem="core-net-filter",
        title="cls_route refcount leak in TC route classifier enabling use-after-free",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 0)),
        affected_max=_series_key((5, 18)) + 30.0,
        required_configs=("CONFIG_NETFILTER",),
        patch_exempt_before="2022-08-05",
        remediation="Update to >= 5.18.15; restrict CAP_NET_ADMIN to netd/privileged domains.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-2586",
    ),
    _entry(
        cve_id="CVE-2023-0384",
        subsystem="core-mm-numa",
        title="MPOL_BIND NUMA policy integer underflow leading to out-of-bounds page-table write",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((5, 8)),
        affected_max=_series_key((6, 1)) + 20.0,
        patch_exempt_before="2023-03-05",
        remediation="Update to >= 6.1.21 / apply the 2023-03 bulletin.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-0384",
    ),
    _entry(
        cve_id="CVE-2023-32254",
        subsystem="core-netfilter",
        title="nf_tables anonymous set tracking use-after-free during GC (net-admin reachable)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="weaponized-in-wild",
        affected_min=_series_key((5, 9)),
        affected_max=_series_key((6, 3)) + 2.0,
        required_configs=("CONFIG_NETFILTER",),
        patch_exempt_before="2023-06-05",
        remediation="Update to >= 6.3.2 / apply the 2023-06 bulletin; confine nftables to trusted uids.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-32254",
    ),
    _entry(
        cve_id="CVE-2021-39633",
        subsystem="mediadrm",
        title="MediaCodecs privileged information disclosure through uninitialized memory read",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:N/A:N",
        exploit_maturity="poc",
        affected_min=_series_key((0, 0)),
        affected_max=99_000.0,
        patch_exempt_before="2021-11-05",
        remediation="Apply the 2021-11 bulletin (framework/media codec hardening).",
        reference="https://source.android.com/docs/security/bulletin/2021-11-01",
    ),
    _entry(
        cve_id="CVE-2023-20947",
        subsystem="framework-profiler",
        title="System server information disclosure via profiler state leakage to untrusted apps",
        cvss_vector="CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:N/A:N",
        exploit_maturity="unknown",
        affected_min=_series_key((0, 0)),
        affected_max=99_000.0,
        patch_exempt_before="2023-03-05",
        remediation="Apply the 2023-03 bulletin; restrict ProfilerInfo to privileged callers.",
        reference="https://source.android.com/docs/security/bulletin/2023-03-01",
    ),
    _entry(
        cve_id="CVE-2019-2024",
        subsystem="ashmem",
        title="Ashmem name ioctl information/context handling weakness in legacy memory shim",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:L/I:L/A:N",
        exploit_maturity="theoretical",
        affected_min=_series_key((3, 0)),
        affected_max=99_000.0,
        required_configs=("CONFIG_ASHMEM",),
        patch_exempt_before="2020-06-05",
        remediation="Remove CONFIG_ASHMEM (deprecated since 5.4); migrate to memfd / Binder FDs.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2019-2024",
    ),
    _entry(
        cve_id="CVE-2020-0038",
        subsystem="qualcomm-gpu",
        title="Qualcomm GPU kernel driver memory-corruption class (kgsl ioctl argument handling)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 0)),
        affected_max=_series_key((5, 4)) + 200.0,
        patch_exempt_before="2020-03-05",
        remediation="Obtain the vendor GPU driver update; restrict kgsl device access via SELinux.",
        reference="https://source.android.com/docs/security/bulletin/2020-03-01",
    ),
    _entry(
        cve_id="CVE-2022-20445",
        subsystem="mediatek-hypervisor",
        title="MediaTek hypervisor IPC input-validation weakness (vELM message boundary)",
        cvss_vector="CVSS:3.1/AV:L/AC:L/UI:N/S:C/C:H/I:H/A:H",
        exploit_maturity="unknown",
        affected_min=_series_key((4, 14)),
        affected_max=_series_key((5, 15)) + 100.0,
        patch_exempt_before="2022-07-05",
        remediation="Apply MediaTek OEM BSP update from the 2022-07 bulletin.",
        reference="https://source.android.com/docs/security/bulletin/2022-07-01",
    ),
    _entry(
        cve_id="CVE-2021-0704",
        subsystem="usb-gadget",
        title="USB gadget functionfs improper input validation in vendor descriptor path",
        cvss_vector="CVSS:3.1/AV:P/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 4)),
        affected_max=_series_key((5, 14)) + 100.0,
        required_configs=("CONFIG_USB_GADGET",),
        patch_exempt_before="2021-06-05",
        remediation="Apply the 2021-06 bulletin; disable ADB-over-USB in production builds.",
        reference="https://source.android.com/docs/security/bulletin/2021-06-01",
    ),
    _entry(
        cve_id="CVE-2022-20172",
        subsystem="exynos-lpa",
        title="Samsung Exynos baseband/proxy ABI weakness class affecting AP-side IPC endpoints",
        cvss_vector="CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H",
        exploit_maturity="poc",
        affected_min=_series_key((4, 9)),
        affected_max=_series_key((5, 15)) + 100.0,
        patch_exempt_before="2022-09-05",
        remediation="Apply Samsung maintenance release >= 2022-09; disable dormant modem proxy services.",
        reference="https://security.samsungmobile.com/workSMSrv.do",
    ),
)


# ---------------------------------------------------------------------------
# Device fingerprinter
# ---------------------------------------------------------------------------


class DeviceFingerprinter:
    """Collects and normalizes *static*, unprivileged device telemetry.

    Parameters
    ----------
    mock_properties:
        When supplied, the fingerprinter operates in *lab / emulator* mode and
        sources Android system properties from this dictionary instead of
        invoking ``getprop``. Keys follow Android property naming
        (``ro.build.version.security_patch`` etc.).
    sysroot:
        Optional alternate root prefix (e.g. an extracted ``vendor`` image tree
        or a mounted emulator system directory) so that a non-Android host can
        audit an Android filesystem snapshot statically.
    allow_subprocess:
        Set to ``False`` to forbid the optional ``getprop`` invocation entirely
        (fully offline mode).
    """

    #: Properties relevant to a security-posture audit.
    INTERESTING_PROPERTIES: Tuple[str, ...] = (
        "ro.product.model",
        "ro.product.manufacturer",
        "ro.product.name",
        "ro.product.device",
        "ro.product.vendor.device",
        "ro.product.board",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.build.fingerprint",
        "ro.build.type",
        "ro.hardware",
        "ro.boot.hardware",
        "ro.boot.baseband",
        "ro.boot.bootloader",
        "ro.boot.verifiedbootstate",
        "ro.boot.vbmeta.device_state",
        "ro.boot.vbmeta.avb_version",
        "ro.boot.veritymode",
        "ro.boot.flash.locked",
        "ro.oem_unlock_supported",
        "ro.crypto.type",
        "ro.crypto.state",
        "ro.boot.fileencryption",
        "fbe.content.mode",
        "fbe.metadata.mode",
        "ro.boot.keystore2",
        "ro.boot.weaver",
        "ro.boot.gatekeeper_timeout",
        "ro.bootimage.build.date",
        "ro.kernel.qemu",
        "ro.debuggable",
        "ro.adb.secure",
        "service.adb.root",
        "ro.control_privapp_permissions",
        "ro.soc.model",
        "ro.soc.manufacturer",
    )

    _SDK_TO_ANDROID: Dict[int, str] = {
        29: "10",
        30: "11",
        31: "12",
        32: "12L",
        33: "13",
        34: "14",
        35: "15",
        36: "16",
    }

    #: SoC heuristics keyed by regex over hardware/board/cpu telemetry.
    _SOC_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
        (r"sdm?\s?8\s?gen\s?[1-3]|sm8\d{3}|snapdragon 8", "Qualcomm", "Snapdragon 8-series"),
        (r"sdm?7\d{3}|snapdragon 7", "Qualcomm", "Snapdragon 7-series"),
        (r"sdm?\s?(?:6|4)\d{3}|snapdragon (?:6|4)", "Qualcomm", "Snapdragon mid/entry"),
        (r"msm\d{4}|qcom", "Qualcomm", "MSM-family (legacy)"),
        (r"mt\d{4}|mediatek|dimensity", "MediaTek", "Dimensity/MTK"),
        (r"exynos\s?\d+|universal\d+", "Samsung", "Exynos"),
        (r"tensor|gs1\d|redfin|oriole|panther|cheetah|raven|lynx|tangorpro", "Google", "Pixel family (Tensor)"),
        (r"kirin\s?\d+", "HiSilicon", "Kirin"),
        (r"ranchu|goldfish|qemu|virt-arm", "Emulator", "QEMU goldfish/ranchu virtual SoC"),
    )

    def __init__(
        self,
        mock_properties: Optional[Dict[str, str]] = None,
        sysroot: Optional[str] = None,
        allow_subprocess: bool = True,
    ) -> None:
        self.mock_properties: Dict[str, str] = dict(mock_properties or {})
        self.sysroot: str = (sysroot or "").rstrip("/")
        self.allow_subprocess: bool = allow_subprocess
        self.lab_mode: bool = bool(self.mock_properties)
        self._raw_properties: Dict[str, str] = {}
        self.telemetry: Optional[KernelTelemetry] = None
        self.fingerprint: Optional[DeviceFingerprint] = None

    # -- path helpers ------------------------------------------------------

    def _path(self, relative: str) -> str:
        """Resolve a path inside the optional sysroot (never escapes it)."""
        cleaned = relative.lstrip("/")
        if not self.sysroot:
            return "/" + cleaned
        candidate = os.path.normpath(os.path.join(self.sysroot, cleaned))
        root = os.path.abspath(self.sysroot)
        if os.path.abspath(candidate) != root and not os.path.abspath(candidate).startswith(
            root + os.sep
        ):
            logger.warning("refusing to read path outside sysroot: %s", relative)
            return os.devnull
        return candidate

    # -- property access ---------------------------------------------------

    def read_properties(self) -> Dict[str, str]:
        """Return the effective Android property snapshot (mock or live)."""
        if self._raw_properties:
            return self._raw_properties

        props: Dict[str, str] = {}
        if self.lab_mode:
            props.update(self.mock_properties)
            logger.info("lab mode: sourcing %d properties from mock dictionary", len(props))
        elif self.allow_subprocess and shutil.which("getprop"):
            props.update(self._read_live_properties())
        else:
            logger.info(
                "no property source available; proceeding with kernel telemetry only"
            )

        overlay = self._path("/property_overlays.prop")
        if os.path.isfile(overlay):
            props.update(self._parse_prop_file(_read_text(overlay)))

        self._raw_properties = props
        return props

    def _read_live_properties(self) -> Dict[str, str]:
        try:
            completed = subprocess.run(
                ["getprop"], capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("getprop unavailable: %s", exc)
            return {}
        if completed.returncode != 0:
            logger.debug("getprop exited %d", completed.returncode)
            return {}
        return self._parse_getprop_output(completed.stdout)

    @staticmethod
    def _parse_getprop_output(text: str) -> Dict[str, str]:
        props: Dict[str, str] = {}
        pattern = re.compile(r"^\[([^\]]+)\]:\s*\[(.*)\]\s*$", re.MULTILINE)
        for key, value in pattern.findall(text):
            props[key.strip()] = value.strip()
        return props

    @staticmethod
    def _parse_prop_file(text: str) -> Dict[str, str]:
        props: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
        return props

    def get_prop(self, key: str, default: str = "") -> str:
        return self.read_properties().get(key, default)

    # -- kernel telemetry --------------------------------------------------

    def collect_kernel_telemetry(self) -> KernelTelemetry:
        """Read world-readable kernel pseudo-files and CPU/SoC identifiers."""
        telemetry = KernelTelemetry(
            source="sysroot-snapshot" if self.sysroot else "live-host"
        )

        telemetry.proc_version = _read_text(self._path("/proc/version")).strip()
        release_from_proc = ""
        match = re.search(r"Linux version (\S+)", telemetry.proc_version)
        if match:
            release_from_proc = match.group(1)

        telemetry.uname_release = release_from_proc or platform.release()
        telemetry.arch = platform.machine() or "unknown"
        try:
            telemetry.hostname = platform.node() or "unknown"
        except Exception:  # pragma: no cover - defensive
            telemetry.hostname = "unknown"

        cpuinfo = _read_text(self._path("/proc/cpuinfo"))
        telemetry.cpu_model = self._extract_cpu_model(cpuinfo)
        implementer = re.search(r"CPU implementer\s*:\s*(0x[0-9a-fA-F]+)", cpuinfo)
        part = re.search(r"CPU part\s*:\s*(0x[0-9a-fA-F]+)", cpuinfo)
        telemetry.cpu_implementer = implementer.group(1) if implementer else "unknown"
        telemetry.cpu_part = part.group(1) if part else "unknown"

        telemetry.soc_id = self._first_line(self._path("/sys/devices/soc0/soc_id")) or "unknown"
        telemetry.soc_family = (
            self._first_line(self._path("/sys/devices/soc0/family")) or "unknown"
        )

        telemetry.config_options = self._load_kernel_config()
        telemetry.l1_config_present = bool(telemetry.config_options)
        telemetry.cmdline_flags = self._load_cmdline_flags()

        self.telemetry = telemetry
        return telemetry

    @staticmethod
    def _first_line(path: str) -> str:
        text = _read_text(path)
        return text.splitlines()[0].strip() if text else ""

    @staticmethod
    def _extract_cpu_model(cpuinfo: str) -> str:
        for pattern in (
            r"model name\s*:\s*(.+)",
            r"Hardware name\s*:\s*(.+)",
            r"Processor\s*:\s*(.+)",
            r"cpu model\s*:\s*(.+)",
        ):
            match = re.search(pattern, cpuinfo)
            if match:
                return match.group(1).strip()
        return "unknown"

    def _load_kernel_config(self) -> Dict[str, str]:
        """Load kernel config from ``/proc/config.gz`` or ``/boot/config-*``.

        Returns a mapping of ``CONFIG_*`` names (without prefix) to their
        literal value (``y``/``m``/``n``/string). Absence of both sources is
        normal on production Android builds (``IKCONFIG`` disabled) and is
        itself an informational observation, not an error.
        """
        candidates: List[str] = []
        gz = self._path("/proc/config.gz")
        if os.path.isfile(gz):
            candidates.append(gz)
        candidates.extend(sorted(glob.glob(self._path("/boot/config-*"))))

        for path in candidates:
            try:
                if path.endswith(".gz"):
                    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                        text = handle.read(4_000_000)
                else:
                    text = _read_text(path, limit=4_000_000)
            except (OSError, EOFError, gzip.BadGzipFile) as exc:
                logger.debug("kernel config source %s unreadable: %s", path, exc)
                continue
            parsed = self._parse_kconfig(text)
            if parsed:
                logger.info("loaded %d kconfig symbols from %s", len(parsed), path)
                return parsed
        logger.info(
            "no accessible kconfig source; config-based checks will be UNVERIFIED"
        )
        return {}

    @staticmethod
    def _parse_kconfig(text: str) -> Dict[str, str]:
        config: Dict[str, str] = {}
        enabled = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(\S+)$")
        disabled = re.compile(r"^# CONFIG_([A-Za-z0-9_]+) is not set$")
        for line in text.splitlines():
            line = line.strip()
            match = enabled.match(line)
            if match:
                config[match.group(1)] = match.group(2)
                continue
            match = disabled.match(line)
            if match:
                config[match.group(1)] = "n"
        return config

    def _load_cmdline_flags(self) -> Dict[str, str]:
        cmdline = _read_text(self._path("/proc/cmdline"))
        flags: Dict[str, str] = {}
        for token in cmdline.split():
            key, sep, value = token.partition("=")
            flags[key] = value if sep else "true"
        return flags

    # -- fingerprint assembly ---------------------------------------------

    def build_fingerprint(self) -> DeviceFingerprint:
        """Combine telemetry + properties into a normalized fingerprint."""
        telemetry = self.telemetry or self.collect_kernel_telemetry()
        props = self.read_properties()

        fingerprint = DeviceFingerprint()
        fingerprint.kernel_version = telemetry.uname_release
        fingerprint.kernel_series = _parse_series(telemetry.uname_release)
        fingerprint.architecture = telemetry.arch or "unknown"
        fingerprint.hardware = props.get("ro.hardware", telemetry.soc_family)
        fingerprint.model = props.get("ro.product.model", fingerprint.model)
        fingerprint.manufacturer = props.get(
            "ro.product.manufacturer", fingerprint.manufacturer
        )
        fingerprint.product = props.get("ro.product.name", fingerprint.product)
        fingerprint.device_name = (
            props.get("ro.product.vendor.device")
            or props.get("ro.product.device")
            or fingerprint.model
        )
        fingerprint.build_fingerprint = props.get("ro.build.fingerprint", "")
        fingerprint.vendor = props.get("ro.product.vendor.name", "")

        sdk_raw = props.get("ro.build.version.sdk", "")
        try:
            fingerprint.sdk_level = int(sdk_raw)
        except ValueError:
            fingerprint.sdk_level = 0
        fingerprint.android_version = (
            props.get("ro.build.version.release")
            or self._SDK_TO_ANDROID.get(fingerprint.sdk_level, "")
        )
        fingerprint.security_patch_level = props.get("ro.build.version.security_patch", "")

        fingerprint.bootloader_state = self._derive_bootloader_state(props, telemetry)
        fingerprint.verified_boot_state = props.get(
            "ro.boot.verifiedbootstate",
            telemetry.cmdline_flags.get("androidboot.verifiedbootstate", "unknown"),
        )
        fingerprint.verity_mode = props.get(
            "ro.boot.veritymode",
            telemetry.cmdline_flags.get("androidboot.veritymode", "unknown"),
        )
        fingerprint.avb_version = self._derive_avb_version(fingerprint.sdk_level, props)
        fingerprint.sepolicy_debug = self._derive_sepolicy_debug(
            props, telemetry.config_options
        )
        fingerprint.developer_options_enabled = self._derive_developer_options(props)

        fingerprint.gki_variant = self._derive_gki_variant(fingerprint.kernel_version)
        fingerprint.kernel_build_host = self._derive_build_host(telemetry.proc_version)

        soc_vendor, soc_codename = self._derive_soc(props, telemetry)
        fingerprint.soc_vendor = soc_vendor
        fingerprint.soc_codename = soc_codename
        fingerprint.soc_id = telemetry.soc_id

        fingerprint.fbe_encryption_type = props.get("ro.crypto.type", "file")
        fingerprint.fbe_content_mode = props.get(
            "fbe.content.mode", "aes-256-xts:integrity:aes-256-cts"
        )
        fingerprint.fbe_metadata_mode = props.get("fbe.metadata.mode", "aes-256-xts")
        fingerprint.fileencryption_token = self._derive_fbe_token(
            props, fingerprint.sdk_level
        )
        fingerprint.keystore2_backend = self._derive_keystore_backend(
            props, fingerprint.sdk_level
        )
        fingerprint.weaver_backend = props.get("ro.boot.weaver", "unspecified")
        fingerprint.gatekeeper_tee_timeout_ms = self._derive_gatekeeper_timeout(props)

        fingerprint.config_options = {
            key.replace("CONFIG_", ""): telemetry.config_options.get(
                key.replace("CONFIG_", ""), "unset"
            )
            for key in TRACKED_CONFIG_KEYS
        }
        fingerprint.hardening_flags = {
            key: value
            for key, value in telemetry.cmdline_flags.items()
            if key.startswith("androidboot.") or key in {"selinux", "loop.max_loop_dev"}
        }
        fingerprint.extra = {
            "cpu_model": telemetry.cpu_model,
            "cpu_implementer": telemetry.cpu_implementer,
            "cpu_part": telemetry.cpu_part,
            "build_type": props.get("ro.build.type", ""),
            "debuggable": props.get("ro.debuggable", ""),
            "adb_secure": props.get("ro.adb.secure", ""),
            "emulator_hint": props.get("ro.kernel.qemu", ""),
            "kconfig_available": "yes" if telemetry.l1_config_present else "no",
            "hostname": telemetry.hostname,
        }

        self.fingerprint = fingerprint
        return fingerprint

    # -- derivation helpers ------------------------------------------------

    def _derive_bootloader_state(
        self, props: Dict[str, str], telemetry: KernelTelemetry
    ) -> str:
        explicit = props.get("ro.boot.vbmeta.device_state", "")
        if explicit:
            return explicit
        flash_locked = props.get("ro.boot.flash.locked", "")
        if flash_locked == "1":
            return "locked"
        if flash_locked == "0":
            return "unlocked"
        state = props.get(
            "ro.boot.verifiedbootstate",
            telemetry.cmdline_flags.get("androidboot.verifiedbootstate", ""),
        )
        return {
            "green": "locked",
            "yellow": "unlocked",
            "orange": "unlocked",
            "red": "critical-state",
        }.get(state.lower(), "unknown")

    @staticmethod
    def _derive_avb_version(sdk_level: int, props: Dict[str, str]) -> str:
        declared = props.get("ro.boot.vbmeta.avb_version", "")
        if declared:
            return declared
        if sdk_level >= 30:
            return "AVB 2.0"
        if sdk_level >= 26:
            return "AVB 1.0/1.1"
        if sdk_level:
            return "legacy verity (pre-AVB)"
        return "unknown"

    @staticmethod
    def _derive_sepolicy_debug(
        props: Dict[str, str], config: Dict[str, str]
    ) -> bool:
        if props.get("ro.control_privapp_permissions", "") in {"log", "disable"}:
            return True
        if props.get("ro.build.type", "") == "userdebug" or props.get("ro.debuggable") == "1":
            return True
        return config.get("SECURITY_SELINUX_DISABLE") == "y"

    @staticmethod
    def _derive_developer_options(props: Dict[str, str]) -> Optional[bool]:
        if props.get("service.adb.root") == "1":
            return True
        if props.get("ro.adb.secure") == "0":
            return True
        if props.get("ro.debuggable") == "1":
            return None  # indistinguishable without settings-DB access (not attempted)
        return False

    @staticmethod
    def _derive_gki_variant(kernel_version: str) -> str:
        """Classify the kernel against the GKI (Generic Kernel Image) program.

        Heuristics: GKI builds expose ``-g<sha>`` ablation suffixes or
        ``-androidXX`` markers; mainline LTS vendor kernels typically carry
        OEM suffixes instead.
        """
        if not kernel_version:
            return "unknown"
        lowered = kernel_version.lower()
        if re.search(r"-android\d{2}", lowered) or lowered.startswith("android"):
            return "GKI (versioned kernel image)"
        if re.search(r"-g[0-9a-f]{8,}$", lowered):
            return "GKI (git-hash ablation build)"
        if "gki" in lowered:
            return "GKI (vendor-labelled)"
        return "non-GKI / vendor kernel"

    @staticmethod
    def _derive_build_host(proc_version: str) -> str:
        match = re.search(r"\(([^)]*)\)\s*#\s*\d+", proc_version)
        if not match:
            return "unknown"
        toolchain = match.group(1).strip()
        return toolchain.split()[0] if toolchain.split() else "unknown"

    def _derive_soc(
        self, props: Dict[str, str], telemetry: KernelTelemetry
    ) -> Tuple[str, str]:
        haystack = " ".join(
            filter(
                None,
                (
                    props.get("ro.soc.model", ""),
                    props.get("ro.soc.manufacturer", ""),
                    props.get("ro.hardware", ""),
                    props.get("ro.boot.hardware", ""),
                    props.get("ro.product.board", ""),
                    telemetry.soc_family,
                    telemetry.cpu_model,
                ),
            )
        ).lower()
        for pattern, vendor, codename in self._SOC_PATTERNS:
            if re.search(pattern, haystack):
                return vendor, codename
        if props.get("ro.soc.manufacturer"):
            return props["ro.soc.manufacturer"], props.get("ro.soc.model", "unidentified")
        return ("unknown", "unidentified")

    @staticmethod
    def _derive_fbe_token(props: Dict[str, str], sdk_level: int) -> str:
        declared = props.get("ro.boot.fileencryption", "")
        if declared:
            return declared
        crypto_type = props.get("ro.crypto.type", "")
        if crypto_type == "file":
            if sdk_level >= 33:
                return (
                    "FBE CE/DE profiles with auth-bound keystore2 keys "
                    "(KeyStorage service, metadata encryption)"
                )
            return "FBE CE/DE profiles (direct-boot aware)"
        if crypto_type == "block":
            return "legacy block/FDE profile (pre-Android 11 devices)"
        if props.get("ro.crypto.state") == "encrypted":
            return "encrypted (profile unspecified)"
        return "none/unencrypted"

    @staticmethod
    def _derive_keystore_backend(props: Dict[str, str], sdk_level: int) -> str:
        declared = props.get("ro.boot.keystore2", "")
        if declared:
            return declared
        if sdk_level >= 31:
            return "keystore2 (StrongBox/TEE HAL)"
        if sdk_level >= 28:
            return "keymaster 4.x HAL"
        if sdk_level:
            return "legacy keymaster HAL"
        return "unspecified"

    @staticmethod
    def _derive_gatekeeper_timeout(props: Dict[str, str]) -> int:
        try:
            return int(props.get("ro.boot.gatekeeper_timeout", ""))
        except ValueError:
            return 0

    # -- identity / hashing ------------------------------------------------

    @staticmethod
    def fingerprint_hash(fingerprint: DeviceFingerprint) -> str:
        """Deterministic short hash of the fingerprint (report correlation id)."""
        canonical = repr(sorted(fingerprint.as_dict().items()))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def run(self) -> DeviceFingerprint:
        """Convenience pipeline: collect telemetry then build the fingerprint."""
        started = time.monotonic()
        self.collect_kernel_telemetry()
        fingerprint = self.build_fingerprint()
        logger.info(
            "fingerprint collected in %.3fs (kernel=%s, patch=%s, soc=%s)",
            time.monotonic() - started,
            fingerprint.kernel_version,
            fingerprint.security_patch_level or "n/a",
            fingerprint.soc_codename,
        )
        return fingerprint


# ---------------------------------------------------------------------------
# Vulnerability surface mapper
# ---------------------------------------------------------------------------


class VulnerabilitySurfaceMapper:
    """Maps a :class:`DeviceFingerprint` onto the curated CVE knowledge base.

    Scoring model (documented for reproducibility in academic reports):

    ``impact``
        CVSS-3.1 sub-score approximation from the advisory vector
        (``Impact = 6.42 * ISCBase`` clamped to ``[1.0, 10.0]``).
    ``likelihood``
        ``AV * AC * UI`` reachability product, normalized to ``[0.15, 1.0]``.
    ``maturity``
        Exploit-maturity multiplier (see ``_EXPLOIT_MATURITY_WEIGHT``).
    ``applicability``
        ``0.0`` / partial factor / ``1.0`` depending on whether the kernel
        series and required subsystem configs indicate the surface is absent,
        unverifiable, or present.
    ``decay``
        Patch-recency decay applied to every contribution.

    ``contribution = impact * likelihood * maturity * applicability * decay``

    ``risk_score = 10 * (1 - prod(1 - contribution_i / 10))`` — complementary
    probability aggregation, so many moderate surfaces cannot exceed the
    severity of one directly-reachable high-impact surface, while cumulative
    exposure is still rewarded. A mitigation credit adjusts the aggregate.
    """

    def __init__(
        self,
        knowledge_base: Optional[Sequence[SurfaceEntry]] = None,
        max_surfaces: int = 12,
    ) -> None:
        self.knowledge_base: Tuple[SurfaceEntry, ...] = tuple(
            knowledge_base or DEFAULT_SURFACE_KNOWLEDGE_BASE
        )
        self.max_surfaces = max_surfaces

    # -- tri-state config helpers -----------------------------------------

    @staticmethod
    def _config_enabled(config: Dict[str, str], bare_name: str) -> Optional[bool]:
        """Tri-state config check: ``True`` enabled, ``False`` disabled, ``None`` unknown.

        ``bare_name`` may be given with or without the ``CONFIG_`` prefix.
        """
        key = bare_name.replace("CONFIG_", "")
        value = config.get(key, "unset")
        if value in {"y", "m"}:
            return True
        if value == "n":
            return False
        return None

    def _subsystem_presence(
        self, fingerprint: DeviceFingerprint
    ) -> Dict[str, Optional[bool]]:
        config = fingerprint.config_options
        binder = self._config_enabled(config, "ANDROID_BINDER_IPC")
        if binder is None:
            binder = self._config_enabled(config, "ANDROID_BINDERFS")
        ion = self._config_enabled(config, "ION")
        heaps = self._config_enabled(config, "DMABUF_HEAPS")
        if ion is None and heaps is not None:
            ion = not heaps  # modern builds replaced ION with dma-buf heaps
        if ion is None and fingerprint.sdk_level:
            ion = fingerprint.sdk_level <= 31  # pre-12 builds shipped legacy ION
        ebpf = self._config_enabled(config, "BPF_SYSCALL")
        if ebpf is None and fingerprint.kernel_series >= (4, 4):
            ebpf = True  # Android kernels ship BPF since 4.4 baseline
        return {"binder": binder, "ion": ion, "ebpf": ebpf, "heaps": heaps}

    # -- applicability -----------------------------------------------------

    def _applicability(
        self, entry: SurfaceEntry, fingerprint: DeviceFingerprint
    ) -> Tuple[float, str, str]:
        """Return ``(factor, status, rationale)`` for one knowledge-base entry."""
        series = _series_key(fingerprint.kernel_series)
        if not (entry.affected_min <= series <= entry.affected_max):
            return (
                0.0,
                "NOT-APPLICABLE",
                f"kernel series {fingerprint.kernel_version or 'unknown'} "
                f"({fingerprint.kernel_series[0]}.{fingerprint.kernel_series[1]}) is outside the "
                f"documented affected range {entry.affected_range}",
            )

        presence = self._subsystem_presence(fingerprint)
        reasons: List[str] = [f"kernel series within documented range {entry.affected_range}"]
        factor = 1.0

        if entry.requires_binder:
            state = presence["binder"]
            if state is False:
                return (0.0, "NOT-APPLICABLE", "binder IPC compiled out of the kernel config")
            if state is None:
                factor *= 0.7
                reasons.append("binder presence inferred (kconfig unavailable)")
            else:
                reasons.append("binder IPC present")

        if entry.requires_ion:
            state = presence["ion"]
            if state is False:
                return (
                    0.0,
                    "NOT-APPLICABLE",
                    "legacy ION allocator absent (dma-buf heaps replacement in use)",
                )
            if state is None:
                factor *= 0.7
                reasons.append("ION/dma-buf presence inferred (kconfig unavailable)")
            else:
                reasons.append("legacy ION allocator indicated")

        if entry.requires_ebpf:
            state = presence["ebpf"]
            if state is False:
                return (0.0, "NOT-APPLICABLE", "CONFIG_BPF_SYSCALL disabled")
            if state is None:
                factor *= 0.7
                reasons.append("eBPF availability inferred (kconfig unavailable)")
            else:
                reasons.append("eBPF syscall surface present")

        for name in entry.required_configs:
            state = self._config_enabled(fingerprint.config_options, name)
            if state is False:
                return (0.0, "NOT-APPLICABLE", f"{name} disabled in kernel config")
            if state is None:
                factor *= 0.7
                reasons.append(f"{name} unverifiable (kconfig unavailable)")
            else:
                reasons.append(f"{name} enabled")

        for name in entry.excluded_configs:
            if self._config_enabled(fingerprint.config_options, name) is True:
                return (
                    0.0,
                    "NOT-APPLICABLE",
                    f"mitigating replacement {name} present in kernel config",
                )

        patch = fingerprint.security_patch_level
        if entry.patch_exempt_before and patch:
            if patch >= entry.patch_exempt_before:
                reasons.append(
                    f"declared patch level {patch} postdates the {entry.patch_exempt_before} "
                    "fix bulletin - remediation expected present"
                )
                factor *= 0.25
                status = "LIKELY-PATCHED"
            else:
                reasons.append(
                    f"declared patch level {patch} predates the {entry.patch_exempt_before} "
                    "fix bulletin"
                )
                status = "EXPOSED-CANDIDATE"
        else:
            if not patch:
                factor *= 0.85
                reasons.append("security patch level unavailable; exposure unconfirmed")
            status = "UNVERIFIED"

        if status == "UNVERIFIED" and factor < 0.5:
            status = "LIKELY-PATCHED"
        return (factor, status, "; ".join(reasons))

    # -- scoring components -------------------------------------------------

    @staticmethod
    def _impact(entry: SurfaceEntry) -> float:
        metrics = parse_cvss_vector(entry.cvss_vector)
        confidentiality = metrics.get("C", 0.22)
        integrity = metrics.get("I", 0.22)
        availability = metrics.get("A", 0.0)
        isc_base = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability))
        impact = 6.42 * isc_base
        return min(10.0, max(1.0, impact))

    @staticmethod
    def _likelihood(entry: SurfaceEntry) -> float:
        metrics = parse_cvss_vector(entry.cvss_vector)
        attack_vector = metrics.get("AV", 0.55)
        complexity = metrics.get("AC", 0.77)
        user_interaction = metrics.get("UI", 0.85)
        raw = attack_vector * complexity * user_interaction
        return min(1.0, max(0.15, raw / 0.85))

    @staticmethod
    def _patch_decay(fingerprint: DeviceFingerprint) -> Tuple[float, str]:
        age = fingerprint.patch_age_days
        if age is None:
            return 0.9, "patch recency unknown (neutral decay applied)"
        if age <= 90:
            return 0.45, f"patch level {age}d old - actively maintained"
        if age <= 365:
            return 0.75, f"patch level {age}d old - moderately stale"
        excess = min(1.0, (age - 365) / _PATCH_RECENCY_CEILING_DAYS)
        decay = 0.75 + 0.25 * excess
        return decay, f"patch level {age}d old - stale"

    def _mitigation_credit(self, fingerprint: DeviceFingerprint) -> Dict[str, float]:
        posture = fingerprint.posture_summary
        config = fingerprint.config_options
        credit: Dict[str, float] = {}
        credit["verified_boot"] = 0.12 if posture["verified_boot_ok"] else 0.0
        credit["selinux_enforcing"] = (
            0.15
            if self._config_enabled(config, "SECURITY_SELINUX") is True
            and not posture["sepolicy_debug"]
            else 0.05
        )
        credit["modern_fbe"] = (
            0.10
            if not posture["fde_legacy"] and not posture["weak_fbe_profile"]
            else 0.0
        )
        credit["gki_lts"] = 0.08 if posture["gki"] else 0.0
        credit["recent_patch"] = (
            0.10
            if posture["patch_age_days"] is not None and posture["patch_age_days"] <= 90
            else 0.0
        )
        credit["dmabuf_heaps"] = (
            0.05 if self._config_enabled(config, "DMABUF_HEAPS") is True else 0.0
        )
        penalties = 0.0
        if posture["bootloader_unlocked"]:
            penalties += 0.10
        if posture["sepolicy_debug"]:
            penalties += 0.08
        if posture["fde_legacy"]:
            penalties += 0.12
        if posture["weak_fbe_profile"]:
            penalties += 0.06
        credit["risk_penalties"] = -penalties
        return credit

    # -- public API ----------------------------------------------------------

    def map_surface(self, fingerprint: DeviceFingerprint) -> List[SurfaceFinding]:
        """Evaluate every knowledge-base entry against the fingerprint."""
        findings: List[SurfaceFinding] = []
        decay, decay_note = self._patch_decay(fingerprint)

        for entry in self.knowledge_base:
            factor, status, rationale = self._applicability(entry, fingerprint)
            if status == "NOT-APPLICABLE":
                continue
            impact = self._impact(entry)
            likelihood = self._likelihood(entry)
            maturity = _EXPLOIT_MATURITY_WEIGHT.get(entry.exploit_maturity.lower(), 0.65)
            contribution = round(
                min(10.0, impact * likelihood * maturity * factor * decay), 3
            )
            findings.append(
                SurfaceFinding(
                    cve_id=entry.cve_id,
                    subsystem=entry.subsystem,
                    title=entry.title,
                    cvss_vector=entry.cvss_vector,
                    cvss_base=round(impact, 2),
                    exploit_maturity=entry.exploit_maturity,
                    affected_range=entry.affected_range,
                    status=status,
                    confidence=round(min(1.0, factor), 3),
                    contribution=contribution,
                    rationale=f"{rationale}; {decay_note}",
                    remediation=entry.remediation,
                    reference=entry.reference,
                )
            )

        findings.sort(key=lambda item: item.contribution, reverse=True)
        return findings[: self.max_surfaces]

    def assess(self, fingerprint: DeviceFingerprint) -> RiskAssessment:
        """Produce the full normalized risk assessment for a fingerprint."""
        findings = self.map_surface(fingerprint)
        credit = self._mitigation_credit(fingerprint)
        decay, decay_note = self._patch_decay(fingerprint)

        subsystem_scores: Dict[str, float] = {}
        for finding in findings:
            subsystem_scores[finding.subsystem] = round(
                subsystem_scores.get(finding.subsystem, 0.0) + finding.contribution, 3
            )

        complementary = 1.0
        for finding in findings:
            complementary *= 1.0 - (finding.contribution / 10.0)
        raw_score = 10.0 * (1.0 - complementary)

        net_credit = sum(credit.values())
        adjusted = raw_score * (1.0 + max(-0.6, min(0.35, net_credit)))
        risk_score = round(min(10.0, max(0.0, adjusted)), 2)

        recommendations = self._recommendations(fingerprint, findings, credit)
        metadata = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "knowledge_base_size": len(self.knowledge_base),
            "surface_candidates": len(findings),
            "raw_aggregated_score": round(raw_score, 3),
            "mitigation_net_credit": round(net_credit, 3),
            "patch_decay": round(decay, 3),
            "patch_decay_note": decay_note,
            "scoring_model": (
                "CVSS3.1-impact x reachability x exploit-maturity x applicability "
                "x patch-decay, complement-aggregated, mitigation-adjusted"
            ),
            "posture": fingerprint.posture_summary,
        }

        return RiskAssessment(
            fingerprint_hash=DeviceFingerprinter.fingerprint_hash(fingerprint),
            raw_score=round(raw_score, 3),
            risk_score=risk_score,
            severity=severity_band(risk_score),
            subsystem_scores=subsystem_scores,
            findings=findings,
            mitigations=credit,
            recommendations=recommendations,
            metadata=metadata,
        )

    @staticmethod
    def _recommendations(
        fingerprint: DeviceFingerprint,
        findings: Sequence[SurfaceFinding],
        credit: Dict[str, float],
    ) -> List[str]:
        """Derive prioritized, defensive remediation guidance."""
        recommendations: List[str] = [
            "Track the latest Android Security Bulletin and OTA baseline; patch age is the "
            "single strongest predictor of aggregate kernel exposure."
        ]
        top_subsystems = sorted(
            {finding.subsystem for finding in findings if finding.contribution >= 2.0}
        )
        if top_subsystems:
            recommendations.append(
                "Prioritize monitoring/verification for the highest-contributing subsystems: "
                + ", ".join(top_subsystems)
                + "."
            )
        if any(finding.cve_id == "CVE-2022-0847" for finding in findings):
            recommendations.append(
                "Verify the 2022-03 (Dirty Pipe) fix is present in the running kernel build via "
                "the vendor changelog rather than the version string alone."
            )
        if any(finding.subsystem == "ion-dmabuf" for finding in findings):
            recommendations.append(
                "Prefer builds that replace legacy ION with dma-buf heaps and constrain heap "
                "access with SELinux genfs contexts."
            )
        if any(finding.subsystem == "ebpf-verifier" for finding in findings):
            recommendations.append(
                "Set kernel.unprivileged_bpf_disabled=1 (or 2 on >= 5.8) and restrict BPF "
                "program loading to trusted domains."
            )
        posture = fingerprint.posture_summary
        if posture["fde_legacy"]:
            recommendations.append(
                "Migrate off legacy block/full-disk encryption to per-file FBE with metadata "
                "encryption (aes-256-xts)."
            )
        if posture["weak_fbe_profile"]:
            recommendations.append(
                "Enforce the modern FBE content profile aes-256-xts with AES-256-CTS integrity; "
                "avoid AES-128-CBC policies."
            )
        if posture["bootloader_unlocked"]:
            recommendations.append(
                "Re-lock the bootloader for production evaluation units: an unlocked device "
                "invalidates AVB trust assumptions across the whole assessment."
            )
        if posture["sepolicy_debug"]:
            recommendations.append(
                "Ship user builds with enforcing SELinux and log-only policy debugging disabled."
            )
        if credit.get("verified_boot", 0.0) <= 0.0:
            recommendations.append(
                "Restore/verify the AVB chain-of-trust (vbmeta digest, rollback protection "
                "indexes) before drawing conclusions about boot-path integrity."
            )
        if fingerprint.config_options.get("KALLSYMS") == "y":
            recommendations.append(
                "Consider CONFIG_KALLSYMS=n (or restricted access) on production builds to "
                "reduce kernel-symbol information disclosure."
            )
        recommendations.append(
            "All findings are *candidates* derived from static version/config correlation; "
            "confirm each via vendor source changelogs before publication."
        )
        return recommendations


__all__ = [
    "KernelTelemetry",
    "DeviceFingerprint",
    "SurfaceFinding",
    "RiskAssessment",
    "SurfaceEntry",
    "DeviceFingerprinter",
    "VulnerabilitySurfaceMapper",
    "DEFAULT_SURFACE_KNOWLEDGE_BASE",
    "TRACKED_CONFIG_KEYS",
    "severity_band",
    "parse_patch_age_days",
    "parse_cvss_vector",
]
