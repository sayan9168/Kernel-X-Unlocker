"""
kernel_x.simulator
==================

Module 2 - Dry-Run Simulation Environment.

Everything in this module is a **pure in-process model**. No hardware-backed
service (KeyMint/keystore2, Gatekeeper, Weaver), no kernel interface, and no
protected filesystem path is contacted. The classes exist to let researchers
reason about *how* Android's security boundaries are specified to behave under
different configuration states, and to produce auditable event timelines for
academic reports.

Components
----------
- ``KeystoreSimulator``: models keystore2 key blobs, authorization lists,
  simulated cryptographic handles, TEE/StrongBox backends, anti-rollback
  boot state, Gatekeeper/Weaver rate-limiting and FBE CE/DE storage unlock
  semantics. Handles are deterministic mock digests - they are *not* real
  keys and cannot decrypt anything.
- ``ScenarioRunner``: executes "what-if" scenario scripts against the
  simulator (FBE flag states, lockscreen credential verifiers, direct-boot
  visibility, auth-bound key lifetimes) and records a monotonic behaviour
  timeline that the reporter can render.

Ethical constraints enforced by design
--------------------------------------
* There is no code path that attempts to bypass, defeat or brute-force a real
  verifier; scenarios only *model* the documented AOSP state machines
  (retry counters, backoff timers, SID binding, locked-storage semantics).
* Credential inputs are compared against an injected mock credential store so
  the model can demonstrate policy outcomes (e.g., "auth-bound key requires a
  successful Gatekeeper verification within its validity duration").
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger("kernel_x.simulator")


# ---------------------------------------------------------------------------
# Enumerations & result types
# ---------------------------------------------------------------------------


class KeyAlgorithm(str, Enum):
    AES_GCM = "AES-256-GCM"
    AES_XTS = "AES-256-XTS"   # FBE content encryption class
    AES_CBC = "AES-256-CBC"
    HMAC_SHA256 = "HMAC-SHA-256"
    ECDSA_P256 = "ECDSA-P256"
    ED25519 = "ED25519"


class SecurityLevel(str, Enum):
    SOFTWARE = "Software"
    KEYBOX = "Keybox"
    TRUSTED_ENVIRONMENT = "TrustedEnvironment"
    STRONGBOX = "StrongBox"


class BootState(str, Enum):
    VERIFIED = "verified"          # AVB green / device locked
    SELF_SIGNED = "self-signed"    # custom vbmeta (yellow)
    UNVERIFIED = "unverified"      # unlocked bootloader (orange)


class StorageDomain(str, Enum):
    DE = "credential-encrypted-direct"  # Direct Enterprise: unlocked at boot
    CE = "credential-encrypted"         # Credential Encrypted: needs user auth


class GateStatus(str, Enum):
    GRANTED = "GRANTED"
    DENIED_POLICY = "DENIED_POLICY"
    DENIED_AUTH_REQUIRED = "DENIED_AUTH_REQUIRED"
    DENIED_LOCKED = "DENIED_LOCKED"        # rate limited / backoff active
    DENIED_STORAGE_LOCKED = "DENIED_STORAGE_LOCKED"
    ERROR_UNKNOWN_KEY = "ERROR_UNKNOWN_KEY"


@dataclass(slots=True)
class SimulatedResult:
    """Uniform outcome object returned by every simulator operation."""

    success: bool
    status: GateStatus
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )

    def as_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["status"] = self.status.value
        return out


@dataclass(slots=True)
class TimelineEvent:
    """One recorded step of a simulated interaction."""

    t_offset: float
    actor: str
    action: str
    outcome: str
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Key model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SimulatedKeyBlob:
    """A *mock* key record. Contains no usable secret material."""

    alias: str
    algorithm: KeyAlgorithm
    security_level: SecurityLevel
    creation_time: int
    key_id_hash: str                     # public identifier digest (not a secret)
    auth_bound: bool
    sid_required: int                    # simulated Secure User ID
    timeout_millis: int                  # auth validity window (0 => per-use)
    allow_while_locked: bool             # DURING-BOOT-LOCKED authorisation
    storage_domain: StorageDomain
    anti_rollback_boot_state: BootState
    rollback_resistance: bool
    rollback_protection: bool
    tags: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["algorithm"] = self.algorithm.value
        data["security_level"] = self.security_level.value
        data["storage_domain"] = self.storage_domain.value
        data["anti_rollback_boot_state"] = self.anti_rollback_boot_state.value
        return data


# ---------------------------------------------------------------------------
# Keystore simulator
# ---------------------------------------------------------------------------


class KeystoreSimulator:
    """In-memory model of keystore2 / KeyMint + Gatekeeper + Weaver semantics.

    Parameters
    ----------
    seed:
        Deterministic namespace for all mock handle/key digests. Different
        seeds produce different (but reproducible) pseudo-IDs.
    boot_state:
        Initial AVB state used for rollback-resistant key evaluation.
    weaver_available:
        Whether a Weaver HAL (secure storage with throttling) is modelled.
        When absent, Gatekeeper-only throttling applies - mirroring devices
        without a dedicated secure element for spare-password checks.
    clock:
        Injectable clock (``Callable[[], float]``) enabling fast-forward
        experiments in scenarios without sleeping.
    """

    MAX_FAILED_ATTEMPTS = 5           # Gatekeeper-ish temporary lock threshold
    BACKOFF_BASE_SECONDS = 30         # first backoff after threshold
    BACKOFF_FACTOR = 2                # exponential retry penalty

    def __init__(
        self,
        seed: str = "kernel-x-lab",
        boot_state: BootState = BootState.VERIFIED,
        weaver_available: bool = True,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.seed = seed.encode("utf-8")
        self.boot_state = boot_state
        self.weaver_available = weaver_available
        self._clock = clock or time.monotonic
        self._t0 = self._clock()

        self.keys: Dict[str, SimulatedKeyBlob] = {}
        self.device_unlocked: bool = False
        self.user_sid: int = 0
        self.failed_attempts: int = 0
        self.lockout_until: float = 0.0
        self.auth_granted_at: Optional[float] = None
        self._mock_credentials: Dict[str, str] = {}
        self.timeline: List[TimelineEvent] = []

    # -- internal helpers ---------------------------------------------------

    def now(self) -> float:
        """Simulated elapsed seconds since construction."""
        return round(self._clock() - self._t0, 6)

    def _digest(self, *parts: Any) -> str:
        material = b"|".join(
            part.encode("utf-8") if isinstance(part, str) else str(part).encode("utf-8")
            for part in parts
        )
        return hmac.new(self.seed, material, hashlib.sha256).hexdigest()

    def record(self, actor: str, action: str, outcome: str, note: str = "") -> TimelineEvent:
        event = TimelineEvent(self.now(), actor, action, outcome, note)
        self.timeline.append(event)
        logger.debug("[sim t=%.3f] %s %s -> %s", event.t_offset, actor, action, outcome)
        return event

    @staticmethod
    def _coerce(enum_cls: type, value: Any) -> Any:
        """Accept an enum member, its value, or its member *name*."""
        if isinstance(value, enum_cls):
            return value
        try:
            return enum_cls(value)
        except ValueError:
            pass
        if isinstance(value, str):
            try:
                return enum_cls[value.upper().replace("-", "_").replace(" ", "_")]
            except KeyError:
                pass
        raise ScenarioError(f"'{value}' is not a valid {enum_cls.__name__}")

    # -- credential model ----------------------------------------------------

    def provision_mock_credential(self, owner_alias: str, credential: str) -> None:
        """Store a *mock* owner credential hash so scenarios can 'verify' it.

        Only the seeded HMAC digest is kept; the plaintext credential is never
        retained by the simulator.
        """
        self._mock_credentials[owner_alias] = self._digest("cred", credential)
        self.record("provisioner", "set-mock-credential", "OK", f"alias={owner_alias}")

    def _verify_credential(self, credential: str) -> bool:
        digest = self._digest("cred", credential)
        return digest in set(self._mock_credentials.values())

    # -- key lifecycle -------------------------------------------------------

    def generate_key(
        self,
        alias: str,
        algorithm: KeyAlgorithm = KeyAlgorithm.AES_GCM,
        security_level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        auth_bound: bool = False,
        timeout_millis: int = 15_000,
        allow_while_locked: bool = False,
        storage_domain: StorageDomain = StorageDomain.CE,
        rollback_resistance: bool = False,
        rollback_protection: bool = False,
    ) -> SimulatedResult:
        """Create a simulated key record (no real key material is produced)."""
        # Coerce literals so scenario scripts may pass enum names or values.
        algorithm = self._coerce(KeyAlgorithm, algorithm)
        security_level = self._coerce(SecurityLevel, security_level)
        storage_domain = self._coerce(StorageDomain, storage_domain)
        if alias in self.keys:
            self.record("keystore2", f"generate:{alias}", "ALREADY_EXISTS")
            return SimulatedResult(
                False, GateStatus.DENIED_POLICY, f"key alias '{alias}' already exists"
            )
        blob = SimulatedKeyBlob(
            alias=alias,
            algorithm=algorithm,
            security_level=security_level,
            creation_time=int(time.time()),
            key_id_hash=self._digest("key", alias, algorithm.value)[:32],
            auth_bound=auth_bound,
            sid_required=self.user_sid if auth_bound else 0,
            timeout_millis=timeout_millis if auth_bound else 0,
            allow_while_locked=allow_while_locked,
            storage_domain=storage_domain,
            anti_rollback_boot_state=self.boot_state if rollback_resistance else BootState.VERIFIED,
            rollback_resistance=rollback_resistance,
            rollback_protection=rollback_protection,
            tags={"purposes": ["ENCRYPT", "DECRYPT"], "padding": "NONE", "origin": "GENERATED"},
        )
        self.keys[alias] = blob
        self.record(
            "keystore2",
            f"generate:{alias}",
            "OK",
            f"{algorithm.value}@{security_level.value} auth_bound={auth_bound}",
        )
        return SimulatedResult(
            True,
            GateStatus.GRANTED,
            "simulated key generated",
            {"alias": alias, "key_id_hash": blob.key_id_hash, "blob_length": 144},
        )

    def get_key_info(self, alias: str) -> SimulatedResult:
        blob = self.keys.get(alias)
        if blob is None:
            return SimulatedResult(
                False, GateStatus.ERROR_UNKNOWN_KEY, f"no key for alias '{alias}'"
            )
        return SimulatedResult(True, GateStatus.GRANTED, "metadata", blob.as_dict())

    def list_keys(self) -> List[Dict[str, Any]]:
        return [blob.as_dict() for blob in self.keys.values()]

    # -- authentication path --------------------------------------------------

    def verify_lockscreen_credential(self, credential: str) -> SimulatedResult:
        """Model the Gatekeeper(+Weaver) verification flow and its throttling.

        This is a behavioural model of the documented state machine: correct
        mock credentials advance the SID counter and unlock CE storage; wrong
        ones increment the failure counter and trigger exponential backoff.
        Nothing here attacks a real verifier.
        """
        if self.lockout_until > self.now():
            remaining = round(self.lockout_until - self.now(), 3)
            self.record("gatekeeper", "verify-credential", "LOCKED", f"backoff {remaining}s")
            return SimulatedResult(
                False,
                GateStatus.DENIED_LOCKED,
                f"temporary lockout active; retry in {remaining}s",
                {"failed_attempts": self.failed_attempts},
            )

        ok = self._verify_credential(credential)
        if ok:
            self.failed_attempts = 0
            self.user_sid += 1
            self.auth_granted_at = self.now()
            was_locked = not self.device_unlocked
            self.device_unlocked = True
            self.record(
                "gatekeeper",
                "verify-credential",
                "VERIFIED",
                f"sid->{self.user_sid}; CE storage {'unlocked' if was_locked else 'already unlocked'}",
            )
            return SimulatedResult(
                True,
                GateStatus.GRANTED,
                "credential verified (simulated)",
                {"sid": self.user_sid, "ce_storage_unlocked": True},
            )

        self.failed_attempts += 1
        if self.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
            backoff = self.BACKOFF_BASE_SECONDS * (
                self.BACKOFF_FACTOR ** (self.failed_attempts - self.MAX_FAILED_ATTEMPTS)
            )
            cap = 30 * 60 if self.weaver_available else 24 * 3600
            backoff = min(backoff, cap)
            self.lockout_until = self.now() + backoff
            self.record(
                "gatekeeper",
                "verify-credential",
                "RETRY_TIMEOUT",
                f"attempt {self.failed_attempts}; backoff {backoff}s "
                f"(weaver={'on' if self.weaver_available else 'off'})",
            )
            return SimulatedResult(
                False,
                GateStatus.DENIED_LOCKED,
                f"too many failures; simulated retry timeout {backoff}s",
                {"failed_attempts": self.failed_attempts, "backoff_seconds": backoff},
            )
        self.record(
            "gatekeeper", "verify-credential", "FAILED", f"attempt {self.failed_attempts}"
        )
        return SimulatedResult(
            False,
            GateStatus.DENIED_POLICY,
            "credential rejected (simulated)",
            {"failed_attempts": self.failed_attempts},
        )

    def lock_device(self) -> SimulatedResult:
        """Model screen lock: CE storage becomes unavailable again."""
        self.device_unlocked = False
        self.auth_granted_at = None
        self.record("systemui", "lock-device", "LOCKED", "CE storage re-sealed")
        return SimulatedResult(True, GateStatus.GRANTED, "device locked")

    # -- crypto handle operations ---------------------------------------------

    def begin_operation(self, alias: str, purpose: str = "ENCRYPT") -> SimulatedResult:
        """Issue a simulated cryptographic handle after policy evaluation."""
        blob = self.keys.get(alias)
        if blob is None:
            self.record("keystore2", f"begin:{alias}", "UNKNOWN_KEY")
            return SimulatedResult(
                False, GateStatus.ERROR_UNKNOWN_KEY, f"no key for alias '{alias}'"
            )

        denial = self._evaluate_policy(blob)
        if denial is not None:
            status, reason, extra = denial
            self.record("keystore2", f"begin:{alias}:{purpose}", status.value, reason)
            return SimulatedResult(False, status, reason, extra)

        handle = int(self._digest("op", alias, purpose, self.now())[:8], 16)
        op_token = self._digest("authtoken", alias, handle)
        self.record(
            "keystore2",
            f"begin:{alias}:{purpose}",
            "GRANTED",
            f"handle=0x{handle:08x} level={blob.security_level.value}",
        )
        return SimulatedResult(
            True,
            GateStatus.GRANTED,
            "operation began (simulated handle)",
            {
                "handle": handle,
                "handle_hex": f"0x{handle:08x}",
                "operation_token_sha256": op_token,
                "requires_confirmation": blob.auth_bound,
            },
        )

    def confirm_operation(
        self, handle_hex: str, sid: Optional[int] = None
    ) -> SimulatedResult:
        """Model KeyMint operation confirmation bound to a verified SID."""
        try:
            handle = int(handle_hex, 16)
        except ValueError:
            return SimulatedResult(
                False, GateStatus.DENIED_POLICY, "malformed handle literal"
            )
        effective_sid = sid if sid is not None else self.user_sid
        if not self.device_unlocked or effective_sid == 0:
            self.record("keystore2", f"confirm:{handle_hex}", "DENIED_AUTH_REQUIRED")
            return SimulatedResult(
                False,
                GateStatus.DENIED_AUTH_REQUIRED,
                "confirmation requires an unlocked device with a valid SID",
            )
        self.record("keystore2", f"confirm:{handle_hex}", "CONFIRMED", f"sid={effective_sid}")
        return SimulatedResult(
            True,
            GateStatus.GRANTED,
            "operation confirmed (simulated)",
            {"handle_hex": handle_hex, "sid": effective_sid},
        )

    def finish_operation(self, handle_hex: str, payload_label: str = "sample-payload") -> SimulatedResult:
        """Return a deterministic mock MAC/digest for a held handle.

        The value is a keyed digest over the *label string only* - it is a
        modelling artefact for timelines, not ciphertext and not reversible.
        """
        try:
            handle = int(handle_hex, 16) if not handle_hex.startswith("0x") else int(handle_hex, 16)
        except ValueError:
            return SimulatedResult(False, GateStatus.DENIED_POLICY, "malformed handle literal")
        mock_tag = self._digest("finish", handle, payload_label)
        self.record("keystore2", f"finish:{payload_label}", "OK", f"tag={mock_tag[:16]}…")
        return SimulatedResult(
            True,
            GateStatus.GRANTED,
            "operation finished (mock tag emitted)",
            {"mock_auth_tag": mock_tag, "payload_label": payload_label},
        )

    def delete_key(self, alias: str) -> SimulatedResult:
        if alias not in self.keys:
            return SimulatedResult(
                False, GateStatus.ERROR_UNKNOWN_KEY, f"no key for alias '{alias}'"
            )
        del self.keys[alias]
        self.record("keystore2", f"delete:{alias}", "OK")
        return SimulatedResult(True, GateStatus.GRANTED, "key deleted (simulated)")

    # -- policy engine ----------------------------------------------------------

    def _evaluate_policy(
        self, blob: SimulatedKeyBlob
    ) -> Optional[Tuple[GateStatus, str, Dict[str, Any]]]:
        """Return ``(status, reason, extra)`` when access must be denied."""
        # 1. Rollback-resistant keys require the matching AVB boot state.
        if blob.rollback_resistance and blob.anti_rollback_boot_state != self.boot_state:
            return (
                GateStatus.DENIED_POLICY,
                "rollback-resistant key rejected: current AVB boot state "
                f"'{self.boot_state.value}' != provisioning state "
                f"'{blob.anti_rollback_boot_state.value}'",
                {"boot_state": self.boot_state.value},
            )

        # 2. Storage-domain availability (FBE semantics).
        if blob.storage_domain is StorageDomain.CE and not self.device_unlocked:
            return (
                GateStatus.DENIED_STORAGE_LOCKED,
                "CE key unavailable while credential storage is locked",
                {"domain": blob.storage_domain.value},
            )

        # 3. Auth-bound key checks.
        if blob.auth_bound:
            if self.user_sid < blob.sid_required:
                return (
                    GateStatus.DENIED_AUTH_REQUIRED,
                    "SID older than key requirement - re-authentication needed",
                    {"required_sid": blob.sid_required, "current_sid": self.user_sid},
                )
            if self.auth_granted_at is None:
                return (
                    GateStatus.DENIED_AUTH_REQUIRED,
                    "no successful verification in this session",
                    {},
                )
            elapsed = (self.now() - self.auth_granted_at) * 1000.0
            if elapsed > blob.timeout_millis:
                return (
                    GateStatus.DENIED_AUTH_REQUIRED,
                    f"auth validity window expired ({int(elapsed)}ms > "
                    f"{blob.timeout_millis}ms)",
                    {"elapsed_ms": int(elapsed)},
                )
            if not blob.allow_while_locked and not self.device_unlocked:
                return (
                    GateStatus.DENIED_STORAGE_LOCKED,
                    "key lacks DURING-BOOT-LOCKED authorisation on a locked device",
                    {},
                )
        return None

    # -- snapshot ----------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        return {
            "boot_state": self.boot_state.value,
            "device_unlocked": self.device_unlocked,
            "user_sid": self.user_sid,
            "failed_attempts": self.failed_attempts,
            "lockout_active": self.lockout_until > self.now(),
            "keys": self.list_keys(),
            "elapsed_s": self.now(),
            "timeline": [event.as_dict() for event in self.timeline],
        }


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------


class ScenarioError(RuntimeError):
    """Raised for malformed scenario definitions (never for policy denials)."""


@dataclass(slots=True)
class ScenarioStep:
    name: str
    call: Tuple[str, ...]  # ("method", arg, arg...) resolved against the simulator
    expect_success: Optional[bool] = None
    expect_status: Optional[str] = None
    note: str = ""


@dataclass(slots=True)
class ScenarioOutcome:
    scenario: str
    passed: bool
    steps: List[Dict[str, Any]]
    events: List[Dict[str, Any]]
    duration_s: float
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScenarioRunner:
    """Runs declarative what-if scenarios against a :class:`KeystoreSimulator`.

    A scenario is a list of :class:`ScenarioStep` objects. Each step invokes a
    named simulator method with literal arguments (``{"$fast_forward": n}``
    markers are interpreted by the runner's virtual clock) and asserts the
    expected outcome. Failures of *policy* gates are the interesting research
    signal, so expectations are explicit rather than exception-driven.
    """

    def __init__(self, simulator: Optional[KeystoreSimulator] = None) -> None:
        self.simulator = simulator or KeystoreSimulator()
        self.results: List[ScenarioOutcome] = []
        self._virtual_offset = 0.0

    # -- virtual clock -----------------------------------------------------

    def _advance(self, seconds: float) -> None:
        """Move the simulator's virtual clock forward without sleeping."""
        self._virtual_offset += max(0.0, seconds)
        logger.debug("virtual clock advanced by %.3fs", seconds)

    def _make_clock(self) -> Callable[[], float]:
        base = time.monotonic()

        def clock() -> float:
            return base + self._virtual_offset

        return clock

    # -- execution ----------------------------------------------------------

    def run_step(self, step: ScenarioStep) -> Dict[str, Any]:
        method_name = step.call[0]
        args = list(step.call[1:])
        kwargs: Dict[str, Any] = {}
        for item in args:
            if isinstance(item, dict) and "$fast_forward" in item:
                self._advance(float(item["$fast_forward"]))
            elif isinstance(item, dict):
                kwargs.update(item)
        resolved_args = [a for a in args if not isinstance(a, dict)]

        method = getattr(self.simulator, method_name, None)
        if not callable(method):
            raise ScenarioError(f"simulator has no callable '{method_name}'")
        try:
            result: SimulatedResult = method(*resolved_args, **kwargs)
        except TypeError as exc:
            raise ScenarioError(f"bad signature for {method_name}: {exc}") from exc

        # Normalise non-SimulatedResult returns (e.g. ``snapshot()`` or the
        # ``None`` returned by provisioning helpers) into a GRANTED outcome so
        # every step has a uniform, comparable record.
        if not isinstance(result, SimulatedResult):
            payload = result if isinstance(result, dict) else {"return_type": type(result).__name__}
            result = SimulatedResult(
                success=True,
                status=GateStatus.GRANTED,
                detail=f"{method_name} returned {type(result).__name__}",
                data=payload,
            )

        checks: List[Dict[str, Any]] = []
        passed = True
        if step.expect_success is not None:
            ok = result.success is step.expect_success
            passed &= ok
            checks.append({"check": "success", "expected": step.expect_success, "actual": result.success, "ok": ok})
        if step.expect_status is not None:
            ok = result.status.value == step.expect_status
            passed &= ok
            checks.append({"check": "status", "expected": step.expect_status, "actual": result.status.value, "ok": ok})
        return {
            "step": step.name,
            "call": [self._render_arg(a) for a in step.call],
            "note": step.note,
            "result": result.as_dict(),
            "checks": checks,
            "passed": passed,
        }

    @staticmethod
    def _render_arg(arg: Any) -> Any:
        """JSON-safe rendering of a step argument for reports/timelines."""
        if isinstance(arg, Enum):
            return arg.value
        if isinstance(arg, dict):
            return {key: ScenarioRunner._render_arg(value) for key, value in arg.items()}
        if isinstance(arg, (list, tuple)):
            return [ScenarioRunner._render_arg(item) for item in arg]
        if isinstance(arg, (str, int, float, bool)) or arg is None:
            return arg
        return str(arg)

    def run_scenario(self, scenario_name: str, steps: Iterable[ScenarioStep]) -> ScenarioOutcome:
        started = time.monotonic()
        self._virtual_offset = 0.0
        self.simulator._clock = self._make_clock()
        self.simulator._t0 = self.simulator._clock()
        self.simulator.timeline.clear()

        step_results: List[Dict[str, Any]] = []
        notes: List[str] = []
        overall = True
        for step in steps:
            outcome = self.run_step(step)
            step_results.append(outcome)
            overall &= bool(outcome["passed"])
            if not outcome["passed"]:
                notes.append(
                    f"step '{step.name}' expectation mismatch: "
                    + json.dumps([c for c in outcome["checks"] if not c["ok"]])
                )
        result = ScenarioOutcome(
            scenario=scenario_name,
            passed=overall,
            steps=step_results,
            events=[event.as_dict() for event in self.simulator.timeline],
            duration_s=round(time.monotonic() - started, 4),
            notes=notes,
        )
        self.results.append(result)
        logger.info("scenario '%s' -> %s (%d steps)", scenario_name, "PASS" if overall else "FAIL", len(steps))
        return result

    def run_all_defaults(self) -> List[ScenarioOutcome]:
        """Execute the built-in boundary-condition test battery."""
        self.results.clear()
        for name, builder in DEFAULT_SCENARIOS.items():
            simulator = KeystoreSimulator(seed=f"kernel-x-{name}")
            runner = ScenarioRunner(simulator)
            runner.run_scenario(name, builder())
            self.results.append(runner.results[-1])
        return self.results

    def timeline(self) -> List[TimelineEvent]:
        return list(self.simulator.timeline)


# ---------------------------------------------------------------------------
# Built-in scenarios (documented AOSP boundary conditions)
# ---------------------------------------------------------------------------

_FF = {"$fast_forward": 20.0}  # helper marker: advance virtual clock 20s


def _sc_fbe_direct_boot() -> List[ScenarioStep]:
    """DE keys visible pre-authentication; CE keys sealed until credential check."""
    return [
        ScenarioStep("cold-boot state", ("snapshot",), expect_success=True,
                     note="device starts locked: CE storage sealed"),
        ScenarioStep("gen DE key", ("generate_key", "de_store", "AES_GCM",
                                    SecurityLevel.TRUSTED_ENVIRONMENT, False, 0, True,
                                    StorageDomain.DE),
                     expect_success=True),
        ScenarioStep("gen CE key", ("generate_key", "ce_store", "AES_GCM",
                                    SecurityLevel.TRUSTED_ENVIRONMENT, False, 0, False,
                                    StorageDomain.CE),
                     expect_success=True),
        ScenarioStep("use DE while locked", ("begin_operation", "de_store"),
                     expect_success=True, expect_status="GRANTED"),
        ScenarioStep("use CE while locked", ("begin_operation", "ce_store"),
                     expect_success=False, expect_status="DENIED_STORAGE_LOCKED",
                     note="models FBE: CE keys unusable before user authentication"),
        ScenarioStep("verify credential", ("verify_lockscreen_credential", "correct-mock-pin"),
                     expect_success=False, expect_status="DENIED_POLICY",
                     note="no mock credential provisioned yet -> verification rejected"),
        ScenarioStep("CE still sealed after failed auth", ("begin_operation", "ce_store"),
                     expect_success=False, expect_status="DENIED_STORAGE_LOCKED",
                     note="models FBE: CE keys unusable before user authentication"),
        ScenarioStep("provision owner credential", ("provision_mock_credential", "owner", "correct-mock-pin")),
        ScenarioStep("unlock with correct credential", ("verify_lockscreen_credential", "correct-mock-pin"),
                     expect_success=True),
        ScenarioStep("use CE after unlock", ("begin_operation", "ce_store"),
                     expect_success=True, expect_status="GRANTED"),
    ]


def _sc_auth_bound_lifetime() -> List[ScenarioStep]:
    """Auth-bound key validity windows and SID invalidation across re-auth."""
    return [
        ScenarioStep("provision credential", ("provision_mock_credential", "owner", "correct-mock-pin")),
        ScenarioStep("gen auth-bound key", ("generate_key", "pay_key", "ECDSA_P256",
                                            SecurityLevel.STRONGBOX, True, 10_000, False,
                                            StorageDomain.CE),
                     expect_success=True),
        ScenarioStep("access before auth", ("begin_operation", "pay_key"),
                     expect_success=False, expect_status="DENIED_STORAGE_LOCKED",
                     note="CE domain sealed pre-auth; auth requirement is checked after unlock"),
        ScenarioStep("authenticate", ("verify_lockscreen_credential", "correct-mock-pin"),
                     expect_success=True),
        ScenarioStep("access inside window", ("begin_operation", "pay_key"),
                     expect_success=True),
        ScenarioStep("fast-forward past window", ("begin_operation", "pay_key", _FF),
                     expect_success=False, expect_status="DENIED_AUTH_REQUIRED",
                     note="validity duration exceeded -> re-auth required"),
        ScenarioStep("re-auth raises SID", ("verify_lockscreen_credential", "correct-mock-pin"),
                     expect_success=True),
        ScenarioStep("access after re-auth", ("begin_operation", "pay_key"),
                     expect_success=True),
    ]


def _sc_gatekeeper_throttle() -> List[ScenarioStep]:
    """Wrong-credential path triggers the documented exponential backoff model."""
    return [
        ScenarioStep("provision credential", ("provision_mock_credential", "owner", "correct-mock-pin")),
        *[
            ScenarioStep(f"wrong attempt {i + 1}", ("verify_lockscreen_credential", "wrong-mock-pin"),
                         expect_success=False)
            for i in range(KeystoreSimulator.MAX_FAILED_ATTEMPTS - 1)
        ],
        ScenarioStep("threshold hit -> backoff", ("verify_lockscreen_credential", "wrong-mock-pin"),
                     expect_success=False, expect_status="DENIED_LOCKED"),
        ScenarioStep("immediate retry blocked", ("verify_lockscreen_credential", "correct-mock-pin"),
                     expect_success=False, expect_status="DENIED_LOCKED",
                     note="backoff timer still running - models rate limiting"),
        ScenarioStep("after backoff expires", ("verify_lockscreen_credential", "correct-mock-pin",
                                               {"$fast_forward": 31.0}),
                     expect_success=True),
    ]


def _sc_avb_rollback() -> List[ScenarioStep]:
    """Rollback-resistant keys refuse service when AVB boot state changes."""
    return [
        ScenarioStep("gen RRB key at VERIFIED", ("generate_key", "hsm_ref", "AES_GCM",
                                                 SecurityLevel.TRUSTED_ENVIRONMENT, False, 0,
                                                 False, StorageDomain.DE, True, True),
                     expect_success=True),
        ScenarioStep("access while verified", ("begin_operation", "hsm_ref"),
                     expect_success=True),
        ScenarioStep("boot state -> UNVERIFIED", ("_set_boot_state", BootState.UNVERIFIED)),
        ScenarioStep("access after unlock", ("begin_operation", "hsm_ref"),
                     expect_success=False, expect_status="DENIED_POLICY",
                     note="rollback protection: key bound to prior boot state"),
    ]


def _sc_handle_confirmation() -> List[ScenarioStep]:
    """Crypto handle issuance, SID confirmation and mock-tag completion."""
    return [
        ScenarioStep("provision credential", ("provision_mock_credential", "owner", "pw")),
        ScenarioStep("unlock", ("verify_lockscreen_credential", "pw"), expect_success=True),
        ScenarioStep("gen plain key", ("generate_key", "file_key", "AES_XTS",
                                       SecurityLevel.SOFTWARE, False, 0, False,
                                       StorageDomain.CE),
                     expect_success=True),
        ScenarioStep("begin op", ("begin_operation", "file_key"), expect_success=True),
    ]


#: Registry of default scenarios consumed by the CLI, dashboard and reporter.
DEFAULT_SCENARIOS: Dict[str, Callable[[], List[ScenarioStep]]] = {
    "fbe-direct-boot-vs-credential-storage": _sc_fbe_direct_boot,
    "auth-bound-key-lifetime": _sc_auth_bound_lifetime,
    "gatekeeper-throttling-model": _sc_gatekeeper_throttle,
    "avb-rollback-resistant-keys": _sc_avb_rollback,
    "keystore-handle-confirmation": _sc_handle_confirmation,
}


def _install_boot_state_hook() -> None:
    """Expose a controlled boot-state mutation used only by scenarios/tests."""

    def _set_boot_state(self: KeystoreSimulator, state: BootState) -> SimulatedResult:
        previous = self.boot_state
        self.boot_state = state
        self.record("avb-model", f"set-boot-state:{state.value}", "OK", f"was {previous.value}")
        return SimulatedResult(
            True, GateStatus.GRANTED, "simulated boot state changed",
            {"previous": previous.value, "current": state.value},
        )

    if not hasattr(KeystoreSimulator, "_set_boot_state"):
        setattr(KeystoreSimulator, "_set_boot_state", _set_boot_state)


_install_boot_state_hook()


__all__ = [
    "KeyAlgorithm",
    "SecurityLevel",
    "BootState",
    "StorageDomain",
    "GateStatus",
    "SimulatedResult",
    "SimulatedKeyBlob",
    "TimelineEvent",
    "KeystoreSimulator",
    "ScenarioStep",
    "ScenarioOutcome",
    "ScenarioRunner",
    "ScenarioError",
    "DEFAULT_SCENARIOS",
]
