#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel_x.keystore_strongbox
===========================

StrongBox / keystore deep probe — **mock state machine only**.
=============================================================

This module models the lifecycle of StrongBox-backed (TEE-bound) keys as
documented for Android Keystore/Keymint:

  * provision a mock credential verifier (Gatekeeper/Weaver analogue — NOT a
    real Gatekeeper, no real biometric/PIN data),
  * generate a key with authorizations (StrongBox hardware binding,
    user-authentication-required, validity window, rollback resistance),
  * bind operations to freshly-obtained auth tokens within a validity window,
  * produce a MOCK attestation record (clearly labeled; not a real
    attestation certificate and not verifiable by a real vendor server),
  * model invalidation on simulated factory reset and anti-rollback replay,
  * model Gatekeeper-style rate limiting / backoff after failed authentications.

Every handle is a deterministic HMAC digest over public parameters — it is
NOT a real key and cannot encrypt or decrypt anything. No /dev/tee, no
keystore2 binder service, no real Gatekeeper/Weaver, no hardware-backed
storage is ever touched.

ETHICAL BOUNDARIES
------------------
* Credentials are checked against an injected mock store only.
* No retry/brute-force of real verifiers; rate-limit logic is purely
  defensive (it models *how long* a real device would back off).
* Attestation output is marked MOCK_ATTESTATION = True.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kernel_x.keystore_strongbox")

MOCK_ATTESTATION = True  # every attestation record emitted here is simulated

# --------------------------------------------------------------------------- #
# Result types                                                                #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ProbeResult:
    success: bool
    status: str
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(
            timespec="milliseconds")
    )

    def as_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        return out


# --------------------------------------------------------------------------- #
# Mock strongbox keystore state machine                                       #
# --------------------------------------------------------------------------- #


class StrongBoxKey:
    """One simulated StrongBox-bound key. Public-parameter digest only."""

    def __init__(
        self,
        key_id: str,
        label: str,
        algorithm: str = "AES-256-GCM",
        strongbox: bool = True,
        user_auth_required: bool = True,
        valid_seconds: Optional[int] = None,
        rollback_resistant: bool = True,
        origin: str = "Generated",
    ) -> None:
        self.key_id = key_id
        self.label = label
        self.algorithm = algorithm
        self.strongbox = strongbox
        self.user_auth_required = user_auth_required
        self.valid_from = time.monotonic()
        self.valid_seconds = valid_seconds
        self.rollback_resistant = rollback_resistant
        self.origin = origin
        self.invalidated = False
        self.use_count = 0
        # Monotonic anti-rollback counter simulated per key.
        self.rollback_counter = 0

    def is_expired(self, now: float) -> bool:
        if self.valid_seconds is None:
            return False
        return (now - self.valid_from) > self.valid_seconds

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "label": self.label,
            "algorithm": self.algorithm,
            "strongbox": self.strongbox,
            "user_auth_required": self.user_auth_required,
            "rollback_resistant": self.rollback_resistant,
            "origin": self.origin,
            "invalidated": self.invalidated,
            "use_count": self.use_count,
            "expired": self.is_expired(time.monotonic()),
        }


class StrongBoxKeystore:
    """
    In-process mock of a StrongBox-backed keystore.

    All state lives in RAM. Handles are HMAC-SHA256 digests over public
    parameters plus a per-probe salt — they carry no real key material.
    """

    def __init__(self, salt: Optional[str] = None) -> None:
        self.salt = salt or hashlib.sha256(
            b"kernel-x-strongbox-probe").hexdigest()[:16]
        self._keys: Dict[str, StrongBoxKey] = {}
        self._handles: Dict[str, str] = {}
        self._rollback_counter = 0
        self._auth_failures = 0
        self._backoff_until = 0.0  # monotonic time when backoff expires
        self._factory_reset_count = 0

    # -- key lifecycle --------------------------------------------------------

    def _handle_for(self, key_id: str) -> str:
        return hmac.new(
            self.salt.encode(), f"strongbox-handle:{key_id}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def generate_key(
        self,
        label: str,
        algorithm: str = "AES-256-GCM",
        strongbox: bool = True,
        user_auth_required: bool = True,
        valid_seconds: Optional[int] = None,
        rollback_resistant: bool = True,
        origin: str = "Generated",
    ) -> ProbeResult:
        if self._in_backoff():
            return ProbeResult(
                False, "DENIED_BACKOFF",
                "simulated Gatekeeper backoff active; try again later")
        key_id = hashlib.sha256(
            f"{label}:{algorithm}:{self.salt}".encode()).hexdigest()[:24]
        key = StrongBoxKey(
            key_id=key_id, label=label, algorithm=algorithm,
            strongbox=strongbox, user_auth_required=user_auth_required,
            valid_seconds=valid_seconds, rollback_resistant=rollback_resistant,
            origin=origin,
        )
        self._keys[key_id] = key
        self._handles[key_id] = self._handle_for(key_id)
        logger.info("generated mock StrongBox key %s (%s)", key_id, label)
        return ProbeResult(
            True, "KEY_GENERATED", "key material never exposed",
            data={"key_id": key_id, "handle": self._handles[key_id],
                  "strongbox": strongbox, "attestation_required": True})

    def begin_operation(
        self,
        key_id: str,
        auth_token: Optional[str],
        now: Optional[float] = None,
    ) -> ProbeResult:
        """Simulate starting a crypto operation bound to an auth session."""
        now = now or time.monotonic()
        if self._in_backoff(now):
            return ProbeResult(False, "DENIED_BACKOFF",
                               "rate-limit backoff active")
        key = self._keys.get(key_id)
        if key is None:
            return ProbeResult(False, "ERROR_UNKNOWN_KEY", "no such key id")
        if key.invalidated:
            return ProbeResult(False, "DENIED_INVALIDATED",
                               "key invalidated (e.g. factory reset)")
        if key.is_expired(now):
            return ProbeResult(False, "DENIED_EXPIRED",
                               "key validity window expired")
        if key.strongbox and not self._tee_available():
            return ProbeResult(False, "DENIED_TEE_UNAVAILABLE",
                               "simulated TEE/StrongBox not available")
        if key.user_auth_required:
            if not self._valid_auth_token(auth_token, key_id):
                return ProbeResult(
                    False, "DENIED_AUTH_REQUIRED",
                    "StrongBox key requires fresh user-auth token")
        self._rollback_counter += 1
        key.use_count += 1
        return ProbeResult(
            True, "OPERATION_BOUND",
            "operation bound to mock handle (no real crypto)",
            data={"handle": self._handles[key_id],
                  "rollback_counter": self._rollback_counter})

    # -- mock authentication (Gatekeeper/Weaver analogue) --------------------

    def authenticate(
        self,
        credential: str,
        expected_credential: str,
        now: Optional[float] = None,
    ) -> ProbeResult:
        """
        Mock credential verification. Returns an opaque auth token bound to
        the key context on success; models failed-attempt backoff on failure.
        Never touches a real Gatekeeper/Weaver service.
        """
        now = now or time.monotonic()
        if self._in_backoff(now):
            return ProbeResult(False, "DENIED_BACKOFF",
                               "too many failed attempts; backoff active")
        if credential == expected_credential:
            self._auth_failures = 0
            token = hmac.new(
                self.salt.encode(),
                f"auth-token:{credential}:{now}".encode(),
                hashlib.sha256,
            ).hexdigest()
            return ProbeResult(
                True, "AUTHENTICATED", "mock auth token issued",
                data={"token": token})
        self._auth_failures += 1
        backoff_s = min(60.0, 1.0 * (2 ** min(self._auth_failures, 6)))
        self._backoff_until = now + backoff_s
        return ProbeResult(
            False, "DENIED_AUTH_FAILED",
            f"mock credential rejected; simulated backoff {backoff_s:.0f}s",
            data={"failures": self._auth_failures,
                  "backoff_seconds": backoff_s})

    def invalidate_all(self, reason: str = "factory reset (simulated)") -> ProbeResult:
        """Simulate factory reset: all user-bound keys invalidated."""
        for key in self._keys.values():
            key.invalidated = True
        self._factory_reset_count += 1
        return ProbeResult(
            True, "INVALIDATED_ALL",
            f"all {len(self._keys)} keys invalidated: {reason}",
            data={"invalidated": len(self._keys),
                  "reset_count": self._factory_reset_count})

    # -- mock attestation -----------------------------------------------------

    def attest(self, key_id: str) -> ProbeResult:
        """Return a MOCK attestation record — NOT a real attestation."""
        key = self._keys.get(key_id)
        if key is None:
            return ProbeResult(False, "ERROR_UNKNOWN_KEY", "no such key id")
        record = {
            "mock_attestation": True,
            "attestation_challenge": hashlib.sha256(
                f"challenge:{key_id}".encode()).hexdigest(),
            "key_id": key_id,
            "security_level": "StrongBox (simulated)",
            "tee_enforced": bool(key.strongbox),
            "tee_version": "0.0.0-simulated",
            "software_enforced": False,
            "rollback_resistant": key.rollback_resistant,
            "origin": key.origin,
            "warning": ("this attestation record is simulated for lab "
                        "research only; it is not issued by a real TEE"),
        }
        return ProbeResult(True, "ATTESTATION_MOCKED",
                           "simulated attestation record (not real)",
                           data=record)

    # -- internal -------------------------------------------------------------

    def _tee_available(self) -> bool:
        """In this lab model, the simulated TEE is always present."""
        return True

    def _in_backoff(self, now: Optional[float] = None) -> bool:
        now = now or time.monotonic()
        return now < self._backoff_until

    def _valid_auth_token(
        self, token: Optional[str], key_id: str
    ) -> bool:
        """Token validation is purely structural in this mock."""
        return isinstance(token, str) and len(token) == 64

    # -- census ---------------------------------------------------------------

    def census(self) -> Dict[str, Any]:
        return {
            "key_count": len(self._keys),
            "strongbox_keys": sum(1 for k in self._keys.values()
                                  if k.strongbox),
            "invalidated_keys": sum(1 for k in self._keys.values()
                                    if k.invalidated),
            "auth_failures": self._auth_failures,
            "factory_resets": self._factory_reset_count,
            "rollback_counter": self._rollback_counter,
        }


# --------------------------------------------------------------------------- #
# Probe runner: repeatable scenarios                                          #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ProbeStepResult:
    step: str
    action: str
    success: bool
    status: str
    detail: str


class StrongBoxProbe:
    """
    Execute a fixed sequence of StrongBox lifecycle steps and record the
    outcome of each — an auditable timeline for reports.
    """

    def __init__(self, expected_credential: str = "demo-lab-credential") -> None:
        self.expected_credential = expected_credential
        self.keystore = StrongBoxKeystore()

    def run(self, session_id: str = "default") -> Dict[str, Any]:
        steps: List[ProbeStepResult] = []
        now = time.monotonic()

        def record(step: str, action: str, res: ProbeResult) -> ProbeResult:
            steps.append(ProbeStepResult(step, action, res.success,
                                         res.status, res.detail))
            return res

        # 1. Provision the mock credential verifier (injected mock store).
        # 2. Authenticate -> mock token.
        auth = record("provision", "authenticate",
                      self.keystore.authenticate(
                          self.expected_credential,
                          self.expected_credential, now=now))
        token = auth.data.get("token") if auth.success else None

        # 3. Generate StrongBox-backed, user-auth-required key (valid 300 s).
        gen = record("generate", "generate_key",
                     self.keystore.generate_key(
                         "probe_key", algorithm="AES-256-GCM",
                         strongbox=True, user_auth_required=True,
                         valid_seconds=300))
        key_id = gen.data.get("key_id") if gen.success else None

        # 4. Operation should be bound while authed & in validity window.
        op_ok = record("operate-unlocked", "begin_operation",
                       self.keystore.begin_operation(key_id, token, now=now))

        # 5. MOCK attestation for the generated key.
        att = record("attest", "attest",
                     self.keystore.attest(key_id))

        # 6. Simulated factory reset invalidates all keys.
        rst = record("invalidate", "invalidate_all",
                     self.keystore.invalidate_all("simulated factory reset"))

        # 7. Same operation must be denied after invalidation.
        op_denied = record("operate-after-reset", "begin_operation",
                           self.keystore.begin_operation(key_id, token,
                                                         now=now))

        # 8. Failed authentication path (negative case).
        bad_auth = record("auth-negative", "authenticate",
                          self.keystore.authenticate(
                              "wrong-credential", self.expected_credential,
                              now=now + 1))

        expected_fail = {"operate-after-reset", "auth-negative"}
        passed = all(
            (s.success == (s.step not in expected_fail)) for s in steps)

        return {
            "session_id": session_id,
            "mock_only": True,
            "passed": passed,
            "steps": [asdict(s) for s in steps],
            "census": self.keystore.census(),
            "key_id": key_id,
            "mock_attestation": MOCK_ATTESTATION,
        }


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        description="StrongBox/keystore deep probe (simulation only)")
    ap.add_argument("--session", default="lab-probe-1",
                    help="session id for the probe timeline")
    ap.add_argument("--credential", default="demo-lab-credential",
                    help="mock credential for the injected verifier")
    ap.add_argument("--out", metavar="PATH",
                    help="write JSON result to this path")
    args = ap.parse_args(argv)

    probe = StrongBoxProbe(expected_credential=args.credential)
    result = probe.run(session_id=args.session)
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[+] probe result written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
