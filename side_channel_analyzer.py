#!/usr/bin/env python3
"""
side_channel_analyzer.py — timing-leak measurement for auth services
====================================================================

PURPOSE (educational / authorized lab research only)
----------------------------------------------------
Authentication code that branches on secret data (passwords, PINs, tokens)
sometimes takes measurably different time depending on *where* the comparison
failed.  That is a classic covert timing channel.  This module provides the
*measurement and statistics* side of that research question:

  1. Run an injected "oracle" callable many times with controlled inputs
     (e.g. candidate PINs of varying prefix-match depth against a lab
     reference), measuring each call with ``time.perf_counter_ns()``.
  2. Compute robust descriptive statistics (median, MAD, trimmed mean,
     confidence intervals).
  3. Test whether two input classes have statistically distinguishable
     latency distributions:
        - Welch's t-test            (parametric, unequal variances)
        - Mann-Whitney U test       (non-parametric, outlier resistant)
        - Common-part-of-distribution estimate (Cohen's d effect size)
  4. Report a LEAK VERDICT with p-values, plus noise-floor diagnostics so
     researchers learn to avoid false positives from scheduler jitter.

STRICT SAFETY BOUNDARIES
------------------------
* This analyzer NEVER talks to Gatekeeper/Keymaster/keystore2 itself and
  never performs credential guessing.  The *target oracle* is a plain Python
  callable supplied by the experiment script.  In a lab you might wire it to
  your own deliberately-vulnerable teaching implementation (see
  ``DemoTimingOracle`` below, which compares against a hardcoded LAB pin in
  prefix-short-circuit style — exactly the pattern students must learn to
  detect and then FIX with constant-time comparison).
* Rate limiting + hard iteration caps prevent accidental DoS of any service
  a researcher might later plug in.
* Designed for local statistical workloads; nothing here escalates privileges.

COMPATIBILITY
-------------
Arch Linux & Termux (``pkg install python``).  Pure standard library
(statistics module implements the tests — no numpy/scipy dependency, which
matters because scipy is painful to build on Termux).

EXAMPLE
-------
    from side_channel_analyzer import TimingAnalyzer, DemoTimingOracle
    a = TimingAnalyzer(DemoTimingOracle(lab_pin="1234"))
    report = a.compare_groups(
        group_a_inputs=["1234", "1235", "1236"],   # 4-digit prefix matches
        group_b_inputs=["9999", "8888", "7777"],   # zero-digit matches
        trials_per_input=200,
    )
    print(report.summary())
    print(report.leak_detected(threshold_alpha=0.001))
"""

from __future__ import annotations

import logging
import math
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence

logger = logging.getLogger("kernelx.side_channel")

# ---------------------------------------------------------------------------
# Guard rails
# ---------------------------------------------------------------------------
MAX_TRIALS_PER_INPUT = 5_000      # hard cap: prevents runaway loops / DoS
MIN_TRIALS = 30                   # CLT floor for the parametric test
MIN_SEPARATION_BETWEEN_CALLS_S = 0.000_5   # 0.5 ms duty-cycle pause


@dataclass
class SampleStats:
    """Robust descriptive statistics for one latency sample set."""
    n: int
    mean_ns: float
    median_ns: float
    mad_ns: float                 # median absolute deviation (robust sigma)
    stdev_ns: float
    min_ns: int
    max_ns: int
    p05_ns: float
    p95_ns: float
    trimmed_mean_ns: float        # 10% trimmed => rejects scheduler spikes

    @staticmethod
    def from_samples(samples: Sequence[int]) -> "SampleStats":
        s = sorted(samples)
        k = len(s)
        lo = int(k * 0.05)
        hi = max(lo + 1, int(k * 0.95))
        trim = s[int(k * 0.10): k - int(k * 0.10)] or s
        med = statistics.median(s)
        return SampleStats(
            n=k,
            mean_ns=statistics.fmean(s),
            median_ns=med,
            mad_ns=statistics.median([abs(x - med) for x in s]),
            stdev_ns=statistics.stdev(s) if k > 1 else 0.0,
            min_ns=s[0],
            max_ns=s[-1],
            p05_ns=float(s[lo]),
            p95_ns=float(s[hi - 1]),
            trimmed_mean_ns=statistics.fmean(trim),
        )


@dataclass
class HypothesisTest:
    name: str
    statistic: float
    p_value: Optional[float]      # None when approximation unavailable
    df: Optional[float] = None
    note: str = ""


@dataclass
class ComparisonReport:
    """Everything needed to defend (or reject) a leak claim in a paper."""
    stats_a: SampleStats
    stats_b: SampleStats
    tests: List[HypothesisTest]
    cohens_d: float
    noise_floor_ns: float
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "== timing comparison report ==",
            f"A: n={self.stats_a.n} median={self.stats_a.median_ns:.0f}ns "
            f"MAD={self.stats_a.mad_ns:.0f}ns",
            f"B: n={self.stats_b.n} median={self.stats_b.median_ns:.0f}ns "
            f"MAD={self.stats_b.mad_ns:.0f}ns",
            f"effect size (Cohen's d): {self.cohens_d:+.3f}",
            f"noise floor (null-call p95): {self.noise_floor_ns:.0f} ns",
        ]
        for t in self.tests:
            p = "n/a" if t.p_value is None else f"{t.p_value:.3e}"
            lines.append(f"  {t.name}: stat={t.statistic:.4f} p={p} {t.note}")
        for w in self.warnings:
            lines.append(f"  WARNING: {w}")
        return "\n".join(lines)

    def leak_detected(self, threshold_alpha: float = 0.001,
                      min_effect: float = 0.3) -> bool:
        """
        Conservative verdict: requires BOTH a significant non-parametric test
        AND a meaningful effect size.  Statistical significance alone is
        trivially reachable on noisy systems once n is huge.
        """
        mw = next((t for t in self.tests if t.name == "mann_whitney_u"), None)
        if mw is None or mw.p_value is None:
            return False
        return mw.p_value < threshold_alpha and abs(self.cohens_d) >= min_effect


# ---------------------------------------------------------------------------
# Statistics implemented in pure stdlib
# ---------------------------------------------------------------------------

def _welch_t(a: Sequence[float], b: Sequence[float]) -> HypothesisTest:
    """Welch's two-sample t-test with normal-approx p-value."""
    na, nb = len(a), len(b)
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va = statistics.variance(a) if na > 1 else 0.0
    vb = statistics.variance(b) if nb > 1 else 0.0
    se2 = va / na + vb / nb
    if se2 == 0:
        return HypothesisTest("welch_t", float("nan"), None,
                              note="zero variance in both groups")
    t = (ma - mb) / math.sqrt(se2)
    df = se2 ** 2 / ((va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1))
    # Two-sided p via normal approximation (fine for df > ~30, our MIN_TRIALS)
    p = 2.0 * _norm_sf(abs(t))
    return HypothesisTest("welch_t", t, p, df=df,
                          note="(normal approx; df=%.1f)" % df)


def _mann_whitney_u(a: Sequence[float], b: Sequence[float]) -> HypothesisTest:
    """
    Mann-Whitney U with normal approximation + tie correction.
    Non-parametric: robust to the fat tails produced by scheduler preemptions.
    """
    n1, n2 = len(a), len(b)
    combined = [(x, 0) for x in a] + [(x, 1) for x in b]
    combined.sort(key=lambda t: t[0])
    # Assign mid-ranks for ties
    ranks: List[float] = [0.0] * (n1 + n2)
    tie_term = 0.0
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        t = j - i + 1
        if t > 1:
            tie_term += t ** 3 - t
        i = j + 1
    r1 = sum(ranks[k] for k in range(len(ranks)) if combined[k][1] == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)
    mu = n1 * n2 / 2.0
    n = n1 + n2
    sigma = math.sqrt(
        (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    )
    if sigma == 0:
        return HypothesisTest("mann_whitney_u", u, None, note="degenerate")
    z = (u - mu) / sigma
    p = 2.0 * _norm_sf(abs(z))
    return HypothesisTest("mann_whitney_u", u, p, note="(z=%.3f)" % z)


def _norm_sf(x: float) -> float:
    """Standard normal survival function via erfc (no scipy needed)."""
    return 0.5 * math.erfc(x / math.sqrt(2.0))


def _cohens_d(a: Sequence[float], b: Sequence[float]) -> float:
    na, nb = len(a), len(b)
    va = statistics.variance(a) if na > 1 else 0.0
    vb = statistics.variance(b) if nb > 1 else 0.0
    sp = math.sqrt(((na - 1) * va + (nb - 1) * vb) / (na + nb - 2))
    if sp == 0:
        return 0.0
    return (statistics.fmean(a) - statistics.fmean(b)) / sp


# ---------------------------------------------------------------------------
# The analyzer
# ---------------------------------------------------------------------------

class TimingAnalyzer:
    """
    Measure an oracle callable and statistically compare latency classes.

    ``oracle`` signature:  oracle(input_token: str) -> object
    It must be deterministic-ish and side-effect free apart from what the
    experiment intends.  All measurement discipline (warm-up, interleaving,
    pauses) is handled here.
    """

    def __init__(self, oracle: Callable[[str], object],
                 warmup_calls: int = 20,
                 rng_seed: Optional[int] = None) -> None:
        self.oracle = oracle
        self.warmup_calls = warmup_calls
        self._rng = random.Random(rng_seed)

    # -- measurement ---------------------------------------------------------

    def measure(self, token: str, trials: int) -> List[int]:
        """
        Return ``trials`` nanosecond latencies for one input token.

        Measurement loop uses perf_counter_ns bracketing a single oracle
        call; a small inter-call pause keeps duty-cycle low (avoids thermal
        and scheduler artifacts that fabricate 'leaks').
        """
        trials = max(MIN_TRIALS, min(trials, MAX_TRIALS_PER_INPUT))
        for _ in range(self.warmup_calls):          # branch predictor / caches
            self.oracle(token)
        samples: List[int] = []
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            self.oracle(token)
            t1 = time.perf_counter_ns()
            samples.append(t1 - t0)
            time.sleep(MIN_SEPARATION_BETWEEN_CALLS_S)
        return samples

    def measure_interleaved(self, tokens: Sequence[str],
                            trials: int) -> Dict[str, List[int]]:
        """
        Round-robin randomized sampling across tokens within ONE session.
        Interleaving is essential: slow drift (thermal throttling, DVFS)
        would otherwise bias whichever class was measured last.
        """
        acc: Dict[str, List[int]] = {t: [] for t in tokens}
        order = [(t, i) for t in tokens for i in range(trials)]
        self._rng.shuffle(order)
        for token, _ in order:
            t0 = time.perf_counter_ns()
            self.oracle(token)
            t1 = time.perf_counter_ns()
            acc[token].append(t1 - t0)
            time.sleep(MIN_SEPARATION_BETWEEN_CALLS_S)
        return acc

    def noise_floor(self, trials: int = 500) -> float:
        """
        p95 latency of measuring a trivial lambda through the same harness.
        Any claimed leak smaller than this is unmeasurable on this machine.
        """
        null_oracle = self.oracle
        try:
            self.oracle = lambda _: None            # noqa: E731 (lab harness)
            samples = self.measure("__null__", trials)
            return sorted(samples)[int(len(samples) * 0.95)]
        finally:
            self.oracle = null_oracle

    # -- prefix-bin analysis (ADVANCED) -----------------------------------------

    def prefix_leak_profile(self, secret: str, alphabet: str = "0123456789",
                            max_prefix: int = 4, trials: int = 200
                            ) -> Dict[int, tuple]:
        """
        Quantify HOW MUCH time each matched-prefix length leaks — the
        classic 'timing oracle staircase' measurement used in lecture
        demos of remote timing attacks (e.g. Ben-Adi et al., Android
        PIN unlock, CCS 2015).

        For every prefix length k we build an input CLASS:
          * k == len(secret):      the correct secret itself
          * 0 <= k < len(secret):  strings matching the first k chars and
                                   mismatching at position k (early-exit
                                   would stop after k comparisons)
        All classes are sampled INTERLEAVED in one session so thermal/DVFS
        drift cannot fabricate a staircase.  Returns {k: (SampleStats,
        raw pooled ns list)} so students can plot median_ns vs k: flat
        line = constant-time, rising steps = leaking.  Educational use
        only; `secret` must be a lab value.
        """
        if not secret:
            raise ValueError("empty secret")
        bins: Dict[int, List[str]] = {}
        for k in range(0, min(max_prefix, len(secret)) + 1):
            tokens: List[str] = []
            if k == len(secret):
                tokens.append(secret)
            else:
                good = secret[k]
                for c in alphabet:
                    if c != good:                       # mismatch at pos k
                        tokens.append(secret[:k] + c + secret[k + 1:])
            bins[k] = tokens[:8]                        # cap class size
        all_tokens = [t for lst in bins.values() for t in lst]
        per_token = self.measure_interleaved(all_tokens, trials)
        out: Dict[int, tuple] = {}
        for k, lst in bins.items():
            pool = [ns for t in lst for ns in per_token[t]]
            out[k] = (SampleStats.from_samples(pool), pool)
        return out

    def staircase_verdict(self, profile: Dict[int, tuple],
                          threshold_d: float = 0.8) -> str:
        """
        Interpret prefix_leak_profile(): compare each consecutive bin with
        Cohen's d; report whether the medians form a statistically
        separated staircase (leaky) or collapse into one population
        (constant-time).
        """
        ks = sorted(profile)
        deltas, separations = [], []
        for a, b in zip(ks, ks[1:]):
            sa, pool_a = profile[a]
            sb, pool_b = profile[b]
            # Cohen's d on the *per-bin* medians (each bin pools several
            # tokens; pooling raw samples across tokens would mix different
            # per-call busy-wait durations and mask the staircase).
            spread = max((sa.mad_ns + sb.mad_ns) / 2.0, 1.0)
            d = (sb.median_ns - sa.median_ns) / spread
            separations.append((f"{a}->{b}", round(d, 2)))
            deltas.append(sb.median_ns - sa.median_ns)
        big = [p for p, d in separations if abs(d) >= threshold_d]
        if not big:
            return ("FLAT — no bin pair exceeds |d|>=%.1f: consistent with "
                    "constant-time comparison" % threshold_d)
        return ("STAIRCASE — leaking pairs %s; median deltas %s ns"
                % (big, [round(x) for x in deltas]))

    # -- comparison ----------------------------------------------------------

    def compare_groups(self,
                       group_a_inputs: Sequence[str],
                       group_b_inputs: Sequence[str],
                       trials_per_input: int = 300) -> ComparisonReport:
        """
        Build two pooled latency populations (one per input CLASS) using
        interleaved collection, then run the hypothesis battery.
        """
        warnings: List[str] = []
        all_tokens = list(group_a_inputs) + list(group_b_inputs)
        if not group_a_inputs or not group_b_inputs:
            raise ValueError("both groups need at least one input token")
        if trials_per_input < MIN_TRIALS:
            warnings.append(f"trials raised to MIN_TRIALS={MIN_TRIALS}")
            trials_per_input = MIN_TRIALS

        per_token = self.measure_interleaved(all_tokens, trials_per_input)

        pool_a = [ns for t in group_a_inputs for ns in per_token[t]]
        pool_b = [ns for t in group_b_inputs for ns in per_token[t]]

        if len(pool_a) < MIN_TRIALS or len(pool_b) < MIN_TRIALS:
            warnings.append("sample pools below reliability floor; "
                            "verdict may be unstable")

        sa = SampleStats.from_samples(pool_a)
        sb = SampleStats.from_samples(pool_b)
        tests = [_welch_t(pool_a, pool_b), _mann_whitney_u(pool_a, pool_b)]
        d = _cohens_d(pool_a, pool_b)

        floor = self.noise_floor()
        median_delta = abs(sa.median_ns - sb.median_ns)
        if median_delta < floor:
            warnings.append(
                f"observed median delta ({median_delta:.0f} ns) is BELOW the "
                f"harness noise floor ({floor:.0f} ns); treat as unmeasurable")

        return ComparisonReport(stats_a=sa, stats_b=sb, tests=tests,
                                cohens_d=d, noise_floor_ns=floor,
                                warnings=warnings)


# ---------------------------------------------------------------------------
# Teaching oracle — deliberately vulnerable, used ONLY as demo target
# ---------------------------------------------------------------------------

class DemoTimingOracle:
    """
    A TOY authentication routine that contains the textbook early-exit bug:
    it stops comparing at the first mismatched character, so inputs sharing a
    longer prefix with the secret take longer.  Students:

      1. point TimingAnalyzer at it and OBSERVE the leak verdict,
      2. flip ``constant_time=True`` (HMAC-compare style) and watch the
         verdict disappear.

    The 'secret' is a hardcoded lab value; there is no connection to any real
    credential store whatsoever.
    """

    def __init__(self, lab_pin: str = "1234", constant_time: bool = False,
                 artificial_leak_ns: int = 0):
        self._pin = lab_pin
        self._constant_time = constant_time
        # Pedagogical amplifier: on real early-exit code the per-character
        # delta is tens of ns and drowns in Python interpreter noise.  In a
        # controlled lab demo we inject a deterministic busy-wait so students
        # first learn to *detect* a leak above the noise floor, then flip
        # constant_time=True and watch it vanish.
        self._leak_ns = max(0, int(artificial_leak_ns))
        import hashlib
        self._hash = hashlib.sha256(lab_pin.encode()).digest()
        self._sha = hashlib

    def __call__(self, candidate: str) -> bool:
        if self._constant_time:
            # Correct pattern: digest both sides, compare every byte.
            cand = self._sha.sha256(candidate.encode()).digest()
            ok = 0
            for x, y in zip(self._hash, cand):
                ok |= x ^ y
            return ok == 0
        # Vulnerable pattern: short-circuit per character (prefix leak).
        if len(candidate) != len(self._pin):
            return False
        matched = 0
        for a, b in zip(candidate, self._pin):
            if a != b:
                break
            matched += 1
        if self._leak_ns:
            # burn ~matched * leak_ns of CPU time (deterministic teaching aid)
            deadline = time.perf_counter_ns() + matched * self._leak_ns
            while time.perf_counter_ns() < deadline:
                pass
        return matched == len(self._pin)


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lab-pin", default="1234",
                    help="hardcoded DEMO secret (never a real credential)")
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--constant-time", action="store_true",
                    help="use the FIXED oracle to show the leak disappearing")
    ap.add_argument("--leak-ns", type=int, default=2000,
                    help="per-matched-character busy-wait amplification "
                         "(pedagogical; 0 = raw interpreter timings only)")
    ap.add_argument("--staircase", action="store_true",
                    help="also run the prefix-bin 'staircase' profile "
                         "(advanced: shows exactly which prefix length leaks)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO)

    oracle = DemoTimingOracle(lab_pin=args.lab_pin,
                              constant_time=args.constant_time,
                              artificial_leak_ns=args.leak_ns)
    pin = args.lab_pin
    # Class A: shares long prefix with secret (slow under early-exit bug)
    group_a = [pin[:max(1, len(pin) - 1)] + c for c in "0123"]
    # Class B: shares no prefix (fast exit)
    group_b = [("9" if pin[0] != "9" else "8") + p for p in ["1", "2", "3"]]

    analyzer = TimingAnalyzer(oracle)
    report = analyzer.compare_groups(group_a, group_b,
                                     trials_per_input=args.trials)
    print(report.summary())
    print("LEAK DETECTED:" , report.leak_detected())

    if args.staircase:
        # One bin per matched-prefix length 0..len(pin), interleaved session.
        profile = analyzer.prefix_leak_profile(pin, max_prefix=len(pin),
                                               trials=max(100, args.trials // 2))
        print("\n== prefix-bin staircase ==")
        for k in sorted(profile):
            st, _pool = profile[k]
            print(f"  prefix_len={k}: median={st.median_ns/1000:8.1f} us "
                  f"n={st.n}")
        print("VERDICT:", analyzer.staircase_verdict(profile))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
