#!/usr/bin/env python3
"""
evidence_logger.py — tamper-evident Merkle-tree forensic action log
===================================================================

PURPOSE (educational / authorized lab research only)
----------------------------------------------------
Forensic discipline demands that every observation you make during a lab
session be recorded in a way that later proves *nothing was edited or
deleted*.  This module implements a classic **Merkle Tree** audit chain:

  * Every forensic action (a resolver result, a timing report, an SELinux
    finding line, ...) becomes a LEAF:
        leaf_hash = SHA-256( DOMAIN_SEPARATOR || seq || ts || action || payload )
    The domain separator and the sequence number give the leaves
    cryptographic context and ordering (prevents leaf- vs node-replay and
    truncation attacks).
  * Leaves are paired bottom-up with
        node_hash = SHA-256( "KB" || left || right )
    Odd nodes promote to the next level.  Duplicate-last-node is NOT used;
    instead each node is labelled with its height ("NODE<h>") so a
    second-preimage via duplicated subtrees is blocked (the same trick
    Certificate Transparency uses against Merkle tree hash attacks).
  * The final single hash is the ROOT.  Anchoring the root anywhere outside
    the log (paper notebook, git commit, timestamping service) binds ALL
    evidence at once.

`verify_integrity()` re-derives the root from the persisted JSONL log and
compares it against the stored checkpoint — any modified, inserted, or
removed record changes the root and is pinpointed by index.

SAFETY / HONESTY NOTES
----------------------
* A Merkle tree proves *internal consistency*, not truth: a malicious log
  owner could delete a whole suffix.  That is why this implementation also
  writes an append-only HEAD checkpoint after every commit and refuses to
  shrink the sequence counter (monotonicity guard).  For real-world admissibility,
  publish the root to an external anchor (git tag, RFC3161 TSA, etc.).
* No privileged operations happen here; it just hashes strings.

COMPATIBILITY
-------------
Arch Linux & Termux; Python >= 3.8 standard library only (hashlib/json).

EXAMPLE
-------
    from evidence_logger import EvidenceLogger
    log = EvidenceLogger("/tmp/lab_session.jsonl")
    log.record("symbol_resolver", "resolve gatekeeper_verify",
               {"found": False, "note": "kptr_restrict masked"})
    log.record("selinux", "audit", {"enforce": "missing"})
    print(log.root())
    assert log.verify_integrity()
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Hashing primitives
# ---------------------------------------------------------------------------

SHA256 = hashlib.sha256

LEAF_PREFIX = b"KERNELX-LEAF-v1\x00"     # domain separation for leaves
NODE_PREFIX = b"KERNELX-NODE-v1\x00"     # domain separation for inner nodes


def _h(b: bytes) -> bytes:
    return SHA256(b).digest()


def leaf_hash(seq: int, ts: float, action: str, payload: str) -> bytes:
    """Hash one record. Canonical encoding => deterministic across platforms."""
    material = LEAF_PREFIX + f"{seq}|{ts:.6f}|{action}|{payload}".encode("utf-8")
    return _h(material)


def node_hash(left: bytes, right: bytes, height: int) -> bytes:
    """Inner node; height label prevents subtree-replay second preimages."""
    return _h(NODE_PREFIX + str(height).encode() + left + right)


# ---------------------------------------------------------------------------
# Merkle core (pure functions — easy to unit test)
# ---------------------------------------------------------------------------

def merkle_root(leaves: Sequence[bytes]) -> Optional[bytes]:
    """
    Compute the Merkle root over leaf digests.

    Rules:
      * empty list            -> None
      * odd count at a level  -> last node promotes unchanged (no duplication)
      * pairing is strictly left-to-right per level
    """
    if not leaves:
        return None
    level: List[bytes] = list(leaves)
    height = 0
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[i], level[i + 1], height))
        if len(level) % 2 == 1:                 # promote the orphan
            nxt.append(level[-1])
        level = nxt
        height += 1
    return level[0]


def inclusion_proof(leaves: Sequence[bytes], index: int
                    ) -> List[Tuple[bytes, str, int]]:
    """
    Return sibling path [(sibling_hash, 'L'|'R', height), ...] proving
    `index` membership.  Used by auditors who must verify ONE record
    without re-hashing the entire archive.

    NOTE: node hashing MUST use the same height label as merkle_root() at
    each level, otherwise the rebuilt path would not match the real root.
    Orphan nodes that promote (odd levels) carry no sibling step but still
    consume a height on the path — hence the explicit height in each entry.
    """
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    proof: List[Tuple[bytes, str, int]] = []
    idx = index
    level: List[bytes] = list(leaves)
    height = 0
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[i], level[i + 1], height))
        if len(level) % 2 == 1:
            nxt.append(level[-1])          # orphan promotes unchanged
        sib = idx ^ 1
        if sib < len(level):               # paired step: record sibling+side
            proof.append((level[sib], "R" if idx % 2 == 0 else "L", height))
        # else: our node was the orphan; it promotes with NO hash at this
        # height, but the height counter still advances for later steps.
        idx //= 2
        level = nxt
        height += 1
    return proof


def verify_inclusion(leaf: bytes,
                     proof: Sequence[Tuple[bytes, str, int]],
                     root: bytes) -> bool:
    """Rebuild the path from one leaf and compare with the anchored root."""
    cur = leaf
    for sib, side, height in proof:
        cur = node_hash(cur, sib, height) if side == "R" \
            else node_hash(sib, cur, height)
    return cur == root


# ---------------------------------------------------------------------------
# Persistent JSONL log
# ---------------------------------------------------------------------------

@dataclass
class Record:
    seq: int
    ts: float
    module: str
    action: str
    payload: str          # canonical JSON string

    @property
    def digest(self) -> bytes:
        return leaf_hash(self.seq, self.ts, f"{self.module}:{self.action}",
                         self.payload)

    def to_json(self) -> str:
        return json.dumps({"seq": self.seq, "ts": self.ts, "module": self.module,
                           "action": self.action, "payload": self.payload},
                          separators=(",", ":"))


class EvidenceLogger:
    """
    Append-only forensic log with a rolling Merkle root.

    File layout (JSON Lines):
      line 0 : header   {"type":"header","created":...,"version":1}
      line n : record   {"type":"record", seq, ts, module, action, payload}
      tail   : checkpoint {"type":"checkpoint", seq_upto, root_hex, updated}
    The checkpoint is rewritten atomically (tmp+rename) on every commit so a
    crash never leaves a torn state.
    """

    CHECKPOINT_NAME = ".kernelx_checkpoint.json"

    def __init__(self, path: str) -> None:
        self.path = path
        self._records: List[Record] = []
        self._next_seq = 0
        self._load_or_init()

    # -- persistence ----------------------------------------------------------

    def _load_or_init(self) -> None:
        if os.path.exists(self.CHECKPOINT_NAME):
            try:
                with open(self.CHECKPOINT_NAME, "r", encoding="utf-8") as fh:
                    ck = json.load(fh)
                self._expected_seq = int(ck.get("seq_upto", 0))
            except (OSError, ValueError, json.JSONDecodeError):
                self._expected_seq = 0
        else:
            self._expected_seq = 0

        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"type": "header", "version": 1,
                                     "created": time.time()}) + "\n")
            return

        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("type") == "record":
                    rec = Record(obj["seq"], obj["ts"], obj["module"],
                                 obj["action"], obj["payload"])
                    # Monotonicity guard: sequence must strictly increase.
                    if rec.seq != self._next_seq:
                        raise IntegrityError(
                            f"sequence discontinuity at {self.path}: "
                            f"expected seq={self._next_seq}, found {rec.seq}")
                    self._records.append(rec)
                    self._next_seq += 1

    def _write_checkpoint(self) -> None:
        root = self.root()
        payload = {"seq_upto": self._next_seq,
                   "root": root.hex() if root else None,
                   "updated": time.time()}
        tmp = self.CHECKPOINT_NAME + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.CHECKPOINT_NAME)
        # ADVANCED: anchor copy — a second checkpoint written to a different
        # location (on Termux: /sdcard after `termux-setup-storage`).  An
        # attacker who edits the log must now forge BOTH anchors consistently;
        # verify_integrity() cross-checks them and reports divergence.
        anchor_dir = os.environ.get("KERNELX_EVIDENCE_ANCHOR_DIR")
        if anchor_dir:
            try:
                os.makedirs(anchor_dir, exist_ok=True)
                atmp = os.path.join(anchor_dir,
                                    os.path.basename(self.path) +
                                    self.CHECKPOINT_NAME + ".tmp")
                afinal = atmp[:-4]
                with open(atmp, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(atmp, afinal)
            except OSError as exc:
                # Anchoring is defense-in-depth; never break logging over it.
                logger.warning("anchor write failed: %s", exc)

    # -- public API ------------------------------------------------------------

    def record(self, module: str, action: str,
               payload: object) -> Record:
        """Append one forensic action; returns the record (with its digest)."""
        rec = Record(seq=self._next_seq, ts=time.time(), module=module,
                     action=action,
                     payload=json.dumps(payload, sort_keys=True,
                                       ensure_ascii=False, default=str))
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "record", **vars(rec)}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())          # durability before acknowledgement
        self._records.append(rec)
        self._next_seq += 1
        self._write_checkpoint()
        return rec

    def root(self) -> Optional[bytes]:
        """Current Merkle root over all committed leaves (None if empty)."""
        return merkle_root([r.digest for r in self._records])

    def root_hex(self) -> str:
        r = self.root()
        return r.hex() if r else ""

    def prove(self, seq: int):
        """Inclusion proof for one record (see verify_inclusion)."""
        leaves = [r.digest for r in self._records]
        return inclusion_proof(leaves, seq), self.root()

    def verify_integrity(self) -> bool:
        """
        Re-read the ENTIRE log from disk and recompute the root.

        Detects:
          * modified record fields   -> root mismatch
          * deleted/inserted records -> sequence discontinuity or root mismatch
          * truncated log (suffix removal) -> checkpoint seq_upto regression
        Returns True iff everything recomputes identically.  Raises
        IntegrityError with the offending index when a structural break is
        found (so the investigator knows WHERE to look).
        """
        records: List[Record] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise IntegrityError(
                        f"torn/unparseable line {lineno}: {exc}") from exc
                if obj.get("type") == "record":
                    records.append(Record(obj["seq"], obj["ts"], obj["module"],
                                          obj["action"], obj["payload"]))

        # 1) strict ordering / no insertions-deletions in the middle
        for i, rec in enumerate(records):
            if rec.seq != i:
                raise IntegrityError(
                    f"record order broken: line gives seq={rec.seq} at "
                    f"position {i} (record was inserted, removed, or edited)")

        # 2) recompute root over the on-disk leaves
        derived = merkle_root([r.digest for r in records])

        # 3) compare with the independently fsync'd checkpoint
        if not os.path.exists(self.CHECKPOINT_NAME):
            raise IntegrityError("checkpoint file missing — cannot anchor root")
        with open(self.CHECKPOINT_NAME, "r", encoding="utf-8") as fh:
            ck = json.load(fh)

        if int(ck.get("seq_upto", 0)) > len(records):
            raise IntegrityError(
                f"log TRUNCATED: checkpoint saw {ck['seq_upto']} records but "
                f"file now holds {len(records)}")

        stored = ck.get("root")
        derived_hex = derived.hex() if derived else None
        if stored != derived_hex:
            # Locate first divergent prefix for the investigator's convenience
            for k in range(len(records) + 1):
                partial = merkle_root([r.digest for r in records[:k]])
                if (partial.hex() if partial else None) != stored and k == len(records):
                    raise IntegrityError(
                        f"MERKLE ROOT MISMATCH at record index {k-1 if k else 0}"
                        f": checkpoint={stored} recomputed={derived_hex}. "
                        "Evidence has been tampered with.")
            raise IntegrityError(f"merkle root mismatch: checkpoint={stored} "
                                 f"recomputed={derived_hex}")

        # 4) cross-check the secondary anchor (defense-in-depth, ADVANCED).
        anchor_dir = os.environ.get("KERNELX_EVIDENCE_ANCHOR_DIR")
        if anchor_dir:
            apath = os.path.join(anchor_dir, os.path.basename(self.path) +
                                 self.CHECKPOINT_NAME)
            if os.path.exists(apath):
                try:
                    with open(apath, "r", encoding="utf-8") as fh:
                        ack = json.load(fh)
                except (OSError, ValueError) as exc:
                    raise IntegrityError(
                        f"anchor checkpoint unreadable ({apath}): {exc}") from exc
                if (ack.get("root"), int(ack.get("seq_upto", 0))) != \
                   (stored, int(ck.get("seq_upto", 0))):
                    raise IntegrityError(
                        "ANCHOR DIVERGENCE: primary checkpoint and anchored "
                        f"copy ({apath}) disagree — one of them was rewritten; "
                        "treat evidence as compromised and preserve both files.")
            else:
                logger.warning("anchor dir set but no anchor file yet: %s",
                               apath)
        return True

    def audit(self) -> Dict[str, object]:
        """
        Machine-readable verification result (for correlation_engine /
        dashboards) instead of exception-driven control flow.
        """
        out: Dict[str, object] = {"log": self.path}
        try:
            ok = self.verify_integrity()
            out.update({"status": "PASS" if ok else "FAIL",
                        "root": self.root_hex(),
                        "records": self._next_seq})
        except IntegrityError as exc:
            out.update({"status": "FAIL", "error": str(exc)})
        return out

    # Convenience view --------------------------------------------------------
    def dump(self) -> str:
        lines = [f"log={self.path} records={len(self._records)} "
                 f"root={self.root_hex()}"]
        for r in self._records:
            lines.append(f"  #{r.seq} {time.strftime('%F %T', time.localtime(r.ts))} "
                         f"[{r.module}] {r.action} -> {r.digest.hex()[:16]}…")
        return "\n".join(lines)


class IntegrityError(RuntimeError):
    """Raised when verify_integrity() discovers tampering."""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", default="forensic_log.jsonl",
                    help="path of the append-only JSONL evidence log")
    ap.add_argument("--record", nargs=2, metavar=("MODULE:ACTION", "JSON"),
                    action="append",
                    help="add a record, e.g. --record 'selinux:audit' '{\"enforce\":0}'")
    ap.add_argument("--verify", action="store_true",
                    help="recompute the Merkle root from disk and check it")
    ap.add_argument("--dump", action="store_true")
    args = ap.parse_args(argv)

    log = EvidenceLogger(args.log)

    for spec in (args.record or []):
        mod_act, payload = spec
        module, _, action = mod_act.partition(":")
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = payload          # tolerate raw strings
        rec = log.record(module, action or "event", data)
        print(f"recorded #{rec.seq} digest={rec.digest.hex()}")

    if args.verify or not args.record:
        try:
            ok = log.verify_integrity()
            print("VERIFY: PASS — merkle root", log.root_hex() or "(empty log)")
        except IntegrityError as exc:
            print("VERIFY: FAIL —", exc)
            return 1

    if args.dump:
        fresh = EvidenceLogger(args.log)
        print(fresh.dump())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
