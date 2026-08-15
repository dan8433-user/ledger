"""arcaeon_ledger — a tamper-evident, append-only action log for AI agents.

Observability tools show you what your agent did. `arcaeon_ledger` lets you
PROVE it: every record is hash-chained to the one before it, so an edit,
deletion, or reorder in the middle of the history breaks every later link and
`verify()` names the exact line. Own the record; prove it wasn't altered.

Zero dependencies (stdlib only). One JSONL file. Two verbs: append, verify.

    from arcaeon_ledger import Ledger
    log = Ledger("agent.log.jsonl")
    log.append({"tool": "search", "query": "weather", "result_ok": True})
    log.verify()          # -> VerifyResult(ok=True, rows=1, ...)

WHAT IT PROVES, AND WHAT IT DOESN'T. A hash chain proves the recorded bytes were
not altered *in place* after they were written — mid-file edit, delete, reorder
all break it. It does NOT, by itself, prove three other things, and honesty
about the boundary is the point:
  - Truncation: lop off the most recent rows and what remains verifies clean.
    No append-only chain catches this alone. Close it by publishing the head
    (see `Ledger.head()`) somewhere outside your own control, on a cadence — an
    external witness that holds the head at time T makes any later rewrite that
    both differs and still verifies impossible.
  - Truth: the chain notarizes whatever was written, true or hallucinated. To
    bind a row to a re-fetchable fact, hash the artefact (URL+bytes, snapshot,
    tool stdout) and store the digest in the row.
  - Authorship: `authority()` records who-claimed-what, but it is data in the
    row, not a signature. A rewriter who re-mints from genesis can re-mint it
    too. External head-anchoring is what a re-minter cannot advance.

Extracted from a hash-chained action ledger running in production. MIT.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

__version__ = "0.5.2"
__all__ = ["Ledger", "VerifyResult", "verify_file", "chain_at", "authority", "Head",
           "bind_artefact", "verify_artefact", "digest_bytes", "digest_json",
           "WitnessStore", "publish_head", "verify_against_witness", "WitnessVerdict"]

_GENESIS = "genesis"
_CHAIN_LEN = 32  # first N hex chars of the sha256 — plenty for tamper-evidence


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain(prev: str, obj: dict) -> str:
    """chain = sha256(prev_chain + canonical-json-of-row-without-chain)."""
    body = json.dumps({k: v for k, v in obj.items() if k != "chain"},
                      ensure_ascii=False, sort_keys=True)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()[:_CHAIN_LEN]


def authority(principal: str, *, capability_version: str | None = None,
              tool_schema: Any = None, time_source: str = "local") -> dict:
    """Build an `authority` block for an entry: WHO acted, with what authority.

    A hash chain proves ORDER, not who wrote each entry or whether they were
    allowed to. Attaching this block makes the audit question sharper — "was
    this edited?" becomes "was this edited AND was the writer authorized?" —
    and lets tamper-evidence compose with permission-replay. (Requested by the
    community on launch, 2026-08-12.)

    - principal: the resolved actor (agent id, user, service).
    - capability_version: the version of the permission/capability set in force.
    - tool_schema: the tool's schema/signature — HASHED, so you bind what the
      tool looked like at call time, not just its name.
    - time_source: where the timestamp came from (e.g. "local", "ntp", an
      external attestation id). Names the trust surface of the clock.
    """
    block: dict[str, Any] = {"principal": principal, "time_source": time_source}
    if capability_version is not None:
        block["capability_version"] = capability_version
    if tool_schema is not None:
        canon = json.dumps(tool_schema, ensure_ascii=False, sort_keys=True)
        block["tool_schema_hash"] = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]
    return block


@dataclass
class VerifyResult:
    ok: bool
    rows: int = 0
    chained: int = 0
    prechain: int = 0
    first_break: str | None = None

    def __bool__(self) -> bool:  # `if log.verify(): ...`
        return self.ok


@dataclass
class Head:
    """A publishable pin of a log's current tip: chain head + row count + time.

    This is what you post somewhere OUTSIDE your own control (a git commit, a
    public comment, a notarization service) to close the truncation gap. Once a
    third party has recorded (chain, rows) at time `as_of`, no later rewrite can
    produce a log that both differs from that pin and still verifies — a
    truncated or re-minted history will disagree with the pinned head.
    """
    chain: str
    rows: int
    as_of: str

    def as_pin(self) -> str:
        """One-line, copy-pasteable pin string for publishing externally."""
        return f"arcaeon-ledger head chain={self.chain} rows={self.rows} as_of={self.as_of}"


class Ledger:
    """A hash-chained append-only JSONL log. One file, atomic appends."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    # -- write --------------------------------------------------------------
    def append(self, record: dict[str, Any], *, authority: dict | None = None) -> str:
        """Append one record; returns its chain hash. Stamps `ts` if absent.

        Pass `authority=` (build it with the module-level `authority()` helper)
        to bind WHO wrote the entry and with what permission — it becomes part
        of the chained, tamper-evident row, so the authority surface is proven
        alongside the order.

        Atomic: append-binary + flush + fsync, so a crash mid-write never
        corrupts the file (a partial line fails to parse and is caught by
        verify, it never silently poisons the chain).
        """
        obj = dict(record)
        if authority is not None:
            obj["authority"] = authority
        obj.setdefault("ts", _now_iso())
        obj.pop("chain", None)
        obj["chain"] = _chain(self._last_chain(), obj)
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as fh:
            fh.write(line.encode("utf-8"))
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass  # network mounts may not support fsync; flush is the floor
        return obj["chain"]

    def _last_chain(self) -> str:
        """Chain of the last row ('genesis' if empty/missing). Tail-read only."""
        try:
            with self.path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 8192))
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return _GENESIS
        for raw in reversed(tail.splitlines()):
            raw = raw.strip()
            if not raw:
                continue
            try:
                return json.loads(raw).get("chain") or _GENESIS
            except ValueError:
                continue
        return _GENESIS

    # -- read ---------------------------------------------------------------
    def __iter__(self) -> Iterator[dict]:
        try:
            for raw in self.path.read_text(encoding="utf-8",
                                           errors="replace").splitlines():
                raw = raw.strip()
                if raw:
                    try:
                        yield json.loads(raw)
                    except ValueError:
                        continue
        except OSError:
            return

    # -- verify -------------------------------------------------------------
    def verify(self) -> VerifyResult:
        return verify_file(self.path)

    # -- external anchoring -------------------------------------------------
    def head(self) -> Head:
        """Current tip of the log — publish this OUTSIDE your control to close
        the truncation gap.

        Returns the last row's chain value, the verified row count, and a
        timestamp. Post `head().as_pin()` somewhere a rewriter can't reach (a
        git commit, a public comment, a notarization anchor) on a cadence; a
        reader then checks a fresh `head()` against the last pin — a truncated
        or re-minted history disagrees. The max gap between pins is your real
        security parameter, not the average, because an attacker picks the gap.
        """
        res = verify_file(self.path)
        return Head(chain=self._last_chain(), rows=res.rows, as_of=_now_iso())


def chain_at(path: str | Path, n: int) -> str | None:
    """The chain value of the n-th row (1-indexed, by total parseable rows —
    matching Head.rows), or None if the file has fewer than n rows or that row
    carries no chain.

    Used to check a log against an external witness pin taken at row n: the pin
    records (rows, chain) at time T; `chain_at(path, pin.rows)` recomputes what
    this log now says at that same row, so a later truncation (fewer rows) or
    rewrite (different chain) is detectable against the outside record.
    """
    if n <= 0:
        return _GENESIS
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    count = 0
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        count += 1
        if count == n:
            return obj.get("chain")
    return None


def verify_file(path: str | Path) -> VerifyResult:
    """Recompute the chain over a file; report the first break by line number.

    Rows with no `chain` field are tolerated ONLY before the first chained row
    (legacy/pre-chain history) — an unchained row appearing after the chain has
    begun is itself a tamper signal. On a mismatch, verification continues from
    the CLAIMED value so later damage is counted honestly rather than cascading.
    """
    res = VerifyResult(ok=True)
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return VerifyResult(ok=False, first_break=f"unreadable: {e}")
    prev = _GENESIS
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            res.ok = False
            res.first_break = res.first_break or f"line {i}: unparseable"
            continue
        res.rows += 1
        claimed = obj.pop("chain", None)
        if claimed is None:
            if res.chained:
                res.ok = False
                res.first_break = res.first_break or f"line {i}: unchained row after chain began"
            else:
                res.prechain += 1
            continue
        want = _chain(prev, obj)
        if claimed != want:
            res.ok = False
            res.first_break = res.first_break or f"line {i}: chain mismatch"
        prev = claimed
        res.chained += 1
    return res


# Sub-module re-exports. Placed at the END, after Ledger/Head/chain_at/verify_file
# are defined, because arcaeon_ledger.witness imports those names back from this
# package — importing the sub-modules earlier would hit a partially-initialized
# module and fail. artefact has no such dependency but is kept here for symmetry.
from arcaeon_ledger.artefact import (  # noqa: E402
    bind_artefact, verify_artefact, digest_bytes, digest_json,
)
from arcaeon_ledger.witness import (  # noqa: E402
    WitnessStore, publish_head, verify_against_witness, WitnessVerdict,
)
