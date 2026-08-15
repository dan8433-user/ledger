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
  - Fabricated-legacy-prepend: rows with no `chain` field are tolerated BEFORE
    the first chained row (adoption-on-existing-log — real pre-chain history).
    That toleration is also a hole: PREPEND fabricated unchained "legacy" rows
    in front of a genuine chain and the file still verifies GREEN, because those
    rows are counted as `prechain` and skipped, not verified. `verify()` exposes
    the count via `prechain`, but the headline `ok`/`__bool__` ignore it. If your
    log has been chained from genesis and must have NO legacy rows, pass
    `verify(strict=True)`: it treats any unchained row as a break. (Inserting an
    unchained row AFTER the chain begins is already flagged in every mode.)

TWO WRITE-SIDE BOUNDARIES, named because a cross-language verifier will meet them
(audited 2026-08-14; both are on the writer, neither weakens `verify()` here):
  - Rows are serialized with Python's json.dumps. If you put float('nan') or
    float('inf') in a record it is written as the bare tokens NaN / Infinity,
    which round-trip in Python but are NOT valid JSON — a strict RFC 8259 parser
    in another language rejects the line and reads your honest log as damaged.
    Keep finite numbers in rows, or stringify them yourself. (`digest_json` DOES
    refuse NaN; the chain path deliberately still accepts what you hand it rather
    than raising inside an append that has already been decided on.)
  - JSON permits duplicate keys and parsers disagree on which wins (Python keeps
    the last). A row containing the same key twice can therefore read differently
    to different verifiers while the chain stays green over the last-wins parse.
    Don't hand-write rows; `append()` never produces one.

Extracted from a hash-chained action ledger running in production. MIT.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:                      # POSIX advisory locks
    import fcntl as _fcntl
except ImportError:       # pragma: no cover - platform dependent
    _fcntl = None
try:                      # Windows byte-range locks
    import msvcrt as _msvcrt
except ImportError:       # pragma: no cover - platform dependent
    _msvcrt = None

__version__ = "0.5.5"
__all__ = ["Ledger", "VerifyResult", "verify_file", "chain_at", "authority", "Head",
           "bind_artefact", "verify_artefact", "digest_bytes", "digest_json",
           "WitnessStore", "publish_head", "verify_against_witness", "WitnessVerdict"]

_GENESIS = "genesis"
_CHAIN_LEN = 32  # first N hex chars of the sha256 — plenty for tamper-evidence


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_SCAN_CHUNK = 8192      # initial backward-scan block
_SCAN_CHUNK_MAX = 1 << 20


def _line_start_before(fh, end: int) -> int:
    """Byte offset just after the last newline strictly before `end` (else 0).

    Walks backwards in doubling blocks, so finding the start of a line costs one
    pass over that line however long it is — a 40 MB row is found in 40 MB of
    reads, not in a fixed window that silently misses it.
    """
    pos = end
    chunk = _SCAN_CHUNK
    while pos > 0:
        start = max(0, pos - chunk)
        fh.seek(start)
        idx = fh.read(pos - start).rfind(b"\n")
        if idx != -1:
            return start + idx + 1
        pos = start
        chunk = min(chunk * 2, _SCAN_CHUNK_MAX)
    return 0


def _chain(prev: str, obj: dict) -> str:
    """chain = sha256(prev_chain + canonical-json-of-row-without-chain)."""
    body = json.dumps({k: v for k, v in obj.items() if k != "chain"},
                      ensure_ascii=False, sort_keys=True)
    # str(prev) is a no-op on every honest path (prev is always a hex string
    # produced here or 'genesis'); it is a defense-in-depth floor so no route to
    # a non-string prev can ever crash the hash with `int + str` (0.5.5).
    return hashlib.sha256((str(prev) + body).encode("utf-8")).hexdigest()[:_CHAIN_LEN]


_APPEND_LOCK_TIMEOUT = 15.0   # seconds to wait for a contended append lock


@contextmanager
def _append_lock(path: Path):
    """Cross-process exclusive lock around the read-tail + write of one append.

    `append()` is a read-modify-write: it reads the previous chain (`_last_chain`)
    then writes a row chaining from it. Without a lock, two concurrent writers
    both read the same previous chain and both chain from it — the chain FORKS
    (later `verify()` reports mismatches) and on Windows the interleaved `"ab"`
    writes also drop rows outright. Serializing the whole read-then-write section
    across processes makes concurrent `append()` safe: each writer sees the tail
    the previous one actually committed.

    Held on a sidecar `<path>.lock` file, never on the ledger itself, so the lock
    never touches the emitted bytes. Acquisition is blocking-with-retry (a busy
    loop against the non-blocking primitive, bounded by `_APPEND_LOCK_TIMEOUT`),
    so contended writers wait and serialize rather than error. If the platform
    offers no lock primitive at all, it degrades to no lock (best-effort,
    single-writer assumption) rather than failing the append — correctness of a
    lone writer is never reduced.
    """
    if _msvcrt is None and _fcntl is None:   # pragma: no cover - exotic platform
        yield False
        return
    lock_path = Path(str(path) + ".lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + _APPEND_LOCK_TIMEOUT
        delay = 0.001
        while True:
            try:
                if _msvcrt is not None:
                    _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                else:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    # Fall through unlocked rather than fail the append. A stuck
                    # lock must not become a hard write outage; the single-writer
                    # path is still correct, and a concurrent one degrades to the
                    # pre-lock behaviour (RED-detectable), never to a lost verdict.
                    yield False
                    return
                time.sleep(delay)
                delay = min(delay * 2, 0.05)
        try:
            yield True
        finally:
            try:
                if _msvcrt is not None:
                    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
                else:
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
            except OSError:              # pragma: no cover - best effort
                pass
    finally:
        os.close(fd)


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
    # Total breaks found, not just the first. Added 0.5.3 so the documented
    # "verification continues from the CLAIMED value, so later damage is counted
    # honestly rather than cascading" is OBSERVABLE: a single mid-file edit must
    # produce breaks == 1. A verifier that cascaded reported the same first_break
    # and was indistinguishable until this field existed.
    breaks: int = 0

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
    """A hash-chained append-only JSONL log. One file; each append is a single
    atomic line write, and the read-tail + write is guarded by a cross-process
    file lock so concurrent writers serialize instead of forking the chain."""

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

        Concurrency-safe: the read-previous-chain + write is held under a
        cross-process file lock (`<path>.lock`), so two processes appending at
        once serialize rather than both chaining from the same tail and forking
        the log. The lock never touches the emitted bytes.
        """
        obj = dict(record)
        if authority is not None:
            obj["authority"] = authority
        obj.setdefault("ts", _now_iso())
        obj.pop("chain", None)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The chain read and the write are ONE critical section: the row must
        # chain from the tail that is still the tail when it lands. Compute the
        # chain, heal a missing newline, and write, all under the lock.
        with _append_lock(self.path):
            obj["chain"] = _chain(self._last_chain(), obj)
            line = json.dumps(obj, ensure_ascii=False) + "\n"
            # Heal a missing trailing newline before appending. A torn prior write
            # (crash mid-append) or a file touched by external tooling can end
            # WITHOUT a final "\n"; appending directly would glue this row onto that
            # last line, producing one unparseable blob and destroying BOTH rows —
            # silently, since append still returns a valid-looking chain hash. A
            # normally-produced ledger always ends in "\n", so this branch never
            # fires on the happy path and the emitted format is unchanged. The
            # separator + row are written in a single call so the torn line becomes
            # its own (flagged) line rather than swallowing the new row.
            sep = b""
            try:
                with self.path.open("rb") as rf:
                    rf.seek(0, os.SEEK_END)
                    if rf.tell() > 0:
                        rf.seek(-1, os.SEEK_END)
                        if rf.read(1) != b"\n":
                            sep = b"\n"
            except OSError:
                pass
            with self.path.open("ab") as fh:
                fh.write(sep + line.encode("utf-8"))
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass  # network mounts may not support fsync; flush is the floor
        return obj["chain"]

    def _last_chain(self) -> str:
        """Chain of the last row ('genesis' if empty/missing).

        Reads BACKWARDS a line at a time until a complete, parseable object row
        is in hand — never a fixed-size tail window.

        This is load-bearing, not a tidy-up (fixed 0.5.3). Through 0.5.2 this read
        a fixed 8 KB tail: a final row LONGER than that window left no parseable
        line inside it, so this returned 'genesis' and the next append started a
        FRESH CHAIN mid-file. Nothing warned; verify() then reported a mismatch on
        an honest log, and — far worse — every row before the reset point became
        detachable: delete them all and the remainder verified GREEN. Rows over
        8 KB are ordinary (a fetched page, tool stdout), so this was reachable
        without an attacker doing anything but waiting.
        """
        try:
            with self.path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                end = fh.tell()
                while end > 0:
                    start = _line_start_before(fh, end)
                    fh.seek(start)
                    raw = fh.read(end - start).strip()
                    if raw:
                        try:
                            obj = json.loads(raw.decode("utf-8", errors="replace"))
                        except ValueError:
                            obj = None  # partial/corrupt line: keep walking back
                        if isinstance(obj, dict):
                            return obj.get("chain") or _GENESIS
                    if start == 0:
                        break
                    end = start - 1  # step over the delimiting newline
        except OSError:
            return _GENESIS
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
    def verify(self, *, strict: bool = False) -> VerifyResult:
        return verify_file(self.path, strict=strict)

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
        if not isinstance(obj, dict):
            continue  # not a row; must be counted exactly as verify_file counts
        count += 1
        if count == n:
            return obj.get("chain")
    return None


def verify_file(path: str | Path, *, strict: bool = False) -> VerifyResult:
    """Recompute the chain over a file; report the first break by line number.

    Rows with no `chain` field are tolerated ONLY before the first chained row
    (legacy/pre-chain history) — an unchained row appearing after the chain has
    begun is itself a tamper signal. On a mismatch, verification continues from
    the CLAIMED value so later damage is counted honestly rather than cascading.

    `strict=True` closes the fabricated-legacy-prepend hole: it treats ANY
    unchained row as a break, so prepended fake "legacy" rows in front of a
    genuine chain no longer verify green. Use it when the log is asserted to be
    chained from genesis with no legitimate pre-chain history. The prechain
    count is still reported either way; strict only decides whether it fails.
    """
    res = VerifyResult(ok=True)
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return VerifyResult(ok=False, first_break=f"unreadable: {e}", breaks=1)
    prev = _GENESIS
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            res.ok = False
            res.breaks += 1
            res.first_break = res.first_break or f"line {i}: unparseable"
            continue
        if not isinstance(obj, dict):
            # A bare scalar/array line is not a row. Before 0.5.3 this reached
            # obj.pop("chain") and raised AttributeError/TypeError out of
            # verify() — one smuggled line turned the verifier into a crash
            # instead of a verdict. It is a break, named like every other break.
            res.ok = False
            res.breaks += 1
            res.first_break = res.first_break or f"line {i}: not a JSON object"
            continue
        res.rows += 1
        claimed = obj.pop("chain", None)
        if claimed is None:
            if res.chained:
                res.ok = False
                res.breaks += 1
                res.first_break = res.first_break or f"line {i}: unchained row after chain began"
            elif strict:
                # A prechain (unchained-before-chain) row. Tolerated by default as
                # legacy history; in strict mode it is a break, so a fabricated
                # "legacy" prepend cannot ride in green. Still counted as prechain
                # so the surfaced count is identical between modes.
                res.prechain += 1
                res.ok = False
                res.breaks += 1
                res.first_break = res.first_break or f"line {i}: unchained (prechain) row rejected in strict mode"
            else:
                res.prechain += 1
            continue
        if not isinstance(claimed, str):
            # A chain link is a hex string. A present-but-NON-STRING chain
            # (int/float/bool/list/dict — all legal JSON, so all arrive from the
            # wire or a corrupt file) is malformed: never a valid link, always a
            # break. It must be reported as one, not crash the verifier. Left
            # unguarded it flowed into `prev = claimed` below, and the NEXT row's
            # `_chain(prev, obj)` does `prev + body` on a non-str prev and raised
            # TypeError — turning verify() into an exception instead of a verdict,
            # the same crash class the bare-scalar guard above closes. Continue
            # from a safe, deterministic string so later rows are still checked
            # and one poisoned link does not cascade (a following honest row was
            # chained from the real hex head, so it still fails against "" — no
            # false green). Found by property-fuzzing, 0.5.5.
            res.ok = False
            res.breaks += 1
            res.first_break = res.first_break or f"line {i}: non-string chain value"
            prev = ""
            res.chained += 1
            continue
        want = _chain(prev, obj)
        if claimed != want:
            res.ok = False
            res.breaks += 1
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
