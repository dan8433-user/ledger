# SPDX-License-Identifier: MIT
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
    Those rows are counted as `prechain` and skipped, not verified — and the
    verifier cannot tell real legacy history from a fabricated prepend. So
    (0.5.7) a non-strict verify that skipped any rows no longer mints a green:
    `ok` is None ("no break found, verified within scope"), `__bool__` is falsy,
    and `verified_scope` says "bounded_prechain_skipped" in-band. Only a scan
    that checked EVERY row returns `ok=True`. If your log has been chained from
    genesis and must have NO legacy rows, pass `verify(strict=True)`: it treats
    any unchained row as a break. (Inserting an unchained row AFTER the chain
    begins is already flagged in every mode.)

A BREAK, ONCE MADE, IS PERMANENT — and `declare_break` (0.6.0) is the only
sanctioned repair. A log written out of band is broken forever and that is
correct; recomputing the chain so the file goes green again is forging it. So
instead you APPEND a row naming the break: which line, the orphan's exact bytes
pinned by sha256, a human reason, a date, and the chain the record resumed from.
`verify()` then stops calling it an unexplained break — and stops short of
calling it verified: `ok` becomes None with `verified_scope`
"bounded_declared_break", the break stays listed in `declared` forever, and
`strict=True` ignores declarations entirely. Its honest limit, stated in its own
docstring rather than buried: anyone who can write the file can write a
declaration, so it raises NO bar against an attacker with write access. It
defends against FORGETTING, not against tampering.

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
from dataclasses import dataclass, field
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

__version__ = "0.7.1"
__all__ = ["LedgerWriteError", "Ledger", "VerifyResult", "verify_file", "chain_at", "authority", "Head",
           "declare_break",
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
    """chain = sha256(prev_chain + json.dumps(row_without_chain, sort_keys=True)).

    Note the separators: this is Python's DEFAULT `", "` / `": "` spacing, NOT the
    compact `json-c14n:v1` form used by `digest_json`. The chain body is its own
    unversioned rule and always has been. Written out here because the README
    described it as "canonical_json", and anyone building a cross-language verifier
    from that word got a mismatch on every honest row.
    """
    body = json.dumps({k: v for k, v in obj.items() if k != "chain"},
                      ensure_ascii=False, sort_keys=True)
    # str(prev) is a no-op on every honest path (prev is always a hex string
    # produced here or 'genesis'); it is a defense-in-depth floor so no route to
    # a non-string prev can ever crash the hash with `int + str` (0.5.5).
    #
    # errors="surrogatepass" (0.5.8) so a LONE SURROGATE cannot turn the verifier
    # into a crash. JSON permits `\udXXX` escapes and `json.dumps` emits them by
    # default, so any cross-language writer or log-shipper can put an unpaired
    # surrogate in a row that is perfectly valid JSON. Plain UTF-8 refuses to
    # encode it, which raised UnicodeEncodeError out of here and left the file
    # append-able and iterable while `verify`, `head` and `bundle` were all
    # PERMANENTLY DEAD on it. That is the exact failure this module refuses twice
    # elsewhere: "one smuggled line turned the verifier into a crash instead of a
    # verdict." surrogatepass is deterministic and byte-identical for every input
    # that could already be encoded, so no honest historical digest moves.
    return hashlib.sha256(
        (str(prev) + body).encode("utf-8", "surrogatepass")).hexdigest()[:_CHAIN_LEN]


class LedgerWriteError(OSError):
    """A row was not stored, and `append()` refuses to report success for it.

    Distinct from the OSErrors the filesystem raises on its own: this one means the
    write reported success and the bytes are not there. It subclasses OSError so
    existing `except OSError` handlers around append keep working.
    """


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
    # Three-valued since 0.5.7 (the continuity-0.2.0 idiom: never mint a bare
    # green whose scope lives in a sibling field the reader isn't forced through):
    #   True  — every row was verified. Full green.
    #   None  — no break found, BUT the scan was bounded: unchained prechain rows
    #           were skipped unverified, and/or a break was excused by a
    #           declaration (0.6.0). "Verified within scope" is not "verified";
    #           the old ok=True here let a fabricated legacy prepend ride a green
    #           the consumer's `if r.ok:` never questioned.
    #   False — a break was found.
    # A consumer that reads only `ok` now gets null/falsy on the bounded case —
    # fail-safe — instead of a false green. The scope rides in-band in
    # `verified_scope`; the skipped-row count stays in `prechain`.
    ok: bool | None
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
    # "full"                     — every parseable row was checked (strict mode
    #                              always; non-strict when prechain == 0).
    # "bounded_prechain_skipped" — non-strict verify skipped `prechain` unchained
    #                              rows unverified; the verdict covers only the
    #                              chained region. Set on failures too: a red over
    #                              a bounded scan is still a bounded scan.
    # "bounded_declared_break"   — no UNDECLARED break, but one or more breaks
    #                              were excused by a `chain_break_declared` row
    #                              (see `declare_break`). Non-strict only.
    # "bounded_prechain_skipped+declared_break" — both of the above at once.
    verified_scope: str = "full"
    # Breaks excused by a declaration (0.6.0). Counted SEPARATELY from `breaks`
    # and never folded into it: a declared break is still a break in the record,
    # it is just one that was named, dated, reasoned and pinned to exact bytes
    # instead of left unexplained. It stays here permanently — there is no mode
    # in which declaring a break makes it disappear from the verdict.
    declared_breaks: int = 0
    #: One human-readable line per excused break, e.g.
    #: "line 25: declared break (hand-appended during an incident)". Present on
    #: every result that excused anything, so a reader who prints the result
    #: cannot miss that the file has a known hole in its chain.
    declared: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # `if log.verify(): ...`
        # Truthy ONLY on the full green. A bounded (ok=None) verification is
        # falsy — fails safe, same as continuity's `faithful is True`.
        return self.ok is True


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
            # STRICT utf-8 on the WRITE, deliberately asymmetric with `_chain`'s
            # surrogatepass. The two sides answer different questions.
            #
            # Write side: a row carrying a lone surrogate must be REFUSED, loudly,
            # before any bytes are written. This raises UnicodeEncodeError here, the
            # file is never opened, and nothing is recorded — which is correct, and
            # is what the library already did. Writing it with surrogatepass instead
            # would emit WTF-8 bytes that the reader (utf-8 + errors="replace")
            # decodes back as U+FFFD, so the row would land and then verify RED
            # forever. A refused write is honest; an accepted write that can never
            # verify is a slow-motion false alarm.
            #
            # Read side: `_chain` must still be able to hash a surrogate-bearing row,
            # because such a row can arrive from a FOREIGN writer: json.dumps with
            # its default ensure_ascii=True emits the six-character escape as pure
            # ASCII, as does JS JSON.stringify. We do not control who appends to a
            # JSONL file. The verifier's job is to return a verdict about that row,
            # not to die on it.
            payload = sep + line.encode("utf-8")
            with self.path.open("ab") as fh:
                fh.write(payload)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass  # network mounts may not support fsync; flush is the floor
                # CONFIRM THE ROW LANDED (0.5.8). Until now `append()` returned a
                # valid chain hash without ever checking that anything was stored,
                # and there is a path where nothing is: on Windows a final path
                # component that is exactly a reserved DEVICE name (`nul`, `NUL`,
                # `nul.`, `con`, ...) opens successfully, accepts every write, and
                # keeps the file at zero bytes. Such a name arrives ordinarily, from
                # a config value or an agent id used to build an extension-less log
                # path. Every append then succeeded, the file stayed empty, and
                # `verify` reported intact — a write black hole that no check saw.
                #
                # `tell()` after a successful append is the cheapest true statement
                # about whether bytes exist. It costs one syscall per row and it is
                # the difference between "the writer believes it wrote" and "the
                # file contains it". A logger that cannot tell those apart is not an
                # audit logger.
                try:
                    landed = fh.tell()
                except OSError as e:
                    raise LedgerWriteError(
                        f"cannot confirm the row landed in {self.path}: {e}") from e
            if landed < len(payload):
                raise LedgerWriteError(
                    f"wrote {len(payload)} bytes to {self.path} but the file holds "
                    f"{landed} — the write was discarded. On Windows this is what a "
                    f"reserved device name (nul, con, aux, prn, com1-9, lpt1-9) does: "
                    f"it accepts writes and stores nothing. Nothing was recorded.")
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
            # split("\n"), NOT splitlines(). read_text() already normalizes
            # \r\n / \r to \n (universal newlines), so "\n" is the only row
            # delimiter this file's writer ever emits. splitlines() ALSO
            # breaks on U+0085/U+2028/U+2029 (and a few C0 separators) —
            # characters json.dumps(..., ensure_ascii=False) does NOT escape
            # (they're outside the mandatory U+0000-U+001F escape range), so
            # they round-trip raw into a row's content. A row containing one
            # of them then gets sliced into fragments that fail to parse:
            # sealed cleanly by append(), unreadable back — same bug class as
            # the 2026-08-15 continuity splitlines find. (Fixed, unreleased.)
            for raw in self.path.read_text(encoding="utf-8",
                                           errors="replace").split("\n"):
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
        # split("\n"), not splitlines() -- see the note in Ledger.__iter__:
        # splitlines() also breaks on U+0085/U+2028/U+2029, which the writer
        # never uses as a delimiter but which unescaped row CONTENT can
        # legitimately contain (ensure_ascii=False doesn't escape them).
        lines = Path(path).read_text(encoding="utf-8", errors="replace").split("\n")
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


_DECLARE_OP = "chain_break_declared"


def declare_break(path: str | Path, orphan_line: int, why: str,
                  *, resume_prev: str | None = None,
                  authority: dict | None = None) -> dict:
    """Name a chain break instead of hiding it, and pin it to exact bytes.

    A chained ledger that has been written out of band is broken forever, and
    that is correct: the break is the true record. The wrong repair is to
    recompute the chain so the file verifies again, because a chain you can
    silently re-forge is not evidence of anything. This is the right repair. It
    APPENDS (never edits) a row saying: this line, these exact bytes, this
    reason, this date, and the chain the record resumed from.

    The break stays a break. `verify()` still reports it, permanently, in
    `declared` / `declared_breaks`, and the verdict stays BOUNDED -- `ok` becomes
    None with `verified_scope` naming the declaration, never True. What changes
    is that a KNOWN, explained break stops masquerading as an unexplained one,
    and the orphan content is pinned: edit those bytes afterwards and the sha
    stops matching and the ledger goes red again.

    INSTRUMENT DEFECTS -- what this does NOT prove, stated first, because
    understating a tool's limits in its own docstring is the exact failure this
    package exists to argue against:

      - IT IS A RECORD DEVICE, NOT A CRYPTOGRAPHIC ONE. Anyone who can write the
        file can write a declaration, so it raises NO bar against an attacker who
        already has write access. It defends against FORGETTING, not against
        tampering. Everything below is one more face of this single fact.
      - It cannot tell an honest out-of-band append from a malicious one. `why`
        is an unverified human claim; nothing checks it, and nothing can.
      - It only declares breaks `verify()` ALREADY FOUND. It does nothing about a
        break nobody noticed, and it gives no help finding one.
      - The declaration is honored on its CONTENT plus one cheap structural bar
        (the declaring row must itself carry a `chain`, i.e. have come through
        `append()`), NOT on that chain having been verified -- the excusal
        decision is made in a pre-scan, before the walk that would judge it. A
        hand-written declaration whose own chain value is bogus still excuses,
        and is then reported as a break in its own right at its own line. That is
        a real hole, and it is the same hole as the first bullet.
      - `resume_prev` is taken on trust, but a wrong value fails the very next
        row, so it cannot launder a rewritten tail without showing up at once.

    Args:
      orphan_line: 1-based line number in the file, exactly as `verify()` reports
        it (rows are split on newline; see `verify_file`).
      why: a non-empty human reason. Blank is refused -- an unexplained
        declaration is not a declaration, it is a mute exemption.
      resume_prev: for an UNCHAINED orphan, the chain value the writer resumed
        from. Omit it and the walk resumes from genesis, which is the honest
        answer when the resume point is genuinely unknown (the following row then
        fails, and that failure is true).

    Returns the appended row.
    """
    if not isinstance(why, str) or not why.strip():
        raise ValueError("declare_break needs a non-empty `why`: an unexplained "
                         "declaration excuses a break without naming it, which is "
                         "the thing this function exists to refuse")
    if not isinstance(orphan_line, int) or isinstance(orphan_line, bool):
        raise ValueError(f"orphan_line must be an int line number, got {orphan_line!r}")
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e}") from e
    if not (1 <= orphan_line <= len(lines)):
        raise ValueError(f"line {orphan_line} is not in {path}")
    raw = lines[orphan_line - 1].strip()
    if not raw:
        raise ValueError(f"line {orphan_line} of {path} is blank; nothing to pin")
    row: dict[str, Any] = {
        "op": _DECLARE_OP,
        "orphan_line": orphan_line,
        # sha256 of the STRIPPED line, the same string `verify_file` hashes. Full
        # 64 hex chars, not the chain's truncated 32: this is a content pin and
        # there is no chaining cost to paying for the whole digest here.
        "orphan_sha256": hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest(),
        "why": why.strip(),
    }
    if resume_prev is not None:
        if not isinstance(resume_prev, str):
            raise ValueError(f"resume_prev must be a chain string, got {resume_prev!r}")
        row["resume_prev"] = resume_prev
    chain = Ledger(path).append(row, authority=authority)
    row["chain"] = chain
    return row


def _scan_declarations(lines: list[str]) -> dict[int, dict]:
    """Pre-scan for `chain_break_declared` rows, keyed by the line each excuses.

    Two bars, both cheap, neither cryptographic (see `declare_break`'s defect
    list). A row must (a) be a well-formed declaration -- the op, an int
    `orphan_line`, a 64-hex `orphan_sha256`, a non-empty `why` -- and (b) carry a
    `chain` field, i.e. have come through `append()` rather than being echoed
    into the file by hand. (b) does not check that the chain VERIFIES; that
    verdict belongs to the walk this scan runs before. It only means a raw
    unchained line cannot hand out exemptions.

    Last declaration for a line wins, so a later corrected declaration supersedes
    an earlier one without anybody editing a row.
    """
    found: dict[int, dict] = {}
    for raw in lines:
        raw = raw.strip()
        if not raw or _DECLARE_OP not in raw:
            continue
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(d, dict) or d.get("op") != _DECLARE_OP:
            continue
        line_no = d.get("orphan_line")
        sha = d.get("orphan_sha256")
        why = d.get("why")
        if (isinstance(line_no, int) and not isinstance(line_no, bool)
                and isinstance(sha, str) and len(sha) == 64
                and isinstance(why, str) and why.strip()
                and isinstance(d.get("chain"), str)):
            found[line_no] = d
    return found


def _excused(declared: dict[int, dict], line_no: int, raw: str) -> dict | None:
    """The declaration covering this line IF it pins these exact bytes, else None.

    The sha comparison is the whole guarantee: a declaration excuses the content
    it named and nothing else. Edit the orphan afterwards, or forge the sha, and
    this returns None and the break is reported like any other.
    """
    d = declared.get(line_no)
    if d is None:
        return None
    got = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()
    return d if d.get("orphan_sha256") == got else None


def verify_file(path: str | Path, *, strict: bool = False) -> VerifyResult:
    """Recompute the chain over a file; report the first break by line number.

    Rows with no `chain` field are tolerated ONLY before the first chained row
    (legacy/pre-chain history) — an unchained row appearing after the chain has
    begun is itself a tamper signal. On a mismatch, verification continues from
    the CLAIMED value so later damage is counted honestly rather than cascading.

    The verdict is three-valued and carries its scope (0.5.7):
      ok=True,  verified_scope="full"                     — every row verified.
      ok=None,  verified_scope="bounded_prechain_skipped" — no break found, but
                `prechain` unchained rows were SKIPPED unverified (non-strict).
                Falsy. Not a green: the verifier cannot distinguish real legacy
                history from a fabricated prepend, so it does not claim to.
      ok=False — a break was found (scope still says what was scanned).

    DECLARED BREAKS (0.6.0). A break that a `chain_break_declared` row names and
    pins (see `declare_break`) is not counted in `breaks` and does not turn the
    verdict red. It is counted in `declared_breaks`, described in `declared`, and
    the verdict becomes ok=None / verified_scope="bounded_declared_break" -- never
    True. The reason it cannot mint a green is this module's own standing rule,
    written for the prechain case in 0.5.7 and applying unchanged here: only a
    scan that CHECKED EVERY ROW returns True. An excused row was not checked; the
    chain does not link across it, and what stands in for the link is a human
    sentence. A declaration converts an unexplained red into a named, bounded
    null. That is the whole of what it does, and it is enough.

    Only two break classes are declarable, both being the signature of an
    out-of-band append: an unchained row after the chain began, and a chain
    mismatch. Unparseable lines, non-object lines, non-string chain values and
    unhashable rows are NOT declarable -- those are malformed bytes, not a
    recorded event somebody wrote outside the tool, and there is nothing there to
    stand behind.

    DECLARATIONS ARE IGNORED ENTIRELY IN STRICT MODE, deliberately. Strict exists
    for the caller who wants no tolerance at all -- it already refuses prechain
    rows that non-strict accepts as legitimate history. A declaration is an
    unverified human claim (`declare_break` says so in its own docstring), and
    honoring an unverified claim is precisely the tolerance strict was asked to
    drop. So `verify(strict=True)` reports a declared break as a break, in
    `breaks` and in `first_break`, exactly as it did before this feature existed:
    adding declarations must not make any strict verdict newly greener, and it
    does not. The declaration rows are still reported in `declared` under strict
    so the mode difference is visible rather than silent.

    `strict=True` closes the fabricated-legacy-prepend hole harder: it treats
    ANY unchained row as a break, so prepended fake "legacy" rows in front of a
    genuine chain fail red. Use it when the log is asserted to be chained from
    genesis with no legitimate pre-chain history. The prechain count is still
    reported either way; strict decides whether skipping is even allowed.
    """
    res = VerifyResult(ok=True)
    try:
        # split("\n"), not splitlines() -- the writer's only row delimiter is
        # a literal LF (append() always writes json.dumps(...) + "\n"), and
        # read_text()'s universal-newline handling already folds \r\n / \r to
        # \n before this line runs. splitlines() additionally treats
        # U+0085/U+2028/U+2029/\x0b/\x0c/\x1c-\x1e as row breaks even though
        # they are ordinary, UNESCAPED row *content* under
        # ensure_ascii=False (json.dumps only escapes U+0000-U+001F) — so an
        # honest row containing one of them was sliced into unparseable
        # fragments and reported as a break, even though nothing was
        # tampered: sealed cleanly by append(), unverifiable on read. Same
        # bug class as the 2026-08-15 continuity splitlines find. (Fixed, unreleased.)
        lines = Path(path).read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError as e:
        return VerifyResult(ok=False, first_break=f"unreadable: {e}", breaks=1)
    # Declarations are read in a pass of their own, because a declaration lives
    # AFTER the break it names (the file is append-only; there is no other place
    # to put it) and the walk below needs the answer when it reaches the orphan.
    # Read `declare_break`'s defect list for what this does and does not buy --
    # in particular, that it buys nothing at all against someone with write
    # access, and is not offered as if it did.
    declared = _scan_declarations(lines)
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
                # The out-of-band-append signature, and the first of the two
                # declarable break classes.
                d = None if strict else _excused(declared, i, raw)
                if d is not None:
                    res.declared_breaks += 1
                    res.declared.append(
                        f"line {i}: declared break ({d['why']})")
                    # Resume from the value the writer says the record resumed
                    # from. Absent, resume from genesis: an unknown resume point
                    # is stated as unknown, and the next row's failure is true.
                    # A WRONG resume_prev fails the very next row, so this
                    # cannot launder a rewritten tail.
                    rp = d.get("resume_prev")
                    prev = rp if isinstance(rp, str) and rp else _GENESIS
                    continue
                res.ok = False
                res.breaks += 1
                if not strict and declared.get(i) is not None:
                    # A declaration exists for this line and does not match these
                    # bytes. Say that, rather than the bare "unchained row": the
                    # difference between "nobody explained this" and "somebody
                    # explained this and then the bytes moved" is the whole point
                    # of pinning the content.
                    res.first_break = res.first_break or (
                        f"line {i}: unchained row after chain began; a declaration "
                        f"exists but its orphan_sha256 does not match these bytes")
                else:
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
        try:
            want = _chain(prev, obj)
        except (UnicodeEncodeError, ValueError, TypeError, RecursionError) as e:
            # Belt to `_chain`'s surrogatepass braces. Anything that makes a row
            # un-hashable is a break with a line number, never an exception out of
            # the verifier: the whole contract of this function is that it returns a
            # verdict about every file, including a hostile one. Continue from a
            # deterministic value so one poisoned row cannot hide the rest.
            res.ok = False
            res.breaks += 1
            res.first_break = res.first_break or f"line {i}: unhashable row ({type(e).__name__})"
            prev = claimed
            res.chained += 1
            continue
        if claimed != want:
            # Second declarable class: a row carrying a chain value that verifies
            # against nothing (hand-written, or edited after append). `prev` still
            # advances to `claimed` below, exactly as on the undeclared path, so
            # `resume_prev` plays no part here -- the file itself already says
            # where it resumed.
            d = None if strict else _excused(declared, i, raw)
            if d is not None:
                res.declared_breaks += 1
                res.declared.append(f"line {i}: declared break ({d['why']})")
            else:
                res.ok = False
                res.breaks += 1
                if not strict and declared.get(i) is not None:
                    res.first_break = res.first_break or (
                        f"line {i}: chain mismatch; a declaration exists but its "
                        f"orphan_sha256 does not match these bytes")
                else:
                    res.first_break = res.first_break or f"line {i}: chain mismatch"
        prev = claimed
        res.chained += 1
    # Scope stamping (0.5.7). In non-strict mode, skipped prechain rows bound
    # the verdict: whatever the answer is, it covers only the chained region.
    # And a green over a bounded scan is not a green — it becomes ok=None
    # ("verified within scope"), so the fabricated-legacy-prepend can no longer
    # ride a bare True past a consumer that reads only `ok`. Strict mode never
    # skips (prechain rows are breaks there), so its scope is always "full".
    #
    # A declared break bounds the verdict the same way, for the same reason: the
    # chain was not checked across that row. `declared_breaks` rides in-band next
    # to it, and `declared` names each one, so the hole is described and not
    # merely counted.
    if not strict and (res.prechain or res.declared_breaks):
        if res.prechain and res.declared_breaks:
            res.verified_scope = "bounded_prechain_skipped+declared_break"
        elif res.prechain:
            res.verified_scope = "bounded_prechain_skipped"
        else:
            res.verified_scope = "bounded_declared_break"
        if res.ok:
            res.ok = None
    elif res.rows == 0 and res.ok:
        # A FILE WITH NO ROWS IS NOT A VERIFIED FILE (0.5.8). This used to return
        # ok=True with verified_scope="full", which reads as "every row was checked
        # and the chain holds" about a file containing nothing. Three things
        # downstream believed it: `bool(verify(...))`, `head()`/`publish_head`, and
        # `build_bundle`, whose auditor README printed "VERDICT: intact. Every row
        # was checked in strict mode and the hash chain holds end to end." over
        # zero bytes, with the sha256 of the empty string beside it.
        #
        # The README already warned that automation branching on `.ok` "needs to
        # check first_break". Our own bundle generator was that automation and did
        # not. When the warning has to be obeyed by the library itself and isn't,
        # the verdict is wrong, not the reader.
        #
        # ok=None reuses the shape this module invented in 0.5.7 for exactly this
        # problem: falsy, so `if verify(...)` stops passing, while still not being a
        # red — an empty log is not evidence of tampering, it is an absence of
        # evidence, and those must not print the same.
        res.ok = None
        res.verified_scope = "empty"
    if strict and declared:
        # Strict honored none of these. List them anyway: a mode that silently
        # drops the explanations makes the two modes disagree for reasons the
        # reader cannot see. `declared_breaks` stays 0 under strict, because
        # nothing was excused.
        res.declared.extend(
            f"line {n}: declaration present, NOT honored (strict mode) ({d['why']})"
            for n, d in sorted(declared.items()))
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
