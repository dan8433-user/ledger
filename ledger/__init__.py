"""ledger — a tamper-evident, append-only action log for AI agents.

Observability tools show you what your agent did. `ledger` lets you PROVE it:
every record is hash-chained to the one before it, so an edit, deletion, or
reorder anywhere in the history breaks every later link and `verify()` names the
exact line. Own the record; prove it wasn't altered.

Zero dependencies (stdlib only). One JSONL file. Two verbs: append, verify.

    from ledger import Ledger
    log = Ledger("agent.log.jsonl")
    log.append({"tool": "search", "query": "weather", "result_ok": True})
    log.verify()          # -> VerifyResult(ok=True, rows=1, ...)

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

__version__ = "0.1.0"
__all__ = ["Ledger", "VerifyResult", "verify_file"]

_GENESIS = "genesis"
_CHAIN_LEN = 32  # first N hex chars of the sha256 — plenty for tamper-evidence


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain(prev: str, obj: dict) -> str:
    """chain = sha256(prev_chain + canonical-json-of-row-without-chain)."""
    body = json.dumps({k: v for k, v in obj.items() if k != "chain"},
                      ensure_ascii=False, sort_keys=True)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()[:_CHAIN_LEN]


@dataclass
class VerifyResult:
    ok: bool
    rows: int = 0
    chained: int = 0
    prechain: int = 0
    first_break: str | None = None

    def __bool__(self) -> bool:  # `if log.verify(): ...`
        return self.ok


class Ledger:
    """A hash-chained append-only JSONL log. One file, atomic appends."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    # -- write --------------------------------------------------------------
    def append(self, record: dict[str, Any]) -> str:
        """Append one record; returns its chain hash. Stamps `ts` if absent.

        Atomic: append-binary + flush + fsync, so a crash mid-write never
        corrupts the file (a partial line fails to parse and is caught by
        verify, it never silently poisons the chain).
        """
        obj = dict(record)
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
