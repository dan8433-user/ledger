# SPDX-License-Identifier: MIT
"""Ledger binding — use `arcaeon-ledger` when it's importable, degrade honestly when it isn't.

WHY this file exists at all: the adapter's whole value proposition is that the
row it writes *proves itself*. That proof lives in `arcaeon-ledger` (hash chain,
canonical-JSON digests, `verify`). So the right dependency is the real library,
and this module's first job is simply to import it.

Its second job is the interesting one. The adapter is meant to be wrapped around
somebody else's MCP server by editing one line of config. That deployer may not
have `arcaeon-ledger` installed, and the failure we must never ship is: the proxy
refuses to start, and the customer's MCP server — which worked fine a minute ago —
is now dead because of *our* audit sidecar. A logging layer that can take down
the thing it logs is worse than no logging layer.

So when the import fails we still write rows, in the ledger's own documented
on-disk shape, with a small local implementation of the two frozen recipes:

    chain     = sha256(prev_chain + json.dumps(row_without_chain,
                                               ensure_ascii=False, sort_keys=True)
                      ).hexdigest()[:32]          # 'genesis' seeds the chain
    digest    = "sha256:json-c14n:v1:" + sha256(canonical.encode("utf-8")).hexdigest()
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False)

Both recipes are frozen specifications, not implementation details, which is the
only reason a re-implementation is legitimate here: files written by the fallback
are byte-compatible with files written by the library, and
`arcaeon_ledger.verify_file` verifies them later on a machine that *does* have it
installed. The selftest proves that claim against the library's own frozen golden
vectors instead of asserting it.

`backend()` reports which path is live, and the proxy stamps it into the
`session_begin` row — a reviewer should never have to guess whether the chain in
front of them came from the library or the fallback.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_GENESIS = "genesis"
_CHAIN_LEN = 32

try:  # the real thing, always preferred
    from arcaeon_ledger import Ledger as _RealLedger  # type: ignore
    from arcaeon_ledger import __version__ as _LEDGER_VERSION  # type: ignore
    from arcaeon_ledger import digest_json as _real_digest_json  # type: ignore
    from arcaeon_ledger import verify_file as _real_verify_file  # type: ignore
    _HAVE_LEDGER = True
except Exception:  # pragma: no cover - exercised only on machines without it
    _RealLedger = None
    _LEDGER_VERSION = None
    _real_digest_json = None
    _real_verify_file = None
    _HAVE_LEDGER = False


def backend() -> str:
    """Which ledger implementation is live, for stamping into `session_begin`."""
    if _HAVE_LEDGER:
        return f"arcaeon-ledger/{_LEDGER_VERSION}"
    return "fallback-jsonl/1"


# -- digests -----------------------------------------------------------------

def canon_json(value: Any) -> bytes:
    """The frozen `json-c14n:v1` canonicalization, byte-for-byte.

    Raises ValueError on NaN/Infinity (allow_nan=False) rather than emitting a
    token no other language's JSON parser accepts. A digest nobody else can
    reproduce is not a digest.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest_json(value: Any) -> str:
    """Self-describing digest of a JSON value: `sha256:json-c14n:v1:<hex>`.

    Self-describing is the point: the string carries its own algorithm, recipe
    name and recipe version, so a stranger holding only the row can reconstruct
    the computation. We never emit a bare hex hash.
    """
    if _HAVE_LEDGER:
        return _real_digest_json(value)
    return "sha256:json-c14n:v1:" + hashlib.sha256(canon_json(value)).hexdigest()


def digest_of_frame(raw: bytes) -> str:
    """Digest an unparseable frame by its bytes, so it is still *named*.

    Used nowhere on the happy path; kept because "we saw something here we could
    not read" is more honest than a silent gap, if a future row wants to say it.
    """
    return "sha256:raw-bytes:v1:" + hashlib.sha256(raw).hexdigest()


# -- the writer --------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chain(prev: str, obj: dict) -> str:
    body = json.dumps({k: v for k, v in obj.items() if k != "chain"},
                      ensure_ascii=False, sort_keys=True)
    return hashlib.sha256((str(prev) + body).encode("utf-8")).hexdigest()[:_CHAIN_LEN]


class _FallbackLedger:
    """Minimal hash-chained JSONL appender, shape-identical to `arcaeon_ledger.Ledger`.

    Deliberately NOT a reimplementation of the library's hardening — no
    cross-process lock, no torn-line healing, no backwards tail scan past the
    last line. It is the degraded path: single-writer, good enough to keep the
    record flowing when the library is absent, and honestly labelled as such in
    `session_begin` via `backend()`. If two processes share one seam log, install
    `arcaeon-ledger`.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._tail: str | None = None

    def _last_chain(self) -> str:
        if self._tail is not None:
            return self._tail
        last = _GENESIS
        try:
            with self.path.open("rb") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw.decode("utf-8", errors="replace"))
                    except ValueError:
                        continue
                    if isinstance(obj, dict) and obj.get("chain"):
                        last = obj["chain"]
        except OSError:
            pass
        self._tail = last
        return last

    def append(self, record: dict[str, Any]) -> str:
        obj = dict(record)
        obj.setdefault("ts", _now_iso())
        obj.pop("chain", None)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            obj["chain"] = _chain(self._last_chain(), obj)
            line = json.dumps(obj, ensure_ascii=False) + "\n"
            with self.path.open("ab") as fh:
                fh.write(line.encode("utf-8"))
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            self._tail = obj["chain"]
        return obj["chain"]


def open_ledger(path: str | Path):
    """The seam ledger. Real library when present, fallback when not."""
    if _HAVE_LEDGER:
        return _RealLedger(path)
    return _FallbackLedger(path)


# -- verification ------------------------------------------------------------

class _FallbackVerify:
    """The three fields a caller actually reads off a verdict."""

    def __init__(self, ok, rows, first_break):
        self.ok = ok
        self.rows = rows
        self.first_break = first_break

    def __bool__(self) -> bool:
        return self.ok is True

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (f"FallbackVerify(ok={self.ok!r}, rows={self.rows}, "
                f"first_break={self.first_break!r})")


def verify_seam_log(path: str | Path):
    """Verify a seam log's chain. Returns something with `.ok` / `.first_break`.

    Prefers `arcaeon_ledger.verify_file` — the hardened verifier with the
    three-valued verdict (`ok=None` for a bounded scan is NOT a green). The
    fallback below is two-valued and re-walks the same recipe; it exists so
    `selftest` can still observe tampering being caught on a machine without the
    library, and its `first_break` string is deliberately formatted identically
    (`"line N: chain mismatch"`) so tests read the same either way.
    """
    if _HAVE_LEDGER:
        return _real_verify_file(Path(path))
    prev = _GENESIS
    rows = 0
    first_break = None
    try:
        raw_text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        return _FallbackVerify(False, 0, f"unreadable: {e}")
    for i, raw in enumerate(raw_text.split("\n"), start=1):
        if not raw.strip():
            continue
        rows += 1
        try:
            obj = json.loads(raw)
        except ValueError:
            if first_break is None:
                first_break = f"line {i}: unparseable"
            continue
        claimed = obj.get("chain")
        if _chain(prev, obj) != claimed and first_break is None:
            first_break = f"line {i}: chain mismatch"
        prev = claimed or prev
    return _FallbackVerify(first_break is None, rows, first_break)
