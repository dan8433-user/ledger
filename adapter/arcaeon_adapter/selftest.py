# SPDX-License-Identifier: MIT
"""Selftest + mutation harness: every claimed check, observed actually failing.

    python -m arcaeon_adapter.selftest

An instrument that has never failed proves nothing. A green suite tells you the
code ran; it does not tell you the checks are wired to anything. So every case
below does four things, in this order — the pattern `arcaeon-ledger`'s own
mutation harness uses, kept identical so the two read as one family:

  1. GREEN first. Build a clean fixture and require the real check to pass. A
     harness that only ever sees red proves nothing either.
  2. NO-OP GUARD. Apply the mutation and require the artifact to actually CHANGE.
     "the mutation did not mutate" is a harness failure, not a pass.
  3. RED on the defect. Run the SAME check against the mutated fixture and require
     it to fail — the specific named failure, not "an error somewhere".
  4. Report by name. A check that stays green on its own defect is decoration in
     this environment, and the harness says so loudly.

The five cases and why each one is load-bearing:

  `passthrough_fidelity`   The P0 property. A client's bytes through the proxy must
                           equal its bytes without the proxy. Mutated by turning on
                           real corruption inside the real relay (`reserialize` — the
                           "I'll just normalize the JSON while I'm in here" bug — and
                           `drop_byte`), so the check is observed catching corruption
                           in the shipping code path, not in a mock of it.
  `one_row_per_call`       One tool call must produce exactly one row. Mutated with a
                           log-as-you-see observer that rows the request AND the
                           response instead of the completed pair; the count check
                           must catch the doubling.
  `unanswered_call_logged` A call whose response never arrives still gets a row. This
                           closes "kill the server mid-call to erase the record".
                           Mutated by skipping the shutdown flush.
  `tamper_detected`        The seam log proves itself. Edit one row in place, keep its
                           chain, and verification must name the exact line.
  `digest_recipe_frozen`   Our digests are the frozen `json-c14n:v1` recipe, checked
                           against vectors frozen when the recipe was frozen. Mutated
                           with a drifted canonicalizer (no key sort) to prove the
                           vectors discriminate rather than decorate.

Exit code 0 = every check was observed catching its own defect. Anything else =
at least one claimed guarantee is unverified in this environment. Do not trust
rows produced by a build that cannot pass this.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from ._ledger import digest_json, open_ledger, verify_seam_log
from .observer import SeamObserver
from .proxy import FAULT_ENV

# Frozen json-c14n:v1 vectors. Same freeze as arcaeon-ledger 0.3.0 (2026-08-13),
# restated here independently so this harness does not depend on that package's
# internal layout — and so a fallback-writer build (no arcaeon-ledger installed)
# is held to the exact same byte-level recipe.
GOLDEN = [
    ("key order must not matter", {"b": 2, "a": 1},
     "sha256:json-c14n:v1:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"),
    ("unicode + emoji", {"claim": "X said Y", "unicode": "éü—🔒"},
     "sha256:json-c14n:v1:03b6bc1350e72d1da527a6c729dd8bb3be1b0f8dd3e82000da68d32e21cc2cf6"),
    ("mixed nesting", [1, "two", None, True, {"k": [3.5]}],
     "sha256:json-c14n:v1:bc0d62567f92e63b16aa724fb3d17141713d486780f41458197d8f7d539f33d5"),
]


class SelftestFailure(AssertionError):
    """A named case did not behave: green fixture failed, mutation no-opped, or a
    check stayed green on the very defect it exists to catch."""


def _require(cond, msg: str) -> None:
    if not cond:
        raise SelftestFailure(msg)


def json_objects(raw: bytes) -> list:
    """Parse a frame into JSON objects, tolerantly. Used by the mutated observers."""
    try:
        msg = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    return [msg] if isinstance(msg, dict) else []


def _noop_guard(case: str, before, after) -> None:
    """The guard on the guard. A mutation that changed nothing proves nothing."""
    if before == after:
        raise SelftestFailure(
            f"mutation did not mutate ({case}): fixture identical after mutation, "
            f"so the RED below would be vacuous")


# -- the scripted client stream ----------------------------------------------
# Deliberately includes everything a naive proxy gets wrong: a notification with
# no id, two malformed lines, a blank line, an unknown method, a multi-megabyte
# result, a call the server never answers, and a final frame with NO trailing
# newline. The last one matters: a client is allowed to write its last message and
# close, and a proxy that only forwards on newline would swallow it.
_FRAMES = [
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"selftest-client","version":"0.1"}}}',
    b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
    b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello  seam"}}}',
    b'this is not json rpc at all',
    b'',
    b'{"jsonrpc":"2.0","id":"str-4","method":"tools/call","params":{"name":"boom","arguments":{}}}',
    b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"big","arguments":{"n":2000000}}}',
    b'{"truncated json',
    b'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"quiet","arguments":{"note":"never answered"}}}',
    b'{"jsonrpc":"2.0","id":7,"method":"resources/list"}',
]
CLIENT_STREAM = b"\n".join(_FRAMES) + b"\n" + (
    # final frame, intentionally unterminated
    b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo","arguments":{"text":"last frame no newline"}}}'
)

#: tools/call frames in the stream above: echo, boom, big, quiet, echo-final.
EXPECTED_CALLS = 5

_ECHO_CMD = [sys.executable, "-m", "arcaeon_adapter._echo_server"]


def _child_env(fault: str | None = None) -> dict:
    """Env for a spawned run. PYTHONPATH points at this checkout so the harness
    works from a clone with nothing installed."""
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    env.pop(FAULT_ENV, None)
    if fault:
        env[FAULT_ENV] = fault
    return env


def _run_direct() -> bytes:
    """The control: the echo server with NO proxy in the path."""
    p = subprocess.run(_ECHO_CMD, input=CLIENT_STREAM, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=_child_env())
    return p.stdout


def _run_proxied(ledger: Path, fault: str | None = None, extra: list | None = None) -> bytes:
    """The same client stream, through the real proxy, with the real echo server."""
    cmd = [sys.executable, "-m", "arcaeon_adapter.proxy", "--ledger", str(ledger)]
    cmd += list(extra or [])
    cmd += ["--"] + _ECHO_CMD
    p = subprocess.run(cmd, input=CLIENT_STREAM, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=_child_env(fault))
    return p.stdout


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.strip():
            out.append(json.loads(line))
    return out


# -- case 1: passthrough fidelity --------------------------------------------

def case_passthrough_fidelity(d: Path) -> bytes:
    """P0. Proxied bytes must equal unproxied bytes, exactly.

    Returns the seam ledger path's rows-producing run so later cases reuse it,
    which also means later cases are checking a ledger produced by a run that was
    PROVEN byte-faithful — not a separate, unaudited one.
    """
    direct = _run_direct()
    _require(len(direct) > 1_000_000,
             f"control run produced only {len(direct)} bytes; the large-frame case "
             f"never exercised, so fidelity was not really tested")

    ledger = d / "seam.log.jsonl"
    proxied = _run_proxied(ledger)
    _require(proxied == direct,
             f"PASSTHROUGH FIDELITY BROKEN: proxied stdout differs from direct "
             f"stdout ({_first_diff(direct, proxied)})")
    print(f"PASS passthrough_fidelity GREEN: {len(direct)} bytes identical "
          f"byte-for-byte through the proxy (large frame, malformed frames, "
          f"notification, unterminated final frame)")

    # RED, twice, inside the real relay. Both mutations produce output a lenient
    # test would call "the same messages"; only a byte comparison catches them.
    for mode in ("reserialize", "drop_byte"):
        mutated = _run_proxied(d / f"seam.{mode}.jsonl", fault=mode)
        _noop_guard(f"fidelity/{mode}", direct, mutated)
        _require(mutated != direct,
                 f"fidelity check stayed GREEN on injected corruption {mode!r} — "
                 f"the comparison is decoration")
        print(f"PASS passthrough_fidelity RED on {mode}: corruption detected "
              f"({_first_diff(direct, mutated)})")
    return ledger


def _first_diff(a: bytes, b: bytes) -> str:
    if len(a) != len(b):
        return f"length {len(a)} vs {len(b)}"
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f"first differing byte at offset {i}: {x!r} vs {y!r}"
    return "identical"


# -- case 2: one row per call ------------------------------------------------

def _count_tool_calls(rows: list[dict]) -> int:
    """THE check under test in case 2. Deliberately a named function so the exact
    same code runs against the clean and the mutated ledger."""
    return sum(1 for r in rows if r.get("evt") == "tool_call")


def case_one_row_per_call(d: Path, ledger: Path) -> None:
    rows = _rows(ledger)
    n = _count_tool_calls(rows)
    _require(n == EXPECTED_CALLS,
             f"expected exactly {EXPECTED_CALLS} tool_call rows for "
             f"{EXPECTED_CALLS} tools/call frames, got {n}")
    seams = {r.get("seam") for r in rows}
    _require(seams == {"mcp-stdio"},
             f"every row must carry seam='mcp-stdio' as provenance; saw {seams}")
    sessions = {r.get("session") for r in rows}
    _require(len(sessions) == 1, f"one proxy process must mint one session; saw {sessions}")
    seqs = [r["seq"] for r in rows]
    _require(seqs == list(range(1, len(rows) + 1)),
             f"seq must be a dense total order over this process's rows; got {seqs}")
    _require(rows[0]["evt"] == "session_begin" and rows[-1]["evt"] == "session_end",
             "session_begin must open the log and session_end must close it "
             "(the begin/end pairing a reviewer needs)")
    print(f"PASS one_row_per_call GREEN: {n} tools/call frames -> {n} tool_call rows, "
          f"{len(rows)} rows total, seq 1..{len(rows)}, one session, begin/end paired")

    # RED: the log-as-you-see bug. A naive observer rows the REQUEST when it sees
    # it and rows again on the response, so every call lands twice. This is the
    # implementation someone writes before thinking about pairing, and it is the
    # defect the "exactly one row per call" check exists to catch.
    #
    # (First attempt at this mutation just delivered every frame twice — and the
    # count did NOT change, because popping the pending map makes the observer
    # idempotent against duplicate delivery. The no-op guard caught that the
    # mutation proved nothing. That robustness is now its own test in
    # test_observer.py; the mutation below actually breaks pairing.)
    class _LogOnRequestObserver(SeamObserver):
        def observe_client_frame(self, raw: bytes) -> None:  # type: ignore[override]
            super().observe_client_frame(raw)
            for msg in json_objects(raw):
                if msg.get("method") == "tools/call":
                    params = msg.get("params") or {}
                    with self._lock:
                        self._row("tool_call", tool=params.get("name"),
                                  status="requested")

    bad_path = d / "seam.log_on_request.jsonl"
    bad = open_ledger(bad_path)
    obs = _LogOnRequestObserver(bad.append, server="echo", session="mutated")
    obs.session_begin()
    _replay_into(obs)
    obs.flush_pending()
    obs.session_end(reason="mutated", exit_code=0)
    bad_rows = _rows(bad_path)
    _noop_guard("one_row_per_call/log_on_request", _count_tool_calls(rows),
                _count_tool_calls(bad_rows))
    _require(_count_tool_calls(bad_rows) != EXPECTED_CALLS,
             "the count check stayed GREEN against a log-on-request observer — "
             "it is not actually counting completed pairs")
    print(f"PASS one_row_per_call RED on log_on_request: count check caught "
          f"{_count_tool_calls(bad_rows)} rows for {EXPECTED_CALLS} calls")


def _replay_into(obs: SeamObserver) -> None:
    """Drive an observer in-process with the same traffic, no subprocess.

    Uses the echo server's `handle()` directly so request/response pairing is real
    traffic rather than hand-written fixtures that could drift from what the server
    actually says.
    """
    from ._echo_server import handle
    for frame in _FRAMES + [CLIENT_STREAM.rsplit(b"\n", 1)[-1]]:
        if not frame.strip():
            continue
        obs.observe_client_frame(frame)
        try:
            msg = json.loads(frame.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(msg, dict):
            continue
        resp = handle(msg)
        if resp is not None:
            obs.observe_server_frame(json.dumps(resp).encode("utf-8"))


# -- case 3: an unanswered call still gets a row -----------------------------

def _find_unanswered(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("evt") == "tool_call"
            and r.get("status") == "unanswered"]


def case_unanswered_call_logged(d: Path, ledger: Path) -> None:
    rows = _rows(ledger)
    orphans = _find_unanswered(rows)
    _require(len(orphans) == 1 and orphans[0].get("tool") == "quiet",
             f"the `quiet` tool call is never answered by the server; it MUST still "
             f"appear with status='unanswered', else killing a server mid-call erases "
             f"the record. Found: {orphans}")
    _require(orphans[0].get("args_digest", "").startswith("sha256:json-c14n:v1:"),
             "an unanswered call must still bind its arguments by digest")
    print(f"PASS unanswered_call_logged GREEN: unanswered `quiet` call rowed with "
          f"args_digest bound (reason={orphans[0].get('reason')!r})")

    # RED: the same session with the shutdown flush skipped. The row disappears,
    # and the check must notice.
    bad_path = d / "seam.noflush.jsonl"
    bad = open_ledger(bad_path)
    obs = SeamObserver(bad.append, server="echo", session="noflush")
    obs.session_begin()
    _replay_into(obs)
    # flush_pending() deliberately NOT called
    obs.session_end(reason="mutated", exit_code=0)
    bad_rows = _rows(bad_path)
    _noop_guard("unanswered/no_flush", len(orphans), len(_find_unanswered(bad_rows)))
    _require(not _find_unanswered(bad_rows),
             "skipping flush_pending still produced an unanswered row — the check "
             "is not testing the flush")
    print("PASS unanswered_call_logged RED on no_flush: dropping the shutdown flush "
          "loses the row, and the check catches it")


# -- case 4: the seam log proves itself --------------------------------------

def case_tamper_detected(d: Path, ledger: Path) -> None:
    v = verify_seam_log(ledger)
    _require(v.ok is True,
             f"a freshly written seam log must verify fully green, got {v!r}")
    print(f"PASS tamper_detected GREEN: seam log verifies (ok=True, rows={v.rows})")

    victim = d / "seam.tampered.jsonl"
    before = ledger.read_bytes()
    lines = before.decode("utf-8").split("\n")
    lines = [l for l in lines if l.strip()]
    # Edit the FIRST tool_call row in place, keeping its now-wrong chain — the
    # realistic tamper: rewrite what a tool was called with, leave the shape alone.
    idx = next(i for i, l in enumerate(lines) if json.loads(l).get("evt") == "tool_call")
    obj = json.loads(lines[idx])
    obj["args_digest"] = "sha256:json-c14n:v1:" + "0" * 64
    lines[idx] = json.dumps(obj, ensure_ascii=False)
    after = ("\n".join(lines) + "\n").encode("utf-8")
    victim.write_bytes(after)
    _noop_guard("tamper/edit_args_digest", before, after)

    v2 = verify_seam_log(victim)
    _require(v2.ok is not True,
             "an edited row verified GREEN — the chain is not protecting the rows")
    _require(v2.first_break == f"line {idx + 1}: chain mismatch",
             f"verification must name the EXACT line; expected "
             f"'line {idx + 1}: chain mismatch', got {v2.first_break!r}")
    print(f"PASS tamper_detected RED on edited args_digest: "
          f"first_break={v2.first_break!r}")


# -- case 5: the digest recipe is frozen -------------------------------------

def case_digest_recipe_frozen() -> None:
    for name, value, frozen in GOLDEN:
        got = digest_json(value)
        _require(got == frozen,
                 f"digest recipe DRIFTED on {name!r}: this build produces {got}, "
                 f"the frozen json-c14n:v1 vector is {frozen}. Rows from this build "
                 f"are not comparable with rows from any other.")
    print(f"PASS digest_recipe_frozen GREEN: {len(GOLDEN)} frozen json-c14n:v1 "
          f"vectors reproduce exactly")

    # RED: a drifted canonicalizer (keys unsorted) must NOT reproduce the vector.
    # Without this, a vector list that happened to match anything would look fine.
    name, value, frozen = GOLDEN[0]
    drifted = "sha256:json-c14n:v1:" + hashlib.sha256(
        json.dumps(value, sort_keys=False, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()
    _noop_guard("digest/unsorted_keys", frozen, drifted)
    _require(drifted != frozen,
             "an unsorted canonicalizer reproduced the frozen vector — the vectors "
             "do not discriminate and prove nothing")
    print(f"PASS digest_recipe_frozen RED on unsorted_keys: drifted canonicalizer "
          f"produces a different digest, so the vectors discriminate")


# -- runner ------------------------------------------------------------------

def main(argv=None) -> int:
    from ._ledger import backend
    print(f"arcaeon-adapter selftest — ledger backend: {backend()}")
    print(f"python: {sys.version.split()[0]} on {sys.platform}")
    print()
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        try:
            ledger = case_passthrough_fidelity(d)
            case_one_row_per_call(d, ledger)
            case_unanswered_call_logged(d, ledger)
            case_tamper_detected(d, ledger)
            case_digest_recipe_frozen()
        except SelftestFailure as e:
            print(f"\nFAIL {e}", file=sys.stderr)
            return 1
    print("\nALL CHECKS PASSED — and every one was observed failing on its own defect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
