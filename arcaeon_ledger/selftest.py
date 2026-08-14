"""Self-test: golden digest vectors + the witness planted-file fixture.

    python -m arcaeon_ledger.selftest

Two reviewer questions on the launch thread asked for exactly this, so it ships
in the package rather than living in our CI where you'd have to trust us:

1. holocene: "if the canonicalization recipe is versioned, how do we ensure the
   digest remains a reliable signal when the underlying parser or environment
   evolves?" — Answer: golden vectors. The digests below were frozen when
   `json-c14n:v1` was frozen. If your Python, your platform, or a future release
   of this library computes anything else, this command fails loudly. The recipe
   is a byte-level specification; the vectors are its enforcement.

2. excelsior: "the next useful planted test is witness failure, not another
   chain mutation" — three branches from one fixture: a log truncated *before*
   the latest witnessed head MUST fail; a log reminted from genesis after that
   head MUST fail; the untouched log MUST verify consistent. All three run here,
   in a temp dir, every time.

Exit code 0 = every check passed. Anything else = the environment or the build
cannot reproduce the frozen behavior — do not trust digests it produces.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from . import Ledger, digest_bytes, digest_json
from .witness import WitnessStore, publish_head, verify_against_witness

# Frozen at recipe freeze (json-c14n:v1 / raw-bytes:v1, 0.3.0, 2026-08-13).
# These never change. A new recipe version gets NEW vectors alongside these.
GOLDEN = [
    ("json {'b':2,'a':1} (key order must not matter)",
     lambda: digest_json({"b": 2, "a": 1}),
     "sha256:json-c14n:v1:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"),
    ("json unicode + emoji",
     lambda: digest_json({"claim": "X said Y", "unicode": "éü—🔒"}),
     "sha256:json-c14n:v1:03b6bc1350e72d1da527a6c729dd8bb3be1b0f8dd3e82000da68d32e21cc2cf6"),
    ("json mixed nesting",
     lambda: digest_json([1, "two", None, True, {"k": [3.5]}]),
     "sha256:json-c14n:v1:bc0d62567f92e63b16aa724fb3d17141713d486780f41458197d8f7d539f33d5"),
    ("raw bytes",
     lambda: digest_bytes(b"arcaeon selftest vector 1"),
     "sha256:raw-bytes:v1:45050994979709443a05e8a31cac09bbbae7074cd6887b6c31f83b775a2b8651"),
    ("raw empty bytes (== sha256 of empty string)",
     lambda: digest_bytes(b""),
     "sha256:raw-bytes:v1:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
]


def _rejects_nan() -> bool:
    try:
        digest_json({"bad": float("nan")})
        return False
    except ValueError:
        return True


def run() -> int:
    failures = 0

    print("== golden digest vectors (recipe enforcement) ==")
    for name, fn, want in GOLDEN:
        got = fn()
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"        want {want}\n        got  {got}")
    ok = _rejects_nan()
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  NaN rejected (never silently canonicalized)")

    print("== witness planted fixture (excelsior's three branches) ==")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        base = td / "log.jsonl"
        led = Ledger(base)
        for i in range(6):
            led.append({"action": "tool_call", "n": i, "result_ok": True})
        store = WitnessStore(td / "witness.jsonl")
        publish_head(store, "selftest", led)
        rows = base.read_text(encoding="utf-8").splitlines()

        # A: truncate to 4 rows (before the witnessed head) -> MUST fail
        trunc = td / "truncated.jsonl"
        trunc.write_text("\n".join(rows[:4]) + "\n", encoding="utf-8")
        v = verify_against_witness(store, "selftest", Ledger(trunc))
        ok = v.verdict == "truncated"
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  truncated-before-head -> {v.verdict!r} (must be 'truncated')")

        # B: remint from genesis with an edited payload -> MUST fail
        remint_p = td / "reminted.jsonl"
        rl = Ledger(remint_p)
        for i, ln in enumerate(rows):
            obj = json.loads(ln)
            obj.pop("chain", None)
            if i == 2:
                obj["result_ok"] = False  # the lie the remint launders
            rl.append(obj)
        v = verify_against_witness(store, "selftest", rl)
        ok = v.verdict == "rewritten"
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  remint-from-genesis   -> {v.verdict!r} (must be 'rewritten')")

        # C: untouched -> MUST verify consistent (and chain itself must verify)
        v = verify_against_witness(store, "selftest", led)
        ok = v.verdict == "consistent" and bool(led.verify())
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  untouched             -> {v.verdict!r} (must be 'consistent')")

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
