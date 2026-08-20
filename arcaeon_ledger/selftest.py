# SPDX-License-Identifier: MIT
"""Self-test: golden digest vectors, planted unsupported recipes, witness fixture.

    python -m arcaeon_ledger.selftest

Two reviewer questions on the launch thread asked for exactly this, so it ships
in the package rather than living in our CI where you'd have to trust us:

1. holocene: "if the canonicalization recipe is versioned, how do we ensure the
   digest remains a reliable signal when the underlying parser or environment
   evolves?" — Answer: golden vectors. The digests below were frozen when
   `json-c14n:v1` was frozen. If your Python, your platform, or a future release
   of this library computes anything else, this command fails loudly. The recipe
   is a byte-level specification; the vectors are its enforcement.

2. The verifier must refuse what it cannot reproduce (0.5.2). A clean artefact is
   verified GREEN first, then four planted digests — an unknown recipe name, an
   unknown recipe VERSION, an unknown algorithm, and a malformed hex body — must each
   be OBSERVED failing with their SPECIFIC typed reason. A digest this build cannot
   recompute is a digest it did not check; reporting one as verified would be the
   overclaim the whole library exists to refuse.

3. excelsior: "the next useful planted test is witness failure, not another
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

from . import (Ledger, bind_artefact, digest_bytes, digest_json,
               verify_artefact, verify_file)
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


# Planted unsupported-label artefacts (0.5.2). Each entry mutates a KNOWN-GOOD
# artefact's digest string into one this build cannot reproduce, and names the typed
# reason verify_artefact must return. Mutation-harness discipline: the check is not
# asserted, it is OBSERVED — the green control below runs first, then each plant must
# be seen going red with its SPECIFIC reason, not just "some failure."
def _plant(art: dict, old: str, new: str) -> dict:
    """Copy an artefact with `old` swapped for `new` in both label fields."""
    planted = json.loads(json.dumps(art))
    planted["digest"] = planted["digest"].replace(old, new, 1)
    planted["recipe"] = planted["recipe"].replace(old, new, 1)
    return planted


PLANTS = [
    ("unknown recipe name  (json-c14n -> json-c14n-drift)",
     lambda a: _plant(a, "json-c14n", "json-c14n-drift"), "unknown_recipe"),
    ("unknown recipe version (v1 -> v9, never shipped)",
     lambda a: _plant(a, ":v1", ":v9"), "unknown_recipe_version"),
    ("unknown algorithm    (sha256 -> md5)",
     lambda a: _plant(a, "sha256", "md5"), "unknown_algorithm"),
    ("malformed hex        (truncated digest body)",
     lambda a: {**json.loads(json.dumps(a)),
                "digest": a["digest"][: -20]}, "malformed_digest"),
]


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

    print("== planted unsupported recipe labels (typed refusal, observed) ==")
    control = bind_artefact({"claim": "the agent read the pricing page", "price": 42})
    res = verify_artefact(control)
    ok = res["digest_ok"] is True and res["reason"] is None
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  GREEN control: clean artefact -> "
          f"digest_ok={res['digest_ok']}, reason={res['reason']!r}")
    for name, mutate, want_reason in PLANTS:
        planted = mutate(control)
        if planted["digest"] == control["digest"]:
            failures += 1
            print(f"  FAIL  {name}: plant did not mutate the digest string")
            continue
        got = verify_artefact(planted)
        ok = got["digest_ok"] is False and got["reason"] == want_reason
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name} -> digest_ok={got['digest_ok']}, "
              f"reason={got['reason']!r} (must be {want_reason!r})")
        if not ok:
            print(f"        notes: {got['notes']}")

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

    print("== planted ledger tampering (THE CENTRAL CLAIM, observed) ==")
    # Why this section exists, and why it is shaped the way it is.
    #
    # An adversarial review replaced verify_file's entire body with a stub returning
    # ok=True for every file, and this selftest printed ALL CHECKS PASSED and exited 0.
    # The proof a buyer runs to check their install did not exercise tamper detection
    # at ALL: the witness branches above compare row counts and chain_at values, and
    # branch C's `bool(led.verify())` is satisfied by any truthy stub.
    #
    # So each case below demands the EXACT first_break string, not merely a red. That
    # is the part that cannot be faked: a stub returning a constant ok=False with a
    # constant message satisfies at most one of these and fails the rest, and the GREEN
    # control immediately below fails any stub that is red-by-default. Both directions
    # are pinned, which is the only way a check earns the right to be believed.
    #
    # Every mutation is also guarded against not mutating. A tamper that silently
    # no-ops looks identical to a detection that worked, and reporting the second when
    # the first happened is how a suite accumulates checks that cannot fail.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        def fresh(name, n=6):
            p = td / name
            lg = Ledger(p)
            for i in range(n):
                lg.append({"action": "tool_call", "n": i, "amount": 100 + i})
            return p

        def lines_of(p):
            return [l for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]

        def check_red(name, p, before, want_break):
            """Require a red naming the exact line, and require the tamper to be real."""
            nonlocal failures
            if p.read_bytes() == before:
                failures += 1
                print(f"  FAIL  {name}: TAMPER DID NOT TAMPER (file unchanged) — "
                      f"nothing was tested")
                return
            r = verify_file(p)
            ok = r.ok is False and r.first_break == want_break
            failures += 0 if ok else 1
            print(f"  {'PASS' if ok else 'FAIL'}  {name} -> ok={r.ok!r} "
                  f"first_break={r.first_break!r} (must be {want_break!r})")

        # GREEN CONTROL FIRST. Without it, a verifier that is red-by-default passes
        # every case below, which is the mirror image of the defect this section fixes.
        clean = fresh("clean.jsonl")
        r = verify_file(clean)
        ok = r.ok is True and r.rows == 6 and r.breaks == 0 and r.verified_scope == "full"
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  GREEN control: untouched 6-row log -> "
              f"ok={r.ok!r} rows={r.rows} scope={r.verified_scope!r}")

        # 1. Edit a field in place. The canonical tamper.
        p = fresh("edited.jsonl"); before = p.read_bytes()
        ls = lines_of(p)
        obj = json.loads(ls[2]); obj["amount"] = 999999
        ls[2] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(ls) + "\n", encoding="utf-8")
        check_red("edit row 3 in place", p, before, "line 3: chain mismatch")

        # 2. Delete a row from the middle.
        p = fresh("deleted.jsonl"); before = p.read_bytes()
        ls = lines_of(p); del ls[2]
        p.write_text("\n".join(ls) + "\n", encoding="utf-8")
        check_red("delete row 3", p, before, "line 3: chain mismatch")

        # 3. Reorder. Same bytes, different history.
        p = fresh("reordered.jsonl"); before = p.read_bytes()
        ls = lines_of(p); ls[1], ls[3] = ls[3], ls[1]
        p.write_text("\n".join(ls) + "\n", encoding="utf-8")
        check_red("swap rows 2 and 4", p, before, "line 2: chain mismatch")

        # 4. A torn final row: what a crash mid-append leaves behind.
        p = fresh("torn.jsonl"); before = p.read_bytes()
        raw = p.read_text(encoding="utf-8")
        p.write_text(raw[:-14], encoding="utf-8")
        check_red("torn final row", p, before, "line 6: unparseable")

        # 5. A bare scalar smuggled in. Before 0.5.3 this CRASHED the verifier
        #    instead of returning a verdict; it must stay a named break forever.
        p = fresh("scalar.jsonl"); before = p.read_bytes()
        with p.open("a", encoding="utf-8") as fh:
            fh.write("42\n")
        check_red("bare scalar line appended", p, before, "line 7: not a JSON object")

        # 6. An unchained row after the chain began — the detach precursor.
        p = fresh("unchained.jsonl"); before = p.read_bytes()
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"action": "sneak", "n": 99}) + "\n")
        check_red("unchained row after the chain began", p, before,
                  "line 7: unchained row after chain began")

        # 7. An EMPTY file must not be a green. 0.5.7 and earlier returned
        #    ok=True/"full" here, and build_bundle printed "VERDICT: intact" over it.
        empty = td / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        r = verify_file(empty)
        rs = verify_file(empty, strict=True)
        ok = (r.ok is None and r.verified_scope == "empty" and not r
              and rs.ok is None and not rs)
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  empty file is NOT a green -> ok={r.ok!r} "
              f"scope={r.verified_scope!r} bool={bool(r)} (strict: ok={rs.ok!r})")

        # 8. A write that goes nowhere must raise, not return a chain hash. On
        #    Windows a reserved device name accepts every write and stores nothing.
        if sys.platform == "win32":
            try:
                Ledger(td / "nul").append({"action": "wire_money", "amount": 50000})
                failures += 1
                print("  FAIL  write to a reserved device name -> returned success; "
                      "the row was discarded and nothing said so")
            except OSError as e:
                print(f"  PASS  write to a reserved device name -> "
                      f"{type(e).__name__} (nothing silently discarded)")
        else:
            print("  SKIP  reserved-device-name check (Windows only) — "
                  "this is a real gap in coverage on this platform, not a pass")

    print("== planted witness-store tampering (the pin file's own chain, observed) ==")
    # 0.5.9 gave the witness store a chain of its own after 0.5.8 retracted the false
    # claim that it was tamper-evident by inspection. A buyer who runs this selftest
    # should see that claim exercised, not just asserted in the changelog. Each case
    # demands a red on a real edit; the first case is the GREEN control so a verify()
    # that is broken-by-default fails here too.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        def fresh_store(name, n=4):
            lg = Ledger(td / (name + ".jsonl"))
            st = WitnessStore(td / (name + "-w.jsonl"))
            for i in range(n):
                lg.append({"action": "tool_call", "n": i})
                st.record("selftest", lg.head())
            return st

        def st_lines(st):
            return [l for l in st.path.read_text(encoding="utf-8").split("\n") if l.strip()]

        st = fresh_store("clean")
        v = st.verify()
        ok = v["ok"] is True and v["pins"] == 4 and v["breaks"] == 0
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  clean pin file -> ok={v['ok']!r} pins={v['pins']}")

        st = fresh_store("edited")
        lines = st_lines(st)
        rec = json.loads(lines[1]); rec["rows"] = 1
        lines[1] = json.dumps(rec)
        st.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        v = st.verify()
        ok = v["ok"] is False and v["first_break"] is not None
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  edited middle pin -> ok={v['ok']!r} "
              f"first_break={v['first_break']!r} (must be a red)")

        st = fresh_store("tail")
        lines = st_lines(st)
        rec = json.loads(lines[-1]); rec["rows"] = 999
        lines[-1] = json.dumps(rec)
        st.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        v = st.verify()
        ok = v["ok"] is False and "own digest" in (v["first_break"] or "")
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  edited LAST pin -> ok={v['ok']!r} "
              f"first_break={v['first_break']!r} (the tail case; must be a red)")

        ok = (not st.verify())
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  broken chain is falsy -> bool(verify)={bool(st.verify())}")


    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
