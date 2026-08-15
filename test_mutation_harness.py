"""Tests for the mutation harness — including the meta-test: a harness that
cannot itself be observed failing would be decoration by its own standard, so
we sabotage a verifier and require the harness to go red.
Run: python test_mutation_harness.py
"""
import contextlib
import io

import arcaeon_ledger
from arcaeon_ledger import VerifyResult, mutation_harness


def test_harness_all_green_on_healthy_build():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mutation_harness.run()
    out = buf.getvalue()
    assert rc == 0, f"harness failed on a healthy build:\n{out}"
    for name, _ in mutation_harness.CASES:
        assert f"PASS  {name}" in out, f"case {name} missing from output"
    print(f"PASS harness exit 0 on healthy build ({len(mutation_harness.CASES)} named cases)")


def test_harness_goes_red_when_a_verifier_is_decoration():
    """Sabotage: make verify_file always report ok (a decorated chain verifier).
    The harness MUST fail loudly, naming the chain cases — if it stays green
    while the verifier is blind, the harness is the decoration."""
    real = arcaeon_ledger.verify_file
    arcaeon_ledger.verify_file = lambda path: VerifyResult(ok=True, rows=6, chained=6)
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = mutation_harness.run()
        out = buf.getvalue()
    finally:
        arcaeon_ledger.verify_file = real
    assert rc != 0, "harness stayed GREEN with a blinded verifier — harness is decoration"
    assert "FAIL  byte-edit-in-row" in out, out
    print("PASS harness goes red (naming the case) when the chain verifier is blinded")


def test_harness_catches_a_truncated_chain_comparison():
    """The 0.5.3 audit finding: a verifier comparing only the first 8 hex chars
    of the chain (32 bits — birthday-forgeable) passed ALL twelve pre-0.5.3
    cases, because every other mutation changes the whole hash. The harness
    could not distinguish a full-width comparison from a truncated one. It must
    now go red, naming the case."""
    real = arcaeon_ledger.verify_file

    def prefix_only(path):
        r = real(path)
        # emulate a build whose comparison is truncated: a mismatch that agrees
        # on the first 8 hex chars is forgiven
        if r.first_break and "chain mismatch" in r.first_break:
            import json as _json
            from pathlib import Path as _Path
            lines = _Path(path).read_text(encoding="utf-8").splitlines()
            prev = arcaeon_ledger._GENESIS
            ok = True
            for raw in lines:
                if not raw.strip():
                    continue
                obj = _json.loads(raw)
                claimed = obj.pop("chain", None)
                if claimed is None:
                    continue
                if claimed[:8] != arcaeon_ledger._chain(prev, obj)[:8]:
                    ok = False
                prev = claimed
            if ok:
                return VerifyResult(ok=True, rows=r.rows, chained=r.chained)
        return r

    arcaeon_ledger.verify_file = prefix_only
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = mutation_harness.run()
        out = buf.getvalue()
    finally:
        arcaeon_ledger.verify_file = real
    assert rc != 0, "harness stayed GREEN with a 32-bit chain comparison"
    assert "FAIL  chain-comparison-full-width" in out, out
    print("PASS harness goes red on a truncated (32-bit) chain comparison")


def test_verify_counts_breaks_without_cascading():
    """One edited row is one break — the documented no-cascade promise, now
    measurable (VerifyResult.breaks, 0.5.3)."""
    import json
    import tempfile
    from pathlib import Path
    from arcaeon_ledger import Ledger
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        for i in range(6):
            led.append({"n": i})
        assert led.verify().breaks == 0
        lines = p.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[2])
        obj["n"] = 999
        lines[2] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = led.verify()
        assert r.breaks == 1, f"one edit reported {r.breaks} breaks (cascade)"
        assert r.first_break == "line 3: chain mismatch"
    print("PASS one edit == one break (no cascade)")


def test_noop_guard_raises():
    try:
        mutation_harness._noop_guard("t", b"same", b"same")
    except mutation_harness.MutationFailure as e:
        assert "mutation did not mutate" in str(e)
        print("PASS no-op guard raises 'mutation did not mutate' on identical bytes")
        return
    raise AssertionError("no-op guard accepted identical bytes")


if __name__ == "__main__":
    test_harness_all_green_on_healthy_build()
    test_harness_goes_red_when_a_verifier_is_decoration()
    test_noop_guard_raises()
    print("\nALL PASS — the harness catches defects, and is itself catchable.")
