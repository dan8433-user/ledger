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
