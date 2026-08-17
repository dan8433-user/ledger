# SPDX-License-Identifier: MIT
"""Hypothesis-driven property tests for arcaeon_ledger's core invariants.

Complements test_property_ledger.py's hand-rolled fuzzer (stdlib `random`,
fixed seed, quotable counts) with `hypothesis`-driven tests proper: minimal
shrunk counterexamples on failure, and explicit, named coverage of three
invariants called out for this pass:

  1. HASH-CHAIN INTEGRITY UNDER ARBITRARY APPENDS: build a ledger from any
     sequence of records, then mutate any ONE row's content in place (keeping
     its now-stale claimed chain). verify() must go RED, and the break must
     be reported starting at exactly that row -- never later, never silently
     absorbed. ("Any mutation of any row breaks verify from that point.")

  2. APPEND-ORDER DETERMINISM: appending the same sequence of records (with
     an explicit `ts` so wall-clock time cannot leak in) into two independent
     fresh ledgers must produce byte-identical chain values at every row.
     `_chain` is a pure function of (prev, body); this is that purity made
     an observable, adversarially-searched property instead of an assertion
     about the source.

  3. UNICODE / LINE-BOUNDARY LOOKALIKES: specifically U+0085 (NEL), U+2028
     (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR), plus the C0 separators
     \\x0b \\x0c \\x1c \\x1d \\x1e -- the exact character set Python's
     str.splitlines() treats as row boundaries but json.dumps(...,
     ensure_ascii=False) does NOT escape (only U+0000-U+001F is mandatory,
     and U+0085/U+2028/U+2029 sit outside that range). A ledger entry field
     containing one of these therefore round-trips RAW into the JSONL bytes.
     Checked here because last night's continuity find was exactly this bug
     class (write ensure_ascii=False + read splitlines() = a row that seals
     cleanly on append() and then can never verify green again). Found
     present in arcaeon_ledger's verify_file/__iter__/chain_at and fixed
     (split("\\n") instead of splitlines()) as part of this pass -- these
     tests pin the fix so it can't silently regress.

Run: python -m pytest test_hypothesis_ledger.py -q
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, HealthCheck, strategies as st

from arcaeon_ledger import Ledger, verify_file, chain_at


# --- strategies --------------------------------------------------------------

# The exact characters implicated in the U+2028-class bug: NOT escaped by
# json.dumps(ensure_ascii=False) (all sit outside U+0000-U+001F), but treated
# as line boundaries by str.splitlines() -- distinct from the literal "\n"
# the writer actually emits as its row delimiter.
LINE_BOUNDARY_LOOKALIKES = "  \x0b\x0c\x1c\x1d\x1e"

_safe_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), max_codepoint=0x10FFFF),
    max_size=30,
)

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10**12, max_value=10**12),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _safe_text,
)

_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(_safe_text, children, max_size=4),
    ),
    max_leaves=8,
)

# Keys avoid "chain" (append() strips it; not what this suite is probing).
_record = st.dictionaries(
    _safe_text.filter(lambda s: s != "chain"), _json_value, max_size=6,
)

_lookalike_text = st.text(
    alphabet=LINE_BOUNDARY_LOOKALIKES + "abcXYZ 09\t",
    min_size=1, max_size=25,
)

# max_examples kept modest (not Hypothesis's 100 default doubled) because each
# example drives real file-locked appends -- Windows' msvcrt.locking path adds
# real per-append overhead (the existing 5000-iter hand-rolled fuzzer in
# test_property_ledger.py already exercises raw volume; these tests exist for
# shrinking + explicit named invariants, not additional bulk coverage).
#
# NOTE on fixtures: every test below builds its own tempfile.mkdtemp() dir
# inside the function body rather than taking pytest's `tmp_path` as a
# parameter. `tmp_path` is scoped to the test FUNCTION CALL, not to each of
# Hypothesis's internal replays of that function -- reusing it across
# examples means every example after the first appends onto a file already
# populated by earlier examples. (Caught mid-pass: an early draft of this
# file used `tmp_path` directly and got spurious "row count corrupted"
# failures that were cross-example pollution, not a library bug.)
_slow_settings = settings(max_examples=50, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
_char_settings = settings(max_examples=100, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])


# --- 1. hash-chain integrity under arbitrary appends -------------------------

@_slow_settings
@given(records=st.lists(_record, min_size=1, max_size=12),
       seed=st.integers(min_value=0))
def test_any_row_mutation_breaks_verify_from_that_row(records, seed):
    """Build an honest ledger; corrupt exactly one row's CONTENT (leave its
    stale claimed chain in place); verify() must go RED and name that row.

    Uses tempfile.mkdtemp() (NOT pytest's tmp_path) so every Hypothesis
    EXAMPLE gets a genuinely fresh directory. tmp_path is fixture-scoped to
    the test FUNCTION CALL, not to each of Hypothesis's internal replays of
    the function body -- reusing it silently accumulates rows from every
    prior example into the same file (caught here: first draft of this test
    used tmp_path directly and got 'row count corrupted: got 39, expected 1'
    on a single-record example, which was cross-example pollution, not a
    library bug)."""
    d = Path(tempfile.mkdtemp(prefix="ledger_hyp_"))
    p = d / "l.jsonl"
    log = Ledger(p)
    for rec in records:
        log.append(dict(rec))

    pre = log.verify()
    assert pre.ok and pre.rows == len(records) and pre.breaks == 0, pre

    lines = p.read_text(encoding="utf-8").split("\n")
    body_idx = [i for i, ln in enumerate(lines) if ln.strip()]
    assert len(body_idx) == len(records)

    target = body_idx[seed % len(body_idx)]
    obj = json.loads(lines[target])
    # Mutate CONTENT only; the claimed chain (computed from the original
    # content) is left stale on purpose -- that mismatch is what must fire.
    obj["__mutated__"] = obj.get("__mutated__", 0) + 1
    stale_chain = obj["chain"]
    mutated_line = json.dumps({**{k: v for k, v in obj.items() if k != "chain"},
                                "chain": stale_chain}, ensure_ascii=False)
    if mutated_line == lines[target]:
        return  # pathological no-op mutation; nothing to assert
    lines[target] = mutated_line
    p.write_text("\n".join(lines), encoding="utf-8")

    post = verify_file(p)
    row_no = body_idx.index(target) + 1  # 1-indexed row among parseable rows
    assert not post.ok, "mutation went undetected"
    assert post.breaks >= 1
    assert post.first_break is not None
    assert post.first_break.startswith(f"line {row_no}:"), (
        f"break reported at {post.first_break!r}, expected to start at row {row_no}")


# --- 2. append-order determinism ---------------------------------------------

@_slow_settings
@given(records=st.lists(_record, min_size=1, max_size=10))
def test_append_order_is_deterministic(records):
    """Same sequence of records (explicit ts, so wall-clock never leaks in)
    appended into two independent fresh ledgers must chain identically at
    every row -- `_chain` is a pure function of (prev, body), and this is
    that purity made an adversarially-searched, observable property.

    Fresh tempfile.mkdtemp() per example -- see the note on
    test_any_row_mutation_breaks_verify_from_that_row for why pytest's
    tmp_path fixture is the wrong tool inside a @given-decorated test."""
    stamped = []
    for i, rec in enumerate(records):
        r = dict(rec)
        r["ts"] = f"fixed-ts-{i}"  # remove _now_iso() wall-clock nondeterminism
        stamped.append(r)

    d1 = Path(tempfile.mkdtemp(prefix="ledger_hyp_run1_"))
    d2 = Path(tempfile.mkdtemp(prefix="ledger_hyp_run2_"))
    p1, p2 = d1 / "l.jsonl", d2 / "l.jsonl"
    log1, log2 = Ledger(p1), Ledger(p2)
    for r in stamped:
        log1.append(dict(r))
    for r in stamped:
        log2.append(dict(r))

    r1, r2 = log1.verify(), log2.verify()
    assert r1.ok and r2.ok
    assert r1.rows == r2.rows == len(records)

    for n in range(1, len(records) + 1):
        c1, c2 = chain_at(p1, n), chain_at(p2, n)
        assert c1 == c2, f"row {n} diverged between identical replays: {c1!r} != {c2!r}"

    assert log1.head().chain == log2.head().chain


# --- 3. unicode / line-boundary lookalikes ------------------------------------

@_slow_settings
@given(values=st.lists(_lookalike_text, min_size=1, max_size=8))
def test_line_boundary_lookalikes_round_trip_and_stay_verifiable(values):
    """U+0085/U+2028/U+2029 (+ the C0 separators) embedded in entry fields:
    written raw by json.dumps(ensure_ascii=False), must NOT fracture the
    JSONL row on read. verify() must stay green, row count must be exact,
    and content must round-trip byte-for-byte through __iter__.

    Fresh tempfile.mkdtemp() per example -- see the note on
    test_any_row_mutation_breaks_verify_from_that_row."""
    p = Path(tempfile.mkdtemp(prefix="ledger_hyp_")) / "l.jsonl"
    log = Ledger(p)
    for v in values:
        log.append({"field": v, "note": "before" + v + "after"})

    res = verify_file(p)
    assert res.ok, f"honest lookalike-bearing ledger verified RED: {res}"
    assert res.rows == len(values), (
        f"row count corrupted: got {res.rows}, expected {len(values)} -- a row "
        "was almost certainly split by a line-boundary lookalike character")
    assert res.breaks == 0

    read_back = list(log)
    assert len(read_back) == len(values)
    for original, row in zip(values, read_back):
        assert row["field"] == original
        assert row["note"] == "before" + original + "after"


@_char_settings
@given(pos=st.integers(min_value=0, max_value=2),
       ch=st.sampled_from(list(LINE_BOUNDARY_LOOKALIKES)))
def test_each_lookalike_char_individually_stays_verifiable(pos, ch):
    """One lookalike character at a time, at the start/middle/end of a field,
    surrounded by ordinary neighbour rows -- pins each character in
    LINE_BOUNDARY_LOOKALIKES individually rather than only in combination.

    Fresh tempfile.mkdtemp() per example -- see the note on
    test_any_row_mutation_breaks_verify_from_that_row."""
    p = Path(tempfile.mkdtemp(prefix="ledger_hyp_")) / "l.jsonl"
    log = Ledger(p)
    log.append({"n": "before"})
    text = {0: ch + "xy", 1: "x" + ch + "y", 2: "xy" + ch}[pos]
    log.append({"n": text})
    log.append({"n": "after"})

    res = verify_file(p)
    assert res.ok and res.rows == 3 and res.breaks == 0, (
        f"char {ch!r} at pos {pos} broke verify: {res}")
    rows = list(log)
    assert rows[1]["n"] == text


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
