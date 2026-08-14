"""Tests for arcaeon_ledger.witness — the outside check that closes truncation.

The load-bearing test is the one the chain ALONE cannot pass: a truncated log
still self-verifies (proved in test_ledger.py), but the external witness catches
it. Also: rewrite detection, the honest 'consistent-and-grown' case, and
'no_record' never returning a false ok. Run: python test_witness.py
"""
import tempfile
from pathlib import Path

from arcaeon_ledger import (Ledger, WitnessStore, publish_head,
                            verify_against_witness, chain_at)


def _log_with(d, name, n):
    log = Ledger(Path(d) / name)
    for i in range(n):
        log.append({"event": i})
    return log


def test_witness_catches_truncation_that_chain_misses():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 6)
        store = WitnessStore(Path(d) / "witness.jsonl")
        publish_head(store, "agent-7", log)          # witness records (rows=6, chain=...)

        # truncate: drop the last two rows
        p = log.path
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")

        # the chain alone still says clean — that's the gap
        assert log.verify().ok, "truncated remainder self-verifies (the whole point)"

        # the witness catches it
        v = verify_against_witness(store, "agent-7", log)
        assert v.verdict == "truncated", v
        assert not v, "a truncated verdict must be falsy"
        assert v.witness_rows == 6 and v.local_rows == 4, v
    print("PASS witness catches truncation the chain alone misses")


def test_witness_consistent_when_untouched():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 5)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)
        v = verify_against_witness(store, "ns", log)
        assert v.verdict == "consistent" and bool(v) is True, v
    print("PASS untouched log verifies consistent against the witness")


def test_witness_consistent_after_growth():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 3)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)               # pinned at 3 rows
        for i in range(4):
            log.append({"more": i})                  # grow to 7
        v = verify_against_witness(store, "ns", log)
        assert v.verdict == "consistent", v
        assert v.witness_rows == 3 and v.local_rows == 7, v
        assert "grown" in v.detail
    print("PASS growth since the pin is consistent (not a false alarm)")


def test_witness_catches_rewrite():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 5)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)               # pin (rows=5, chain=X)

        # rewrite from genesis with different content but a fresh, self-consistent chain
        p = Path(d) / "log.jsonl"
        p.unlink()
        rewritten = Ledger(p)
        for i in range(5):
            rewritten.append({"event": i + 100})     # different payloads -> different chain
        assert rewritten.verify().ok, "a re-minted log self-verifies (why the witness is needed)"

        v = verify_against_witness(store, "ns", rewritten)
        assert v.verdict == "rewritten", v
        assert not v
    print("PASS witness catches a full rewrite (same row count, different chain)")


def test_no_record_is_not_a_false_ok():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 2)
        store = WitnessStore(Path(d) / "w.jsonl")
        v = verify_against_witness(store, "never-pinned", log)
        assert v.verdict == "no_record" and bool(v) is False, v
    print("PASS a namespace the witness never saw returns no_record, never a false ok")


def test_chain_at_matches_head():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 4)
        h = log.head()
        # chain_at(total rows) must equal the head's chain
        assert chain_at(log.path, h.rows) == h.chain
        assert chain_at(log.path, 99) is None          # beyond the log
        assert chain_at(log.path, 0) == "genesis"
    print("PASS chain_at is consistent with head() and honest past the end")


def test_witness_store_is_append_only_history():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 2)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)
        log.append({"event": 99})
        publish_head(store, "ns", log)
        hist = store.history("ns")
        assert len(hist) == 2 and hist[0]["rows"] == 2 and hist[1]["rows"] == 3, hist
        assert store.latest("ns")["rows"] == 3
    print("PASS witness keeps append-only pin history; latest() returns the newest")


if __name__ == "__main__":
    test_witness_catches_truncation_that_chain_misses()
    test_witness_consistent_when_untouched()
    test_witness_consistent_after_growth()
    test_witness_catches_rewrite()
    test_no_record_is_not_a_false_ok()
    test_chain_at_matches_head()
    test_witness_store_is_append_only_history()
    print("\nALL PASS — the external witness catches truncation AND rewrite that the "
          "chain alone cannot, stays quiet on honest growth, and never returns a false ok.")
