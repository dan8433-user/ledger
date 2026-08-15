"""Regression tests for the 0.5.3 integrity audit.

Each test here was written FAILING against 0.5.2 and names the exact hole it
closes. The first one is the serious one: a row larger than the tail window
silently reset the chain to genesis, so deleting every row before that point
produced a log that verified GREEN — a tampered ledger passing verify().

Run: python -m pytest test_integrity_regressions.py
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon_ledger import (Ledger, chain_at, verify_artefact, verify_file,
                            bind_artefact, _chain, _GENESIS)


# --------------------------------------------------------------------------
# 1. Large rows must not reset the chain (CRITICAL: tampered log passed verify)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("size", [8192, 9000, 40000, 300000])
def test_append_after_large_row_keeps_the_chain(size):
    """A row bigger than the tail read window must still be chained FROM.

    Before 0.5.3 `_last_chain()` read a fixed 8 KB tail; a final row longer
    than that left no parseable line in the window, so it returned 'genesis'
    and the next append started a fresh chain mid-file.
    """
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"event": "web.read", "body": "X" * size})
        led.append({"event": "note", "n": 2})
        r = led.verify()
        assert r.ok, f"honest appends produced a broken chain: {r}"
        assert r.rows == 2 and r.chained == 2

        rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
        body = {k: v for k, v in rows[1].items() if k != "chain"}
        assert rows[1]["chain"] != _chain(_GENESIS, body), \
            "row 2 was chained from genesis — the chain was silently reset"


def test_deleting_history_before_a_large_row_is_caught():
    """The attack the reset enabled: drop everything before the reset point
    and the remainder self-verifies. Must now be caught."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"event": "payment", "amount": 10})
        led.append({"event": "fraud_flag", "case": "the row someone wants gone"})
        led.append({"event": "web.read", "body": "X" * 9000})
        led.append({"event": "payment", "amount": 30})
        led.append({"event": "payment", "amount": 40})
        assert led.verify().ok, "clean fixture must verify GREEN first"

        lines = p.read_text(encoding="utf-8").splitlines()
        tampered = Path(d) / "tampered.jsonl"
        tampered.write_text("\n".join(lines[3:]) + "\n", encoding="utf-8")
        r = verify_file(tampered)
        assert not r.ok, "deleting the first three rows still verified GREEN"
        assert r.first_break == "line 1: chain mismatch", r.first_break


def test_last_chain_survives_a_multi_megabyte_row():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"blob": "Y" * 2_000_000})
        led.append({"n": 2})
        assert led.verify().ok


# --------------------------------------------------------------------------
# 2. Non-object rows: typed failure, never a crash
# --------------------------------------------------------------------------

@pytest.mark.parametrize("smuggled", ['123', 'null', '"a string"', '[1,2]',
                                      'true', '3.5'])
def test_non_object_row_is_a_typed_break_not_a_crash(smuggled):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        Ledger(p).append({"a": 1})
        with p.open("a", encoding="utf-8") as fh:
            fh.write(smuggled + "\n")
        r = verify_file(p)                       # must not raise
        assert not r.ok
        assert r.first_break == "line 2: not a JSON object", r.first_break


def test_append_after_a_non_object_row_does_not_crash():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        Ledger(p).append({"a": 1})
        with p.open("a", encoding="utf-8") as fh:
            fh.write("123\n")
        c2 = Ledger(p).append({"b": 2})          # must not raise
        # the smuggled line is not a row, so the appended dict IS row 2, and it
        # chains from row 1 — the junk line neither counts nor resets the chain
        assert chain_at(p, 2) == c2              # must not raise
        assert chain_at(p, 3) is None
        r = verify_file(p)
        assert not r.ok and r.first_break == "line 2: not a JSON object"
        assert r.rows == 2 and r.chained == 2


def test_chain_at_skips_non_object_rows_without_crashing():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"a": 1})
        with p.open("a", encoding="utf-8") as fh:
            fh.write("null\n")
        assert chain_at(p, 1) is not None
        assert chain_at(p, 2) is None


# --------------------------------------------------------------------------
# 3. verify_artefact: typed failure on type confusion, never an exception
# --------------------------------------------------------------------------

@pytest.mark.parametrize("art", [
    {"digest": 123},
    {"digest": None},
    {"digest": ["sha256", "raw-bytes", "v1", "ab"]},
    {"digest": {"a": 1}},
    {"digest": b"sha256:raw-bytes:v1:" + b"a" * 64},
    "not a dict at all",
    ["not", "a", "dict"],
    None,
    42,
])
def test_verify_artefact_type_confusion_is_typed(art):
    out = verify_artefact(art)                   # must not raise
    assert out["digest_ok"] is False
    assert out["reason"] == "malformed_digest", out


def test_verify_artefact_non_dict_subject_is_typed():
    art = {"digest": "sha256:raw-bytes:v1:" + "a" * 64, "subject": "nope"}
    out = verify_artefact(art)
    assert out["digest_ok"] is False
    assert out["reason"] == "malformed_digest", out


def test_verify_artefact_non_dict_subject_digest_is_typed():
    art = {"digest": "sha256:raw-bytes:v1:" + "a" * 64,
           "subject": {"digest": "not-a-dict"}}
    out = verify_artefact(art)
    assert out["digest_ok"] is False
    assert out["reason"] == "malformed_digest", out


# --------------------------------------------------------------------------
# 4. Hex case: an upper-cased digest must not read as a different digest
# --------------------------------------------------------------------------

def test_uppercase_hex_still_matches_its_subject():
    art = bind_artefact(b"hello")
    algo, rec, ver, hx = art["digest"].split(":")
    art["digest"] = f"{algo}:{rec}:{ver}:{hx.upper()}"
    out = verify_artefact(art)   # subject still lower-case: same digest, different case
    assert out["digest_ok"] is True, out
    assert out["reason"] is None


def test_genuinely_different_subject_hex_still_fails():
    art = bind_artefact(b"hello")
    art["subject"]["digest"]["sha256"] = "0" * 64
    out = verify_artefact(art)
    assert out["digest_ok"] is False
    assert out["reason"] == "subject_digest_mismatch"


# --------------------------------------------------------------------------
# 5. The chain comparison must be full-width (the harness gap)
# --------------------------------------------------------------------------

def test_chain_comparison_is_full_width():
    """A forged chain differing from the true one only in its LAST character
    must be rejected. A verifier comparing any prefix passes this fixture."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"n": 1})
        led.append({"n": 2})
        lines = p.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[1])
        true_chain = obj["chain"]
        obj["chain"] = true_chain[:-1] + ("0" if true_chain[-1] != "0" else "1")
        lines[1] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = verify_file(p)
        assert not r.ok, "a chain differing only in the last character passed"
        assert r.first_break == "line 2: chain mismatch"


# --------------------------------------------------------------------------
# 0.5.4 — concurrent append must not fork the chain or lose rows (M3)
# --------------------------------------------------------------------------

def _conc_worker(args):
    path, tag, n = args
    led = Ledger(path)
    for i in range(n):
        led.append({"tool": tag, "i": i})
    return n


def test_concurrent_appends_do_not_fork_or_lose_rows():
    """Two processes each appending 20 rows onto a 1-row seed must yield a
    single continuous 41-row chain — no forks, no lost rows.

    Before 0.5.4 the read-tail + write was unlocked: both writers read the same
    previous chain and forked it, and interleaved "ab" writes dropped rows. The
    scrutiny measured 41 -> rows=38, breaks=17. The cross-process append lock
    serializes the critical section.
    """
    import multiprocessing as mp
    with tempfile.TemporaryDirectory() as d:
        path = str(Path(d) / "conc.jsonl")
        Ledger(path).append({"tool": "seed", "i": 0})
        with mp.Pool(2) as pool:
            pool.map(_conc_worker, [(path, "A", 20), (path, "B", 20)])
        r = verify_file(path)
        assert r.ok, f"concurrent appends forked the chain: {r}"
        assert r.rows == 41, f"expected 41 rows, got {r.rows}"
        assert r.breaks == 0, f"expected 0 breaks, got {r.breaks}"


# --------------------------------------------------------------------------
# 0.5.4 — strict verify surfaces a fabricated-legacy-prepend (M2)
# --------------------------------------------------------------------------

def test_strict_mode_rejects_prepended_fabricated_legacy_row():
    """A fabricated unchained row prepended before a genuine chain verifies
    GREEN by default (tolerated as pre-chain legacy) but must be a break under
    strict=True. The default path stays green and exposes prechain=1."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"tool": "real", "amount": 1})
        led.append({"tool": "real", "amount": 2})
        lines = p.read_text(encoding="utf-8").splitlines()
        fake = json.dumps({"tool": "INJECTED_fake_history", "amount": 9999})
        p.write_text(fake + "\n" + "\n".join(lines) + "\n", encoding="utf-8")

        default = verify_file(p)
        assert default.ok and default.prechain == 1, default

        strict = verify_file(p, strict=True)
        assert not strict.ok, "strict mode passed a prepended fabricated legacy row"
        assert strict.prechain == 1
        assert strict.breaks == 1
        assert "prechain" in strict.first_break

        # A clean chain-from-genesis log stays green in strict mode.
        assert verify_file(p.with_name("absent.jsonl"), strict=True).rows == 0
        p2 = Path(d) / "clean.jsonl"
        c = Ledger(p2)
        c.append({"n": 1}); c.append({"n": 2})
        assert verify_file(p2, strict=True).ok


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
