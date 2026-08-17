# SPDX-License-Identifier: MIT
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


@pytest.mark.parametrize("bad_chain", [1, 1.5, True, ["a"], {"x": 1}])
def test_non_string_chain_field_is_a_typed_break_not_a_crash(bad_chain):
    # Mutation-testing survivor (2026-08-16): deleting the `isinstance(claimed, str)`
    # guard in verify_file() passed the whole fast suite — only the slow fuzzer had
    # a chance to construct a non-string chain value. A chain link is a hex string;
    # a present-but-non-string chain (all legal JSON, so all arrivable from the wire
    # or a corrupt file) must return a typed break, never crash the verifier. This
    # pins the guard so its removal fails fast, not by luck. (The bug shipped once at
    # 0.5.5 — this is the regression fence.)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        Ledger(p).append({"a": 1})
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"b": 2, "chain": bad_chain}) + "\n")
        r = verify_file(p)                       # must not raise
        assert not r.ok
        assert r.first_break == "line 2: non-string chain value", r.first_break


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


@pytest.mark.parametrize("falsy_chain", [None, ""])
def test_append_after_a_falsy_chain_row_chains_from_genesis(falsy_chain):
    # Mutation-testing survivor L5 (2026-08-16): dropping `_last_chain()`'s
    # `or _GENESIS` fallback (`return obj.get("chain")` bare) survived the
    # whole fast suite -- no fixture ends in a row whose "chain" is null or
    # "". The honest writer never emits one, but a hand-edited or rewritten
    # file can; without the fallback the next append computes
    # _chain(None, body) -- chaining from the literal string "None" -- and
    # silently forks the log from a value no verifier ever derives. The
    # fallback must repair a falsy tail chain to genesis; this pins the
    # ACTUAL value chained from, not just "verify stays green".
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        p.write_text(json.dumps({"event": 1, "chain": falsy_chain}) + "\n",
                     encoding="utf-8")
        Ledger(p).append({"event": 2})
        rows = [json.loads(l)
                for l in p.read_text(encoding="utf-8").splitlines()]
        body = {k: v for k, v in rows[1].items() if k != "chain"}
        assert rows[1]["chain"] == _chain(_GENESIS, body), \
            "append after a falsy tail chain did not restart from genesis"


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


# --------------------------------------------------------------------------
# unreleased — U+2028-class line-boundary characters: sealed-but-unverifiable
# --------------------------------------------------------------------------
# The same bug class found in continuity's own event log the night of
# 2026-08-15: rows are written with json.dumps(..., ensure_ascii=False), which
# escapes only the MANDATORY U+0000-U+001F control range -- U+0085 (NEL),
# U+2028 (LINE SEPARATOR), and U+2029 (PARAGRAPH SEPARATOR) sit outside that
# range and round-trip RAW into the JSONL bytes. Reads went through
# str.splitlines(), which treats those three (plus \x0b \x0c \x1c \x1d \x1e)
# as row boundaries -- distinct from the literal "\n" the writer actually
# uses as its delimiter. A row containing one of them therefore sealed
# cleanly (append() computed and stored a correct chain over the true
# content) and then could never verify green again: split into fragments,
# each unparseable, reported as a tamper that never happened. Fixed by
# switching every read path (Ledger.__iter__, chain_at, verify_file) from
# `.splitlines()` to `.split("\n")` -- read_text()'s universal-newline
# handling already folds \r\n / \r to \n, so "\n" is the writer's only real
# delimiter either way.

_LINE_BOUNDARY_LOOKALIKES = "\x85  \x0b\x0c\x1c\x1d\x1e"


def test_u2028_class_content_does_not_break_verify():
    """An honest row whose content contains U+2028/U+2029/U+0085 (or the C0
    separators splitlines() also treats as boundaries) must verify GREEN and
    round-trip its content exactly -- written FAILING before this fix, where
    it verified RED with an 'unparseable' break despite zero tampering."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        led.append({"note": "before"})
        led.append({"note": f"contains {_LINE_BOUNDARY_LOOKALIKES} right here"})
        led.append({"note": "after"})

        r = led.verify()
        assert r.ok, f"honest lookalike-bearing row verified RED: {r}"
        assert r.rows == 3, f"row count corrupted by a split: got {r.rows}"
        assert r.breaks == 0

        rows = list(led)
        assert len(rows) == 3
        assert rows[1]["note"] == f"contains {_LINE_BOUNDARY_LOOKALIKES} right here"


def test_u2028_class_content_survives_chain_at_and_head():
    """chain_at() and Ledger.head() read the same way; both must still find
    the correct row count and chain value when a middle row's content
    contains a lookalike character."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        led = Ledger(p)
        for i in range(4):
            note = f"row{i}" if i != 2 else f"row2 with U+2028  inside"
            led.append({"note": note})

        r = led.verify()
        assert r.ok and r.rows == 4

        h = led.head()
        assert h.rows == 4
        assert chain_at(p, 4) == h.chain
        # every intermediate chain value must be independently reachable too
        for n in range(1, 5):
            assert chain_at(p, n) is not None


# --------------------------------------------------------------------------
# 6. _chain() operand order is pinned by a frozen wire-format vector
# --------------------------------------------------------------------------
# `chain = sha256(prev_chain + canonical_json_body)` is the documented wire
# format (module docstring, README) -- the whole point of publishing it is so
# a SECOND implementation (a cross-language verifier) can reproduce the exact
# same hash. `append()`/`verify_file()` both call this one `_chain()`, so an
# operand-order swap (`body + prev` instead of `prev + body`) is fully
# self-consistent -- nothing that only round-trips through this package's own
# read/write path would ever notice. It would silently break interop with any
# outside verifier that read the docstring and implemented it correctly.
# These vectors are computed independently below (hashlib + json.dumps
# directly, NOT by calling `_chain`), then frozen as literals -- the same
# pattern as `mutation_harness._DRIFT_FROZEN` -- so a change to `_chain`'s
# internals (operand order, separator, encoding) fails against a fixed
# external answer instead of against itself.

_CHAIN_VECTOR_1_ROW = {"a": 1}
_CHAIN_VECTOR_1_PREV = _GENESIS
_CHAIN_VECTOR_1_HASH = "bfd5f35b43681d586db0f4a547a500ca"

_CHAIN_VECTOR_2_ROW = {"ts": "2026-01-01T00:00:00Z", "tool": "search",
                       "query": "weather", "n": 1}
_CHAIN_VECTOR_2_PREV = _GENESIS
_CHAIN_VECTOR_2_HASH = "acbfb38fb4f6bf82da44d411f2a0ad82"

# A second link chained from the first, so an operand-order swap that only
# happens to no-op on the genesis case (str(prev) == "genesis", commutative
# in length but not in bytes) is still caught downstream.
_CHAIN_VECTOR_3_ROW = {"ts": "2026-01-01T00:00:01Z", "tool": "pay",
                       "amount": 42.5, "ok": True}
_CHAIN_VECTOR_3_PREV = _CHAIN_VECTOR_2_HASH
_CHAIN_VECTOR_3_HASH = "7a20bd04f9d17432ade36e7f252dcf26"


def test_chain_hash_matches_frozen_wire_format_vector():
    """Pins the exact byte sequence _chain() hashes: sha256(prev + canonical
    json body)[:32]. A mutant that swaps the operand order, changes the
    separator, or changes the truncation length is internally self-consistent
    (append and verify agree with each other either way) and passes every
    other test in this suite -- only a fixed external vector catches it."""
    assert _chain(_CHAIN_VECTOR_1_PREV, _CHAIN_VECTOR_1_ROW) == _CHAIN_VECTOR_1_HASH
    assert _chain(_CHAIN_VECTOR_2_PREV, _CHAIN_VECTOR_2_ROW) == _CHAIN_VECTOR_2_HASH
    assert _chain(_CHAIN_VECTOR_3_PREV, _CHAIN_VECTOR_3_ROW) == _CHAIN_VECTOR_3_HASH


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
