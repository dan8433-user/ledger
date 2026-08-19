# SPDX-License-Identifier: MIT
"""Tests for the ledger binding, including the claim that degradation is honest.

`_ledger.py` says: if `arcaeon-ledger` is not installed, we still write rows, in
the library's own on-disk shape, using a local implementation of its two frozen
recipes — and a machine that DOES have the library can verify those files later.

That is a strong claim and it would be easy to ship as a comment. So it is tested:
the fallback writer and the real `Ledger` are driven over identical rows and their
files must come out byte-identical (modulo the `ts` stamp, which is a clock read).
If the recipes ever drift apart, this goes red here rather than silently producing
a second, incompatible dialect of "arcaeon ledger" in the field.

Run: pytest -q
"""
import json

import pytest

from arcaeon_adapter import _ledger as L


def test_backend_names_which_writer_is_live():
    """A reviewer must never have to guess which implementation made the chain."""
    b = L.backend()
    assert b.startswith("arcaeon-ledger/") or b == "fallback-jsonl/1"


def test_canon_json_is_the_frozen_recipe():
    assert L.canon_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert L.canon_json({"u": "é🔒"}) == '{"u":"é🔒"}'.encode("utf-8")  # not \\u escaped
    with pytest.raises(ValueError):
        L.canon_json({"bad": float("nan")})   # no token other languages can't parse


def test_digest_is_self_describing_never_a_bare_hash():
    d = L.digest_json({"a": 1})
    algo, recipe, ver, hexpart = d.split(":")
    assert (algo, recipe, ver) == ("sha256", "json-c14n", "v1")
    assert len(hexpart) == 64 and int(hexpart, 16) >= 0


def test_digest_matches_the_frozen_golden_vector():
    assert L.digest_json({"b": 2, "a": 1}) == (
        "sha256:json-c14n:v1:"
        "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777")


def test_fallback_chain_is_byte_compatible_with_the_real_ledger(tmp_path):
    """The degradation claim, actually checked."""
    real_cls = L._RealLedger
    if real_cls is None:                      # pragma: no cover
        pytest.skip("arcaeon-ledger not installed; nothing to compare against")

    rows = [{"evt": "session_begin", "seq": 1, "ts": "2026-08-19T00:00:00Z"},
            {"evt": "tool_call", "seq": 2, "tool": "echo", "ts": "2026-08-19T00:00:01Z"},
            {"evt": "session_end", "seq": 3, "ts": "2026-08-19T00:00:02Z"}]

    a, b = tmp_path / "real.jsonl", tmp_path / "fallback.jsonl"
    real, fake = real_cls(a), L._FallbackLedger(b)
    for r in rows:
        ca, cb = real.append(dict(r)), fake.append(dict(r))
        assert ca == cb, f"chain hash diverged on {r['evt']}: {ca} vs {cb}"
    assert a.read_bytes() == b.read_bytes()


def test_fallback_resumes_an_existing_chain(tmp_path):
    """Appending to a file the real library wrote must continue its chain, not fork
    one — the failure mode that makes earlier rows quietly detachable."""
    real_cls = L._RealLedger
    if real_cls is None:                      # pragma: no cover
        pytest.skip("arcaeon-ledger not installed")
    p = tmp_path / "mixed.jsonl"
    real_cls(p).append({"evt": "written_by_library"})
    L._FallbackLedger(p).append({"evt": "written_by_fallback"})
    v = L.verify_seam_log(p)
    assert v.ok is True, v


def test_fallback_verifier_catches_an_edited_row(tmp_path):
    """The fallback verifier exists so `selftest` still observes tampering being
    caught on a machine without the library. It must actually catch it."""
    p = tmp_path / "f.jsonl"
    log = L._FallbackLedger(p)
    for i in range(4):
        log.append({"evt": "tool_call", "n": i})
    lines = [l for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]
    obj = json.loads(lines[1])
    obj["n"] = 999
    lines[1] = json.dumps(obj, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify with the fallback verifier explicitly, regardless of what's installed.
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is False
    assert v.first_break == "line 2: chain mismatch"   # same string either way
    assert not v                                        # falsy, so `if v:` fails safe


def test_verify_reports_a_missing_file_as_a_failure_not_a_green(tmp_path):
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(tmp_path / "nope.jsonl")
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is False and "unreadable" in v.first_break


def test_open_ledger_creates_parent_directories(tmp_path):
    """A `--ledger logs/seam.jsonl` into a non-existent dir must not kill a session."""
    log = L.open_ledger(tmp_path / "deep" / "nested" / "seam.jsonl")
    log.append({"evt": "session_begin"})
    assert (tmp_path / "deep" / "nested" / "seam.jsonl").exists()
