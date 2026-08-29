# SPDX-License-Identifier: MIT
"""Declared chain breaks (0.6.0).

A ledger written out of band is broken forever, and that is correct. These tests
exist to prove `declare_break` cannot be used to launder a tamper: the ONLY thing
a declaration buys is that a break somebody named, dated, reasoned and pinned to
exact bytes stops reading like an unexplained one. It never buys a green.

Every test here was watched failing against a deliberately broken implementation
before it was kept (see CHANGELOG 0.6.0 for the mutation runs).
"""
from __future__ import annotations

import json

import pytest

from arcaeon_ledger import Ledger, declare_break, verify_file


def _read(p):
    return p.read_text(encoding="utf-8").split("\n")


def _write(p, lines):
    p.write_text("\n".join(lines), encoding="utf-8")


def _orphan_ledger(tmp_path):
    """Two clean rows, then an UNCHAINED row hand-appended after the chain began.

    This is the real 2026-08-15 shape from bridge/state/commitments_ledger.jsonl
    line 25: a live session wrote JSON straight into the file instead of calling
    append().
    """
    p = tmp_path / "orphan.jsonl"
    log = Ledger(p)
    log.append({"op": "create", "id": "a"})
    log.append({"op": "update", "id": "a"})
    with p.open("ab") as fh:
        fh.write(b'{"op": "update", "id": "a", "note": "by hand"}\n')
    return p


def _bogus_chain_ledger(tmp_path):
    """Two clean rows, then a row carrying a chain that verifies against nothing.

    The commitments ledger line-26 shape: hand-written, or edited after append.
    """
    p = tmp_path / "bogus.jsonl"
    log = Ledger(p)
    log.append({"op": "create", "id": "b"})
    log.append({"op": "update", "id": "b"})
    with p.open("ab") as fh:
        fh.write(b'{"op": "update", "id": "b", "chain": "ffffffffffffffffffffffffffffffff"}\n')
    return p


# --- property 1: an undeclared break still fails. always. -------------------

def test_undeclared_orphan_still_fails(tmp_path):
    r = verify_file(_orphan_ledger(tmp_path))
    assert r.ok is False
    assert r.breaks == 1
    assert r.first_break == "line 3: unchained row after chain began", r.first_break
    assert r.declared_breaks == 0 and r.declared == []


def test_undeclared_bogus_chain_still_fails(tmp_path):
    r = verify_file(_bogus_chain_ledger(tmp_path))
    assert r.ok is False
    assert r.breaks == 1
    assert r.first_break == "line 3: chain mismatch", r.first_break


def test_declaring_one_break_does_not_excuse_another(tmp_path):
    """Declaring line 3 must leave an undeclared line-4 break red."""
    p = _orphan_ledger(tmp_path)
    with p.open("ab") as fh:
        fh.write(b'{"op": "update", "id": "a", "note": "also by hand"}\n')
    declare_break(p, 3, "hand-appended during an incident")
    r = verify_file(p)
    assert r.ok is False
    assert r.breaks == 1 and r.declared_breaks == 1
    assert "line 4" in (r.first_break or ""), r.first_break


# --- property 5: a declared break is bounded, and never invisible -----------

def test_declared_orphan_is_bounded_never_green(tmp_path):
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    r = verify_file(p)
    # Not red...
    assert r.breaks == 0
    assert r.first_break is None
    # ...and emphatically not green. Only a scan that checked every row is True.
    assert r.ok is None, r
    assert bool(r) is False
    assert r.verified_scope == "bounded_declared_break", r.verified_scope
    # ...and permanently visible.
    assert r.declared_breaks == 1
    assert r.declared == ["line 3: declared break (hand-appended during an incident)"], r.declared


def test_declared_bogus_chain_is_bounded_never_green(tmp_path):
    p = _bogus_chain_ledger(tmp_path)
    declare_break(p, 3, "chain value verifies against nothing; preserved verbatim")
    r = verify_file(p)
    assert r.breaks == 0 and r.first_break is None
    assert r.ok is None and bool(r) is False
    assert r.verified_scope == "bounded_declared_break"
    assert r.declared_breaks == 1 and "line 3" in r.declared[0]


def test_declaration_does_not_hide_the_break_from_a_printed_result(tmp_path):
    """The reason `declared` is a list of sentences and not a bare count."""
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "incident 2026-08-15, written outside the tool")
    text = repr(verify_file(p))
    assert "declared break" in text
    assert "incident 2026-08-15, written outside the tool" in text


# --- property 2: a declaration excuses the exact bytes it pinned, and no others

def test_editing_a_declared_orphan_re_breaks_it(tmp_path):
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    assert verify_file(p).ok is None            # bounded, before the edit
    lines = _read(p)
    row = json.loads(lines[2])
    row["note"] = "rewritten later"             # the orphan's content moves
    lines[2] = json.dumps(row, ensure_ascii=False)
    _write(p, lines)
    r = verify_file(p)
    assert r.ok is False
    assert r.declared_breaks == 0
    assert "orphan_sha256 does not match" in (r.first_break or ""), r.first_break


# --- property 3: a forged pin excuses nothing -------------------------------

def test_forged_orphan_sha256_excuses_nothing(tmp_path):
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    lines = _read(p)
    for i, line in enumerate(lines):
        if '"chain_break_declared"' in line:
            d = json.loads(line)
            d["orphan_sha256"] = "0" * 64
            lines[i] = json.dumps(d, ensure_ascii=False)
    _write(p, lines)
    r = verify_file(p)
    assert r.ok is False
    assert r.declared_breaks == 0
    assert "orphan_sha256 does not match" in (r.first_break or ""), r.first_break


def test_declaration_pointing_at_the_wrong_line_excuses_nothing(tmp_path):
    """Right hash, wrong line: the break at line 3 is still a break."""
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    lines = _read(p)
    for i, line in enumerate(lines):
        if '"chain_break_declared"' in line:
            d = json.loads(line)
            d["orphan_line"] = 2
            lines[i] = json.dumps(d, ensure_ascii=False)
    _write(p, lines)
    r = verify_file(p)
    assert r.ok is False and r.declared_breaks == 0


def test_unchained_handwritten_declaration_excuses_nothing(tmp_path):
    """A declaration must at least have come through append(). Echoing one into
    the file by hand hands out no exemptions -- and is itself a second break."""
    import hashlib
    p = _orphan_ledger(tmp_path)
    orphan = _read(p)[2].strip()
    row = {"op": "chain_break_declared", "orphan_line": 3,
           "orphan_sha256": hashlib.sha256(orphan.encode()).hexdigest(),
           "why": "smuggled in without append()"}
    with p.open("ab") as fh:
        fh.write((json.dumps(row) + "\n").encode("utf-8"))
    r = verify_file(p)
    assert r.ok is False
    assert r.declared_breaks == 0
    assert r.breaks == 2, r.breaks         # the orphan AND the smuggled row


def test_declaration_with_blank_reason_is_refused_at_write_time(tmp_path):
    p = _orphan_ledger(tmp_path)
    with pytest.raises(ValueError):
        declare_break(p, 3, "   ")
    with pytest.raises(ValueError):
        declare_break(p, 99, "line does not exist")


def test_reasonless_declaration_row_excuses_nothing(tmp_path):
    """And if one is written past declare_break, the verifier refuses it too."""
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    lines = _read(p)
    for i, line in enumerate(lines):
        if '"chain_break_declared"' in line:
            d = json.loads(line)
            d["why"] = ""
            lines[i] = json.dumps(d, ensure_ascii=False)
    _write(p, lines)
    assert verify_file(p).ok is False


# --- property 4: ordinary tampering is caught, unchanged --------------------

def test_ordinary_tamper_on_a_chained_row_still_caught(tmp_path):
    p = tmp_path / "t.jsonl"
    log = Ledger(p)
    for i in range(5):
        log.append({"tool": "pay", "amount": i})
    lines = _read(p)
    row = json.loads(lines[2])
    row["amount"] = 999
    lines[2] = json.dumps(row, ensure_ascii=False)
    _write(p, lines)
    r = verify_file(p)
    assert r.ok is False
    assert r.breaks == 1
    assert r.first_break == "line 3: chain mismatch", r.first_break
    assert r.declared_breaks == 0


def test_a_declaration_elsewhere_does_not_soften_a_real_tamper(tmp_path):
    """The dangerous shape: a legitimately declared break in the same file as a
    genuine mid-file edit. The edit must still be red."""
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    lines = _read(p)
    row = json.loads(lines[1])
    row["id"] = "TAMPERED"
    lines[1] = json.dumps(row, ensure_ascii=False)
    _write(p, lines)
    r = verify_file(p)
    assert r.ok is False
    assert "line 2: chain mismatch" == r.first_break, r.first_break


def test_unparseable_and_nonobject_lines_are_not_declarable(tmp_path):
    """Malformed bytes are not a recorded event somebody wrote outside the tool.
    There is nothing to stand behind, so there is nothing to declare."""
    import hashlib
    p = tmp_path / "u.jsonl"
    log = Ledger(p)
    log.append({"op": "create", "id": "c"})
    with p.open("ab") as fh:
        fh.write(b'{"op": "broken", "id": \n')          # unparseable fragment
    junk = _read(p)[1].strip()
    declared_ok = True
    try:
        declare_break(p, 2, "garbage from a torn write")
    except ValueError:
        declared_ok = False
    assert declared_ok        # you may declare it; it just does not excuse
    r = verify_file(p)
    assert r.ok is False
    assert r.breaks >= 1
    assert "unparseable" in (r.first_break or ""), r.first_break
    assert hashlib.sha256(junk.encode()).hexdigest()  # sanity: bytes were there


# --- property 6: strict is not weakened ------------------------------------

def test_strict_ignores_declarations_entirely(tmp_path):
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "hand-appended during an incident")
    lenient = verify_file(p, strict=False)
    strict = verify_file(p, strict=True)
    assert lenient.ok is None and lenient.breaks == 0
    assert strict.ok is False, strict
    # TWO breaks under strict, not one, and that is the honest count: strict does
    # not take the declaration's resume point either, so it walks past the orphan
    # still holding line 2's chain, and the declaration row -- which append()
    # correctly chained from genesis, because the unchained orphan carried no
    # chain to follow -- mismatches against it. Strict refusing the resume claim
    # is the same refusal as strict refusing the excusal; a mode that declined
    # the exemption but quietly accepted the pointer that came with it would be
    # honoring half of an unverified claim.
    assert strict.breaks == 2, strict
    assert strict.first_break == "line 3: unchained row after chain began"
    assert strict.declared_breaks == 0          # strict excused nothing
    # ...but it still SAYS it saw a declaration, so the mode gap is not silent.
    assert strict.declared and "NOT honored (strict mode)" in strict.declared[0]


def test_strict_ignores_declarations_on_a_bogus_chain_too(tmp_path):
    p = _bogus_chain_ledger(tmp_path)
    declare_break(p, 3, "chain value verifies against nothing")
    assert verify_file(p, strict=False).ok is None
    strict = verify_file(p, strict=True)
    assert strict.ok is False and strict.breaks == 1
    assert strict.first_break == "line 3: chain mismatch"
    assert strict.declared_breaks == 0


# --- resume_prev is trusted, but not usefully forgeable ---------------------

def test_wrong_resume_prev_fails_the_very_next_row(tmp_path):
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "orphan", resume_prev="a" * 32)
    # The declaration row itself (line 4) was appended chaining from what
    # _last_chain() found, not from the lie -- so the lie fails immediately.
    r = verify_file(p)
    assert r.ok is False
    assert r.first_break == "line 4: chain mismatch", r.first_break
    assert r.declared_breaks == 1     # line 3 is still honestly declared


def test_honest_resume_prev_lets_the_chain_continue(tmp_path):
    p = _orphan_ledger(tmp_path)
    declare_break(p, 3, "orphan")     # resumes from genesis, which is the truth
    Ledger(p).append({"op": "update", "id": "a", "note": "back on the rails"})
    r = verify_file(p)
    assert r.ok is None and r.breaks == 0
    assert r.chained == 4             # rows 1, 2, 4, 5
    assert r.declared_breaks == 1


# --- interaction with the existing bounded-scope idiom ---------------------

def test_prechain_and_declared_break_together_name_both(tmp_path):
    p = tmp_path / "mix.jsonl"
    p.write_text('{"op": "legacy", "id": "z"}\n', encoding="utf-8")
    log = Ledger(p)
    log.append({"op": "create", "id": "z"})
    with p.open("ab") as fh:
        fh.write(b'{"op": "update", "id": "z", "note": "by hand"}\n')
    declare_break(p, 3, "hand-appended during an incident")
    r = verify_file(p)
    assert r.ok is None and r.breaks == 0
    assert r.prechain == 1 and r.declared_breaks == 1
    assert r.verified_scope == "bounded_prechain_skipped+declared_break", r.verified_scope
