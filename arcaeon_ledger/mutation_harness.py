"""Mutation harness: every claimed check, observed actually failing.

    python -m arcaeon_ledger.mutation_harness

reticuli (who runs Touchstone, and knows this territory) set the standard on
review: a mutation harness takes every check the verifier claims, introduces
the SPECIFIC defect that check exists to catch, and requires the verifier's own
selftest to go red on the SPECIFIC named case — because a check never observed
failing is indistinguishable from decoration. This module is that harness,
shipped in the package so you run it yourself rather than trusting our CI.

Every named case does four things, in order:
  1. GREEN first: build a clean fixture in a temp dir and require the relevant
     verifier to pass on it. A harness that only ever sees red proves nothing.
  2. NO-OP GUARD: capture the fixture bytes, apply the mutation, and require
     the mutated bytes to DIFFER. A mutation that changes nothing must not
     count as caught — "mutation did not mutate" is itself a harness failure.
     (reticuli's mutation-guard guards itself the same way; so does this one,
     and the guard has its own case below proving it trips.)
  3. RED on the defect: run the verifier against the mutated fixture and
     require it to fail with the EXPECTED verdict / first_break — not just
     "some error somewhere," the named failure this check exists to produce.
  4. A verifier that stays green on its own defect fails the harness loudly,
     naming the case. That is the harness doing its job, not a bug in it.

Exit code 0 = every check was observed catching its own defect. Anything else =
at least one claimed check is decoration in this environment — do not trust it.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from . import Ledger, digest_json, bind_artefact, verify_artefact
from .witness import WitnessStore, publish_head, verify_against_witness

# Frozen json-c14n:v1 vector (same freeze as selftest.py, 0.3.0, 2026-08-13).
# Re-stated here independently so the drift case doesn't depend on selftest's
# internal layout.
_DRIFT_VALUE = {"claim": "X said Y", "unicode": "éü—🔒"}
_DRIFT_FROZEN = "sha256:json-c14n:v1:03b6bc1350e72d1da527a6c729dd8bb3be1b0f8dd3e82000da68d32e21cc2cf6"


class MutationFailure(AssertionError):
    """A named case did not behave: green fixture failed, mutation no-opped,
    or a verifier stayed green on its own defect."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise MutationFailure(msg)


def _noop_guard(case: str, before: bytes, after: bytes) -> None:
    """The guard on the guard: a mutation that changed nothing proves nothing."""
    if before == after:
        raise MutationFailure(f"mutation did not mutate ({case}): "
                              "fixture bytes identical before and after")


def _mint(path: Path, n: int = 6) -> Ledger:
    """A clean chained fixture: n rows, verified green by the caller."""
    led = Ledger(path)
    for i in range(n):
        led.append({"action": "tool_call", "n": i, "result_ok": True})
    return led


# --- chain verifier cases ----------------------------------------------------

def case_byte_edit_in_row() -> str:
    """Defect: one field edited in place mid-file, stale chain kept.
    Check that must catch it: verify() -> chain mismatch at the exact line."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "log.jsonl"
        led = _mint(p)
        _require(led.verify().ok, "clean fixture must verify GREEN before mutation")
        before = p.read_bytes()
        lines = before.decode("utf-8").splitlines()
        obj = json.loads(lines[2])
        obj["n"] = 999999  # the edit this check exists to catch
        lines[2] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _noop_guard("byte-edit-in-row", before, p.read_bytes())
        r = led.verify()
        _require(not r.ok, "verify() stayed GREEN on an in-place byte edit — decoration")
        _require(r.first_break == "line 3: chain mismatch",
                 f"wrong first_break: {r.first_break!r} (want 'line 3: chain mismatch')")
        return "RED first_break='line 3: chain mismatch'"


def case_row_reorder() -> str:
    """Defect: two rows swapped, every byte of every row preserved.
    Check that must catch it: verify() -> mismatch at the first displaced row."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "log.jsonl"
        led = _mint(p)
        _require(led.verify().ok, "clean fixture must verify GREEN before mutation")
        before = p.read_bytes()
        lines = before.decode("utf-8").splitlines()
        lines[1], lines[3] = lines[3], lines[1]  # swap rows 2 and 4
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _noop_guard("row-reorder", before, p.read_bytes())
        r = led.verify()
        _require(not r.ok, "verify() stayed GREEN on a row reorder — decoration")
        _require(r.first_break == "line 2: chain mismatch",
                 f"wrong first_break: {r.first_break!r} (want 'line 2: chain mismatch')")
        return "RED first_break='line 2: chain mismatch'"


def case_mid_row_delete() -> str:
    """Defect: one row deleted from the middle; neighbors untouched.
    Check that must catch it: verify() -> mismatch where the gap closes."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "log.jsonl"
        led = _mint(p)
        _require(led.verify().ok, "clean fixture must verify GREEN before mutation")
        before = p.read_bytes()
        lines = before.decode("utf-8").splitlines()
        del lines[2]  # row 3 vanishes
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _noop_guard("mid-row-delete", before, p.read_bytes())
        r = led.verify()
        _require(not r.ok, "verify() stayed GREEN on a mid-file deletion — decoration")
        _require(r.first_break == "line 3: chain mismatch",
                 f"wrong first_break: {r.first_break!r} (want 'line 3: chain mismatch')")
        return "RED first_break='line 3: chain mismatch'"


def case_unchained_row_after_chain_start() -> str:
    """Defect: a chainless row smuggled in AFTER the chain has begun (the
    'legacy row' excuse used where it can't apply).
    Check that must catch it: verify() -> 'unchained row after chain began'."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "log.jsonl"
        led = _mint(p)
        _require(led.verify().ok, "clean fixture must verify GREEN before mutation")
        before = p.read_bytes()
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"action": "smuggled", "note": "no chain field"}) + "\n")
        _noop_guard("unchained-row-after-chain-start", before, p.read_bytes())
        r = led.verify()
        _require(not r.ok, "verify() stayed GREEN on an unchained late row — decoration")
        _require(r.first_break == "line 7: unchained row after chain began",
                 f"wrong first_break: {r.first_break!r}")
        return "RED first_break='line 7: unchained row after chain began'"


# --- witness verifier cases --------------------------------------------------

def case_truncation_vs_witness() -> str:
    """Defect: tail rows chopped AFTER the head was witnessed. The chain alone
    is blind to this by design (the remainder self-verifies) — the witness is
    the check that exists to catch it, and IT must go red 'truncated'."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        p = td / "log.jsonl"
        led = _mint(p)
        store = WitnessStore(td / "witness.jsonl")
        publish_head(store, "mutation", led)
        _require(verify_against_witness(store, "mutation", led).verdict == "consistent",
                 "clean fixture must be witness-GREEN ('consistent') before mutation")
        before = p.read_bytes()
        lines = before.decode("utf-8").splitlines()
        p.write_text("\n".join(lines[:4]) + "\n", encoding="utf-8")
        _noop_guard("truncation-vs-witness", before, p.read_bytes())
        _require(led.verify().ok,
                 "truncated remainder should still self-verify (the documented "
                 "blindness this case exists to route around)")
        v = verify_against_witness(store, "mutation", led)
        _require(v.verdict == "truncated",
                 f"witness stayed non-red on truncation: {v.verdict!r} (want 'truncated')")
        return "chain-only stays green (documented); witness RED verdict='truncated'"


def case_remint_vs_witness() -> str:
    """Defect: the whole log re-minted from genesis with one payload edited —
    an internally perfect forgery. The chain MUST verify green (that is the
    forgery's whole point); the witness must go red 'rewritten'."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        p = td / "log.jsonl"
        led = _mint(p)
        store = WitnessStore(td / "witness.jsonl")
        publish_head(store, "mutation", led)
        _require(verify_against_witness(store, "mutation", led).verdict == "consistent",
                 "clean fixture must be witness-GREEN ('consistent') before mutation")
        before = p.read_bytes()
        rows = [json.loads(ln) for ln in before.decode("utf-8").splitlines()]
        remint_p = td / "reminted.jsonl"
        rl = Ledger(remint_p)
        for i, obj in enumerate(rows):
            obj.pop("chain", None)
            if i == 2:
                obj["result_ok"] = False  # the lie the remint launders
            rl.append(obj)
        _noop_guard("remint-vs-witness", before, remint_p.read_bytes())
        _require(rl.verify().ok,
                 "a remint must self-verify green — otherwise this case tests nothing")
        v = verify_against_witness(store, "mutation", rl)
        _require(v.verdict == "rewritten",
                 f"witness stayed non-red on a remint: {v.verdict!r} (want 'rewritten')")
        return "remint self-verifies green (the forgery works); witness RED verdict='rewritten'"


# --- artefact / digest cases -------------------------------------------------

def case_artefact_digest_mismatch() -> str:
    """Defect: subject.digest.sha256 edited so it disagrees with the
    self-describing digest string.
    Check that must catch it: verify_artefact() -> digest_ok=False, named note."""
    art = bind_artefact({"claim": "the agent read the pricing page", "price": 42})
    _require(verify_artefact(art)["digest_ok"] is True,
             "clean artefact must verify GREEN before mutation")
    before = json.dumps(art, sort_keys=True).encode("utf-8")
    art["subject"]["digest"]["sha256"] = "0" * 64  # the edit
    _noop_guard("artefact-digest-mismatch", before,
                json.dumps(art, sort_keys=True).encode("utf-8"))
    out = verify_artefact(art)
    _require(out["digest_ok"] is False,
             "verify_artefact stayed GREEN on a subject/digest disagreement — decoration")
    _require(out["reason"] == "subject_digest_mismatch",
             f"wrong typed reason: {out['reason']!r} (want 'subject_digest_mismatch')")
    _require(any("does not match" in n for n in out["notes"]),
             f"wrong failure note: {out['notes']!r}")
    return "RED digest_ok=False reason='subject_digest_mismatch'"


def case_canonicalization_recipe_drift() -> str:
    """Defect, two arms:
    (a) a DRIFTED canonicalizer (ascii-escaping, i.e. ensure_ascii=True) minting
        digests under the json-c14n:v1 label — the golden vector is the check
        that exists to catch this, and the drifted digest must NOT reproduce it;
    (b) a digest string claiming a recipe this library does not know — must
        fail verify_artefact's self-consistency check ('unknown recipe')."""
    # (a) drifted canonicalizer vs the frozen vector
    import hashlib
    true_canon = json.dumps(_DRIFT_VALUE, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False).encode("utf-8")
    drift_canon = json.dumps(_DRIFT_VALUE, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("utf-8")
    _noop_guard("canonicalization-recipe-drift (canonical bytes)", true_canon, drift_canon)
    drifted = f"sha256:json-c14n:v1:{hashlib.sha256(drift_canon).hexdigest()}"
    _require(digest_json(_DRIFT_VALUE) == _DRIFT_FROZEN,
             "clean digest must reproduce the frozen golden vector (GREEN) first")
    _require(drifted != _DRIFT_FROZEN,
             "drifted canonicalizer reproduced the golden vector — the vector "
             "does not discriminate and is decoration")
    # (b) unknown recipe label must fail verify_artefact
    art = bind_artefact(_DRIFT_VALUE)
    _require(verify_artefact(art)["digest_ok"] is True,
             "clean artefact must verify GREEN before mutation")
    before = json.dumps(art, sort_keys=True).encode("utf-8")
    art["digest"] = art["digest"].replace("json-c14n", "json-c14n-drift")
    art["recipe"] = art["recipe"].replace("json-c14n", "json-c14n-drift")
    _noop_guard("canonicalization-recipe-drift (recipe label)", before,
                json.dumps(art, sort_keys=True).encode("utf-8"))
    out = verify_artefact(art)
    _require(out["digest_ok"] is False,
             "verify_artefact stayed GREEN on an unknown recipe — decoration")
    _require(out["reason"] == "unknown_recipe",
             f"wrong typed reason: {out['reason']!r} (want 'unknown_recipe')")
    _require(any("unknown recipe" in n for n in out["notes"]),
             f"wrong failure note: {out['notes']!r}")
    return "RED both arms (golden vector rejects drifted bytes; unknown recipe -> reason='unknown_recipe')"


def case_unknown_recipe_version() -> str:
    """Defect: a digest claiming json-c14n:v9 — a version of a KNOWN recipe that
    this build has never shipped and cannot recompute.

    This case exists because the harness carried it as a standing NOTE through
    0.5.0/0.5.1: verify_artefact returned digest_ok=True with only a warning note,
    on the reasoning that old rows keep old versions. But a FUTURE version cannot be
    an old row, and the leniency was doing the one thing this library refuses —
    reporting an unchecked digest as verified. 0.5.2 makes it a typed failure, and
    the boundary that was named is now a case observed going red."""
    art = bind_artefact({"k": 1})
    _require(verify_artefact(art)["digest_ok"] is True,
             "clean artefact must verify GREEN before mutation")
    before = json.dumps(art, sort_keys=True).encode("utf-8")
    art["digest"] = art["digest"].replace(":v1:", ":v9:")
    art["recipe"] = art["recipe"].replace(":v1", ":v9")
    _noop_guard("unknown-recipe-version", before,
                json.dumps(art, sort_keys=True).encode("utf-8"))
    out = verify_artefact(art)
    _require(out["digest_ok"] is False,
             "verify_artefact stayed GREEN on a version it cannot reproduce — "
             "the 0.5.0 known-boundary NOTE, unclosed")
    _require(out["reason"] == "unknown_recipe_version",
             f"wrong typed reason: {out['reason']!r} (want 'unknown_recipe_version')")
    return "RED digest_ok=False reason='unknown_recipe_version' (0.5.0 NOTE closed)"


def case_unknown_algorithm() -> str:
    """Defect: the algorithm field swapped to one this build does not compute
    (sha256 -> md5) while the hex body is left alone.
    Check that must catch it: the 'sha256:' prefix is a CLAIM about what was
    computed, not decoration — an unsupported algo must be a typed failure, not a
    pass on the strength of a recipe name that happens to still be registered."""
    art = bind_artefact(b"the agent read this")
    _require(verify_artefact(art)["digest_ok"] is True,
             "clean artefact must verify GREEN before mutation")
    before = json.dumps(art, sort_keys=True).encode("utf-8")
    art["digest"] = art["digest"].replace("sha256:", "md5:", 1)
    art["recipe"] = art["recipe"].replace("sha256:", "md5:", 1)
    _noop_guard("unknown-algorithm", before,
                json.dumps(art, sort_keys=True).encode("utf-8"))
    out = verify_artefact(art)
    _require(out["digest_ok"] is False,
             "verify_artefact stayed GREEN on an algorithm it never ran — decoration")
    _require(out["reason"] == "unknown_algorithm",
             f"wrong typed reason: {out['reason']!r} (want 'unknown_algorithm')")
    return "RED digest_ok=False reason='unknown_algorithm'"


def case_nan_rejection() -> str:
    """Defect: NaN injected into a value bound for digesting. The check that
    exists to catch it: digest_json must REFUSE (ValueError), never silently
    canonicalize a value other environments cannot reproduce."""
    clean = {"metric": 1.0}
    digest_json(clean)  # GREEN: the clean value digests without complaint
    mutated = {"metric": float("nan")}
    _noop_guard("NaN-rejection", repr(clean).encode(), repr(mutated).encode())
    try:
        digest_json(mutated)
        survived = True
    except ValueError:
        survived = False
    _require(not survived,
             "digest_json silently canonicalized NaN — the rejection is decoration")
    return "RED ValueError (NaN refused, never silently canonicalized)"


# --- the guard on the guard --------------------------------------------------

def case_noop_guard_guards_itself() -> str:
    """reticuli's own requirement, applied to this harness: a mutation that
    changes nothing must NOT count as caught. Prove the guard trips."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "log.jsonl"
        _mint(p)
        before = p.read_bytes()
        p.write_bytes(before)  # the identity "mutation"
        try:
            _noop_guard("self-test", before, p.read_bytes())
        except MutationFailure:
            return "identity mutation correctly flagged 'mutation did not mutate'"
        raise MutationFailure("the no-op guard did NOT trip on an identity "
                              "mutation — the guard itself is decoration")


CASES = [
    ("byte-edit-in-row", case_byte_edit_in_row),
    ("row-reorder", case_row_reorder),
    ("mid-row-delete", case_mid_row_delete),
    ("unchained-row-after-chain-start", case_unchained_row_after_chain_start),
    ("truncation-vs-witness", case_truncation_vs_witness),
    ("remint-vs-witness", case_remint_vs_witness),
    ("artefact-digest-mismatch", case_artefact_digest_mismatch),
    ("canonicalization-recipe-drift", case_canonicalization_recipe_drift),
    ("unknown-recipe-version", case_unknown_recipe_version),
    ("unknown-algorithm", case_unknown_algorithm),
    ("NaN-rejection", case_nan_rejection),
    ("no-op-guard-self-test", case_noop_guard_guards_itself),
]


def _finding_subject_absent() -> str | None:
    """Non-fatal probe, reported honestly — the leniency that REPLACED the
    version-ahead one (that boundary is now case_unknown_recipe_version, red).

    An artefact carrying a well-formed, supported-recipe digest string but NO
    `subject` block passes with digest_ok=True: there is no second copy of the hex
    to cross-check it against, so the check has nothing to disagree with. That is
    honest — digest_ok means "this label is reproducible and the string is
    self-consistent," and a lone string is trivially self-consistent — but a caller
    treating digest_ok as "the artefact was checked against its source" is reading
    more than it says. Only refetch=True on a URL does that."""
    art = bind_artefact({"k": 1})
    art.pop("subject", None)
    out = verify_artefact(art)
    if out["digest_ok"]:
        return ("verify_artefact returns digest_ok=True for a digest string with no "
                "subject block — nothing to cross-check the hex against. digest_ok "
                "means 'reproducible label, self-consistent string', never 'the "
                "bytes were re-checked'; refetch=True is the only check that does that")
    return None


def run() -> int:
    failures = 0
    print("== mutation harness (every claimed check, observed failing) ==")
    for name, fn in CASES:
        try:
            detail = fn()
            print(f"  PASS  {name} -> {detail}")
        except MutationFailure as e:
            failures += 1
            print(f"  FAIL  {name}: {e}")
        except Exception as e:  # a case crashing is a failure, not a skip
            failures += 1
            print(f"  FAIL  {name}: harness error {type(e).__name__}: {e}")

    finding = _finding_subject_absent()
    if finding:
        print(f"  NOTE  known-boundary: {finding}")

    total = len(CASES)
    if failures == 0:
        print(f"\nALL {total} CASES BEHAVED — every check was observed catching "
              "its own defect (and green on clean fixtures first)")
    else:
        print(f"\n{failures}/{total} CASE(S) MISBEHAVED — a check that cannot be "
              "observed failing is decoration; do not trust it")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
