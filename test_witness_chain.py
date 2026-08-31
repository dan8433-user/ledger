# SPDX-License-Identifier: MIT
"""The pin file is chained. Prove an edited pin is detectable, and prove the boundary.

WHY THIS EXISTS. Through 0.5.8 `WitnessStore`'s docstring claimed its record was
"tamper-evident by inspection" because it is written append-only. Append-only describes
how the class WRITES; it was never a property of the file. `record()` wrote a plain JSON
line with no chain, no digest and no signature, and `latest()` took the last matching
line, so an edited pin was undetectable. An adversarial review demonstrated it: a
truncated log plus an edited pin returned `consistent` and truthy.

That was wrong in the direction this library exists to refuse — the witness is the whole
answer to the truncation gap, so a witness with no integrity of its own means the answer
rests on nothing checkable. The claim was retracted before the mechanism existed. This
file is the mechanism's demonstrated red.

Every test here asserts a tamper is CAUGHT with a specific line number, or asserts the
boundary that makes the feature tolerable. The three-valued verdict matters as much as
the detection: a legacy file with no chain must come back falsy-but-not-red, because a
witness that screams tamper at its own history turns every real pin into a false alarm.
"""
import json

from arcaeon_ledger import Ledger
from arcaeon_ledger.witness import (
    WitnessStore, publish_head, verify_against_witness,
)


def _pins(tmp_path, n=3, ns="ns"):
    """A store with n honest chained pins, and the ledger they were taken from."""
    log = tmp_path / "agent.jsonl"
    lg = Ledger(log)
    store = WitnessStore(tmp_path / "witness.jsonl")
    for i in range(n):
        lg.append({"tool": "search", "i": i})
        store.record(ns, lg.head())
    return store, lg


def _lines(store):
    return [l for l in store.path.read_text(encoding="utf-8").split("\n") if l.strip()]


def _write(store, lines):
    store.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# -- the green control, first, so a red-by-default verifier fails too ----------

def test_honest_pin_file_verifies_clean(tmp_path):
    store, _ = _pins(tmp_path, 4)
    v = store.verify()
    assert v["ok"] is True, v
    assert v["pins"] == 4 and v["chained"] == 4
    assert v["unchained"] == 0 and v["breaks"] == 0
    assert v["first_break"] is None


def test_every_pin_carries_a_link(tmp_path):
    store, _ = _pins(tmp_path, 3)
    recs = [json.loads(l) for l in _lines(store)]
    assert all("prev" in r for r in recs)
    assert recs[0]["prev"] == "witness-genesis", "first pin seeds from genesis"
    assert len({r["prev"] for r in recs}) == 3, "each link must differ"


# -- the tampers that used to be undetectable ---------------------------------

def test_editing_a_stored_pin_is_caught(tmp_path):
    """The exact attack the review demonstrated: change a pin's row count.

    This is the one that mattered. An attacker who can write to the witness file
    previously edited a pin to match a truncated log and the verdict came back
    `consistent` and truthy.
    """
    store, _ = _pins(tmp_path, 4)
    lines = _lines(store)
    rec = json.loads(lines[1])
    rec["rows"] = 1                      # make the pin agree with a truncated log
    lines[1] = json.dumps(rec)
    _write(store, lines)

    v = store.verify()
    assert v["ok"] is False, v
    # The self-digest trips on line 2, the line actually edited, BEFORE the back-link
    # trips on line 3. That ordering is better than the reverse: it names the tampered
    # record rather than its innocent successor. My first expectation here was the
    # line-3 chain mismatch, which was the pre-self-digest behaviour.
    assert v["first_break"] == "line 2: pin content does not match its own digest",         v["first_break"]


def test_editing_a_pins_chain_value_is_caught(tmp_path):
    store, _ = _pins(tmp_path, 3)
    lines = _lines(store)
    rec = json.loads(lines[0])
    rec["chain"] = "0" * 32
    lines[0] = json.dumps(rec)
    _write(store, lines)
    assert store.verify()["ok"] is False


def test_deleting_a_pin_from_the_middle_is_caught(tmp_path):
    store, _ = _pins(tmp_path, 4)
    lines = _lines(store)
    del lines[1]
    _write(store, lines)

    v = store.verify()
    assert v["ok"] is False
    assert "line 2" in v["first_break"], v["first_break"]


def test_reordering_pins_is_caught(tmp_path):
    store, _ = _pins(tmp_path, 4)
    lines = _lines(store)
    lines[1], lines[2] = lines[2], lines[1]
    _write(store, lines)
    assert store.verify()["ok"] is False


def test_appending_a_forged_pin_is_caught(tmp_path):
    """The forged pin from the review: hand-write a plausible record onto the end."""
    store, lg = _pins(tmp_path, 2)
    forged = {"namespace": "ns", "rows": 99, "chain": "f" * 32,
              "as_of": "2026-08-19T00:00:00Z", "received_at": None,
              "prev": "deadbeef" * 4}
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged) + "\n")

    v = store.verify()
    assert v["ok"] is False
    assert v["first_break"] == "line 3: pin chain mismatch"


def test_the_chain_spans_namespaces(tmp_path):
    """Deleting every pin for ONE namespace must not leave the rest verifying clean.

    Per-namespace chaining would allow exactly that, which is the detachment problem
    the ledger already guards against. The chain is over the whole file on purpose.
    """
    log = tmp_path / "a.jsonl"
    lg = Ledger(log)
    store = WitnessStore(tmp_path / "w.jsonl")
    for ns in ("alpha", "beta", "alpha", "beta"):
        lg.append({"ns": ns})
        store.record(ns, lg.head())
    assert store.verify()["ok"] is True

    lines = [l for l in _lines(store)
             if json.loads(l)["namespace"] != "alpha"]
    _write(store, lines)
    assert store.verify()["ok"] is False, "dropping one namespace must break the chain"


def test_editing_the_LAST_pin_is_caught(tmp_path):
    """The tail case, and the one the first draft of this feature MISSED.

    A back-chain links each record to the one before it, so it protects records
    1..N-1 and leaves the last one unguarded — nothing links forward from it. That
    matters more than it sounds, because the last pin is the one `latest()` returns
    and therefore the one a verifier actually reads.

    The reviewer's original attack was editing a single pin, and in a store with one
    pin that pin IS the tail. The first implementation reported ok=True over it. The
    `self` digest exists solely to close this.
    """
    store, lg = _pins(tmp_path, 3)
    lines = _lines(store)
    rec = json.loads(lines[-1])
    rec["rows"] = 1
    lines[-1] = json.dumps(rec)
    _write(store, lines)

    v = store.verify()
    assert v["ok"] is False, "editing the tail pin must be caught"
    assert "own digest" in v["first_break"], v["first_break"]


def test_editing_the_ONLY_pin_is_caught(tmp_path):
    """The narrowest version of the same hole: a store holding exactly one pin."""
    log = tmp_path / "a.jsonl"
    lg = Ledger(log)
    lg.append({"amount": 1000})
    store = WitnessStore(tmp_path / "w.jsonl")
    store.record("ns", lg.head())
    assert store.verify()["ok"] is True

    rec = json.loads(_lines(store)[0])
    rec["chain"] = "0" * 32
    _write(store, [json.dumps(rec)])
    assert store.verify()["ok"] is False


def test_the_verdict_is_falsy_unless_it_is_a_real_green(tmp_path):
    """`if store.verify():` must not pass over a broken chain.

    Writing this test is what exposed the defect: `verify()` returned a plain dict,
    and a non-empty dict is unconditionally truthy, so the container said yes while
    the verdict inside it said no. Same shape as a verifier reporting ok=True over an
    empty file.
    """
    store, _ = _pins(tmp_path, 3)
    assert bool(store.verify()) is True

    lines = _lines(store)
    rec = json.loads(lines[1]); rec["rows"] = 99
    lines[1] = json.dumps(rec)
    _write(store, lines)
    v = store.verify()
    assert v["ok"] is False
    assert bool(v) is False, "a broken chain must be falsy, not merely carry ok=False"


# -- the boundaries that make it tolerable ------------------------------------

def test_legacy_unchained_pins_are_bounded_not_broken(tmp_path):
    """A pre-0.5.9 file must not read as tampered. Falsy, but not red.

    This is the half that keeps the feature from being worse than nothing. A witness
    that rejects its own history the moment it upgrades converts every genuine pin
    into a false alarm, and an alarm that is always on is an alarm nobody reads.
    """
    store = WitnessStore(tmp_path / "legacy.jsonl")
    store.path.write_text(
        json.dumps({"namespace": "ns", "rows": 2, "chain": "a" * 32,
                    "as_of": "2026-01-01T00:00:00Z", "received_at": None}) + "\n"
        + json.dumps({"namespace": "ns", "rows": 5, "chain": "b" * 32,
                      "as_of": "2026-01-02T00:00:00Z", "received_at": None}) + "\n",
        encoding="utf-8")

    v = store.verify()
    assert v["ok"] is None, v
    assert not v, "ok=None must be falsy — it is not a green"
    assert v["unchained"] == 2 and v["breaks"] == 0
    assert v["first_break"] is None


def test_a_legacy_file_can_be_extended_and_the_new_pins_verify(tmp_path):
    """Upgrade path: old pins stay unchained, new ones chain from the last one."""
    store = WitnessStore(tmp_path / "mixed.jsonl")
    store.path.write_text(
        json.dumps({"namespace": "ns", "rows": 1, "chain": "a" * 32,
                    "as_of": "2026-01-01T00:00:00Z", "received_at": None}) + "\n",
        encoding="utf-8")
    lg = Ledger(tmp_path / "l.jsonl")
    lg.append({"x": 1})
    store.record("ns", lg.head())

    v = store.verify()
    assert v["unchained"] == 1 and v["chained"] == 1
    assert v["breaks"] == 0
    assert v["ok"] is None, "any unchained region bounds the verdict"


def test_an_unchained_pin_AFTER_the_chain_began_is_a_break(tmp_path):
    """Legacy rows can only precede chained ones. Otherwise it is a fabricated prepend."""
    store, _ = _pins(tmp_path, 2)
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"namespace": "ns", "rows": 9,
                             "chain": "c" * 32, "as_of": "x"}) + "\n")
    v = store.verify()
    assert v["ok"] is False
    assert "unchained pin after the chain began" in v["first_break"], v["first_break"]


def test_an_empty_store_is_not_a_green(tmp_path):
    """Same rule the ledger learned today: nothing verified is not everything verified."""
    store = WitnessStore(tmp_path / "empty.jsonl")
    store.path.write_text("", encoding="utf-8")
    v = store.verify()
    assert v["ok"] is None and not v
    assert v["pins"] == 0


def test_an_unparseable_line_is_a_named_break_not_a_crash(tmp_path):
    store, _ = _pins(tmp_path, 2)
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    v = store.verify()
    assert v["ok"] is False
    assert v["first_break"] == "line 3: unparseable"


def test_latest_and_history_still_work_with_the_chain(tmp_path):
    """The chain must not change what the store is FOR."""
    store, _ = _pins(tmp_path, 3)
    assert store.latest("ns")["rows"] == 3
    assert [h["rows"] for h in store.history("ns")] == [1, 2, 3]
    assert store.latest("absent") is None


# -- verify_against_witness now refuses to bless broken records ----------------

def test_a_forged_pin_file_blocks_consistent(tmp_path):
    """A witness whose own chain is broken cannot bless a log.

    Before 0.5.9 verify_against_witness never checked the pin file's integrity, so an
    attacker who could write to the witness edited a pin to match a truncated log and
    the verdict came back 'consistent'. Now the pin file's own chain is checked first.
    """
    from arcaeon_ledger.witness import verify_against_witness
    store, lg = _pins(tmp_path, 4)
    # truncate the log to 4 -> still fine; now forge the pin to agree, breaking its chain
    lines = _lines(store)
    rec = json.loads(lines[1]); rec["rows"] = 1
    lines[1] = json.dumps(rec)
    _write(store, lines)

    v = verify_against_witness(store, "ns", lg)
    assert v.verdict == "witness_broken", v
    assert not v, "a broken witness must be falsy, never consistent"


def test_a_locally_broken_log_blocks_consistent(tmp_path):
    """A log whose own chain is broken is not made consistent by agreeing at one row."""
    from arcaeon_ledger.witness import verify_against_witness
    store, lg = _pins(tmp_path, 4)
    # tamper the LOG in place, leaving the witness file honest
    llines = [l for l in lg.path.read_text(encoding="utf-8").split("\n") if l.strip()]
    obj = json.loads(llines[2]); obj["i"] = 999
    llines[2] = json.dumps(obj, ensure_ascii=False)
    lg.path.write_text("\n".join(llines) + "\n", encoding="utf-8")

    v = verify_against_witness(store, "ns", lg)
    assert v.verdict == "local_broken", v
    assert not v


def test_honest_log_and_witness_still_read_consistent(tmp_path):
    """The guards must not false-alarm on the ordinary case."""
    from arcaeon_ledger.witness import verify_against_witness
    store, lg = _pins(tmp_path, 4)
    v = verify_against_witness(store, "ns", lg)
    assert v.verdict == "consistent", v
    assert bool(v) is True


def test_deleting_the_self_digest_from_the_tail_pin_is_caught(tmp_path):
    """The bypass an auditor found: edit the tail pin AND delete its `self` field.

    The first version of the self-digest guard only checked `self` when it was
    PRESENT. So the truncation-laundering attack the whole feature exists to stop
    reopened: edit the last pin to agree with a truncated log, drop its `self`, and
    neither the back-link (no successor) nor the self-check (skipped) fires. The tests
    missed it because every one of them edited `rows` while KEEPING `self`. A chained
    pin missing its self-digest is now a break.
    """
    store, _ = _pins(tmp_path, 4)
    lines = _lines(store)
    tail = json.loads(lines[-1]); tail["rows"] = 1; tail.pop("self", None)
    lines[-1] = json.dumps(tail)
    _write(store, lines)

    v = store.verify()
    assert v["ok"] is False, "a chained pin with no self-digest must be a break"
    assert "missing its self-digest" in v["first_break"], v["first_break"]


def test_deleting_self_from_a_middle_pin_is_also_caught(tmp_path):
    """Not just the tail — any chained pin stripped of its self-digest is a break."""
    store, _ = _pins(tmp_path, 4)
    lines = _lines(store)
    rec = json.loads(lines[1]); rec.pop("self", None)
    lines[1] = json.dumps(rec)
    _write(store, lines)
    assert store.verify()["ok"] is False


# ---------------------------------------------------------------------------
# C14 (pre-invite adversarial audit, 2026-08-23): a REMOTE witness client
# bypasses the witness-integrity guard entirely.
#
# `verify_against_witness` calls `getattr(store, "verify", None)` and, when the
# store exposes no verify(), proceeds with {"ok": None}. That contract
# compatibility is DELIBERATE and correct — requiring verify() unconditionally
# broke every hosted client the moment the method appeared. The defect is that
# the resulting verdict looked identical to one backed by a fully self-verified
# witness, so a forged pin delivered through a `.latest()`-only client could
# mint a clean "consistent" with nothing in the verdict saying the witness's own
# integrity was never established. The hosted witness IS that shape: it is the
# deployment, so the defence was bypassed exactly where it is most needed.
#
# The fix is NOT to hard-fail (that reintroduces the original bug). It is to
# make the unestablished state visible on the verdict, so a consumer cannot
# mistake "not checked" for "checked and fine".
# ---------------------------------------------------------------------------

class _LatestOnlyClient:
    """A hosted-witness client, exactly as the documented contract allows:
    it exposes .latest(namespace) and nothing else."""

    def __init__(self, pin):
        self._pin = pin

    def latest(self, namespace):
        return dict(self._pin)


def test_latest_only_client_marks_witness_self_integrity_unestablished(tmp_path):
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(5):
        led.append({"e": i})
    head = led.head()

    # An honest pin, delivered by a client that cannot self-verify.
    client = _LatestOnlyClient({"namespace": "ns", "rows": head.rows,
                                "chain": head.chain})
    v = verify_against_witness(client, "ns", Ledger(log))

    assert v.verdict == "consistent"
    assert v.witness_self_integrity == "unestablished", (
        "a witness that cannot self-verify must say so on the verdict; "
        "otherwise a PASS silently rests on an unverified witness"
    )


def test_forged_pin_through_latest_only_client_is_not_silently_clean(tmp_path):
    """The attack: delete records, forge the pin to match. The comparison
    agrees — that is the point of forging it — so the ONLY thing standing
    between this and a clean PASS is the caller being told the witness was
    never verified."""
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(5):
        led.append({"e": i})

    rows = log.read_text(encoding="utf-8").strip().split("\n")
    log.write_text("\n".join(rows[:3]) + "\n", encoding="utf-8")  # 2 deleted
    forged = Ledger(log).head()                                   # re-pin to match

    client = _LatestOnlyClient({"namespace": "ns", "rows": forged.rows,
                                "chain": forged.chain})
    v = verify_against_witness(client, "ns", Ledger(log))

    assert v.witness_self_integrity == "unestablished", (
        "forged pin through a hosted-shaped client reported "
        f"witness_self_integrity={v.witness_self_integrity!r}"
    )


def test_real_store_reports_witness_self_integrity_verified(tmp_path):
    """The green control: a real WitnessStore CAN self-verify, so the same
    field must positively read 'verified' — otherwise the flag is useless."""
    log = tmp_path / "audit.jsonl"
    led = Ledger(log)
    for i in range(4):
        led.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", Ledger(log))

    v = verify_against_witness(store, "ns", Ledger(log))
    assert v.verdict == "consistent"
    assert v.witness_self_integrity == "verified"


# ---------------------------------------------------------------------------
# C2 (pre-invite adversarial audit, 2026-08-23): a pin taken over an EMPTY log
# returns the library's one truthy verdict against ANY log, including a 96%
# truncation.
#
# chain_at(path, 0) returns _GENESIS WITHOUT OPENING THE FILE, so the
# comparison "genesis != genesis" is False and it falls through to "consistent".
# witness.py already says in prose that "a pin recorded over an empty log
# constrains nothing at all" -- and then the code blessed it. The
# anti-truncation mechanism blessing a truncation.
# ---------------------------------------------------------------------------

def test_zero_row_pin_does_not_bless_an_unrelated_log(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")

    store = WitnessStore(tmp_path / "w.jsonl")
    try:
        publish_head(store, "ns", Ledger(empty))
    except ValueError:
        return  # refusing to mint the useless pin is the preferred fix

    # If minting is allowed, the pin must still constrain nothing -- it must
    # never read as a positive confirmation.
    real = tmp_path / "real.jsonl"
    led = Ledger(real)
    for i in range(50):
        led.append({"e": i})

    v = verify_against_witness(store, "ns", Ledger(real))
    assert v.verdict != "consistent", (
        "a pin over an empty log positively confirmed an unrelated 50-row log"
    )
    assert not bool(v)


def test_zero_row_pin_does_not_bless_a_truncated_log(tmp_path):
    """The attack in its sharpest form: pin while empty, fill, truncate 50->2,
    and the witness still says everything is fine."""
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")

    store = WitnessStore(tmp_path / "w.jsonl")
    try:
        publish_head(store, "ns", Ledger(log))
    except ValueError:
        return

    led = Ledger(log)
    for i in range(50):
        led.append({"e": i})
    rows = log.read_text(encoding="utf-8").strip().split("\n")
    log.write_text("\n".join(rows[:2]) + "\n", encoding="utf-8")  # 48 deleted

    v = verify_against_witness(store, "ns", Ledger(log))
    assert v.verdict != "consistent", (
        "a zero-row pin blessed a log truncated from 50 rows to 2"
    )


# ---------------------------------------------------------------------------
# C11 (pre-invite adversarial audit, 2026-08-23): latest()/history() crash on a
# non-UTF8 byte in the pin file instead of producing a verdict. verify() (this
# same file) already tolerates it with errors="replace"; these two never
# inherited the fix. This contradicts the module's own stated principle that a
# damaged log is the one you most need to export -- it hardened the log path
# and left the witness path fatal.
# ---------------------------------------------------------------------------

def test_latest_tolerates_a_non_utf8_byte_in_the_pin_file(tmp_path):
    log = tmp_path / "a.jsonl"
    lg = Ledger(log)
    for i in range(3):
        lg.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", Ledger(log))

    # append one non-UTF8 byte to the pin file, the way a truncated write or a
    # corrupted disk sector would
    with open(store.path, "ab") as fh:
        fh.write(b"\xff\xfe")

    # must not raise
    result = store.latest("ns")
    assert result is not None, "a trailing garbage byte lost a recoverable pin"


def test_history_tolerates_a_non_utf8_byte_in_the_pin_file(tmp_path):
    log = tmp_path / "a.jsonl"
    lg = Ledger(log)
    for i in range(2):
        lg.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", Ledger(log))

    with open(store.path, "ab") as fh:
        fh.write(b"\xff\xfe")

    result = store.history("ns")
    assert len(result) == 1, "a trailing garbage byte lost recoverable history"


def test_export_bundle_does_not_crash_on_a_corrupted_witness_file(tmp_path):
    """The end-to-end case: export must produce a verdict, not a traceback, over
    a damaged witness -- exactly the principle this fix restores."""
    # Cross-package guard test. arcaeon-audit DEPENDS ON arcaeon-ledger, so audit
    # can never be declared as a dependency here (circular); on the single-package
    # CI env it is absent. Skip LOUDLY rather than fail collection -- the test still
    # runs everywhere the full line is installed (dev machines, smoke_from_dist),
    # and the skip reason is visible in the pytest summary, not silent.
    import pytest
    export_bundle = pytest.importorskip(
        "arcaeon_audit",
        reason="cross-package test: arcaeon-audit not installed (circular dep, "
               "cannot be declared); runs wherever the full arcaeon line is present",
    ).export_bundle
    import json as _json

    log = tmp_path / "a.jsonl"
    lg = Ledger(log)
    for i in range(3):
        lg.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", Ledger(log))
    with open(store.path, "ab") as fh:
        fh.write(b"\xff\xfe")

    out = tmp_path / "bundle"
    export_bundle(str(log), str(out), witness=str(store.path), witness_namespace="ns")
    integ = _json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert "verdict" in integ  # produced SOMETHING, did not crash


def test_verify_against_witness_does_not_crash_on_pins_none(tmp_path):
    """A remote client returning {"ok": False, "pins": None} (key present,
    value None, not absent) must not raise -- wv.get("pins", 0) only
    substitutes for a MISSING key."""
    log = tmp_path / "a.jsonl"
    lg = Ledger(log)
    lg.append({"e": 0})

    class _BrokenClient:
        def verify(self):
            return {"ok": False, "pins": None}
        def latest(self, ns):
            return None

    result = verify_against_witness(_BrokenClient(), "ns", Ledger(log))
    assert result.verdict in ("witness_broken", "no_record")


def test_monotonic_guard_refuses_backward_pin(tmp_path):
    """C3 (pre-invite audit 2026-08-23; re-demonstrated by independent review
    2026-08-24): truncate the log, re-pin the smaller head, and the new pin
    became latest() while the larger disproof sat unread in history() --
    verify_against_witness then reported consistent over a truncation. The
    hosted JS service has refused this since 8/14; the Python reference now
    matches: record() compares against the namespace's HISTORY high-water
    mark and raises on a backward head."""
    import pytest
    log = tmp_path / "log.jsonl"
    lg = Ledger(log)
    for i in range(5):
        lg.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", lg)  # pins 5 rows

    # The attack: rebuild a valid 3-row log, try to pin the smaller head.
    log2 = tmp_path / "log2.jsonl"
    lg2 = Ledger(log2)
    for i in range(3):
        lg2.append({"e": i})
    with pytest.raises(ValueError, match="monotonic violation"):
        publish_head(store, "ns", lg2)

    # The disproof pin is still the latest -- the attack left no trace as
    # accepted state, and verification against the REAL log still passes.
    assert store.latest("ns")["rows"] == 5
    v = verify_against_witness(store, "ns", lg)
    assert v.verdict == "consistent"


def test_monotonic_guard_allows_equal_and_advancing_pins(tmp_path):
    """Green control for C3: the guard must not break the two legitimate
    shapes -- an idempotent equal-rows re-pin (the heartbeat case, same as
    the JS service) and a normal advancing pin."""
    log = tmp_path / "log.jsonl"
    lg = Ledger(log)
    for i in range(3):
        lg.append({"e": i})
    store = WitnessStore(tmp_path / "w.jsonl")
    publish_head(store, "ns", lg)
    publish_head(store, "ns", lg)          # equal re-pin: allowed
    lg.append({"e": 3})
    publish_head(store, "ns", lg)          # advancing pin: allowed
    assert store.latest("ns")["rows"] == 4
    assert len(store.history("ns")) == 3


def test_monotonic_guard_uses_high_water_not_latest(tmp_path):
    """The guard anchors to the history HIGH-WATER mark, not latest(): a
    store file that already contains a backward pin (written before this
    guard existed) must not let the low mark become the new bar."""
    import pytest
    store = WitnessStore(tmp_path / "w.jsonl")
    log5 = tmp_path / "log5.jsonl"
    lg5 = Ledger(log5)
    for i in range(5):
        lg5.append({"e": i})
    publish_head(store, "legacy", lg5)     # high-water: 5

    # Simulate a pre-guard backward pin already in the file: append a 2-row
    # pin by writing through record() is now impossible, so plant it raw --
    # exactly what a legacy file would contain.
    import json as _json
    raw = _json.loads(store.path.read_text(encoding="utf-8").strip().split("\n")[-1])
    legacy = dict(raw)
    legacy["rows"] = 2
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write(_json.dumps(legacy) + "\n")
    assert store.latest("legacy")["rows"] == 2  # latest is the LOW pin

    # A 3-row pin clears latest() but NOT the high-water of 5: must refuse.
    log3 = tmp_path / "log3.jsonl"
    lg3 = Ledger(log3)
    for i in range(3):
        lg3.append({"e": i})
    with pytest.raises(ValueError, match="high-water is 5"):
        publish_head(store, "legacy", lg3)
