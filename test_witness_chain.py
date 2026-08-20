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
from arcaeon_ledger.witness import WitnessStore


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
