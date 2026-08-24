# SPDX-License-Identifier: MIT
"""arcaeon_ledger.witness — the outside check that closes the truncation gap.

An append-only hash chain cannot, by itself, catch TRUNCATION: lop off the most
recent rows and the remainder still verifies clean (see the README). The fix is an
EXTERNAL WITNESS — a party outside your own control that records your log's head
(chain + row count) on a cadence. Once someone else holds `(rows, chain)` at time
T, no later rewrite can produce a log that both differs from that pin and still
verifies: a truncated log has FEWER rows than the witness saw, and a rewritten one
has a DIFFERENT chain at the witnessed row.

This module ships two halves:

  * `WitnessStore` — the reference witness core: a file-backed, append-only store
    of pins keyed by namespace. It holds ONLY fingerprints (chain + row count +
    time), never your log content — a "password nowhere" design: if the store is
    breached there is nothing sensitive to steal, only hashes useless without the
    original log. A serverless HTTP endpoint (Stage 0 of the hosted service) is a
    thin wrapper over exactly this object; running it locally is a complete,
    offline, zero-cost witness you fully control.

  * the client half — `publish_head` (send your current head to a witness) and
    `verify_against_witness` (fetch the last pin and check your log against it,
    HONESTLY: consistent / truncated / rewritten / no-record).

The honest boundary: a witness proves your log was not truncated or rewritten
*relative to what the witness saw, and only as recently as the last pin*. The MAX
gap between pins is your real security parameter, not the average — an attacker
picks the gap. It says nothing about whether the logged content was TRUE; that's
what `bind_artefact` is for. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from arcaeon_ledger import Head, Ledger, chain_at

__all__ = ["WitnessStore", "publish_head", "verify_against_witness", "WitnessVerdict"]


@dataclass
class WitnessVerdict:
    """The result of checking a log against an external witness pin.

    verdict:
      "consistent"  — the log still matches what the witness saw at the witnessed
                       row (and may have grown since — that's fine and expected).
      "truncated"   — the log now has FEWER rows than the witness recorded, or the
                       witnessed row is unreachable: witnessed history is missing.
      "rewritten"   — the log has enough rows but its chain at the witnessed row
                       DIFFERS from the pin: history was rewritten from some point.
      "no_record"   — the witness holds no pin for this namespace to check against.
      "witness_broken" — the witness pin file fails its OWN chain: a pin from a
                       tampered witness cannot be trusted, so no comparison is run.
      "local_broken"   — the log fails its own chain; agreement at the pinned row
                       does not make a locally tampered log consistent.
    (The docstring listed only the first four while the code returned six —
    a consumer switching on the documented set silently mishandled a tampered
    witness. Pre-invite audit, 2026-08-23.)

    witness_self_integrity: whether the WITNESS could vouch for itself.
      "verified"      — the store self-verified its own pin chain.
      "unestablished" — the store exposes no verify() (every hosted/remote
                       client is this shape), so its self-integrity was never
                       checked. The comparison still runs, but a caller must not
                       read the result as a witness-backed guarantee.
      "broken"        — the store self-verified and FAILED.
    """
    verdict: str
    detail: str
    witness_rows: int | None = None
    witness_chain: str | None = None
    local_rows: int | None = None
    witness_self_integrity: str = "unknown"

    def __bool__(self) -> bool:
        # truthy only when the outside check positively confirms consistency
        return self.verdict == "consistent"


#: Chain seed for the pin file. Distinct from the ledger's so a pin digest can
#: never be confused with a log row digest.
_WITNESS_GENESIS = "witness-genesis"


class WitnessVerify(dict):
    """The pin-chain verdict. A dict, so `v["ok"]` reads naturally, but with truthiness
    bound to the verdict rather than to whether the dict has contents.

    Why this is not a plain dict: a non-empty dict is unconditionally truthy, so
    `if store.verify(): trust_the_pins()` returned True over a BROKEN chain. That is the
    same shape as a verifier reporting ok=True over an empty file — the container said
    yes while the verdict inside it said no. Caught by writing the test that asserts
    ok=None is falsy, which a bare dict could never satisfy.

    Truthy ONLY when ok is exactly True. ok=None (legacy pins skipped, or an empty
    store) is falsy on purpose: it is a bounded answer, not a green.
    """

    def __bool__(self) -> bool:
        return self.get("ok") is True


class WitnessStore:
    """Reference witness: an append-only, file-backed store of head pins.

    Holds only fingerprints, never log content. One JSONL file; each line is a
    recorded pin `{namespace, rows, chain, as_of, received_at}`.

    THE PIN FILE IS ITSELF CHAINED (0.5.9). Each record carries `prev`, the digest of
    the record before it, AND `self`, the digest of its own content. Both are needed:
    `prev` catches deletion and reordering, and `self` catches an edit to the LAST pin,
    which a back-link structurally cannot see because nothing links forward from it. The
    first draft of this feature had only `prev`, and a demonstrated-red run showed it
    missing the reviewer's actual attack — editing the only pin in the file. `verify()`
    names the offending line. This closes a gap that was real and was documented
    wrongly: through 0.5.8 the docstring claimed the record was "tamper-evident by
    inspection" because it is written append-only. Append-only describes how this class
    WRITES. It was never a property of the file, and nothing here detected a pin edited
    afterwards. That claim was retracted before the mechanism existed; the mechanism now
    exists.

    LEGACY FILES KEEP WORKING, deliberately. Pins written before 0.5.9 have no `prev`.
    `verify()` reports those as `unchained` and does NOT call them broken, because a
    witness that rejects its own history the moment it upgrades turns every real pin
    into a false alarm, which is worse than having no chain at all. A file with
    unchained rows and no breaks returns `ok=None`, not `ok=True` — falsy, scoped, and
    honest about what was actually checked.

    WHAT THE CHAIN STILL DOES NOT DO, because this is the part that gets overclaimed.
    It makes an edit to a stored pin DETECTABLE. It does not stop anyone with write
    access from discarding the file and minting a fresh consistent one, exactly as the
    ledger's own chain cannot stop a consistent full rewrite. So the protection is
    still substantially the independence of the host: a pin is worth the separation
    between whoever holds it and whoever wrote the log. Put the store somewhere the
    logging party cannot reach. Two further limits worth knowing: a pin constrains
    nothing about rows appended after it was taken, and a pin recorded over an empty
    log constrains nothing at all.

    A hosted witness (Stage 0) is an HTTP endpoint wrapping this: POST a pin ->
    `record`, GET the latest -> `latest`. Running it in-process, as the tests and
    `verify_against_witness` do, is a complete local witness.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def record(self, namespace: str, head: Head, *, received_at: str | None = None) -> dict:
        """Append a pin for `namespace`, chained to the pin before it. Returns the record.

        The chain spans the WHOLE FILE, not one namespace. Per-namespace chaining would
        let an attacker delete every pin for one namespace and leave the rest verifying
        clean, which is the same detachment problem the ledger guards against.
        """
        rec = {
            "namespace": namespace,
            "rows": head.rows,
            "chain": head.chain,
            "as_of": head.as_of,
            # received_at is the witness's OWN clock — the trust surface is that
            # this timestamp is the witness's, not the publisher's. Left to the
            # caller/server to stamp; None if the store isn't clock-authoritative.
            "received_at": received_at,
            "prev": self._tail_digest(),
        }
        # `self` commits the record to its OWN content, which is what protects the TAIL.
        # `prev` links backwards, so a pure back-chain guards records 1..N-1 and leaves
        # the last one open — and the last one is the pin a verifier actually reads.
        rec["self"] = self._digest_record(rec)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as fh:
            payload = (json.dumps(rec) + "\n").encode("utf-8")
            fh.write(payload)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass          # network mounts may not support fsync; flush is the floor
            # Confirm the pin landed. Same reason as the ledger's append: a path that
            # accepts writes and stores nothing (a Windows reserved device name) would
            # otherwise return a plausible record for a pin that does not exist.
            try:
                landed = fh.tell()
            except OSError as e:
                raise OSError("cannot confirm the pin landed in %s: %s" % (self.path, e))
        if landed < len(payload):
            raise OSError(
                "wrote %d bytes to %s but the file holds %d — the pin was discarded, "
                "nothing was recorded" % (len(payload), self.path, landed))
        return rec

    @staticmethod
    def _digest_record(rec: dict) -> str:
        """Digest one pin's CONTENT. Excludes the two derived fields, `prev` and
        `self`, so the value is reproducible by anyone holding the record."""
        body = {k: v for k, v in rec.items() if k not in ("prev", "self")}
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:32]

    def _tail_digest(self) -> str:
        """Digest of the last pin in the file, or GENESIS when the file is empty."""
        last = None
        try:
            for raw in self.path.read_text(encoding="utf-8", errors="replace").split("\n"):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    last = json.loads(raw)
                except ValueError:
                    continue          # unparseable line: verify() names it, record() steps past
        except OSError:
            return _WITNESS_GENESIS
        if not isinstance(last, dict):
            return _WITNESS_GENESIS
        return self._digest_record(last)

    def verify(self) -> dict:
        """Recompute the pin chain. Returns a verdict naming the first break by line.

        Three-valued, matching the ledger's own shape:
          ok=True   — every pin chained and every link recomputed.
          ok=None   — no break found, but `unchained` legacy pins were skipped. FALSY.
                      Not a green: a pre-0.9 file cannot be distinguished from a
                      fabricated prepend, so it does not claim to be.
          ok=False  — a break was found.
        """
        out = WitnessVerify(ok=True, pins=0, chained=0, unchained=0,
                            breaks=0, first_break=None)
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError as e:
            return WitnessVerify({**out, "ok": False, "breaks": 1,
                                  "first_break": "unreadable: %s" % e})
        prev_digest = _WITNESS_GENESIS
        for i, raw in enumerate(lines, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or "line %d: unparseable" % i
                continue
            if not isinstance(rec, dict):
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or "line %d: not a JSON object" % i
                continue
            out["pins"] += 1
            claimed = rec.get("prev")
            if claimed is None:
                if out["chained"]:
                    # An unchained pin AFTER the chain began is a tamper signal, not
                    # legacy history. Legacy rows can only precede chained ones.
                    out.update(ok=False, breaks=out["breaks"] + 1)
                    out["first_break"] = out["first_break"] or (
                        "line %d: unchained pin after the chain began" % i)
                else:
                    out["unchained"] += 1
                prev_digest = self._digest_record(rec)
                continue
            if claimed != prev_digest:
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or "line %d: pin chain mismatch" % i
            content = self._digest_record(rec)
            own = rec.get("self")
            if own is None:
                # A CHAINED pin (it has `prev`, so we reached here) MUST carry `self`.
                # The first version of this guard only checked `self` when present, and
                # an attacker closed the tail-edit hole by editing the last pin AND
                # DELETING its `self` field: no successor to catch it via `prev`, no
                # `self` to catch it directly. That reopened the exact truncation
                # laundering this whole feature exists to stop. A chained pin missing
                # its self-digest is now a break, not a skipped check. (Legacy pins are
                # unchained, handled above at `claimed is None`, and never reach here.)
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or (
                    "line %d: chained pin missing its self-digest" % i)
            elif own != content:
                # Catches an edit to the LAST pin, which the back-link cannot see.
                out.update(ok=False, breaks=out["breaks"] + 1)
                out["first_break"] = out["first_break"] or (
                    "line %d: pin content does not match its own digest" % i)
            prev_digest = content
            out["chained"] += 1
        if out["ok"] and out["unchained"]:
            out["ok"] = None          # bounded: legacy pins were not verifiable
        if out["ok"] and out["pins"] == 0:
            out["ok"] = None          # an empty store verifies nothing
        return out

    def latest(self, namespace: str) -> dict | None:
        """The most recently recorded pin for `namespace`, or None."""
        found = None
        try:
            for raw in self.path.read_text(encoding="utf-8").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("namespace") == namespace:
                    found = rec  # last one wins (append-only, chronological)
        except OSError:
            return None
        return found

    def history(self, namespace: str) -> list[dict]:
        """All pins recorded for `namespace`, in order."""
        out: list[dict] = []
        try:
            for raw in self.path.read_text(encoding="utf-8").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("namespace") == namespace:
                    out.append(rec)
        except OSError:
            pass
        return out


def publish_head(store: WitnessStore, namespace: str, ledger: Ledger,
                 *, received_at: str | None = None) -> dict:
    """Record the ledger's CURRENT head with the witness under `namespace`.

    Call this on a cadence (the max gap between calls is your security parameter).
    `store` is any object with a `record(namespace, head, received_at=)` method —
    the reference `WitnessStore`, or a client wrapper that POSTs to a hosted one.

    REFUSES A ZERO-ROW PIN (pre-invite audit 2026-08-23, C2). `chain_at(path, 0)`
    returns the genesis constant WITHOUT OPENING THE FILE, so a pin taken over an
    empty log compared "genesis" against "genesis", matched, and fell through to
    the library's one truthy verdict — against ANY log, including one truncated
    from 50 rows to 2. This module's own prose already said "a pin recorded over
    an empty log constrains nothing at all"; the code then blessed it, which is
    the anti-truncation mechanism certifying a truncation. A pin that constrains
    nothing is not a weak pin, it is a misleading one, so it is not minted.
    """
    head = ledger.head()
    if not head.rows:
        raise ValueError(
            "refusing to pin an empty log: a zero-row pin constrains nothing and "
            "would read as a positive confirmation against any log. Append at "
            "least one record before publishing a head.")
    return store.record(namespace, head, received_at=received_at)


def verify_against_witness(store: WitnessStore, namespace: str,
                           ledger: Ledger) -> WitnessVerdict:
    """Check the ledger against the witness's most recent pin for `namespace`.

    This is the outside check the chain alone cannot do. Returns a WitnessVerdict;
    it is truthy only on "consistent". Honest by construction: "truncated" and
    "rewritten" are positive detections, and a re-fetch that can't reach the witness
    is "no_record", never a false ok.

    Two integrity guards run BEFORE the comparison, added in 0.5.9 once both records
    gained a chain of their own: if the witness pin file fails its own chain the
    verdict is "witness_broken", and if the log fails its own chain it is
    "local_broken". Both are falsy. Without these, a forged pin or a locally tampered
    log could still be compared and reported "consistent" — the comparison would
    agree over data that was already broken.
    """
    # BEFORE any comparison, establish that both records can be trusted at all. A
    # "consistent" verdict is the truthy state, and returning truthy while either the
    # witness file or the log is internally broken is the exact container-says-yes
    # defect this library keeps finding: the comparison would agree, over forged data.
    #
    # Witness first. If the pin file fails its own chain, `latest()` may return an
    # edited pin, so agreeing with it proves nothing. ok is False is a real break;
    # ok=None (legacy unchained pins) is bounded, not tampered, and does NOT block.
    #
    # CONTRACT COMPATIBILITY (2026-08-23, caught by arcaeon-audit's suite): the
    # documented witness contract downstream — arcaeon-audit's docstring and
    # CHANGELOG — is "any object exposing .latest(namespace)". Requiring .verify()
    # unconditionally broke every hosted/remote witness client the moment this
    # method appeared. A store that cannot self-verify is not thereby BROKEN; its
    # self-integrity is simply UNESTABLISHED — three-valued, like everything else
    # here. The comparison proceeds and the caller's witness block still records
    # the store's nature (self-declared vs undeclared) for the reader to weigh.
    _verify = getattr(store, "verify", None)
    wv = _verify() if callable(_verify) else {"ok": None, "pins": None,
                                              "note": "store exposes no verify(); "
                                                      "self-integrity unestablished"}
    # Self-integrity of the WITNESS ITSELF, carried on every verdict below so a
    # caller can never mistake "not checked" for "checked and fine". A hosted
    # client exposing only .latest() is the deployment shape, and before this it
    # produced a verdict indistinguishable from one backed by a self-verified
    # witness (pre-invite audit 2026-08-23, C14).
    if not callable(_verify):
        _si = "unestablished"
    elif wv.get("ok") is True:
        _si = "verified"
    elif wv.get("ok") is False:
        _si = "broken"
    else:
        _si = "unestablished"

    def _V(*a, **kw):
        kw.setdefault("witness_self_integrity", _si)
        return WitnessVerdict(*a, **kw)

    if wv.get("ok") is False and wv.get("pins", 0) > 0:
        # pins > 0 is the difference between a TAMPERED witness and an ABSENT one.
        # A missing or empty file reads as ok=False/unreadable but holds no pins, and
        # that is a legitimate no-pin state that falls through to "no_record" below —
        # not a break. Only a genuine chain break AMONG real pins blocks here.
        return _V(
            "witness_broken",
            "the witness pin file fails its own chain (%s): a pin from a tampered "
            "witness cannot be trusted, so no comparison is meaningful"
            % wv.get("first_break"))

    # Then the log itself. Agreeing with a pin at one row says nothing about a log
    # whose own chain is already broken elsewhere.
    lv = ledger.verify()
    if lv.ok is False:
        return _V(
            "local_broken",
            "the log fails its own chain (%s): witness agreement at the pinned row "
            "does not make a locally tampered log consistent" % lv.first_break)

    pin = store.latest(namespace)
    if pin is None:
        return _V("no_record",
                              f"witness holds no pin for namespace {namespace!r}")

    w_rows = pin.get("rows")
    w_chain = pin.get("chain")
    local = ledger.head()
    local_rows = local.rows

    if not isinstance(w_rows, int):
        return _V("no_record", "witness pin missing a valid row count",
                              witness_chain=w_chain, local_rows=local_rows)

    # A ZERO-ROW PIN CONSTRAINS NOTHING (pre-invite audit 2026-08-23, C2).
    # publish_head now refuses to mint one, but pins minted before that fix — or
    # by a remote store that does not refuse — must still never read as a
    # positive confirmation. The comparison below would match "genesis" against
    # "genesis" and return the one truthy verdict against ANY log, including one
    # truncated to almost nothing. "The witness saw nothing" is a no_record, not
    # a pass.
    if w_rows == 0:
        return _V("no_record",
                  "the witness pin for namespace %r was taken over an EMPTY log "
                  "(0 rows): it constrains nothing and cannot confirm this or any "
                  "other log. Re-pin against a non-empty head." % namespace,
                  witness_rows=0, witness_chain=w_chain, local_rows=local_rows)

    if local_rows < w_rows:
        return _V(
            "truncated",
            f"log has {local_rows} rows but the witness recorded {w_rows}: "
            f"{w_rows - local_rows} witnessed row(s) are missing (truncation)",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    local_chain_at = chain_at(ledger.path, w_rows)
    if local_chain_at is None:
        return _V(
            "truncated",
            f"cannot reach row {w_rows} in the log to compare against the witness",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    if local_chain_at != w_chain:
        return _V(
            "rewritten",
            f"log's chain at the witnessed row {w_rows} differs from the pin: "
            f"history was rewritten from at or before that point",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    grew = local_rows - w_rows
    detail = "log matches the witness at the witnessed row"
    if grew:
        detail += f" and has grown {grew} row(s) since (expected)"
    return _V("consistent", detail,
                          witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)
