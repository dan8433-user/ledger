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

import json
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
    """
    verdict: str
    detail: str
    witness_rows: int | None = None
    witness_chain: str | None = None
    local_rows: int | None = None

    def __bool__(self) -> bool:
        # truthy only when the outside check positively confirms consistency
        return self.verdict == "consistent"


class WitnessStore:
    """Reference witness: an append-only, file-backed store of head pins.

    Holds only fingerprints, never log content. One JSONL file; each line is a
    recorded pin `{namespace, rows, chain, as_of, received_at}`. Append-only, so
    the witness's own record is itself tamper-evident by inspection.

    A hosted witness (Stage 0) is an HTTP endpoint wrapping this: POST a pin ->
    `record`, GET the latest -> `latest`. Running it in-process, as the tests and
    `verify_against_witness` do, is a complete local witness.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def record(self, namespace: str, head: Head, *, received_at: str | None = None) -> dict:
        """Append a pin for `namespace`. Returns the stored record."""
        rec = {
            "namespace": namespace,
            "rows": head.rows,
            "chain": head.chain,
            "as_of": head.as_of,
            # received_at is the witness's OWN clock — the trust surface is that
            # this timestamp is the witness's, not the publisher's. Left to the
            # caller/server to stamp; None if the store isn't clock-authoritative.
            "received_at": received_at,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec

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
    """
    return store.record(namespace, ledger.head(), received_at=received_at)


def verify_against_witness(store: WitnessStore, namespace: str,
                           ledger: Ledger) -> WitnessVerdict:
    """Check the ledger against the witness's most recent pin for `namespace`.

    This is the outside check the chain alone cannot do. Returns a WitnessVerdict;
    it is truthy only on "consistent". Honest by construction: a "truncated" or
    "rewritten" verdict is a positive detection, while a re-fetch that can't reach
    the witness is left to the caller (no witness => "no_record", never a false ok).
    """
    pin = store.latest(namespace)
    if pin is None:
        return WitnessVerdict("no_record",
                              f"witness holds no pin for namespace {namespace!r}")

    w_rows = pin.get("rows")
    w_chain = pin.get("chain")
    local = ledger.head()
    local_rows = local.rows

    if not isinstance(w_rows, int):
        return WitnessVerdict("no_record", "witness pin missing a valid row count",
                              witness_chain=w_chain, local_rows=local_rows)

    if local_rows < w_rows:
        return WitnessVerdict(
            "truncated",
            f"log has {local_rows} rows but the witness recorded {w_rows}: "
            f"{w_rows - local_rows} witnessed row(s) are missing (truncation)",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    local_chain_at = chain_at(ledger.path, w_rows)
    if local_chain_at is None:
        return WitnessVerdict(
            "truncated",
            f"cannot reach row {w_rows} in the log to compare against the witness",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    if local_chain_at != w_chain:
        return WitnessVerdict(
            "rewritten",
            f"log's chain at the witnessed row {w_rows} differs from the pin: "
            f"history was rewritten from at or before that point",
            witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)

    grew = local_rows - w_rows
    detail = "log matches the witness at the witnessed row"
    if grew:
        detail += f" and has grown {grew} row(s) since (expected)"
    return WitnessVerdict("consistent", detail,
                          witness_rows=w_rows, witness_chain=w_chain, local_rows=local_rows)
