# SPDX-License-Identifier: MIT
"""The vendored adapter's FALLBACK verifier must not green an empty seam log.

Found 2026-08-30 by the denominator enumeration (adapter rows #1/#2), scoped
precisely by direct probe: with arcaeon-ledger installed, verify_seam_log
delegates to the real three-valued verifier (empty -> ok=None, correct). The
defect lived in the FALLBACK shim — the path a deployer hits when running the
adapter WITHOUT arcaeon-ledger installed, which is exactly the no-dependency
environment the shim exists to serve honestly. There, an empty seam log
returned ok=True: "I checked nothing" rendered as "I checked everything and
it was fine." The fix (tri-state ok, breaks count, verified_scope) existed in
the standalone arcaeon-adapter repo for four days, unvendored. These tests
pin the FALLBACK path by forcing _HAVE_LEDGER=False.
"""
import json

from adapter.arcaeon_adapter import _ledger


def test_fallback_empty_seam_log_is_falsy_not_green(tmp_path, monkeypatch):
    monkeypatch.setattr(_ledger, "_HAVE_LEDGER", False)
    log = tmp_path / "seam.jsonl"
    log.write_text("", encoding="utf-8")
    v = _ledger.verify_seam_log(str(log))
    assert v.ok is not True, "FALLBACK greened an empty seam log: nothing was checked"
    assert not v.ok, "empty-scope fallback verdict must be falsy"


def test_fallback_counts_every_break(tmp_path, monkeypatch):
    monkeypatch.setattr(_ledger, "_HAVE_LEDGER", False)
    log = tmp_path / "seam.jsonl"
    lg = _ledger.open_ledger(str(log))
    for i in range(4):
        lg.append({"i": i})
    lines = log.read_text(encoding="utf-8").splitlines()
    for idx in (1, 3):
        row = json.loads(lines[idx])
        row["chain"] = "deadbeef" + row["chain"][8:]
        lines[idx] = json.dumps(row)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = _ledger.verify_seam_log(str(log))
    assert v.ok is False
    assert getattr(v, "breaks", 1) >= 2, "a second break went unlooked-for"
