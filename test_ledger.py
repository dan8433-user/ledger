"""Tests for ledger — the whole product claim is 'tamper-evident,' so the
negative test (tampering is CAUGHT at the exact line) is the load-bearing one.
Run: python test_ledger.py
"""
import json
import tempfile
from pathlib import Path

from ledger import Ledger


def test_append_and_verify_clean():
    with tempfile.TemporaryDirectory() as d:
        log = Ledger(Path(d) / "a.jsonl")
        for i in range(5):
            log.append({"tool": "search", "n": i})
        r = log.verify()
        assert r.ok, r
        assert r.rows == 5 and r.chained == 5 and r.prechain == 0
    print("PASS clean append+verify (5 rows chain intact)")


def test_tamper_edit_is_caught():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "b.jsonl"
        log = Ledger(p)
        for i in range(5):
            log.append({"tool": "pay", "amount": i})
        # Tamper: edit row 3's amount in place, keep its (now-wrong) chain.
        lines = p.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[2])
        obj["amount"] = 999
        lines[2] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = log.verify()
        assert not r.ok, "tamper went undetected!"
        assert r.first_break == "line 3: chain mismatch", r.first_break
    print(f"PASS tamper caught at exact line (first_break='line 3: chain mismatch')")


def test_delete_row_is_caught():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.jsonl"
        log = Ledger(p)
        for i in range(5):
            log.append({"event": i})
        lines = p.read_text(encoding="utf-8").splitlines()
        del lines[2]  # delete row 3
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = log.verify()
        assert not r.ok, "deletion went undetected!"
    print("PASS deletion caught (removing a row breaks the chain)")


def test_reorder_is_caught():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "e.jsonl"
        log = Ledger(p)
        for i in range(5):
            log.append({"event": i})
        lines = p.read_text(encoding="utf-8").splitlines()
        lines[1], lines[3] = lines[3], lines[1]  # swap rows 2 and 4
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = log.verify()
        assert not r.ok, "reorder went undetected!"
    print("PASS reorder caught (swapping rows breaks the chain)")


def test_authority_block_is_chained():
    from ledger import authority
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "auth.jsonl"
        log = Ledger(p)
        auth = authority("agent://scout-7", capability_version="v3",
                         tool_schema={"name": "web.search", "args": ["q"]},
                         time_source="ntp")
        log.append({"tool": "web.search", "q": "weather"}, authority=auth)
        # the authority block is present, hashed schema, and inside the chain
        row = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
        assert row["authority"]["principal"] == "agent://scout-7"
        assert row["authority"]["capability_version"] == "v3"
        assert len(row["authority"]["tool_schema_hash"]) == 16
        assert log.verify().ok
        # tamper the principal -> chain must break (authority is protected)
        row["authority"]["principal"] = "agent://impostor"
        p.write_text(json.dumps(row) + "\n", encoding="utf-8")
        assert not log.verify().ok, "editing the authority block should break the chain!"
    print("PASS authority block chained + tamper-protected")


if __name__ == "__main__":
    test_append_and_verify_clean()
    test_tamper_edit_is_caught()
    test_delete_row_is_caught()
    test_reorder_is_caught()
    test_authority_block_is_chained()
    print("\nALL PASS — tamper-evidence holds against edit, delete, and reorder.")
