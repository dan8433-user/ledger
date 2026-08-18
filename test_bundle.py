# SPDX-License-Identifier: MIT
"""Tests for arcaeon_ledger.bundle — the one-command auditor evidence bundle.

Covers: bundle creation (dir and zip), byte-identical ledger copy, manifest
hash correctness (every listed hash re-verified from disk), strict verify
report inclusion (green and red ledgers), witness inclusion via an injected
fetcher, the no-namespace and offline fallbacks (stated, never silent), the
never-mutate-the-input guarantee, and CLI exit codes.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from arcaeon_ledger import Ledger
from arcaeon_ledger.bundle import build_bundle, main


def _make_ledger(tmp_path: Path, rows: int = 3) -> Path:
    p = tmp_path / "agent.log.jsonl"
    log = Ledger(p)
    for i in range(rows):
        log.append({"tool": "search", "step": i, "ok": True})
    return p


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


FAKE_PIN = json.dumps({"namespace": "ns-x", "rows": 3, "chain": "ab" * 16,
                       "head_state": "content_advanced"}).encode("utf-8")


def _fake_fetcher(url):
    return 200, FAKE_PIN


def _offline_fetcher(url):
    raise OSError("network unreachable (simulated offline)")


# -- creation -----------------------------------------------------------------

def test_bundle_directory_contains_all_core_files(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    assert not res.is_zip
    names = {p.name for p in res.out_path.iterdir()}
    assert names == {"agent.log.jsonl", "verify_report.json", "README.txt",
                     "MANIFEST.json"}


def test_ledger_copy_is_byte_identical_and_sha_stated(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    copy = res.out_path / "agent.log.jsonl"
    assert copy.read_bytes() == src.read_bytes()
    assert res.ledger_sha256 == _sha256(src)
    assert res.manifest["ledger_sha256"] == _sha256(src)
    # the sha is also stated in the auditor-facing README
    assert _sha256(src) in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_input_ledger_is_never_mutated(tmp_path):
    src = _make_ledger(tmp_path)
    before = src.read_bytes()
    build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                 fetcher=_fake_fetcher)
    assert src.read_bytes() == before


def test_missing_ledger_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_bundle(tmp_path / "nope.jsonl", out=tmp_path / "bundle")


def test_refuses_non_empty_out_dir(tmp_path):
    src = _make_ledger(tmp_path)
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "junk.txt").write_text("x")
    with pytest.raises(FileExistsError):
        build_bundle(src, out=out)


# -- manifest -----------------------------------------------------------------

def test_manifest_hashes_match_files_on_disk(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                       fetcher=_fake_fetcher)
    manifest = json.loads((res.out_path / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["files"], "manifest lists no files"
    for name, meta in manifest["files"].items():
        p = res.out_path / name
        assert p.is_file(), f"manifest lists {name} but it is not in the bundle"
        assert _sha256(p) == meta["sha256"], f"hash mismatch for {name}"
        assert p.stat().st_size == meta["bytes"]
    # every file in the bundle except the manifest itself is listed
    on_disk = {p.name for p in res.out_path.iterdir()} - {"MANIFEST.json"}
    assert on_disk == set(manifest["files"])
    assert manifest["package_version"]
    assert manifest["generated_at"].endswith("Z")
    assert "arcaeon_ledger.bundle" in manifest["generation_command"]


def test_manifest_detects_a_tampered_bundle_file(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    victim = res.out_path / "verify_report.json"
    victim.write_bytes(victim.read_bytes() + b" ")
    manifest = json.loads((res.out_path / "MANIFEST.json").read_text(encoding="utf-8"))
    assert _sha256(victim) != manifest["files"]["verify_report.json"]["sha256"]


# -- verify report ------------------------------------------------------------

def test_verify_report_is_strict_and_complete_green(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    report = json.loads((res.out_path / "verify_report.json").read_text(encoding="utf-8"))
    assert report["mode"] == "strict"
    r = report["result"]
    assert r["ok"] is True
    assert r["rows"] == 3 and r["chained"] == 3 and r["prechain"] == 0
    assert r["breaks"] == 0 and r["verified_scope"] == "full"
    assert report["command"] == "python -m arcaeon_ledger.cli verify --strict agent.log.jsonl"
    assert res.verify_ok is True


def test_verify_report_states_red_on_tampered_ledger(tmp_path):
    src = _make_ledger(tmp_path)
    lines = src.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["step"] = 999  # edit content, keep stale chain
    lines[1] = json.dumps(row)
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = build_bundle(src, out=tmp_path / "bundle")  # still succeeds: evidence of a break
    report = json.loads((res.out_path / "verify_report.json").read_text(encoding="utf-8"))
    assert report["result"]["ok"] is False
    assert report["result"]["breaks"] >= 1
    assert "BROKEN" in (res.out_path / "README.txt").read_text(encoding="utf-8")


# -- witness ------------------------------------------------------------------

def test_witness_response_included_verbatim_with_history_url(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns x/1",
                       fetcher=_fake_fetcher)
    assert (res.out_path / "witness_latest.json").read_bytes() == FAKE_PIN
    w = res.manifest["witness"]
    assert w["included"] is True and w["http_status"] == 200
    # namespace is URL-encoded in both URLs
    assert w["url"].endswith("?ns=ns%20x%2F1")
    assert w["history_url"] == ("https://github.com/dan8433-user/arcaeon-witness-pins"
                                "/commits/main/pins/ns%20x%2F1")
    assert w["history_url"] in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_no_namespace_is_a_stated_absence_not_silence(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    assert not (res.out_path / "witness_latest.json").exists()
    w = res.manifest["witness"]
    assert w["included"] is False and w["status"] == "not_requested"
    assert "No witness evidence included" in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_offline_witness_fetch_is_a_stated_failure_not_silence(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                       fetcher=_offline_fetcher)
    assert not (res.out_path / "witness_latest.json").exists()
    w = res.manifest["witness"]
    assert w["included"] is False
    assert w["status"].startswith("fetch_failed: OSError")
    readme = (res.out_path / "README.txt").read_text(encoding="utf-8")
    assert "No witness evidence included" in readme
    # the public history URL survives the failure so a stranger can still look
    assert w["history_url"] in readme


def test_witness_http_error_body_is_still_evidence(tmp_path):
    src = _make_ledger(tmp_path)
    body = b'{"error":"no pin for namespace"}'
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                       fetcher=lambda url: (404, body))
    assert (res.out_path / "witness_latest.json").read_bytes() == body
    assert res.manifest["witness"]["http_status"] == 404


# -- zip output ---------------------------------------------------------------

def test_zip_bundle_round_trips_with_valid_manifest(tmp_path):
    src = _make_ledger(tmp_path)
    out = tmp_path / "evidence.zip"
    res = build_bundle(src, out=out, namespace="ns-x", fetcher=_fake_fetcher)
    assert res.is_zip and out.is_file()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert names == {"agent.log.jsonl", "verify_report.json",
                         "witness_latest.json", "README.txt", "MANIFEST.json"}
        assert zf.read("agent.log.jsonl") == src.read_bytes()
        manifest = json.loads(zf.read("MANIFEST.json"))
        for name, meta in manifest["files"].items():
            assert hashlib.sha256(zf.read(name)).hexdigest() == meta["sha256"]


def test_zip_refuses_to_overwrite_existing_file(tmp_path):
    src = _make_ledger(tmp_path)
    out = tmp_path / "evidence.zip"
    out.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        build_bundle(src, out=out)
    assert out.read_bytes() == b"precious"


# -- README honesty -----------------------------------------------------------

def test_readme_never_claims_compliance(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    readme = (res.out_path / "README.txt").read_text(encoding="utf-8").lower()
    for banned in ("ai act compliant", "article 12 compliant", "audit-ready",
                   "audit ready"):
        assert banned not in readme
    assert "does not prove" in readme
    assert "art. 12(1)" in readme and "art. 19(1)" in readme and "art. 26(6)" in readme


def test_anchor_section_is_a_stated_not_included(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    assert res.manifest["anchor"]["included"] is False
    assert "Not included" in res.manifest["anchor"]["statement"]


# -- CLI ----------------------------------------------------------------------

def test_cli_builds_bundle_and_exits_zero(tmp_path, capsys, monkeypatch):
    src = _make_ledger(tmp_path)
    out = tmp_path / "clibundle"
    rc = main([str(src), "--out", str(out)])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["verify_ok"] is True
    assert printed["witness"] == "not_requested"
    assert (out / "MANIFEST.json").is_file()
    # the verbatim CLI invocation is recorded in the manifest
    manifest = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["generation_command"] == \
        f"python -m arcaeon_ledger.bundle {src} --out {out}"


def test_cli_usage_errors_exit_one(tmp_path, capsys):
    assert main([]) == 1
    assert main(["--out"]) == 1
    assert main(["a.jsonl", "--bogus"]) == 1
    assert main([str(tmp_path / "missing.jsonl")]) == 1
    assert main(["-h"]) == 0
