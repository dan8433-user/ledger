# SPDX-License-Identifier: MIT
"""A call must appear in the seam log even when its content is hostile.

These pin two fixes found by adversarial review rather than by the suite, both of
which broke the single property the adapter exists to provide: that everything
crossing the instrumented seam is in the record.

THE BUG THESE EXIST TO PREVENT COMING BACK. JSON permits `\\udXXX` escapes, so a
frame can legally carry a LONE SURROGATE. `json.loads` returns it as a real `str`
and `.encode("utf-8")` then refuses it, so the append raised at the chain-hash
step before writing any bytes. `proxy.relay` swallows observer exceptions on
purpose (transport must never break for logging), so the call ran, its response
was forwarded, and its row did not exist. **The chain still verified green**,
because verification checks linkage and nothing checks `seq` density. One
character in a tool name, or in `--raw` mode one character in a tool's own
response, was enough for the audited party to erase its own call.

That is why the assertions below are shaped the way they are: it is not enough
that `verify` passes, because `verify` passed while the row was missing. Each
test asserts the ROW IS PRESENT, and separately that the log is honest about any
gap it does have. A green verdict over an incomplete log is the failure mode.

Every test here was confirmed to FAIL against the parent commit before the fix
landed. A regression test whose red has never been observed is decoration.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon_adapter._ledger import verify_seam_log
from arcaeon_adapter.observer import SeamObserver, _escape_unencodable
from arcaeon_adapter.proxy import FAULT_ENV, REDACTED, _redact_argv

ROOT = str(Path(__file__).resolve().parent)
ECHO = [sys.executable, "-m", "arcaeon_adapter._echo_server"]

#: A REAL lone high surrogate, not the text "\\ud800".
#:
#: Getting this wrong is the trap, and it caught the first draft of this file. Written
#: as "\\\\ud800" it is nine ordinary ASCII characters, `json.dumps` emits a literal
#: backslash, the far side decodes eight harmless characters, and every assertion here
#: passes while testing nothing. Written as below it is one code point in the D800-DFFF
#: range that UTF-8 refuses to encode, which is the actual attack.
#:
#: It still survives the wire because `json.dumps` defaults to ensure_ascii=True and
#: emits the six-character escape `\\ud800`, which is pure ASCII and encodes fine. The
#: receiving `json.loads` turns it back into the real surrogate. That asymmetry is
#: precisely why this reaches a logger that never expected it.
LONE_SURROGATE = "\ud800"


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env.pop(FAULT_ENV, None)
    return env


def _proxied(stream: bytes, ledger: Path, *flags, cmd=None):
    argv = [sys.executable, "-m", "arcaeon_adapter.proxy", "--ledger", str(ledger)]
    argv += list(flags) + ["--"] + list(cmd or ECHO)
    return subprocess.run(argv, input=stream, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=_env(), timeout=120)


def _rows(path: Path):
    if not Path(path).exists():
        return []
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").split("\n")
            if l.strip()]


def _calls(rows):
    return [r for r in rows if r.get("evt") == "tool_call"]


# -- the row must exist -------------------------------------------------------

def test_surrogate_in_tool_name_still_produces_a_row(tmp_path):
    """The original attack, end to end through the real proxy subprocess.

    Two calls cross the seam. The first carries a lone surrogate in its tool
    name. Before the fix, exactly one `tool_call` row came back and the chain
    verified green, so the log said one call happened when two did.
    """
    ledger = tmp_path / "seam.jsonl"
    stream = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "pay" + LONE_SURROGATE,
                               "arguments": {"amount": "9000"}}}) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "benign", "arguments": {}}}) + "\n"
    ).encode("utf-8")

    _proxied(stream, ledger)
    rows = _rows(ledger)
    calls = _calls(rows)

    assert len(calls) == 2, (
        "both calls crossed the seam; a row for each is the whole product. "
        f"got {[c.get('tool') for c in calls]}")

    hostile = [c for c in calls if c.get("tool") != "benign"]
    assert len(hostile) == 1
    row = hostile[0]
    assert row.get("record_repair"), (
        "the row was altered to make it writable, so it must SAY it was altered; "
        "a silently repaired audit row is its own kind of lie")
    assert "ud800" in json.dumps(row), (
        "backslashreplace is chosen over dropping the character so an auditor can "
        "see what was actually there")


def test_the_repaired_log_is_still_a_valid_chain(tmp_path):
    """Repair must not buy row-presence at the cost of verifiability."""
    ledger = tmp_path / "seam.jsonl"
    stream = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "x" + LONE_SURROGATE,
                                     "arguments": {}}}) + "\n").encode("utf-8")
    _proxied(stream, ledger)
    assert verify_seam_log(ledger).ok is True


def test_surrogate_in_a_tool_response_cannot_erase_the_call(tmp_path):
    """The dangerous direction: the audited party erasing its own call.

    In `--raw` mode the response body is stored, so a malicious tool could put a
    surrogate in its OWN reply and vanish from the record. The echo server
    reflects arguments back, which is how the surrogate reaches the response.
    """
    ledger = tmp_path / "seam.jsonl"
    stream = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "wire_transfer",
                                     "arguments": {"note": LONE_SURROGATE}}}) + "\n"
              ).encode("utf-8")

    _proxied(stream, ledger, "--raw")
    calls = _calls(_rows(ledger))

    assert [c.get("tool") for c in calls] == ["wire_transfer"], (
        "a tool must not be able to delete its own row by choosing its output")


def test_session_end_declares_rows_it_could_not_write(tmp_path):
    """An absence has to be reported, because a silent `seq` gap verifies green.

    Driven at the observer rather than through the proxy: this needs an emit that
    fails unconditionally, which no real content can cause now that repair works.
    """
    def always_fails(_row):
        raise RuntimeError("disk is gone")

    obs = SeamObserver(always_fails, server="s", session="sess")

    # BOTH halves matter, and they point at different readers. The raise is for the
    # caller — `relay` catches it, so transport is unaffected, and `test_emit_failure_
    # does_not_propagate_out_of_the_relay_path` exists to keep that swallow a
    # deliberate policy rather than accidental silence. The counter is for whoever
    # reads the log later. An observer that only raised would leave the FILE silent;
    # one that only counted would make the swallow in `relay` meaningless. Silence in
    # either direction is what let the surrogate bug hide.
    with pytest.raises(RuntimeError):
        obs._row("tool_call", tool="silent")
    assert obs.rows_unlogged == 1
    assert obs.rows == 0

    written = []
    obs._emit = written.append
    obs.session_end(reason="eof", exit_code=0)

    assert written[-1]["rows_unlogged"] == 1, (
        "the log must be able to say 'I am missing something' in its own words")


def test_a_clean_session_does_not_claim_a_gap(tmp_path):
    """The other half of the previous test, and the reason it means anything.

    A counter that is always present reads as noise and gets ignored. It is
    omitted when zero, so its presence is a signal.
    """
    ledger = tmp_path / "seam.jsonl"
    stream = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "ordinary", "arguments": {}}}) + "\n"
              ).encode("utf-8")
    _proxied(stream, ledger)
    ends = [r for r in _rows(ledger) if r.get("evt") == "session_end"]
    assert ends and "rows_unlogged" not in ends[0]


def test_escape_helper_leaves_ordinary_text_untouched(tmp_path):
    """The repair must be inert on everything that is not broken.

    Emoji, CJK, accents and control characters are all legal UTF-8 and must pass
    through byte-identical; a repair that mangles valid content would corrupt far
    more records than the bug it fixes.
    """
    for value in ["plain", "café", "日本語", "😀", "tab\there", "nl\nhere", "", "0"]:
        assert _escape_unencodable(value) == value
    nested = {"a": ["b", {"c": "😀"}], "d": 1, "e": None, "f": True}
    assert _escape_unencodable(nested) == nested


# -- the command line must not carry credentials ------------------------------

def test_secret_flag_values_are_redacted(tmp_path):
    """The reliable rule: a value is secret because of the slot it sits in."""
    argv = ["srv", "--api-key", "sk_live_REALKEY", "--token=abc123",
            "--password", "hunter2", "--log", "audit.jsonl"]
    out, hits = _redact_argv(argv)

    assert "sk_live_REALKEY" not in out
    assert "abc123" not in " ".join(out)
    assert "hunter2" not in out
    assert hits == 3
    assert out[-2:] == ["--log", "audit.jsonl"], (
        "non-secret flags must survive intact or the row loses its audit value")


def test_secret_shaped_values_are_redacted_in_any_slot(tmp_path):
    for token in ["sk_live_x", "ghp_abcdef", "AKIAIOSFODNN7EXAMPLE", "glpat-xyz"]:
        out, hits = _redact_argv(["srv", token])
        assert out == ["srv", REDACTED] and hits == 1, token


def test_url_credentials_are_redacted_in_place(tmp_path):
    out, hits = _redact_argv(["srv", "--url", "https://api.example.com/v1?api_key=SECRET&page=2"])
    joined = " ".join(out)
    assert "SECRET" not in joined
    assert "page=2" in joined, "the rest of the URL is useful and must survive"
    assert "api.example.com/v1" in joined
    assert hits == 1

    out, hits = _redact_argv(["srv", "postgres://user:pw@db.internal/x"])
    assert "pw" not in " ".join(out).replace(REDACTED, "")
    assert hits == 1


def test_ordinary_commands_are_not_touched(tmp_path):
    """A redactor that fires on everything is as useless as one that never fires."""
    argv = [sys.executable, "-m", "arcaeon_ledger.mcp_server", "--log", "a.jsonl"]
    out, hits = _redact_argv(argv)
    assert out == argv and hits == 0


def test_session_begin_row_carries_no_secret_but_still_pins_the_command(tmp_path):
    """The end-to-end version, and the reason the digest is over the ORIGINAL argv.

    The row must be safe to hand an auditor AND still pin exactly what ran. If the
    digest were taken over the redacted form, the record would verify against a
    command that never executed, which is the quieter bug.
    """
    ledger = tmp_path / "seam.jsonl"
    secret = "sk_live_MUSTNOTAPPEAR"
    cmd = ECHO + ["--api-key", secret]

    _proxied(b"", ledger, cmd=cmd)
    text = ledger.read_text(encoding="utf-8")
    begin = [r for r in _rows(ledger) if r.get("evt") == "session_begin"][0]

    assert secret not in text, "a live credential must never reach the evidence file"
    assert REDACTED in begin["command"]
    assert begin.get("command_redactions") == 1
    assert begin["command_digest"], "the command must still be pinned"

    from arcaeon_adapter.proxy import _digest
    assert begin["command_digest"] == _digest(cmd), (
        "the digest is over the real argv, so someone who knows the command can "
        "still check it; digesting the redacted form would pin a fiction")
