# SPDX-License-Identifier: MIT
"""Process-level tests: the proxy against a real child over real pipes.

The load-bearing one is `test_passthrough_fidelity_*`. Everything else in this
package is a feature; byte-faithful relay is the license to be in the pipe at
all. A proxy that mangles a customer's JSON-RPC is worse than no proxy, so the
comparison is bytes-to-bytes against an unproxied control run — not "the same
messages", not "the same JSON", the same BYTES.

Run: pytest -q
"""
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from arcaeon_adapter._ledger import verify_seam_log
from arcaeon_adapter.observer import FrameSplitter, SeamObserver
from arcaeon_adapter.proxy import FAULT_ENV, _Corruptor, _server_label, relay

ROOT = str(Path(__file__).resolve().parent)
ECHO = [sys.executable, "-m", "arcaeon_adapter._echo_server"]


def _env(fault=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env.pop(FAULT_ENV, None)
    if fault:
        env[FAULT_ENV] = fault
    return env


def _direct(stream: bytes):
    p = subprocess.run(ECHO, input=stream, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=_env(), timeout=120)
    return p


def _proxied(stream: bytes, ledger: Path, *flags, fault=None, cmd=None):
    argv = [sys.executable, "-m", "arcaeon_adapter.proxy", "--ledger", str(ledger)]
    argv += list(flags) + ["--"] + list(cmd or ECHO)
    p = subprocess.run(argv, input=stream, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=_env(fault), timeout=120)
    return p


def _rows(path: Path):
    if not Path(path).exists():
        return []
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").split("\n")
            if l.strip()]


def _frame(mid, method, params=None):
    m = {"jsonrpc": "2.0", "id": mid, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m).encode()


def _tool(mid, name, args=None):
    return _frame(mid, "tools/call", {"name": name, "arguments": args or {}})


SIMPLE = (b"\n".join([
    _frame(1, "initialize", {"protocolVersion": "2025-06-18",
                             "clientInfo": {"name": "pytest", "version": "1"}}),
    b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
    _frame(2, "tools/list"),
    _tool(3, "echo", {"text": "hello"}),
]) + b"\n")


# -- P0: passthrough fidelity ------------------------------------------------

@pytest.mark.parametrize("name,stream", [
    ("simple", SIMPLE),
    ("malformed_frames_relayed_untouched",
     b'not json\n' + _tool(1, "echo", {"text": "a"}) + b'\n{"truncated\n\n   \n'
     + _tool(2, "echo", {"text": "b"}) + b"\n"),
    ("unicode_payload",
     _tool(1, "echo", {"text": "héllo — 🔒 ünïcode"}) + b"\n"),
    ("embedded_crlf_and_tabs",
     _tool(1, "echo", {"text": "a\r\nb\tc"}) + b"\n"),
    ("notification_only_no_response_expected",
     b'{"jsonrpc":"2.0","method":"notifications/cancelled"}\n'),
    ("unterminated_final_frame", SIMPLE + _tool(4, "echo", {"text": "no newline"})),
    ("error_paths", _tool(1, "boom") + b"\n" + _frame(2, "no/such/method") + b"\n"),
    ("empty_stream", b""),
])
def test_passthrough_fidelity(tmp_path, name, stream):
    """Proxied stdout must equal unproxied stdout, byte for byte."""
    control = _direct(stream)
    through = _proxied(stream, tmp_path / f"{name}.jsonl")
    assert through.stdout == control.stdout, (
        f"[{name}] fidelity broken: {len(control.stdout)} control bytes vs "
        f"{len(through.stdout)} proxied bytes")
    assert through.returncode == control.returncode


def test_passthrough_fidelity_large_frame(tmp_path):
    """A 4 MB response spans ~64 pipe reads. It must arrive with no seam in it."""
    stream = _tool(1, "big", {"n": 4_000_000}) + b"\n"
    control = _direct(stream)
    through = _proxied(stream, tmp_path / "big.jsonl")
    assert len(control.stdout) > 4_000_000
    assert through.stdout == control.stdout


def test_passthrough_fidelity_many_interleaved_calls(tmp_path):
    """Ordering within a direction is the OS's; the proxy must not shuffle it."""
    stream = b"".join(_tool(i, "echo", {"text": f"m{i}"}) + b"\n" for i in range(200))
    control = _direct(stream)
    through = _proxied(stream, tmp_path / "many.jsonl")
    assert through.stdout == control.stdout
    assert len(_rows(tmp_path / "many.jsonl")) == 202  # begin + 200 calls + end


@pytest.mark.parametrize("mode", _Corruptor.MODES)
def test_fidelity_check_goes_red_on_injected_corruption(tmp_path, mode):
    """The check must be observed FAILING, or it proves nothing.

    Corruption is injected into the real relay, not a mock, so what is proven is
    that this comparison would catch a regression in the shipping code path.
    """
    control = _direct(SIMPLE)
    through = _proxied(SIMPLE, tmp_path / f"c-{mode}.jsonl", fault=mode)
    assert through.stdout != control.stdout, (
        f"fault {mode!r} produced identical bytes — the mutation no-opped and the "
        f"fidelity assertion above would be vacuous")
    assert FAULT_ENV in through.stderr.decode("utf-8", "replace"), (
        "a deliberately-corrupting proxy must announce itself on stderr")


def test_child_exit_code_is_propagated(tmp_path):
    """A wrapped server that dies of status 3 must look like one that died of 3."""
    cmd = [sys.executable, "-c", "import sys; sys.stdin.read(); sys.exit(3)"]
    p = _proxied(SIMPLE, tmp_path / "code.jsonl", cmd=cmd)
    assert p.returncode == 3
    assert _rows(tmp_path / "code.jsonl")[-1]["exit_code"] == 3


def test_proxy_is_silent_on_stderr_on_an_honest_run(tmp_path):
    """The proxy inherits the wrapped server's stderr, so ANYTHING we print lands
    in the customer's server log — from a tool whose pitch is that it changes
    nothing about how their server behaves.

    This caught a real one: importing `.proxy` from the package `__init__` made
    runpy emit a `RuntimeWarning: ... found in sys.modules` on every single launch.
    """
    p = _proxied(SIMPLE, tmp_path / "quiet.jsonl")
    assert p.stderr == b"", f"proxy polluted stderr: {p.stderr!r}"


def test_dash_m_package_shorthand_is_equivalent(tmp_path):
    """`python -m arcaeon_adapter` is what goes in a config file; it must work."""
    argv = [sys.executable, "-m", "arcaeon_adapter", "--ledger",
            str(tmp_path / "short.jsonl"), "--"] + ECHO
    p = subprocess.run(argv, input=SIMPLE, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=_env(), timeout=120)
    assert p.stdout == _direct(SIMPLE).stdout
    assert p.stderr == b""


def test_version_is_declared_in_exactly_one_place():
    """`seam_impl` is stamped on every row; two copies of the version would drift
    and rows would start lying about which build wrote them.

    Two teeth beyond the constant-identity check, both grown after an audit found
    `SeamObserver.__init__` carrying its own hardcoded "arcaeon-adapter/0.1.1" —
    a second place the version lived, which this test as first written never saw:

    1. The default a SeamObserver stamps when nobody passes `impl` must equal the
       constant. (Equality, not identity — string interning makes `is` on equal
       literals implementation-defined, and the literal-hunt below is what catches
       a copied string anyway.)
    2. No file in the package other than `_version.py` may contain a version-shaped
       literal at all, so a future hardcode fails even if its value happens to be
       current at the time it is written — which is exactly how the observer.py one
       stayed invisible.
    """
    import pathlib
    import re

    import arcaeon_adapter
    from arcaeon_adapter import _version, observer, proxy
    assert arcaeon_adapter.VERSION is _version.VERSION is proxy.VERSION
    assert proxy.IMPL == f"arcaeon-adapter/{proxy.VERSION}"
    assert observer.SeamObserver.__init__.__kwdefaults__["impl"] == _version.IMPL
    pkg = pathlib.Path(arcaeon_adapter.__file__).parent
    offenders = [
        "%s:%d: %s" % (py.name, lineno, line.strip())
        for py in sorted(pkg.glob("*.py")) if py.name != "_version.py"
        for lineno, line in enumerate(
            py.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"arcaeon-adapter/\d", line)
    ]
    assert not offenders, (
        "version-shaped literal outside _version.py (a second copy will drift):\n  "
        + "\n  ".join(offenders))


def test_child_stderr_is_inherited_not_swallowed(tmp_path):
    """The server's diagnostics must keep flowing to the client's log unchanged."""
    cmd = [sys.executable, "-c",
           "import sys; sys.stderr.write('server diagnostic\\n'); sys.stdin.read()"]
    p = _proxied(SIMPLE, tmp_path / "err.jsonl", cmd=cmd)
    assert b"server diagnostic" in p.stderr


def test_unstartable_server_fails_cleanly_and_leaves_a_record(tmp_path):
    """We must not die silently: a spawn failure is itself an auditable event."""
    ledger = tmp_path / "nostart.jsonl"
    p = _proxied(b"", ledger, cmd=[sys.executable + "-does-not-exist-xyz"])
    assert p.returncode == 127
    rows = _rows(ledger)
    assert [r["evt"] for r in rows] == ["session_begin", "session_end"]
    assert rows[-1]["reason"] == "spawn_failed"


def test_no_command_is_a_usage_error(tmp_path):
    p = subprocess.run(
        [sys.executable, "-m", "arcaeon_adapter.proxy", "--ledger",
         str(tmp_path / "x.jsonl")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(), timeout=60)
    assert p.returncode != 0
    assert b"server command" in p.stderr


# -- what lands in the ledger ------------------------------------------------

def test_one_row_per_call_and_the_session_brackets(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    stream = SIMPLE + _tool(4, "boom") + b"\n"
    _proxied(stream, ledger)
    rows = _rows(ledger)
    evts = [r["evt"] for r in rows]
    assert evts[0] == "session_begin" and evts[-1] == "session_end"
    assert evts.count("tool_call") == 2
    assert evts.count("mcp_initialize") == 1
    assert evts.count("tools_list") == 1
    calls = [r for r in rows if r["evt"] == "tool_call"]
    assert [c["tool"] for c in calls] == ["echo", "boom"]
    assert [c["status"] for c in calls] == ["ok", "error"]
    assert all(c["args_digest"].startswith("sha256:json-c14n:v1:") for c in calls)
    assert all(isinstance(c["ms"], int) for c in calls)


def test_every_row_carries_seam_provenance(tmp_path):
    """`seam` is what lets a downstream verifier tell infrastructure-grade capture
    from a cooperative in-process callback the agent could simply not call."""
    ledger = tmp_path / "seam.jsonl"
    _proxied(SIMPLE, ledger)
    rows = _rows(ledger)
    assert rows and all(r["seam"] == "mcp-stdio" for r in rows)
    assert all(r["seam_impl"].startswith("arcaeon-adapter/") for r in rows)


def test_session_begin_records_the_wrapped_command_and_backend(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    _proxied(SIMPLE, ledger)
    begin = _rows(ledger)[0]
    assert begin["evt"] == "session_begin"
    assert begin["command"][-1] == "arcaeon_adapter._echo_server"
    assert begin["command_digest"].startswith("sha256:json-c14n:v1:")
    assert begin["ledger_backend"]          # names WHICH writer produced this chain
    assert begin["raw_payloads"] is False
    assert "fault_injected" not in begin    # absent on an honest run


def test_seam_log_verifies_and_a_tampered_row_is_named(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    _proxied(SIMPLE, ledger)
    assert verify_seam_log(ledger).ok is True

    lines = [l for l in ledger.read_text(encoding="utf-8").split("\n") if l.strip()]
    i = next(i for i, l in enumerate(lines) if json.loads(l).get("evt") == "tool_call")
    obj = json.loads(lines[i])
    obj["tool"] = "something_else"        # rewrite history, keep the chain field
    lines[i] = json.dumps(obj, ensure_ascii=False)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    v = verify_seam_log(ledger)
    assert v.ok is not True
    assert v.first_break == f"line {i + 1}: chain mismatch"


def test_digests_only_by_default_payload_never_lands(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    _proxied(_tool(1, "echo", {"text": "SENSITIVE-abc123"}) + b"\n", ledger)
    assert "SENSITIVE-abc123" not in ledger.read_text(encoding="utf-8")


def test_raw_flag_embeds_payloads(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    _proxied(_tool(1, "echo", {"text": "SENSITIVE-abc123"}) + b"\n", ledger, "--raw")
    assert "SENSITIVE-abc123" in ledger.read_text(encoding="utf-8")
    call = [r for r in _rows(ledger) if r["evt"] == "tool_call"][0]
    assert call["args"] == {"text": "SENSITIVE-abc123"}
    assert call["args_digest"].startswith("sha256:")   # digest stays either way


def test_unanswered_call_is_rowed_when_the_session_ends(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    _proxied(_tool(1, "quiet", {"amount": 9000}) + b"\n", ledger)
    calls = [r for r in _rows(ledger) if r["evt"] == "tool_call"]
    assert len(calls) == 1
    assert calls[0]["status"] == "unanswered" and calls[0]["tool"] == "quiet"
    assert _rows(ledger)[-1]["unanswered"] == 1


def test_server_label_defaults_and_override(tmp_path):
    assert _server_label(["python", "-m", "arcaeon_ledger.mcp_server", "--log", "x"]) \
        == "arcaeon_ledger.mcp_server"
    assert _server_label(["/usr/local/bin/my-server", "--flag"]) == "my-server"
    assert _server_label([]) == "unknown"
    ledger = tmp_path / "seam.jsonl"
    _proxied(SIMPLE, ledger, "--server", "billing")
    assert all(r["server"] == "billing" for r in _rows(ledger))


def test_session_id_is_one_per_process_and_overridable(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _proxied(SIMPLE, a)
    _proxied(SIMPLE, b)
    sa = {r["session"] for r in _rows(a)}
    sb = {r["session"] for r in _rows(b)}
    assert len(sa) == 1 and len(sb) == 1 and sa != sb
    c = tmp_path / "c.jsonl"
    _proxied(SIMPLE, c, "--session", "fixed-id")
    assert {r["session"] for r in _rows(c)} == {"fixed-id"}


def test_two_sessions_append_to_one_ledger_and_still_verify(tmp_path):
    """Sequential runs share a chain; `seq` restarts per process, `session` is what
    separates them. A reviewer pairs begin/end by session, not by seq."""
    ledger = tmp_path / "shared.jsonl"
    _proxied(SIMPLE, ledger)
    _proxied(SIMPLE, ledger)
    assert verify_seam_log(ledger).ok is True
    rows = _rows(ledger)
    assert len({r["session"] for r in rows}) == 2
    assert [r["evt"] for r in rows].count("session_begin") == 2
    assert [r["evt"] for r in rows].count("session_end") == 2


def test_oversize_frame_is_relayed_but_reported_as_unlogged(tmp_path):
    """A gap in the record must be visible IN the record."""
    ledger = tmp_path / "seam.jsonl"
    stream = _tool(1, "big", {"n": 300_000}) + b"\n"
    control = _direct(stream)
    p = _proxied(stream, ledger, "--max-frame", "1000")
    assert p.stdout == control.stdout          # fidelity is unaffected by the cap
    end = _rows(ledger)[-1]
    assert end["oversize_frames_unlogged"] >= 1


# -- silent failures made countable -------------------------------------------
#
# The relay swallows observer exceptions BY DESIGN (a logging bug must never
# become a transport failure), and it treats read/write OSErrors as shutdown
# races. Both policies are right; both were also INVISIBLE: an observer that
# raised on every frame left a session_end indistinguishable from a clean one,
# while an oversized frame — the same kind of survivable logging gap — was
# counted and reported. These tests hold the swallow to the oversize standard:
# swallowed, AND counted, AND declared in session_end.

_QUIET_CHILD = [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"]


def test_observe_exceptions_are_counted_not_just_swallowed():
    """relay() must keep transport intact AND tally each swallowed observe error."""
    frames = _tool(1, "echo", {"text": "a"}) + b"\n" + _tool(2, "echo", {"text": "b"}) + b"\n"
    src, dst = io.BytesIO(frames), io.BytesIO()
    sp = FrameSplitter()

    def broken_observer(frame):
        raise RuntimeError("observer bug")

    relay(src, dst, broken_observer, splitter=sp)
    assert dst.getvalue() == frames, "the swallow exists to protect transport"
    assert sp.observe_failures == 2


def test_observe_failures_are_reported_in_session_end(tmp_path, monkeypatch):
    """An observer failing on every frame must be a DECLARED hole, like oversize."""
    from arcaeon_adapter import proxy as proxy_mod

    class _Sabotaged(SeamObserver):
        def observe_client_frame(self, raw):
            raise RuntimeError("observer bug")

    monkeypatch.setattr(proxy_mod, "SeamObserver", _Sabotaged)
    ledger = tmp_path / "obsfail.jsonl"
    stream = _tool(1, "echo", {"text": "x"}) + b"\n"
    proxy_mod.run(_QUIET_CHILD, str(ledger), stdin=io.BytesIO(stream),
                  stdout=io.BytesIO())
    end = [r for r in _rows(ledger) if r["evt"] == "session_end"][-1]
    assert end.get("observe_failures", 0) >= 1, (
        "an observer that raised left no trace in session_end: %s" % end)


def test_read_side_oserror_is_counted_not_presumed_normal():
    """EIO on the source is caught as a shutdown race. Fine — but count it."""
    class _EIOStream:
        def read1(self, n):
            raise OSError(5, "Input/output error")

    sp = FrameSplitter()
    relay(_EIOStream(), io.BytesIO(), lambda f: None, splitter=sp)
    assert sp.relay_errors == 1


def test_relay_errors_are_reported_in_session_end(tmp_path):
    """The counted shutdown-race exception must ride out in session_end."""
    from arcaeon_adapter import proxy as proxy_mod

    class _EIOStream:
        def read1(self, n):
            raise OSError(5, "Input/output error")

    ledger = tmp_path / "eio.jsonl"
    proxy_mod.run(_QUIET_CHILD, str(ledger), stdin=_EIOStream(), stdout=io.BytesIO())
    end = [r for r in _rows(ledger) if r["evt"] == "session_end"][-1]
    assert end.get("relay_errors", 0) >= 1, (
        "a read-side I/O error left no trace in session_end: %s" % end)


def test_upstream_counters_are_read_only_after_the_thread_is_joined(tmp_path, monkeypatch):
    """Pins the up-thread join before the counter reads.

    The race being closed: the up thread's last counter increment can land a beat
    after the child exits (write done, bookkeeping preempted), while the main thread
    is already composing session_end from those counters. Reproduced deterministically
    by wrapping relay() so the up thread's final increment arrives 0.3s late; without
    a bounded join, session_end reads zero and the gap goes undeclared.
    """
    from arcaeon_adapter import proxy as proxy_mod
    real_relay = proxy_mod.relay

    def slow_finish_relay(src, dst, observe=None, **kw):
        real_relay(src, dst, observe, **kw)
        if kw.get("on_eof") is not None:            # the client->server thread
            time.sleep(0.3)                          # preempted mid-bookkeeping
            kw["splitter"].dropped_oversize += 1

    monkeypatch.setattr(proxy_mod, "relay", slow_finish_relay)
    ledger = tmp_path / "race.jsonl"
    proxy_mod.run(_QUIET_CHILD, str(ledger), stdin=io.BytesIO(b""), stdout=io.BytesIO())
    end = [r for r in _rows(ledger) if r["evt"] == "session_end"][-1]
    assert end.get("oversize_frames_unlogged", 0) == 1, (
        "a counter increment racing session_end was lost: %s" % end)
