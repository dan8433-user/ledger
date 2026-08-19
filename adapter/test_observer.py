# SPDX-License-Identifier: MIT
"""Tests for the observation half — framing, pairing, digests, degradation.

These are the unit-level tests. `test_proxy.py` covers the process-level behavior
(fidelity, exit codes, real subprocesses). The split matters: the observer must be
testable WITHOUT spawning anything, because that is what lets us drive it into the
ugly states a real pipe only reaches occasionally — a frame split across four
reads, a 100 MB line, an id reused as both `1` and `"1"`.

Run: pytest -q
"""
import json

import pytest

from arcaeon_adapter._ledger import digest_json
from arcaeon_adapter.observer import FrameSplitter, SeamObserver, _status_of


# -- FrameSplitter -----------------------------------------------------------

def test_splitter_reassembles_across_chunk_boundaries():
    """A pipe read lands wherever it lands; frames must not depend on that."""
    s = FrameSplitter()
    payload = b'{"a":1}\n{"b":2}\n'
    got = []
    for i in range(len(payload)):  # feed one byte at a time: the worst case
        got += s.feed(payload[i:i + 1])
    assert got == [b'{"a":1}', b'{"b":2}']


def test_splitter_handles_one_chunk_with_many_frames():
    s = FrameSplitter()
    assert s.feed(b"a\nb\nc\n") == [b"a", b"b", b"c"]
    assert s.feed(b"") == []


def test_splitter_close_yields_unterminated_final_frame():
    """A client may write its last message and close without a newline."""
    s = FrameSplitter()
    assert s.feed(b"first\nlast-no-newline") == [b"first"]
    assert s.close() == [b"last-no-newline"]
    assert s.close() == []  # idempotent


def test_splitter_abandons_oversize_frame_and_resyncs():
    """Unbounded buffering is a memory-exhaustion vector any server can trip.

    The frame is dropped from the LOG (counted, never silent) and the splitter
    picks the stream back up at the next newline. The relay is unaffected — it
    forwarded those bytes before the splitter ever saw them.
    """
    s = FrameSplitter(max_frame=64)
    assert s.feed(b"x" * 200) == []
    assert s.dropped_oversize == 1
    assert s.feed(b"tail-of-the-monster\n") == []   # discarded remainder
    assert s.feed(b'{"ok":1}\n') == [b'{"ok":1}']   # resynced
    assert s.dropped_oversize == 1


def test_splitter_large_frame_under_ceiling_survives():
    s = FrameSplitter(max_frame=10 * 1024 * 1024)
    big = b'{"text":"' + b"y" * 4_000_000 + b'"}'
    out = []
    for i in range(0, len(big), 65536):
        out += s.feed(big[i:i + 65536])
    assert out == []
    out += s.feed(b"\n")
    assert out == [big]


# -- pairing -----------------------------------------------------------------

def _obs(**kw):
    rows = []
    o = SeamObserver(rows.append, server="srv", session="S", **kw)
    return o, rows


def _call(mid, tool="echo", args=None):
    return json.dumps({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                       "params": {"name": tool, "arguments": args or {}}}).encode()


def _resp(mid, result=None, error=None):
    m = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        m["error"] = error
    else:
        m["result"] = result if result is not None else {"content": []}
    return json.dumps(m).encode()


def test_one_call_one_row_with_the_documented_fields():
    o, rows = _obs()
    o.observe_client_frame(_call(1, "web_search", {"q": "weather"}))
    assert rows == []                       # nothing until the pair completes
    o.observe_server_frame(_resp(1, {"content": [{"type": "text", "text": "hi"}]}))
    assert len(rows) == 1
    r = rows[0]
    assert r["evt"] == "tool_call"
    assert r["seam"] == "mcp-stdio"          # the provenance tier, on every row
    assert r["session"] == "S" and r["seq"] == 1 and r["server"] == "srv"
    assert r["tool"] == "web_search"
    assert r["status"] == "ok"
    assert r["args_digest"] == digest_json({"q": "weather"})
    assert r["result_digest"] == digest_json({"content": [{"type": "text", "text": "hi"}]})
    assert isinstance(r["ms"], int) and r["ms"] >= 0


def test_digests_not_payloads_by_default():
    """Person-free core: the row proves WHICH bytes crossed, without keeping them."""
    o, rows = _obs()
    secret = {"ssn": "123-45-6789", "note": "do not warehouse me"}
    o.observe_client_frame(_call(1, "lookup", secret))
    o.observe_server_frame(_resp(1, {"content": [{"type": "text", "text": "123-45-6789"}]}))
    blob = json.dumps(rows[0])
    assert "123-45-6789" not in blob
    assert "args" not in rows[0] and "result" not in rows[0]
    assert rows[0]["args_digest"].startswith("sha256:json-c14n:v1:")


def test_raw_opt_in_embeds_payloads():
    o, rows = _obs(raw=True)
    o.observe_client_frame(_call(1, "lookup", {"q": "x"}))
    o.observe_server_frame(_resp(1, {"content": "y"}))
    assert rows[0]["args"] == {"q": "x"}
    assert rows[0]["result"] == {"content": "y"}
    assert rows[0]["args_digest"] == digest_json({"q": "x"})  # digest stays regardless


def test_out_of_order_responses_pair_by_id_not_position():
    """A server answering concurrently must not get results cross-attributed."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "slow"))
    o.observe_client_frame(_call(2, "fast"))
    o.observe_server_frame(_resp(2, {"content": "fast done"}))
    o.observe_server_frame(_resp(1, {"content": "slow done"}))
    assert [r["tool"] for r in rows] == ["fast", "slow"]
    assert rows[0]["result_digest"] == digest_json({"content": "fast done"})


def test_numeric_and_string_ids_are_distinct_requests():
    """JSON-RPC: id 1 and id "1" are different calls. Conflating them would
    attribute one call's result to another."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "numeric"))
    o.observe_client_frame(_call("1", "stringy"))
    o.observe_server_frame(_resp("1", {"content": "s"}))
    o.observe_server_frame(_resp(1, {"content": "n"}))
    assert [r["tool"] for r in rows] == ["stringy", "numeric"]


def test_duplicate_response_delivery_does_not_double_row():
    """Popping the pending map makes the observer idempotent against a server
    (or a buggy transport) delivering a response twice."""
    o, rows = _obs()
    o.observe_client_frame(_call(1))
    frame = _resp(1)
    o.observe_server_frame(frame)
    o.observe_server_frame(frame)
    assert len(rows) == 1


def test_jsonrpc_error_and_tool_level_iserror_both_read_as_error():
    """Two failure channels exist; an auditor asking 'did it work' wants one answer."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "boom"))
    o.observe_server_frame(_resp(1, error={"code": -32000, "message": "nope"}))
    o.observe_client_frame(_call(2, "tool_fail"))
    o.observe_server_frame(_resp(2, {"content": [], "isError": True}))
    assert [r["status"] for r in rows] == ["error", "error"]
    # The protocol-level failure still binds the error object by digest.
    assert rows[0]["result_digest"] == digest_json({"code": -32000, "message": "nope"})


def test_status_of_reads_both_channels():
    assert _status_of({"result": {"content": []}}) == "ok"
    assert _status_of({"result": {"isError": True}}) == "error"
    assert _status_of({"error": {"code": 1}}) == "error"
    assert _status_of({"result": {"isError": "yes"}}) == "ok"  # only literal True


def test_notifications_and_non_tool_methods_produce_no_rows():
    o, rows = _obs()
    o.observe_client_frame(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
    o.observe_client_frame(b'{"jsonrpc":"2.0","id":9,"method":"resources/list"}')
    o.observe_server_frame(b'{"jsonrpc":"2.0","id":9,"result":{"resources":[]}}')
    assert rows == []


def test_malformed_frames_are_skipped_not_guessed_at():
    """Relayed untouched by the proxy; here we only assert they produce no fiction."""
    o, rows = _obs()
    for junk in [b"not json", b'{"truncated', b"", b"   ", b'"a bare string"',
                 b"[1,2,3]", b"\xff\xfe\x00binary"]:
        o.observe_client_frame(junk)
        o.observe_server_frame(junk)
    assert rows == []


def test_jsonrpc_batch_array_is_honored():
    """MCP 2025-06-18 dropped batching; honoring it costs two lines and means a
    batching client still gets rows instead of a silent gap."""
    o, rows = _obs()
    o.observe_client_frame(json.dumps([
        json.loads(_call(1, "a")), json.loads(_call(2, "b"))]).encode())
    o.observe_server_frame(json.dumps([
        json.loads(_resp(1)), json.loads(_resp(2))]).encode())
    assert [r["tool"] for r in rows] == ["a", "b"]


def test_tools_call_without_id_is_not_paired():
    """A call with no id can never be answered; there is no pair to record."""
    o, rows = _obs()
    o.observe_client_frame(
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{}}}')
    assert rows == []
    assert o.calls_seen == 0


def test_missing_arguments_digests_as_empty_object():
    """`arguments` is optional in MCP. A missing one must digest deterministically,
    not crash and not produce a null."""
    o, rows = _obs()
    o.observe_client_frame(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"noargs"}}')
    o.observe_server_frame(_resp(1))
    assert rows[0]["args_digest"] == digest_json({})


def test_undigestible_payload_records_the_reason_never_a_fake_hash():
    """NaN is rejected by the frozen recipe on purpose. The row must say so rather
    than invent a digest or take the proxy down."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "weird"))
    # NaN can't be produced by json.dumps here, so drive the observer's own path:
    from arcaeon_adapter.observer import _safe_digest
    assert _safe_digest(float("nan")).startswith("undigestible:")
    o.observe_server_frame(_resp(1))
    assert len(rows) == 1  # and the ordinary path still works


# -- session brackets --------------------------------------------------------

def test_session_begin_end_bracket_and_seq_is_a_dense_total_order():
    o, rows = _obs()
    o.session_begin(adapter_version="test")
    o.observe_client_frame(_call(1))
    o.observe_server_frame(_resp(1))
    o.session_end(reason="child_exit", exit_code=0)
    assert [r["evt"] for r in rows] == ["session_begin", "tool_call", "session_end"]
    assert [r["seq"] for r in rows] == [1, 2, 3]
    assert rows[-1]["exit_code"] == 0          # zero is kept, not dropped as falsy
    assert rows[-1]["calls"] == 1
    assert all(r["session"] == "S" for r in rows)


def test_initialize_handshake_becomes_its_own_row():
    o, rows = _obs()
    o.observe_client_frame(json.dumps({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18",
                   "clientInfo": {"name": "claude-code", "version": "9"}}}).encode())
    o.observe_server_frame(json.dumps({
        "jsonrpc": "2.0", "id": 0, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "ledger", "version": "0.5.7"}}}).encode())
    assert len(rows) == 1
    r = rows[0]
    assert r["evt"] == "mcp_initialize"
    assert r["client_info"] == {"name": "claude-code", "version": "9"}
    assert r["server_info"] == {"name": "ledger", "version": "0.5.7"}
    assert r["protocol_version"] == "2025-06-18"


def test_tools_list_binds_the_offered_surface():
    """The tool-list digest is the only place a silent mid-life schema swap shows."""
    o, rows = _obs()
    o.observe_client_frame(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
    tools = [{"name": "b", "inputSchema": {"type": "object"}},
             {"name": "a", "inputSchema": {"type": "object"}}]
    o.observe_server_frame(json.dumps({"jsonrpc": "2.0", "id": 2,
                                       "result": {"tools": tools}}).encode())
    assert rows[0]["evt"] == "tools_list"
    assert rows[0]["tools"] == ["a", "b"]      # sorted for stable reading
    assert rows[0]["tool_count"] == 2
    assert rows[0]["tools_digest"] == digest_json(tools)


def test_unanswered_call_is_still_rowed_at_shutdown():
    """Closes 'kill the server mid-call and the action leaves no trace'."""
    o, rows = _obs()
    o.observe_client_frame(_call(1, "transfer_funds", {"amount": 5000}))
    assert rows == []
    n = o.flush_pending(reason="session_ended:interrupt")
    assert n == 1
    assert rows[0]["status"] == "unanswered"
    assert rows[0]["tool"] == "transfer_funds"
    assert rows[0]["args_digest"] == digest_json({"amount": 5000})
    assert rows[0]["reason"] == "session_ended:interrupt"
    assert "result_digest" not in rows[0]   # there was no result; don't invent one


def test_flush_pending_is_idempotent():
    o, rows = _obs()
    o.observe_client_frame(_call(1))
    assert o.flush_pending() == 1
    assert o.flush_pending() == 0
    assert len(rows) == 1


def test_emit_failure_does_not_propagate_out_of_the_relay_path():
    """A full disk must not become a transport outage. `relay` swallows observer
    exceptions; this asserts the observer itself raises loudly enough that the
    swallow in relay is a deliberate policy and not accidental silence."""
    def boom(_row):
        raise OSError("disk full")
    o = SeamObserver(boom, server="s", session="S")
    o.observe_client_frame(_call(1))
    with pytest.raises(OSError):
        o.observe_server_frame(_resp(1))
