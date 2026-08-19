# SPDX-License-Identifier: MIT
"""Non-destructive observation of a relayed JSON-RPC stream.

This module never touches the bytes on their way through. `proxy.py` writes each
chunk to its destination FIRST and hands a *copy* to the observer afterwards.
That ordering is the design, not an optimization: it makes it structurally
impossible for a parsing bug in here to corrupt or delay a customer's traffic.
The worst thing a defect in this file can do is produce a wrong row or no row.

Two objects live here.

`FrameSplitter` turns a stream of arbitrarily-chopped byte chunks into complete
newline-delimited frames. MCP stdio framing is one JSON message per line, but a
pipe read can land mid-frame, and a single frame can be megabytes (a tool that
returns a fetched page). So the splitter buffers across reads, and has a hard
`max_frame` ceiling: past it, the partial frame is *abandoned for logging* and we
resync at the next newline. The ceiling exists because an observer that buffers
without bound is a memory-exhaustion vector reachable by any server that forgets
a newline — and dropping a log row is a survivable failure while dying mid-session
is not. The relay is unaffected either way; it already forwarded those bytes.

`SeamObserver` pairs `tools/call` requests with their responses by JSON-RPC `id`
and appends one row per completed pair. Notes on the decisions inside:

* **Pairing is by `id`, not by order.** MCP servers may answer concurrently and
  out of order; matching positionally would mis-attribute results to tools, which
  is a far worse failure than a missing row.
* **Digests by default, payloads never unless asked.** `args_digest` /
  `result_digest` prove *which* bytes crossed the seam without warehousing them.
  A person-free core is the default because an audit log that quietly becomes a
  copy of every prompt is a liability, not an asset. `raw=True` embeds payloads
  for deployers who own that risk.
* **An unanswered call still gets a row.** If the child dies (or is killed) with
  a call in flight, `flush_pending` writes it with `status="unanswered"`. Without
  this, "kill the server mid-call" would be a way to make an action leave no
  trace at the seam, which is exactly the hole the adapter exists to close.
* **Malformed frames are skipped, silently and deliberately.** Not every line on
  an MCP pipe is JSON-RPC (a chatty server logging to stdout, a partial write, a
  future framing). We relay it untouched and log nothing about it: guessing would
  put fiction in an audit record.
* **Every row carries `seam`.** `seam="mcp-stdio"` is the provenance tier — it
  says a separate process observed this at the protocol level, as opposed to a
  cooperative in-process callback the agent could simply not call. A downstream
  verifier reads this field to decide how much the row is worth. `seam_impl`
  carries the version that produced it.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Callable

SEAM = "mcp-stdio"

#: Frames longer than this are relayed but not logged (see module docstring).
DEFAULT_MAX_FRAME = 64 * 1024 * 1024


class FrameSplitter:
    """Byte chunks in, complete newline-delimited frames out.

    Handles the three cases a naive `chunk.split(b"\\n")` gets wrong: a chunk
    that ends mid-frame (buffer it), a frame larger than any single read
    (accumulate), and a frame larger than we are willing to hold (abandon and
    resync). `close()` yields a final unterminated frame, because a client that
    writes its last message without a trailing newline before closing stdin is
    legal and its call must still be logged.
    """

    def __init__(self, max_frame: int = DEFAULT_MAX_FRAME):
        self.max_frame = max_frame
        self._buf = bytearray()
        self._resyncing = False
        #: Count of frames abandoned for exceeding `max_frame`. Surfaced in
        #: `session_end` so an oversized-frame gap is visible, never silent.
        self.dropped_oversize = 0

    def feed(self, chunk: bytes) -> list[bytes]:
        out: list[bytes] = []
        if not chunk:
            return out
        self._buf.extend(chunk)
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            frame = bytes(self._buf[:nl])
            del self._buf[:nl + 1]
            if self._resyncing:
                # Tail of an abandoned oversized frame: discard exactly one line
                # and start reading frames again.
                self._resyncing = False
                continue
            out.append(frame)
        if len(self._buf) > self.max_frame:
            self._buf.clear()
            self._resyncing = True
            self.dropped_oversize += 1
        return out

    def close(self) -> list[bytes]:
        """Final residue: an unterminated last frame, if any."""
        if self._resyncing or not self._buf:
            self._buf.clear()
            return []
        frame = bytes(self._buf)
        self._buf.clear()
        return [frame]


def _parse(raw: bytes) -> list[dict]:
    """Parse one frame into zero or more JSON-RPC message objects.

    Returns [] for anything that isn't a JSON object (or an array of them) —
    blank lines, log noise, partial writes, a framing we don't know. JSON-RPC 2.0
    batches are arrays; MCP 2025-06-18 dropped batching but honoring it here is
    two lines and means a batching client still gets rows.
    """
    txt = raw.strip()
    if not txt:
        return []
    try:
        msg = json.loads(txt.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    if isinstance(msg, dict):
        return [msg]
    if isinstance(msg, list):
        return [m for m in msg if isinstance(m, dict)]
    return []


def _id_key(mid: Any) -> str | None:
    """A hashable, stable key for a JSON-RPC id.

    JSON-RPC allows string OR number ids, and `1` and `"1"` are *different*
    requests. Typing the key ("i:1" vs "s:1") keeps them apart, so a client
    mixing both can't have one call's result attributed to another's.
    """
    if isinstance(mid, bool) or mid is None:
        return None
    if isinstance(mid, int):
        return f"i:{mid}"
    if isinstance(mid, float):
        return f"f:{mid!r}"
    if isinstance(mid, str):
        return f"s:{mid}"
    return None


class _Pending:
    __slots__ = ("tool", "args_digest", "args", "t0", "rpc_id")

    def __init__(self, tool, args_digest, args, t0, rpc_id):
        self.tool = tool
        self.args_digest = args_digest
        self.args = args
        self.t0 = t0
        self.rpc_id = rpc_id


class SeamObserver:
    """Watches both directions of one MCP stdio session and emits ledger rows.

    Thread-safe: the proxy runs one relay thread per direction, and both call in
    here. One lock guards the pending map and the sequence counter, so `seq` is a
    true total order over the rows this process wrote.
    """

    def __init__(self, emit: Callable[[dict], Any], *, server: str,
                 session: str | None = None, raw: bool = False,
                 impl: str = "arcaeon-adapter/0.1.0",
                 clock: Callable[[], float] = time.monotonic):
        self._emit = emit
        self.server = server
        self.session = session or str(uuid.uuid4())
        self.raw = raw
        self.impl = impl
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._seq = 0
        self.rows = 0
        self.calls_seen = 0
        #: Filled from the `initialize` handshake if we see it; a client that
        #: never initializes just leaves these None rather than blocking a row.
        self.client_info: dict | None = None
        self.protocol_version: str | None = None
        self._init_ids: set[str] = set()
        self._toollist_ids: set[str] = set()

    # -- row emission -------------------------------------------------------

    def _row(self, evt: str, **fields) -> dict:
        """Build and append one row. Caller must hold `self._lock`."""
        self._seq += 1
        row = {
            "evt": evt,
            "seam": SEAM,
            "seam_impl": self.impl,
            "session": self.session,
            "seq": self._seq,
            "server": self.server,
        }
        row.update({k: v for k, v in fields.items() if v is not None})
        self._emit(row)
        self.rows += 1
        return row

    def session_begin(self, **fields) -> dict:
        """The Art. 12(3)(a) opening bracket.

        Emitted at process start, NOT at the MCP `initialize` handshake. A begin
        row that waits for `initialize` does not exist when a client connects and
        dies, or speaks a framing we don't recognize — and then there is nothing
        to pair a `session_end` with. What `initialize` tells us later arrives as
        its own `mcp_initialize` row, keyed to the same session.
        """
        with self._lock:
            return self._row("session_begin", **fields)

    def session_end(self, *, reason: str, exit_code: int | None = None,
                    **fields) -> dict:
        with self._lock:
            return self._row("session_end", reason=reason, exit_code=exit_code,
                             rows_before_end=self.rows, calls=self.calls_seen,
                             **fields)

    # -- observation --------------------------------------------------------

    def observe_client_frame(self, raw: bytes) -> None:
        """Client -> server. Already relayed; this only reads a copy."""
        for msg in _parse(raw):
            method = msg.get("method")
            key = _id_key(msg.get("id"))
            if method == "tools/call":
                if key is None:
                    continue  # a tools/call with no id is unanswerable; nothing to pair
                params = msg.get("params") or {}
                if not isinstance(params, dict):
                    params = {}
                args = params.get("arguments")
                if args is None:
                    args = {}
                tool = params.get("name")
                with self._lock:
                    self._pending[key] = _Pending(
                        tool=tool if isinstance(tool, str) else None,
                        args_digest=_safe_digest(args),
                        args=args if self.raw else None,
                        t0=self._clock(),
                        rpc_id=msg.get("id"),
                    )
                    self.calls_seen += 1
            elif method == "initialize" and key is not None:
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                with self._lock:
                    self._init_ids.add(key)
                    ci = (params or {}).get("clientInfo")
                    self.client_info = ci if isinstance(ci, dict) else None
                    pv = (params or {}).get("protocolVersion")
                    self.protocol_version = pv if isinstance(pv, str) else None
            elif method == "tools/list" and key is not None:
                with self._lock:
                    self._toollist_ids.add(key)

    def observe_server_frame(self, raw: bytes) -> None:
        """Server -> client. Already relayed; this only reads a copy."""
        for msg in _parse(raw):
            key = _id_key(msg.get("id"))
            if key is None:
                continue  # notification or un-keyed frame: nothing to pair
            has_result = "result" in msg
            has_error = "error" in msg
            if not (has_result or has_error):
                continue  # a request from the server to the client, not a response
            with self._lock:
                pend = self._pending.pop(key, None)
                is_init = key in self._init_ids
                is_toollist = key in self._toollist_ids
                self._init_ids.discard(key)
                self._toollist_ids.discard(key)
                if pend is not None:
                    payload = msg.get("error") if has_error else msg.get("result")
                    self._row(
                        "tool_call",
                        tool=pend.tool,
                        rpc_id=_render_id(pend.rpc_id),
                        args_digest=pend.args_digest,
                        result_digest=_safe_digest(payload),
                        status=_status_of(msg),
                        ms=int(round((self._clock() - pend.t0) * 1000)),
                        args=pend.args,
                        result=payload if self.raw else None,
                    )
                elif is_init:
                    res = msg.get("result") if has_result else None
                    server_info = res.get("serverInfo") if isinstance(res, dict) else None
                    proto = res.get("protocolVersion") if isinstance(res, dict) else None
                    self._row(
                        "mcp_initialize",
                        status=_status_of(msg),
                        client_info=self.client_info,
                        server_info=server_info if isinstance(server_info, dict) else None,
                        protocol_version=proto if isinstance(proto, str)
                        else self.protocol_version,
                        result_digest=_safe_digest(res if has_result else msg.get("error")),
                    )
                elif is_toollist:
                    res = msg.get("result") if has_result else None
                    tools = res.get("tools") if isinstance(res, dict) else None
                    names = sorted(t.get("name") for t in tools
                                   if isinstance(t, dict) and isinstance(t.get("name"), str)
                                   ) if isinstance(tools, list) else None
                    # The tool-list digest binds the *surface the agent was
                    # offered* at this moment. A server that silently swaps a
                    # tool's schema mid-life produces a different digest here,
                    # which is the only place that change is visible at all.
                    self._row(
                        "tools_list",
                        status=_status_of(msg),
                        tools=names,
                        tool_count=len(names) if names is not None else None,
                        tools_digest=_safe_digest(tools) if tools is not None else None,
                    )

    def flush_pending(self, *, reason: str = "no_response") -> int:
        """Row every call that never got an answer. Returns how many.

        Called at shutdown. See module docstring: killing the child mid-call must
        not be a way to erase the fact that the call crossed the seam.
        """
        with self._lock:
            items = list(self._pending.items())
            self._pending.clear()
            for _key, pend in items:
                self._row(
                    "tool_call",
                    tool=pend.tool,
                    rpc_id=_render_id(pend.rpc_id),
                    args_digest=pend.args_digest,
                    status="unanswered",
                    reason=reason,
                    ms=int(round((self._clock() - pend.t0) * 1000)),
                    args=pend.args,
                )
        return len(items)


def _render_id(mid: Any) -> str | None:
    """The JSON-RPC id, stringified.

    Kept in the row because request ordering and pairing are auditable facts and
    a reviewer needs to re-derive them from the log alone. Stringified so a row's
    type is stable no matter what the client used.
    """
    if mid is None or isinstance(mid, bool):
        return None
    return str(mid)


def _safe_digest(value: Any) -> str | None:
    """Digest a payload, or say so honestly if it cannot be digested.

    A JSON value that arrived over the wire is normally digestible. But NaN /
    Infinity are rejected by the frozen recipe on purpose (no other language
    parses them the same way), and a pathological structure can hit recursion
    limits. In those cases the row records the *reason* rather than a hash we
    could not compute — never a fabricated digest, never a crash that takes the
    proxy down with it.
    """
    from ._ledger import digest_json  # local import keeps this module import-light
    try:
        return digest_json(value)
    except Exception as e:
        return f"undigestible:{type(e).__name__}"


def _status_of(msg: dict) -> str:
    """ok / error, reading BOTH places MCP can put a failure.

    Two distinct failure channels exist and conflating them loses real signal:
    a JSON-RPC `error` object (protocol-level: unknown method, bad params) and a
    `result` carrying `isError: true` (tool-level: the tool ran and failed). Both
    are `"error"` here, because an auditor asking "did this action succeed?" does
    not care which layer said no.
    """
    if "error" in msg:
        return "error"
    res = msg.get("result")
    if isinstance(res, dict) and res.get("isError") is True:
        return "error"
    return "ok"
