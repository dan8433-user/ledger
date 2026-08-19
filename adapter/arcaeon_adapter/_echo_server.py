# SPDX-License-Identifier: MIT
"""A synthetic MCP server, for proving passthrough fidelity. Not a product surface.

    python -m arcaeon_adapter._echo_server

The fidelity test compares the bytes a client receives when it talks to this
server DIRECTLY against the bytes it receives when it talks to the same server
THROUGH the proxy. For that comparison to mean anything, this server's output must
be a pure, deterministic function of its input:

  * no timestamps, no random ids, no clock, no environment reads
  * binary stdout only — a text-mode write on Windows would turn "\\n" into
    "\\r\\n" and the test would be measuring the CRT, not the proxy
  * unparseable input produces NO output (so garbage frames test the relay, not
    this server's error handling)
  * a final line with no trailing newline is still handled, because a client is
    allowed to write its last message and close

Four tools, each present to exercise one thing the proxy must get right:
  `echo`  — the ordinary success path
  `boom`  — a tool-level failure (`isError: true` inside a `result`), which the
            observer must record as status="error" even though JSON-RPC says ok
  `big`   — a multi-megabyte result, so a frame that spans many pipe reads gets
            reassembled for logging and forwarded without a seam
  `quiet` — a call the server never answers, so the unanswered-call row is real
"""
from __future__ import annotations

import json
import sys

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {"name": "echo", "description": "Echo the text back.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
    {"name": "boom", "description": "Always fails at the tool level.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "big", "description": "Return a large payload.",
     "inputSchema": {"type": "object", "properties": {"n": {"type": "integer"}}}},
    {"name": "quiet", "description": "Never answers.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def handle(msg: dict):
    """Return a response dict, or None to say nothing (notifications, `quiet`)."""
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "echo", "version": "1.0.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "echo":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": str(args.get("text", ""))}]}}
        if name == "boom":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "detonated"}], "isError": True}}
        if name == "big":
            n = args.get("n")
            n = n if isinstance(n, int) and 0 < n <= 8_000_000 else 2_000_000
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "x" * n}]}}
        if name == "quiet":
            return None  # deliberately unanswered
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}}
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main(argv=None) -> int:
    out = getattr(sys.stdout, "buffer", sys.stdout)
    inp = getattr(sys.stdin, "buffer", sys.stdin)
    buf = bytearray()
    while True:
        chunk = inp.read1(65536) if hasattr(inp, "read1") else inp.read(65536)
        if not chunk:
            break
        buf.extend(chunk)
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line = bytes(buf[:nl])
            del buf[:nl + 1]
            _serve(line, out)
    if buf:
        _serve(bytes(buf), out)  # final frame, no trailing newline
    return 0


def _serve(line: bytes, out) -> None:
    line = line.strip()
    if not line:
        return
    try:
        msg = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return  # not JSON-RPC: say nothing, so garbage tests the relay only
    if not isinstance(msg, dict):
        return
    resp = handle(msg)
    if resp is None:
        return
    out.write(json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n")
    out.flush()


if __name__ == "__main__":
    sys.exit(main())
