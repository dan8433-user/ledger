# SPDX-License-Identifier: MIT
"""ledger MCP server — drop-in tamper-evident logging for any MCP agent.

Zero dependencies: MCP is JSON-RPC 2.0 over stdio, so this speaks it directly
rather than pulling the SDK (keeps the whole product install-free). Any MCP
client (Claude Code, etc.) can wire it in and its agent gets two tools:

  ledger_append(record)  -> chain hash   (log an action, tamper-evidently)
  ledger_verify(strict?) -> verify result (prove the log wasn't altered;
                            ok true/null/false — null = prechain rows skipped,
                            not a green; strict=true makes them hard failures)

Run:  python -m arcaeon_ledger.mcp_server [--log PATH]
Wire into an MCP client (e.g. Claude Code .mcp.json):
  { "mcpServers": { "ledger": {
      "command": "python", "args": ["-m", "arcaeon_ledger.mcp_server", "--log", "agent.log.jsonl"] } } }

Implements the slice of MCP a tool server needs: initialize, tools/list,
tools/call. Protocol version 2025-06-18. Notifications are ignored (no id).
"""
from __future__ import annotations

import argparse
import json
import sys

from arcaeon_ledger import Ledger, __version__

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {
        "name": "ledger_append",
        "description": ("Append one action record to a tamper-evident, hash-chained "
                        "log. Returns the record's chain hash. Use this to log every "
                        "consequential action (tool calls, payments, decisions) so the "
                        "history can later be proven unaltered."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "record": {
                    "type": "object",
                    "description": "Any JSON object describing the action (tool, args, "
                                   "result, actor, etc.). A `ts` timestamp is added if absent.",
                    "additionalProperties": True,
                },
            },
            "required": ["record"],
        },
    },
    {
        "name": "ledger_verify",
        "description": ("Verify the hash chain over the log. Returns a three-valued "
                        "verdict: ok=true means EVERY row verified; ok=null means no "
                        "break was found but unchained `prechain` rows were skipped "
                        "UNVERIFIED (verified_scope='bounded_prechain_skipped' — "
                        "treat as not-green); ok=false names the exact line of the "
                        "first break (edit, deletion, reorder). Pass strict=true to "
                        "make any unchained row a hard failure instead of a skip."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "strict": {
                    "type": "boolean",
                    "description": "Treat ANY unchained row as a break (closes the "
                                   "fabricated-legacy-prepend hole). Default false: "
                                   "unchained rows before the first chained row are "
                                   "skipped, counted in `prechain`, and cap the "
                                   "verdict at ok=null.",
                },
            },
        },
    },
]


def _result(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _text_content(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


def handle(msg: dict, log: Ledger):
    """Return a response dict, or None for notifications (no id)."""
    mid = msg.get("id")
    method = msg.get("method")
    if mid is None:  # notification (e.g. notifications/initialized) — no reply
        return None

    if method == "initialize":
        return _result(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ledger", "version": __version__},
        })
    if method == "tools/list":
        return _result(mid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name == "ledger_append":
                record = args.get("record")
                if not isinstance(record, dict):
                    return _result(mid, {**_text_content(
                        {"error": "record must be a JSON object"}), "isError": True})
                chain = log.append(record)
                return _result(mid, _text_content({"ok": True, "chain": chain}))
            if name == "ledger_verify":
                r = log.verify(strict=bool(args.get("strict")))
                return _result(mid, _text_content(r.__dict__))
            return _result(mid, {**_text_content(
                {"error": f"unknown tool {name}"}), "isError": True})
        except Exception as e:  # never crash the server on one bad call
            return _result(mid, {**_text_content({"error": str(e)}), "isError": True})

    return _error(mid, -32601, f"method not found: {method}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="agent.log.jsonl", help="ledger file path")
    args = ap.parse_args(argv)
    log = Ledger(args.log)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue  # not JSON-RPC; skip
        resp = handle(msg, log)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
