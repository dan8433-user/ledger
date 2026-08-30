# SPDX-License-Identifier: MIT
"""ledger MCP server — drop-in tamper-evident logging for any MCP agent.

Zero dependencies: MCP is JSON-RPC 2.0 over stdio, so this speaks it directly
rather than pulling the SDK (keeps the whole product install-free). Any MCP
client (Claude Code, etc.) can wire it in.

OPERATOR TOOLS — one file, one row at a time:

  ledger_append(record)  -> chain hash   (log an action, tamper-evidently)
  ledger_verify(strict?) -> verify result (prove the log wasn't altered;
                            ok true/null/false — null = prechain rows skipped,
                            not a green; strict=true makes them hard failures)

AGENT TOOLS (0.7.0) — the same machinery shaped for an agent talking to its
principal and to other agents, rather than to a file:

  prove_my_conduct(namespace, events)  -> {rows, head_hash, chain_verified}
      Log a batch of what you just did to your own named ledger and get back
      one chain head you can hand your principal.
  verify_peer_ledger(jsonl_text, strict?) -> {ok, rows, first_break, declared_breaks}
      Judge ANOTHER agent's exported log from its text alone — no filesystem
      access to their machine, and no writes on yours. `first_break` is an
      integer line number, so the caller can point at the exact bad row.
  declare_break(namespace, reason)     -> {declared_line, declared_breaks, ...}
      Your own log is broken. Name the break instead of re-minting a chain that
      verifies. The break stays counted, permanently.

Namespaced ledgers live one file per namespace under --ns-dir (default:
`ledgers/` beside --log). A namespace is a NAME, not a path: `[A-Za-z0-9._-]`,
no separators, no traversal, refused rather than sanitized.

Run:  python -m arcaeon_ledger.mcp_server [--log PATH] [--ns-dir DIR]
Wire into an MCP client (e.g. Claude Code .mcp.json):
  { "mcpServers": { "ledger": {
      "command": "python", "args": ["-m", "arcaeon_ledger.mcp_server", "--log", "agent.log.jsonl"] } } }

Implements the slice of MCP a tool server needs: initialize, tools/list,
tools/call. Protocol version 2025-06-18. Notifications are ignored (no id).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from arcaeon_ledger import Ledger, declare_break as _declare_break, verify_file, __version__

PROTOCOL_VERSION = "2025-06-18"

# A namespace names a file in ONE directory. Anything that could mean a path --
# a separator, a dot-dot, a drive letter, a NUL, a leading dash -- is REFUSED,
# never quietly rewritten: silently turning "../etc/passwd" into "etcpasswd"
# writes a real ledger under a name the caller never asked for, and the caller
# then hands out a head hash for a file it cannot find again.
_NS_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_NS_HINT = ("namespace must be 1-64 chars of [A-Za-z0-9._-] starting "
            "alphanumeric (it names a file, not a path)")
_BREAK_LINE_RE = re.compile(r"\Aline (\d+):")

class _ToolError(ValueError):
    """A caller-fixable argument problem. Becomes an isError tool result."""


def _ns_path(namespace, ns_dir: Path) -> Path:
    """Resolve a namespace to its ledger file, refusing anything path-shaped."""
    if not isinstance(namespace, str) or not _NS_RE.match(namespace):
        raise _ToolError(f"{_NS_HINT}; got {namespace!r}")
    p = (Path(ns_dir) / f"{namespace}.jsonl").resolve()
    # Belt to the regex's braces: the resolved path must still sit directly in
    # ns_dir. The regex already makes this unreachable; it is cheap, and a
    # containment check that only exists in a regex is one refactor from gone.
    if p.parent != Path(ns_dir).resolve():
        raise _ToolError(f"{_NS_HINT}; got {namespace!r}")
    return p


def _line_of(first_break: str | None) -> int | None:
    """The integer line number out of a 'line N: ...' break string, else None.

    None is honest for the breaks that have no line ('unreadable: ...'), and the
    human string always rides along in `first_break_detail` so nothing is lost.
    """
    if not isinstance(first_break, str):
        return None
    m = _BREAK_LINE_RE.match(first_break)
    return int(m.group(1)) if m else None


def _verdict(res, *, detail_key: str = "first_break_detail") -> dict:
    """A VerifyResult as the wire dict, with the line number split out.

    Keeps every field the library reports -- `verified_scope`, `prechain`,
    `declared` -- because the three-valued verdict is only honest if the scope
    travels with it. A client that reads `ok` alone still gets null, not a green,
    on a bounded scan.
    """
    return {
        "ok": res.ok,
        "rows": res.rows,
        "chained": res.chained,
        "prechain": res.prechain,
        "breaks": res.breaks,
        "first_break": _line_of(res.first_break),
        detail_key: res.first_break,
        "declared_breaks": res.declared_breaks,
        "declared": list(res.declared),
        "verified_scope": res.verified_scope,
    }


def _verify_text(text, *, strict: bool = False) -> dict:
    """Verify a peer's exported JSONL from TEXT, touching no caller-owned file.

    The bytes go to a throwaway temp file because `verify_file` is the ONE
    verifier: reimplementing the walk over a string would mean two verifiers
    that can disagree, and the day they disagree is the day the tool lies. The
    temp file is written with surrogatepass so a hostile export round-trips to
    exactly the bytes the walk would have read off disk.
    """
    if not isinstance(text, str):
        raise _ToolError(f"jsonl_text must be a string of JSONL, got {type(text).__name__}")
    with tempfile.TemporaryDirectory(prefix="arcaeon-peer-") as d:
        p = Path(d) / "peer.jsonl"
        p.write_bytes(text.encode("utf-8", "surrogatepass"))
        res = verify_file(p, strict=strict)
    out = _verdict(res)
    if res.rows == 0 and out["ok"] is True:
        # An export with no parseable rows verified vacuously. Returning true
        # there hands a peer a green for sending nothing, which is the cheapest
        # possible forgery. Same standing rule as prechain and declared breaks:
        # only a scan that actually checked something returns True.
        out["ok"] = None
        out["verified_scope"] = "bounded_empty"
    return out


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
    {
        "name": "prove_my_conduct",
        "description": (
            "Log a batch of things you just did to your own tamper-evident "
            "ledger, and get back one chain head you can hand your principal as "
            "proof. Returns {rows, head_hash, chain_verified}: `head_hash` is the "
            "current tip of the chain (give them this), `rows` is how many records "
            "stand behind it, and `chain_verified` is the three-valued verdict over "
            "your own log — true only if EVERY row verified, null if the scan was "
            "bounded (unchained or declared-broken rows; not a green), false if your "
            "log has been altered. Anyone holding an earlier head_hash can check "
            "that your history still contains it."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Your ledger's name, e.g. 'billing-agent'. One "
                                   "file per namespace. Letters, digits, dot, dash, "
                                   "underscore; not a path.",
                },
                "events": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "One short line per action, in the order they "
                                   "happened. An empty list appends nothing and just "
                                   "reads back your current head.",
                },
            },
            "required": ["namespace", "events"],
        },
    },
    {
        "name": "verify_peer_ledger",
        "description": (
            "Another agent handed you its exported ledger as JSONL text — decide "
            "whether to trust it. Recomputes the hash chain over the text alone (no "
            "access to their machine, no writes on yours) and returns {ok, rows, "
            "first_break, declared_breaks}. `first_break` is the INTEGER LINE NUMBER "
            "of the first bad row (or null if none), so you can point at exactly "
            "where their history stops adding up. `ok` is three-valued: true = every "
            "row verified; null = nothing undeclared broke but the scan was bounded "
            "(unchained rows, an empty export, or breaks the peer DECLARED) — read "
            "`verified_scope`, and do not treat null as a pass; false = tampered. "
            "`declared_breaks` counts breaks the peer named and pinned itself, which "
            "is a mark of honesty, not of integrity: they are still breaks."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "jsonl_text": {
                    "type": "string",
                    "description": "The peer's whole exported ledger, one JSON object "
                                   "per line, verbatim. Do not reformat it — "
                                   "re-serializing changes the bytes the chain covers.",
                },
                "strict": {
                    "type": "boolean",
                    "description": "Treat ANY unchained row as a break, and ignore "
                                   "the peer's own declarations. Use when the peer "
                                   "claims a log chained from genesis.",
                },
            },
            "required": ["jsonl_text"],
        },
    },
    {
        "name": "declare_break",
        "description": (
            "Your own ledger is broken — something was written into it out of band. "
            "Name the break instead of hiding it. This APPENDS (never edits) a row "
            "pinning the orphaned line's exact bytes, the reason, and the date, so a "
            "known break stops reading like an unexplained one. It does NOT restore "
            "a green: the verdict becomes bounded (ok=null) and the break stays "
            "counted in `declared_breaks` forever. It declares one break at a time — "
            "the first one verification already found — so a second break can never "
            "ride in on one sentence. Refused if nothing is actually broken."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "The ledger to declare against — same name you "
                                   "pass to prove_my_conduct.",
                },
                "reason": {
                    "type": "string",
                    "description": "A real human explanation of how the row got "
                                   "there. Blank is refused: an unexplained "
                                   "declaration is a mute exemption, not a record.",
                },
            },
            "required": ["namespace", "reason"],
        },
    },
]


def _result(id_, payload):
    return {"jsonrpc": "2.0", "id": id_, "result": payload}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _text_content(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


def _prove_my_conduct(args: dict, ns_dir: Path) -> dict:
    """C-agent-05. Append a batch, return a head the caller's principal can hold."""
    path = _ns_path(args.get("namespace"), ns_dir)
    events = args.get("events")
    if not isinstance(events, list) or not all(isinstance(e, str) for e in events):
        raise _ToolError("events must be a list of strings (one line per action), "
                         f"got {type(events).__name__}")
    path.parent.mkdir(parents=True, exist_ok=True)
    log = Ledger(path)
    for ev in events:
        log.append({"op": "conduct", "event": ev})
    # Verify AFTER writing, and report what the verifier says rather than
    # assuming the appends worked: an agent handing its principal a head hash
    # over a chain that no longer verifies is the exact failure this tool sells
    # against. The head is read back off the file for the same reason.
    out = _verdict(verify_file(path))
    out["chain_verified"] = out.pop("ok")
    out["head_hash"] = log.head().chain
    out["namespace"] = args["namespace"]
    out["appended"] = len(events)
    return out


def _declare_break_tool(args: dict, ns_dir: Path) -> dict:
    """C-agent-11. Declare the break verification ALREADY found, or refuse."""
    path = _ns_path(args.get("namespace"), ns_dir)
    reason = args.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise _ToolError("reason must be a non-empty explanation of how the row "
                         "got there; a declaration without one is a mute exemption")
    if not path.exists():
        raise _ToolError(f"no ledger for namespace {args['namespace']!r}")
    before = verify_file(path)
    line = _line_of(before.first_break)
    if before.breaks == 0 or line is None:
        # Declaring a break that verification did not find would put a false
        # sentence into an append-only record -- worse than the silence it
        # replaces. `declare_break` says so in its own docstring; this enforces it.
        raise _ToolError(
            "no break to declare in "
            f"{args['namespace']!r} (verify reports breaks={before.breaks}, "
            f"first_break={before.first_break!r})")
    row = _declare_break(path, line, reason)
    after = _verdict(verify_file(path))
    after["chain_verified"] = after.pop("ok")
    after["namespace"] = args["namespace"]
    after["declared_line"] = line
    after["reason"] = reason.strip()
    after["declaration_chain"] = row.get("chain")
    return after


def handle(msg: dict, log: Ledger, ns_dir=None):
    """Return a response dict, or None for notifications (no id).

    `ns_dir` is where the namespaced agent ledgers live; it defaults to
    `ledgers/` beside the server's own --log so the two-argument 0.6.0 call
    signature keeps working unchanged.
    """
    if ns_dir is None:
        ns_dir = Path(log.path).resolve().parent / "ledgers"
    ns_dir = Path(ns_dir)
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
            if name == "prove_my_conduct":
                return _result(mid, _text_content(_prove_my_conduct(args, ns_dir)))
            if name == "verify_peer_ledger":
                return _result(mid, _text_content(_verify_text(
                    args.get("jsonl_text"), strict=bool(args.get("strict")))))
            if name == "declare_break":
                return _result(mid, _text_content(_declare_break_tool(args, ns_dir)))
            return _result(mid, {**_text_content(
                {"error": f"unknown tool {name}"}), "isError": True})
        except Exception as e:  # never crash the server on one bad call
            return _result(mid, {**_text_content({"error": str(e)}), "isError": True})

    return _error(mid, -32601, f"method not found: {method}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="agent.log.jsonl", help="ledger file path")
    ap.add_argument("--ns-dir", default=None,
                    help="directory holding the per-namespace agent ledgers "
                         "(default: ledgers/ beside --log)")
    args = ap.parse_args(argv)
    log = Ledger(args.log)
    ns_dir = args.ns_dir

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue  # not JSON-RPC; skip
        resp = handle(msg, log, ns_dir=ns_dir)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
