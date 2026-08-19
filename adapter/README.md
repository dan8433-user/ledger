# arcaeon-adapter

**`arcaeon-ledger` proves a record wasn't altered. It can't prove the record is _complete_ — because the agent decides what to write. This moves the pen.**

`arcaeon-adapter` is a stdio proxy that sits between an MCP client and an MCP
server. It forwards JSON-RPC byte-for-byte, and on every `tools/call` it writes
one hash-chained row to its own ledger: which tool, digests of the arguments and
the result, ok or error, how long it took.

It runs in its own OS process. The agent is not consulted, cannot skip it, and
cannot see it.

```
pip install arcaeon-adapter arcaeon-ledger
```

Wrap any MCP server's command — one line of config, zero code:

```json
{ "mcpServers": {
    "ledger": {
      "command": "python",
      "args": ["-m", "arcaeon_adapter", "--ledger", "seam.log.jsonl", "--",
               "python", "-m", "arcaeon_ledger.mcp_server", "--log", "agent.log.jsonl"]
    }
} }
```

Or straight from a shell:

```
python -m arcaeon_adapter --ledger seam.log.jsonl -- <your mcp server command...>
```

## What lands in the log

Real rows, from wrapping `arcaeon-ledger`'s own MCP server (the ledger logging
itself through the ledger), trimmed for width:

```json
{"evt":"session_begin","seam":"mcp-stdio","seam_impl":"arcaeon-adapter/0.1.0",
 "session":"25eda195-70e8-45cb-9035-be9f61cfc759","seq":1,
 "server":"arcaeon_ledger.mcp_server","ledger_backend":"arcaeon-ledger/0.5.7",
 "command":["python","-m","arcaeon_ledger.mcp_server","--log","agent.log.jsonl"],
 "command_digest":"sha256:json-c14n:v1:ec06bd01…","raw_payloads":false,
 "ts":"2026-08-19T14:18:08Z","chain":"0081ec1fe5d98395192f595e553b4133"}

{"evt":"tools_list","seq":3,"tools":["ledger_append","ledger_verify"],"tool_count":2,
 "tools_digest":"sha256:json-c14n:v1:b85c9fce…","status":"ok", …}

{"evt":"tool_call","seq":4,"tool":"ledger_append","rpc_id":"3",
 "args_digest":"sha256:json-c14n:v1:cfb2bb50…",
 "result_digest":"sha256:json-c14n:v1:ba037f70…",
 "status":"ok","ms":144, …}

{"evt":"session_end","seq":6,"reason":"child_exit","exit_code":0,
 "rows_before_end":5,"calls":2, …}
```

In that same run, the wrapped server's *own* log — the diary it keeps when the
agent remembers to call `ledger_append` — had **one** row. The seam log had six.
That difference is the entire product.

| field | why it's there |
|---|---|
| `evt` | `tool_call`, `session_begin`, `session_end`, `mcp_initialize`, `tools_list` |
| `seam` | always `"mcp-stdio"` — the **provenance tier**. A separate process saw this at the protocol level. A downstream verifier reads this field to tell infrastructure-grade capture from a cooperative in-process callback the agent could simply not call. |
| `session` / `seq` | one proxy process = one session; `seq` is a dense total order within it. `session_begin` + `session_end` bracket the run so a reviewer can pair a session's start and end. |
| `args_digest` / `result_digest` | `sha256:json-c14n:v1:<hex>` — self-describing, so a stranger holding only the row can reproduce the computation. |
| `status` / `ms` | `ok` / `error` / `unanswered`, and wall-clock duration. `error` covers **both** a JSON-RPC `error` and a `result` carrying `isError: true`. |

**Digests, not payloads, by default.** The row proves *which* bytes crossed the
seam without keeping them. An audit log that quietly becomes a copy of every
prompt and every result is a liability, not an asset — and a person-free core is
much easier to retain for years. `--raw` embeds the payloads for deployers who
own that risk; the digests stay either way.

**A call that never gets an answer still gets a row** (`status: "unanswered"`).
Otherwise "kill the server mid-call" would be a way to make an action leave no
trace at the seam, which is the exact hole this exists to close.

## Verify it

The seam log is an ordinary `arcaeon-ledger` file:

```
python -m arcaeon_ledger.cli verify seam.log.jsonl
```

Edit a row, delete one, reorder them — every later link breaks and `verify` names
the exact line.

## The honest limit

> **An adapter on one seam logs that seam completely — and nothing else.** An
> agent can still act around it: a direct HTTP call, an un-wrapped MCP server, a
> shell command never crosses this proxy and never hits this ledger. The
> second-set-of-books problem does not go away; no logging layer can force total
> honesty. What the adapter guarantees is narrower and real: *everything that
> crossed the instrumented seam is in the record, automatically, and the record
> proves itself.* Honesty is forced at the seams, not everywhere — not a lock, a
> neighborhood.

Specifically **blind** to:

- your harness's built-in tools (Bash, file edits, web fetch) — they never touch MCP
- any MCP server you did not wrap
- HTTP the agent makes natively
- the model's reasoning, which is not an action and leaves no wire trace
- frames larger than `--max-frame` (relayed fine; counted and reported in
  `session_end` as `oversize_frames_unlogged`, never a silent gap)

And on compliance, plainly: **this does not make anyone compliant with
anything.** Regulations like the EU AI Act's Art. 12 place duties on a *provider*
or *deployer*, and duties land on people, not libraries. What this is: a
mechanism that makes recording at one seam automatic rather than voluntary,
which is a thing you would otherwise have to build. Retention policy, log
semantics, risk classification, and every other obligation remain yours. Anyone
selling you a package that "makes you compliant" is selling you a story.

Whoever controls the config can also remove the wrapper. That is the same class
of limit every logging layer has, and it is stated here rather than in a footnote.

## Fidelity is the P0 property

A proxy that corrupts, reorders, or delays a customer's JSON-RPC is worse than no
proxy at all. So the design puts fidelity ahead of observation, structurally:

- **Bytes are forwarded first, observed second, from a copy.** A parsing defect
  here cannot alter or withhold traffic; the worst it can do is produce a wrong
  row.
- **Raw binary end to end.** No text mode anywhere — on Windows that would rewrite
  `\n` as `\r\n` and silently alter every frame.
- **No reframing, ever.** We never parse a frame and re-emit it. The classic proxy
  bug is `json.dumps(json.loads(frame))`: semantically identical, byte-different.
- **One thread per direction**, so ordering within a direction is the OS's.
- **The child's stderr is inherited, not piped.** Its diagnostics land exactly
  where they did unwrapped, and the proxy itself prints nothing on an honest run.
- **Malformed frames are relayed untouched and not logged.** A server that prints
  a stray line to stdout keeps working; we don't guess, because a guess in an
  audit record is fiction.
- **The child's exit code is the proxy's exit code.**

This is tested by running a scripted client against a synthetic MCP server
directly, then through the proxy, and requiring the two stdout streams to be
identical *bytes* — including a 4 MB frame spanning ~64 pipe reads, unicode,
embedded CRLF, malformed lines, a notification with no id, and a final frame with
no trailing newline.

## Prove the checks can fail

```
python -m arcaeon_adapter.selftest
```

An instrument that has never failed proves nothing. Every case runs GREEN on a
clean fixture, then **mutates** and requires the same check to go RED — with a
no-op guard in between, because a mutation that changes nothing proves nothing
either.

```
PASS passthrough_fidelity GREEN: 2001202 bytes identical byte-for-byte through the proxy
PASS passthrough_fidelity RED on reserialize: corruption detected (length 2001202 vs 2001097)
PASS passthrough_fidelity RED on drop_byte: corruption detected (length 2001202 vs 2001168)
PASS one_row_per_call GREEN: 5 tools/call frames -> 5 tool_call rows, 9 rows total, seq 1..9
PASS one_row_per_call RED on log_on_request: count check caught 10 rows for 5 calls
PASS unanswered_call_logged GREEN: unanswered `quiet` call rowed with args_digest bound
PASS unanswered_call_logged RED on no_flush: dropping the shutdown flush loses the row
PASS tamper_detected GREEN: seam log verifies (ok=True, rows=9)
PASS tamper_detected RED on edited args_digest: first_break='line 4: chain mismatch'
PASS digest_recipe_frozen GREEN: 3 frozen json-c14n:v1 vectors reproduce exactly
PASS digest_recipe_frozen RED on unsorted_keys: drifted canonicalizer produces a different digest

ALL CHECKS PASSED — and every one was observed failing on its own defect.
```

The fidelity mutations are injected into the **real relay**, not a mock, so what's
proven is that the comparison would catch a regression in the shipping code path.

## Options

```
--ledger PATH      seam ledger (required). Keep it SEPARATE from any ledger the
                   wrapped server writes: one file, one writer, clean provenance.
--server NAME      label for the wrapped server in every row (default: derived
                   from the command — `-m pkg.mod` reads as "pkg.mod", not "python")
--session ID       session id (default: a fresh uuid4 per proxy process)
--raw              embed raw argument and result payloads. Off by default.
--max-frame BYTES  frames larger than this are relayed but not logged (default 64 MiB)
```

## Install and dependencies

Stdlib only at runtime. `arcaeon-ledger` is the intended writer and is what makes
a row provable — but it is **not** a hard dependency, on purpose: this gets
wrapped around somebody else's working MCP server by editing one line of config,
and a missing package must never be why their server fails to start. Without it,
rows are written by a byte-compatible fallback and `session_begin` says so in
`ledger_backend`, so a reviewer never has to guess which writer produced a chain.
(That byte-compatibility is asserted in the test suite, not just claimed here.)

**No network calls at runtime.** Ever.

```
pytest -q                            # 65 tests
python -m arcaeon_adapter.selftest   # the mutation harness
```

## Status

v0. Works, tested, dogfooded on our own MCP server. Deliberately not yet built:
`--authority` stamping, `--bind-inputs` artefact binding, `--auto-pin` witness
publication, and harness-hook / HTTP-gateway seams. See `CHANGELOG.md`.

MIT.
