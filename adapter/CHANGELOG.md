# Changelog

## 0.1.0 — 2026-08-19

First version. An MCP stdio proxy that records every tool call to a tamper-evident
ledger without the agent's cooperation.

### Why this exists

`arcaeon_ledger.Ledger.append()` records whatever a caller chooses to pass it.
That is a diary: an agent that skips the append leaves no trace, and one that
curates its appends leaves a flattering record. Any regime asking for *automatic*
recording (EU AI Act Art. 12(1) is the one on our desk) cannot be met by a library
the logged party calls voluntarily. MCP stdio is the seam where "no cooperation
required" is literally true — the client and server talk newline-delimited
JSON-RPC over a pipe, and a process sitting in that pipe sees everything at the
protocol level, in a process the agent does not own.

Design memo: `projects/online_business/ADAPTER_LAYER_DESIGN_2026-08-18.md`
(seam ranking, schema, pricing sketch, and the frozen honest-limit copy).

### Added

- **`arcaeon_adapter/proxy.py`** — the proxy.
  `python -m arcaeon_adapter --ledger PATH -- <server command...>`. Spawns the
  wrapped server, relays stdin→child and child→stdout byte-for-byte, logs the
  seam. Child's stderr is inherited (not piped); child's exit code is propagated.
- **`arcaeon_adapter/observer.py`** — non-destructive stream observation.
  `FrameSplitter` (chunk reassembly, unterminated final frame, bounded buffer with
  resync) and `SeamObserver` (request/response pairing by JSON-RPC `id`, row
  emission, session brackets).
- **`arcaeon_adapter/_ledger.py`** — ledger binding, with a byte-compatible
  fallback writer + verifier for machines without `arcaeon-ledger` installed.
- **`arcaeon_adapter/selftest.py`** — mutation harness. Five cases, each observed
  GREEN then forced RED on its own defect, with a no-op guard between.
- **`arcaeon_adapter/_echo_server.py`** — deterministic synthetic MCP server, so
  fidelity can be measured against an unproxied control run.
- **Row schema:** `tool_call`, `session_begin`, `session_end`, `mcp_initialize`,
  `tools_list`. Every row carries `seam="mcp-stdio"` + `seam_impl`, `session`,
  `seq`, `server`.
- **Flags:** `--ledger`, `--server`, `--session`, `--raw`, `--max-frame`.
- 65 pytest tests.

### Decisions, and what they cost

- **Digest-only by default; `--raw` opt-in.** Rows prove *which* bytes crossed
  the seam without warehousing them. Cost: you cannot reconstruct a payload from
  a row after the fact. That is the trade we want — an audit log that silently
  accumulates everyone's data is a liability, and person-free rows are far easier
  to retain for years.
- **Session is process-scoped, not `initialize`-scoped.** One proxy process = one
  session, and `session_begin` fires at start rather than at the MCP handshake. A
  begin row that waits for `initialize` does not exist when a client connects and
  dies, and then there is nothing for `session_end` to pair with. What the
  handshake tells us arrives separately as `mcp_initialize`.
- **`seam` is `"mcp-stdio"`.** The design memo sketched `"mcp-proxy/0.1"`, folding
  the tier and the version into one string. Split: `seam` names the *provenance
  tier* and must stay stable for a downstream verifier to switch on, while
  `seam_impl` carries the build. A tier identifier that changes every release is
  not a tier identifier.
- **An unanswered call is still rowed** (`status="unanswered"`, at shutdown).
  Without it, killing the server mid-call erases the fact that the call crossed
  the seam.
- **Oversized frames are counted and reported**, not silently skipped. A gap in
  the record has to be visible in the record.
- **`arcaeon-ledger` is not a hard dependency.** This gets wrapped around
  somebody else's working server by a config edit; a missing package must never be
  why their server fails to start. The fallback is byte-compatible and labelled in
  `ledger_backend`.
- **`.proxy` is imported lazily from `__init__`.** Not tidiness: importing it
  eagerly made runpy print a `RuntimeWarning` to stderr on every launch, and the
  proxy inherits the wrapped server's stderr. A logging sidecar that dirties the
  logs is a bad joke. Guarded by a test.

### Found while building

- The mutation harness's no-op guard fired twice, correctly, on mutations that
  proved nothing:
  1. The `reserialize` fidelity fault originally did `json.dumps(json.loads(f))`,
     which reproduced the echo server's own output byte-for-byte — a no-op. It now
     re-emits sorted + compact, which actually differs.
  2. The `one_row_per_call` mutation originally delivered every frame twice, and
     the row count did **not** change: popping the pending map makes the observer
     idempotent against duplicate delivery. Good property, useless mutation. The
     robustness is now its own test (`test_duplicate_response_delivery_does_not_
     double_row`) and the mutation is a log-as-you-see observer that really does
     break pairing.

  Both are the harness doing its job — a check that stays green on its own defect
  is decoration.

### Deliberately left for v1

- `--authority principal=...` — stamp `arcaeon_ledger.authority()` on every row.
- `--bind-inputs` — auto `bind_artefact` on input payloads.
- `--auto-pin N` — publish a head pin every N rows to a witness (this is the
  metered surface; the library itself stays free).
- Harness-hook recipe (`examples/claude_code_hooks/`) — catches built-ins the
  proxy is structurally blind to, at the cost of being per-harness config and
  cooperative-grade rather than infrastructure-grade.
- HTTP/gateway seam — the widest view of agent *intent*, and the most
  person-full; a hosted-tier feature, not a v0 move.
- Streamable-HTTP MCP transport. v0 is stdio only, which is the transport where
  a proxy is a config edit rather than a deployment.
- A `verify`-side reader that reports seam coverage across many session logs.
