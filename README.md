# ledger

**Observability tools show you what your agent did. `ledger` lets you _prove_ it.**

Every record is hash-chained to the one before it. Edit a row, delete one, or
reorder history, and every later link breaks — `verify` names the exact line.
You own the record, and you can prove it wasn't altered. Zero dependencies, one
JSONL file, two verbs.

```
pip install arcaeon-ledger
```

```python
from ledger import Ledger

log = Ledger("agent.log.jsonl")
log.append({"tool": "web.search", "query": "weather in LA", "result_ok": True})
log.append({"tool": "payment", "amount": "49.00", "currency": "USD"})

log.verify()          # VerifyResult(ok=True, rows=2, chained=2, ...)
```

Tampering is caught, not hoped against:

```python
# someone edits row 1's amount in the file by hand...
log.verify()          # VerifyResult(ok=False, first_break="line 1: chain mismatch")
```

CLI (wire it into CI or a pre-ship gate — a tampered log exits nonzero):

```
python -m ledger.cli append agent.log.jsonl '{"tool":"search","ok":true}'
python -m ledger.cli verify agent.log.jsonl        # exit 0 = intact, 1 = broken
```

## Prove *who* acted, not just the order

A hash chain proves sequence integrity — it can't prove who wrote each entry or
whether they were allowed to. Attach an `authority` block to bind the actor and
their permission surface into the chained (tamper-evident) row:

```python
from ledger import Ledger, authority

log = Ledger("agent.log.jsonl")
log.append(
    {"tool": "payment", "amount": "49.00"},
    authority=authority(
        "agent://billing-7",
        capability_version="v3",              # what they were allowed to do
        tool_schema={"name": "payment", "args": ["amount"]},  # hashed, not just named
        time_source="ntp",                    # trust surface of the clock
    ),
)
```

Now the audit question sharpens from *"was this edited?"* to *"was this edited
**and** was the writer authorized?"* — editing the principal, capability, or
schema hash breaks the chain like any other tamper. This composes tamper-evidence
with permission-replay. (Shipped in response to community feedback on launch.)

## Why this exists

The loudest unmet pain for agent builders in 2026 is the reliability/audit gap:
an agent "completes" a task and the result is quietly wrong, and you can't
reconstruct — or prove — what actually happened. Observability platforms trace
runs; none give you a **tamper-evident, portable, ownable** record. Regulations
(EU AI Act Art. 12, tamper-evident AI decision records) are starting to require
exactly this. `ledger` is the smallest honest version: a cryptographically
chained action log you drop in, own, and verify.

## How the chain works

`chain = sha256(prev_chain + canonical_json(row_without_chain))[:32]`

Each row commits to the entire history before it. The first row chains from a
fixed `"genesis"` seed. Rows without a `chain` field are tolerated only before
the first chained row (so you can adopt it on an existing log); an unchained row
appearing *after* the chain begins is itself flagged. On a mismatch, verify
keeps going from the claimed value so it counts later damage honestly instead of
cascading one break into noise.

The honest limit: `ledger` proves a file wasn't altered *after* writing. It does
not prove the writer was honest at write time, and it does not by itself defend
against someone who rewrites the whole chain from a chosen point forward — for
that you periodically anchor the latest chain value somewhere you don't control
(a commit, a timestamp service, a witness). That anchoring is on the roadmap;
the core tamper-evidence is here and tested.

## Drop it into any MCP agent

`ledger` ships a zero-dependency MCP server, so any MCP client (Claude Code,
etc.) can give its agent tamper-evident logging with no code. Wire it in:

```json
{
  "mcpServers": {
    "ledger": {
      "command": "python",
      "args": ["-m", "ledger.mcp_server", "--log", "agent.log.jsonl"]
    }
  }
}
```

The agent then has two tools: `ledger_append(record)` to log an action
(returns its chain hash) and `ledger_verify()` to prove the whole log is
intact (or get the exact tampered line back). MCP is JSON-RPC over stdio and
this server speaks it directly — no SDK, no extra install.

## Status

Core library, CLI, and a drop-in **MCP server**, all tested: the library
against edit / delete / reorder tampering (`test_ledger.py`), the MCP server
through a full initialize → tools/list → append → verify handshake including
tamper detection over the wire. Extracted from a hash-chained action ledger
running in production. A hosted collection tier (retention + compliance export)
and periodic external anchoring are the next layers.

MIT.
