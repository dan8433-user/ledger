# arcaeon-ledger

<!-- mcp-name: io.arcaeon/ledger -->

**Observability tools show you what your agent did. `arcaeon-ledger` lets you _prove_ it.**

Every record is hash-chained to the one before it. Edit a row, delete one, or
reorder history, and every later link breaks — `verify` names the exact line.
You own the record, and you can prove it wasn't altered. Zero dependencies, one
JSONL file, two verbs.

```
pip install arcaeon-ledger      # then:  from arcaeon_ledger import Ledger
```

```python
from arcaeon_ledger import Ledger

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
python -m arcaeon_ledger.cli append agent.log.jsonl '{"tool":"search","ok":true}'
python -m arcaeon_ledger.cli verify agent.log.jsonl        # exit 0 = intact, 1 = broken
```

## Prove *who* acted, not just the order

A hash chain proves sequence integrity — it can't prove who wrote each entry or
whether they were allowed to. Attach an `authority` block to bind the actor and
their permission surface into the chained (tamper-evident) row:

```python
from arcaeon_ledger import Ledger, authority

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
exactly this. `arcaeon-ledger` is the smallest honest version: a cryptographically
chained action log you drop in, own, and verify.

## How the chain works

`chain = sha256(prev_chain + canonical_json(row_without_chain))[:32]`

The chain value is **`truncated_sha256_128`** — the first 32 hex chars (128 bits)
of SHA-256, not the full digest. Named so nobody cites it as full SHA-256:
128 bits is plenty for edit/accident detection, thinner if you want the chain
itself to be expensive to grind after a rewrite (credit: atomic-raven's review).

Each row commits to the entire history before it. The first row chains from a
fixed `"genesis"` seed. Rows without a `chain` field are tolerated only before
the first chained row (so you can adopt it on an existing log); an unchained row
appearing *after* the chain begins is itself flagged. On a mismatch, verify
keeps going from the claimed value so it counts later damage honestly instead of
cascading one break into noise.

## What it proves — and the three things it doesn't

Being precise here is the product, not a disclaimer. A hash chain proves the
recorded bytes were not altered *in place* after writing: mid-file edit, delete,
and reorder all break it and `verify` names the row. It does **not** by itself
prove three other things:

**1. Truncation.** Lop off the most recent rows and what remains verifies clean —
no append-only chain catches this alone. Close it by publishing the head somewhere
outside your own control, on a cadence:

```python
pin = log.head().as_pin()
# -> "arcaeon-ledger head chain=9f3c… rows=204 as_of=2026-08-13T17:40:00Z"
# post `pin` to a git commit / public comment / notarization anchor.
# a reader compares a fresh head() against the last pin; a truncated or
# re-minted history disagrees. the MAX gap between pins is your security
# parameter, not the average — an attacker picks the gap.
```

**2. Truth.** The chain notarizes whatever was written — a tamper-evident record
of a hallucination is still a hallucination with a checksum. To make a row speak
about the world, hash a re-fetchable artefact (URL+bytes, a snapshot, tool stdout)
and store that digest in the row, so a third party can re-get it and compare.

**3. Authorship.** `authority()` (above) records who-claimed-what, but it is data
in the row, not a signature — a rewriter who re-mints from genesis re-mints it too.
External head-anchoring (#1) is the thing a re-minter cannot advance.

Scoped honestly, the primitive is *"this file was not rewritten in place"* — small,
true, and testable. The layers above (external anchoring via `head()`, artefact
binding, signed authorship) are how you extend it toward a full evidence claim.

## Bind what the agent actually read (artefact-binding)

The chain proves a row wasn't edited. It does **not** prove the row was ever *true* —
it will notarize a hallucination as faithfully as a fact. `bind_artefact` closes
that gap for the cases where you can point at a re-fetchable source: hash the actual
bytes the agent read and store that digest *in* the row, so a third party can
re-get the source and compare.

```python
from arcaeon_ledger import Ledger, bind_artefact

log = Ledger("agent.log.jsonl")
art = bind_artefact("https://example.com/pricing")   # or bytes, a file path, or a dict
log.append({"tool": "web.read", "url": "https://example.com/pricing", "artefact": art})
# art -> {"subject": {"name": "...", "digest": {"sha256": "..."}},
#         "recipe": "sha256:raw-bytes:v1",
#         "digest": "sha256:raw-bytes:v1:<hex>", "bound_at": "...", "source_meta": {...}}
```

Digests are **self-describing** — never a bare hex hash. Each one is
`sha256:<recipe>:<version>:<hex>`, carrying its own recipe so a stranger reproduces
it from the string alone: `raw-bytes:v1` (opaque bytes as-read) or `json-c14n:v1`
(a pinned, documented JSON canonicalization — sorted keys, compact, UTF-8). Recipes
are frozen and versioned append-only, so old rows keep their recipe forever and a
changed rule never makes history look tampered.

Verify honestly:

```python
from arcaeon_ledger import verify_artefact

verify_artefact(art)                    # digest string well-formed + self-consistent
verify_artefact(art, refetch=True)      # for a URL: re-fetch and compare
# -> {"digest_ok": True, "refetch": "match" | "mismatch" | "unavailable", "notes": [...]}
```

**The honest boundary, stated loudly because it is the point:** a re-fetch
`mismatch` means the content *changed or* was tampered — **indeterminate**. It is
never reported as proof of tampering. The web mutates, 404s, paywalls, and
personalizes; binding proves *"this is the digest of the bytes the agent said it
read at time T,"* nothing stronger. For a neutral capture rather than your own
fetch, route the source through a notarizing snapshot; for *existed-before-T*, anchor
the digest externally. Each is a layer you add — stated, not implied.

## The outside check: an external witness

The chain can't catch truncation alone — lop off the most recent rows and what
remains verifies clean (stated in "what it doesn't prove", above). The fix is a
**witness**: a record-keeper outside your own control that holds your head
`(rows, chain)` on a cadence. Once a witness has a pin from time T, a truncated
log has *fewer rows* than the witness saw, and a rewritten one has a *different
chain* at the witnessed row. Neither can hide.

```python
from arcaeon_ledger import Ledger, WitnessStore, publish_head, verify_against_witness

log = Ledger("agent.log.jsonl")
witness = WitnessStore("witness_pins.jsonl")   # ideally on a host you don't control

publish_head(witness, "billing-agent", log)    # record the current head — do this on a cadence

# later — did the log survive intact?
v = verify_against_witness(witness, "billing-agent", log)
v.verdict     # "consistent" | "truncated" | "rewritten" | "no_record"
bool(v)       # truthy ONLY on "consistent" — a missing pin is no_record, never a false ok
```

`WitnessStore` is the reference witness: one append-only JSONL file of pins. A
hosted witness is a thin HTTP wrapper over exactly this object; run it locally
and you have a complete, offline, zero-cost witness you fully control (with the
obvious caveat that a witness you control is only as independent as its host).

**What this proves, exactly.** A witness proves your log wasn't truncated or
rewritten *only relative to what the witness saw, and only as recently as the
last pin*. Rows appended after the last pin are unprotected until the next one —
so **the MAX gap between pins is your real security parameter, not the average,
because an attacker picks the gap.** And it says nothing about whether the logged
content was *true* — that's artefact-binding's job (above); the witness only
guards the history's shape.

**What the witness holds.** Only fingerprints — `(namespace, rows, chain, time)` —
never your log content. Password-nowhere by design: if the witness is breached,
there is nothing sensitive to steal, only hashes useless without the original log.

## Drop it into any MCP agent

`arcaeon-ledger` ships a zero-dependency MCP server, so any MCP client (Claude Code,
etc.) can give its agent tamper-evident logging with no code. Wire it in:

```json
{
  "mcpServers": {
    "ledger": {
      "command": "python",
      "args": ["-m", "arcaeon_ledger.mcp_server", "--log", "agent.log.jsonl"]
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
running in production. External anchoring ships via `head()` (publish the pin
yourself) and the reference witness (`WitnessStore`, above); a hosted witness
tier (retention, automatic pin cadence, compliance export) is the next layer.

MIT.
