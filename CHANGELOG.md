# Changelog

## 0.3.0 — 2026-08-13
- **Artefact-binding — `bind_artefact()` / `verify_artefact()`.** The move from "tamper-evident diary" toward "evidence layer": bind a re-fetchable fact to a row so a third party can check what the agent actually read, not just that the row wasn't edited. `bind_artefact(source)` accepts bytes, a URL (fetched + hashed with http metadata), a file path, or any JSON value; returns an in-toto-`subject`-shaped dict you chain into a ledger row. Directly answers the launch code-review (a hash chain notarizes a hallucination as faithfully as a fact — bind the source so the claim can be re-checked against it).
- **Self-describing, reproducible digests.** No bare hex ever. Every digest is `sha256:<recipe>:<ver>:<hex>`, carrying its own recipe so a stranger reproduces it from the string alone. Two recipes: `raw-bytes:v1` (opaque bytes as-read) and `json-c14n:v1` (a pinned, documented JSON canonicalization — sorted keys, compact, UTF-8, NaN/Inf rejected). Recipes are frozen and versioned append-only, so a future rule mints `v2` and old rows keep `v1` — a drifted canonicalizer never reads history as tampered. The recipe is deliberately **not** labelled RFC 8785/JCS: a stdlib serialization isn't bit-for-bit JCS on every float edge, and claiming a standard we don't exactly meet is the overclaim this library exists to refuse.
- **Honest verify semantics.** `verify_artefact()` always re-checks the digest string's self-consistency; with `refetch=True` on a URL it re-fetches and reports `match` / `mismatch` / `unavailable` — and a `mismatch` is documented as "content changed OR was tampered, INDETERMINATE," never a bare "tampered." The web mutates; a mismatch is not proof of foul play.
- `digest_bytes()` / `digest_json()` exported for the primitives directly.

## 0.2.1 — 2026-08-13
- **Import name fixed.** The package now imports as `arcaeon_ledger` (matching `pip install arcaeon-ledger`), instead of squatting the generic top-level name `ledger`. Both were flagged repeatedly by reviewers on launch — `pip install arcaeon-ledger; import arcaeon_ledger` now just works, and the CLI/MCP module paths are `arcaeon_ledger.cli` / `arcaeon_ledger.mcp_server`. (Breaking, but done now while adoption is ~0.)
- **`Ledger.head()` + `Head` — external anchoring shipped.** Returns the current chain head + row count + timestamp; `head().as_pin()` gives a one-line, publishable pin. Publishing it somewhere outside your control closes the **truncation gap** (chop the tail and the remainder still verifies — a property of every append-only chain). This was the single most-repeated reviewer critique; the fix is making the anchor a first-class, obvious step rather than a roadmap footnote.
- **Honesty pass on the docs.** README and module docstring now state plainly the three things a hash chain does *not* prove on its own — truncation, truth-of-content, and authorship — each with the concrete way to close it. Being precise about the boundary is the product.

## 0.2.0 — 2026-08-12
- Added `authority()` helper + `append(..., authority=...)`: bind WHO wrote each entry and with what permission (resolved principal, capability version, hashed tool schema, trusted time source). It chains like any field, so editing the writer identity breaks the chain too. Composes tamper-evidence with permission-replay. Shipped same-day in response to community feedback on launch.


## 0.1.0 — 2026-08-12
- Initial release. Zero-dependency tamper-evident, hash-chained action log for AI agents.
- Core library: `Ledger(path).append(record)` and `.verify()`; module `verify_file(path)`.
- Hash chain: `sha256(prev_chain + canonical_json(row_without_chain))[:32]`, genesis-seeded, atomic append (append-binary + flush + fsync).
- CLI: `ledger verify|append` with nonzero exit on a broken chain (CI/pre-ship gate).
- MCP server (`python -m arcaeon_ledger.mcp_server`): drop-in `ledger_append` / `ledger_verify` tools for any MCP client, zero-dependency JSON-RPC over stdio.
- Tested against edit, delete, and reorder tampering, and a full MCP handshake including tamper detection over the wire.
