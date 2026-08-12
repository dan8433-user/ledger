# Changelog

## 0.1.0 — 2026-08-12
- Initial release. Zero-dependency tamper-evident, hash-chained action log for AI agents.
- Core library: `Ledger(path).append(record)` and `.verify()`; module `verify_file(path)`.
- Hash chain: `sha256(prev_chain + canonical_json(row_without_chain))[:32]`, genesis-seeded, atomic append (append-binary + flush + fsync).
- CLI: `ledger verify|append` with nonzero exit on a broken chain (CI/pre-ship gate).
- MCP server (`python -m ledger.mcp_server`): drop-in `ledger_append` / `ledger_verify` tools for any MCP client, zero-dependency JSON-RPC over stdio.
- Tested against edit, delete, and reorder tampering, and a full MCP handshake including tamper detection over the wire.
