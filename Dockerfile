# arcaeon-ledger MCP server — minimal image for Glama's build/introspection checks.
#
# The server speaks MCP (JSON-RPC 2.0) over stdio: no network port, no runtime
# dependencies (stdlib only). This image just needs the package installed and
# a command that starts arcaeon_ledger.mcp_server, which then answers
# `initialize` / `tools/list` / `tools/call` on stdin/stdout.
#
# Local build/run verification: Docker was not available in this environment
# (checked 2026-08-16 — `docker --version` and `Get-Command docker` both
# failed), so this file is syntax-reviewed, not build-tested. It follows the
# same minimal pip-install pattern as every other stdio MCP server image;
# nothing here needs compilation (arcaeon-ledger has zero third-party deps).

FROM python:3.12-slim

RUN pip install --no-cache-dir arcaeon-ledger==0.5.6

WORKDIR /app

# Ledger file lives inside the container's writable layer by default; mount a
# volume at /app if the log should persist across container restarts:
#   docker run -i -v ledger-data:/app arcaeon-ledger-mcp
ENTRYPOINT ["python", "-m", "arcaeon_ledger.mcp_server", "--log", "/app/agent.log.jsonl"]
