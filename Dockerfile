# arcaeon-ledger MCP server — minimal image for Glama's build/introspection checks.
#
# The server speaks MCP (JSON-RPC 2.0) over stdio: no network port, no runtime
# dependencies (stdlib only). This image just needs the package installed and
# a command that starts arcaeon_ledger.mcp_server, which then answers
# `initialize` / `tools/list` / `tools/call` on stdin/stdout.
#
# Local build/run verification: Docker is STILL not available in this
# environment. Re-checked 2026-08-19 — `docker`, `go` and `task` are all absent
# on the host, and the WSL Ubuntu-22.04 image has no docker either. So this
# file remains syntax-reviewed, not build-tested. It follows the same minimal
# pip-install pattern as every other stdio MCP server image; nothing here needs
# compilation (arcaeon-ledger has zero third-party deps).
#
# What HAS been verified, on 2026-08-19, is the part most likely to be wrong:
# the pinned version resolves on PyPI and the ENTRYPOINT command starts and
# answers MCP. Untested remains the container layer itself.
#
# The pin was 0.5.6 while the repo shipped 0.5.7, because 0.5.7 had been
# committed and pushed but never PUBLISHED — one unpublished artefact silently
# left this image a version behind the code it claims to package. Fixed by
# publishing 0.5.7 rather than by editing the number. See scar #91.

FROM python:3.12-slim

RUN pip install --no-cache-dir arcaeon-ledger==0.5.8

WORKDIR /app

# Ledger file lives inside the container's writable layer by default; mount a
# volume at /app if the log should persist across container restarts:
#   docker run -i -v ledger-data:/app arcaeon-ledger-mcp
ENTRYPOINT ["python", "-m", "arcaeon_ledger.mcp_server", "--log", "/app/agent.log.jsonl"]
