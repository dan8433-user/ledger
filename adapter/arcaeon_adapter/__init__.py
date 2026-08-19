# SPDX-License-Identifier: MIT
"""arcaeon-adapter — infrastructure-grade action logging at the MCP stdio seam.

`arcaeon-ledger` proves a record wasn't altered. It cannot prove the record is
*complete*, because `append()` records whatever a caller chooses to pass: the
agent holds the pen. This package moves the pen into the pipe the agent's actions
flow through — a stdio proxy, in its own OS process, that sees every `tools/call`
and every response at the protocol level and writes a hash-chained row per pair
without the agent's cooperation, knowledge, or consent.

    python -m arcaeon_adapter.proxy --ledger seam.log.jsonl -- <mcp server command...>
    python -m arcaeon_adapter.selftest        # every claimed check, observed failing

The honest limit travels with the claim, always: an adapter on one seam logs that
seam completely and nothing else. A direct HTTP call, an un-wrapped server, or a
shell command never crosses this proxy and never lands in this ledger. This is
not a lock. It is a neighborhood.
"""
from __future__ import annotations

from typing import Any

from ._version import IMPL, VERSION
from .observer import SEAM, FrameSplitter, SeamObserver

__version__ = VERSION
__all__ = ["SEAM", "IMPL", "VERSION", "__version__",
           "FrameSplitter", "SeamObserver", "main", "relay", "run"]

# `proxy` is imported LAZILY, and that is load-bearing rather than tidy.
# `python -m arcaeon_adapter.proxy` runs this package's __init__ first; if we
# imported .proxy here, runpy would then find it already in sys.modules and print
#     RuntimeWarning: 'arcaeon_adapter.proxy' found in sys.modules ...
# to STDERR — on every single launch. The proxy inherits the wrapped server's
# stderr, so that warning lands in the customer's server log, from a tool whose
# entire pitch is that it changes nothing about how their server behaves. A
# logging sidecar that dirties the logs is a bad joke. PEP 562 lazy attributes
# keep `from arcaeon_adapter import run` working without the import at load time.
_LAZY = {"main", "relay", "run"}


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from . import proxy
        return getattr(proxy, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list:
    return sorted(__all__)
