# SPDX-License-Identifier: MIT
"""arcaeon-adapter — an MCP stdio proxy that records every tool call without the agent's help.

    python -m arcaeon_adapter.proxy --ledger seam.log.jsonl -- <server command...>

Wire it in by wrapping the server's command in your MCP client config; no code
changes anywhere, and the agent is not consulted:

    "ledger": { "command": "python",
      "args": ["-m", "arcaeon_adapter.proxy", "--ledger", "seam.log.jsonl", "--",
               "python", "-m", "arcaeon_ledger.mcp_server", "--log", "agent.log.jsonl"] }

WHY THIS EXISTS
---------------
`Ledger.append()` records whatever a caller chooses to pass it. That is a diary.
It is useful, and it is self-report: an agent that skips the append leaves no
trace, and an agent that curates its appends leaves a flattering one. Any regime
that asks for *automatic* recording of events over a system's lifetime (EU AI Act
Art. 12(1) is the one on our desk) cannot be satisfied by a library the logged
party calls voluntarily.

MCP stdio is the seam where "no cooperation required" is literally true. The
client and the server talk newline-delimited JSON-RPC over a pipe. Sit in that
pipe, in your own OS process, and every `tools/call` and every response is
visible at the protocol level — in a process the agent does not own, cannot
introspect, and cannot silence by choosing not to call a function.

THE P0 PROPERTY: FIDELITY BEFORE OBSERVATION
--------------------------------------------
A proxy that corrupts, reorders, or delays a customer's JSON-RPC is worse than no
proxy. So this file is built around one invariant:

    bytes are forwarded FIRST, and observed SECOND, from a copy.

Concretely:
  * Both directions are raw binary the whole way. No text mode anywhere — on
    Windows a text-mode stream would rewrite "\\n" as "\\r\\n" and every frame
    would arrive subtly altered.
  * Chunks are relayed exactly as read: no reframing, no re-serialization, no
    pretty-printing, no whitespace normalization. We never parse a frame and
    re-emit it; the classic proxy bug is `json.dumps(json.loads(frame))`, which
    is semantically identical and byte-different, and `selftest` deliberately
    turns that bug on to prove the fidelity check can go red.
  * One thread per direction, each with a single destination, so ordering within
    a direction is the OS's ordering and cannot be shuffled by us.
  * The child's stderr is inherited, not piped — it goes straight to our stderr
    on the same fd. Nothing to copy, nothing to deadlock, and the client's server
    logs look exactly as they did unwrapped.
  * Unparseable frames are relayed untouched and simply not logged. A server that
    prints a stray line to stdout keeps working.
  * Exit code is the child's exit code. A wrapped server that dies of status 2
    must look to the client like a server that died of status 2.

WHAT IT WRITES
--------------
One row per completed `tools/call` request/response pair, to its own seam ledger
(`--ledger`) — deliberately a DIFFERENT file from any ledger the wrapped server
writes. Mixing them muddies provenance and invites two processes appending to one
file. Plus `session_begin` / `session_end` brackets, and `mcp_initialize` /
`tools_list` rows when that handshake crosses the pipe.

Rows carry digests, not payloads, by default: `sha256:json-c14n:v1:<hex>` over
the arguments and the result. That proves *which* bytes crossed the seam without
turning an audit log into a warehouse of everyone's data. `--raw` embeds payloads
for deployers who own that risk.

THE HONEST LIMIT
----------------
An adapter on one seam logs that seam completely — and nothing else. An agent can
still act around it: a direct HTTP call, an un-wrapped MCP server, a shell
command never crosses this proxy and never hits this ledger. The second-set-of-
books problem does not go away; no logging layer can force total honesty. What
this guarantees is narrower and real: everything that crossed the instrumented
seam is in the record, automatically, and the record proves itself. Honesty is
forced at the seams, not everywhere — not a lock, a neighborhood.

No network calls at runtime. Stdlib only, plus `arcaeon-ledger` when installed
(and a documented, byte-compatible fallback writer when it isn't).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from ._ledger import backend, open_ledger
from ._version import IMPL, VERSION
from .observer import DEFAULT_MAX_FRAME, FrameSplitter, SeamObserver

__all__ = ["main", "run", "relay", "IMPL", "VERSION"]

#: How much we try to move per read. Not a frame limit — a frame spanning many
#: reads is reassembled by FrameSplitter for observation, while the relay simply
#: forwards each chunk as it arrives.
CHUNK = 65536

#: Harness-only fault injection. `selftest` sets this to prove the fidelity check
#: can actually go red; a check never observed failing is decoration. When set,
#: the proxy shouts on stderr, because a corrupting proxy must never run quietly.
FAULT_ENV = "ARCAEON_ADAPTER_SELFTEST_CORRUPT"


# -- fault injection (test harness only) -------------------------------------

class _Corruptor:
    """Deliberately damages relayed bytes. Only ever constructed when FAULT_ENV is set.

    Modes:
      `reserialize` — parse each frame and re-emit it canonicalized (`sort_keys`,
        compact separators). Semantically identical, byte-different: the exact bug
        a fidelity test exists to catch, and the one a well-meaning implementer
        writes on purpose ("I'll just normalize it while I'm in here"). Note the
        compact/sorted form is REQUIRED for this fault to bite — a plain
        `json.dumps(json.loads(frame))` reproduces most servers' own output
        byte-for-byte and would make the mutation a no-op, which the harness's
        no-op guard caught the first time this was written the lazy way.
      `drop_byte`   — truncate the last byte of each chunk. Coarse corruption.
      `strip_newline` — remove frame delimiters, destroying framing while keeping
        every content byte. Catches a check that compares content but not shape.
    """

    MODES = ("reserialize", "drop_byte", "strip_newline")

    def __init__(self, mode: str):
        if mode not in self.MODES:
            raise ValueError(f"unknown fault mode {mode!r}; expected one of {self.MODES}")
        self.mode = mode
        self._split = FrameSplitter() if mode == "reserialize" else None

    def feed(self, chunk: bytes) -> bytes:
        if self.mode == "drop_byte":
            return chunk[:-1]
        if self.mode == "strip_newline":
            return chunk.replace(b"\n", b"")
        out = bytearray()
        for frame in self._split.feed(chunk):
            try:
                out += json.dumps(json.loads(frame.decode("utf-8")), sort_keys=True,
                                  separators=(",", ":")).encode("utf-8")
            except (ValueError, UnicodeDecodeError):
                out += frame
            out += b"\n"
        return bytes(out)

    def close(self) -> bytes:
        if self._split is None:
            return b""
        return b"".join(f + b"\n" for f in self._split.close())


# -- the relay ---------------------------------------------------------------

def _read_some(stream, n: int) -> bytes:
    """One read that returns as soon as ANY bytes are available.

    `BufferedReader.read(n)` blocks until it has all n bytes or hits EOF, which
    in a proxy is a deadlock: we would sit on a complete request waiting for a
    buffer to fill while the server waits for the request. `read1` is the
    "give me what you have" call. A raw FileIO has no `read1` but its `read` is
    already a single syscall, so the fallback is correct rather than a guess.
    """
    read1 = getattr(stream, "read1", None)
    if read1 is not None:
        return read1(n)
    return stream.read(n)


def relay(src, dst, observe=None, *, on_eof=None, corruptor=None,
          max_frame: int = DEFAULT_MAX_FRAME, splitter=None) -> None:
    """Pump `src` -> `dst` byte-faithfully, handing a copy of each frame to `observe`.

    The order of operations in the loop body IS the safety property: write, flush,
    then observe. Observation happens after the bytes are already gone, so no
    parsing cost sits on the latency path and no parsing defect can alter or
    withhold traffic. Any exception from `observe` is swallowed for the same
    reason — a logging bug must never become a transport failure.

    Pass `splitter=` to own the FrameSplitter from outside, which is how the caller
    reads its `dropped_oversize` counter after the thread is done — a gap in the
    log must be reportable, not merely survivable.

    Exits on EOF from `src`, or on a broken pipe to `dst` (the peer died; there is
    nothing useful left to do but let the caller reap it).
    """
    if observe is None:
        splitter = None            # nothing to hand frames to; don't buffer for nobody
    elif splitter is None:
        splitter = FrameSplitter(max_frame=max_frame)
    try:
        while True:
            chunk = _read_some(src, CHUNK)
            if not chunk:
                break
            out = corruptor.feed(chunk) if corruptor is not None else chunk
            if out:
                dst.write(out)
                dst.flush()
            if splitter is not None:
                for frame in splitter.feed(chunk):
                    try:
                        observe(frame)
                    except Exception:
                        pass  # observation is never allowed to break transport
    except (BrokenPipeError, OSError, ValueError):
        # ValueError = "write to closed file": the other side of the proxy already
        # tore down. Both are normal shutdown races, not errors worth surfacing.
        pass
    finally:
        if corruptor is not None:
            try:
                tail = corruptor.close()
                if tail:
                    dst.write(tail)
                    dst.flush()
            except Exception:
                pass
        if splitter is not None:
            for frame in splitter.close():
                try:
                    observe(frame)
                except Exception:
                    pass
        if on_eof is not None:
            try:
                on_eof()
            except Exception:
                pass


# -- session wiring ----------------------------------------------------------

def _server_label(command: list[str]) -> str:
    """A short, human-meaningful name for the wrapped server.

    `python -m arcaeon_ledger.mcp_server --log x` should read as
    "arcaeon_ledger.mcp_server", not "python" — every row names this, and "python"
    would be useless in a log covering three wrapped servers.
    """
    if not command:
        return "unknown"
    for i, tok in enumerate(command):
        if tok == "-m" and i + 1 < len(command):
            return command[i + 1]
    return Path(command[0]).stem or command[0]


def run(command: list[str], ledger_path: str, *, server: str | None = None,
        session: str | None = None, raw: bool = False,
        max_frame: int = DEFAULT_MAX_FRAME,
        stdin=None, stdout=None) -> int:
    """Spawn `command`, proxy stdio through it, log the seam. Returns the child's exit code."""
    log = open_ledger(ledger_path)
    label = server or _server_label(command)
    obs = SeamObserver(log.append, server=label, session=session, raw=raw, impl=IMPL)

    fault = os.environ.get(FAULT_ENV)
    corruptor = None
    if fault:
        corruptor = _Corruptor(fault)
        sys.stderr.write(
            f"arcaeon-adapter: WARNING {FAULT_ENV}={fault} is set; this process is "
            f"DELIBERATELY CORRUPTING relayed bytes. Test harness only.\n")
        sys.stderr.flush()

    obs.session_begin(
        adapter_version=VERSION,
        ledger_backend=backend(),
        command=list(command),
        command_digest=_digest(command),
        cwd=os.getcwd(),
        pid=os.getpid(),
        raw_payloads=raw,
        fault_injected=fault or None,
    )

    cin = stdin if stdin is not None else _binary_stdin()
    cout = stdout if stdout is not None else _binary_stdout()

    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,   # inherited: the wrapped server's diagnostics stay where they were
            bufsize=0,     # unbuffered binary pipes; buffering is latency we can't justify
        )
    except OSError as e:
        sys.stderr.write(f"arcaeon-adapter: cannot start server {command!r}: {e}\n")
        obs.session_end(reason="spawn_failed", exit_code=127, error=str(e))
        return 127

    def close_child_stdin():
        """Client hung up: pass the hangup on, which is how an MCP server is told to exit."""
        try:
            child.stdin.close()
        except Exception:
            pass

    up_split = FrameSplitter(max_frame=max_frame)
    down_split = FrameSplitter(max_frame=max_frame)
    up = threading.Thread(
        target=relay, args=(cin, child.stdin, obs.observe_client_frame),
        kwargs={"on_eof": close_child_stdin, "splitter": up_split},
        name="adapter-client-to-server", daemon=True)
    down = threading.Thread(
        target=relay, args=(child.stdout, cout, obs.observe_server_frame),
        kwargs={"corruptor": corruptor, "splitter": down_split},
        name="adapter-server-to-client", daemon=True)
    up.start()
    down.start()

    reason = "child_exit"
    try:
        code = child.wait()
        # The child is gone; drain whatever it wrote before dying, then stop. The
        # downstream thread is the one holding those bytes, so joining it (briefly)
        # before we return is what keeps the last response from being lost.
        down.join(timeout=5.0)
    except KeyboardInterrupt:
        reason = "interrupt"
        try:
            child.terminate()
        except Exception:
            pass
        code = child.wait()
        down.join(timeout=5.0)

    # `up` is a daemon blocked on a stdin read that may never return; we do not
    # join it. Its only remaining job (closing the child's stdin) is moot now.
    orphans = obs.flush_pending(reason=f"session_ended:{reason}")
    # An oversized frame is relayed but NOT logged. That is a real hole in the
    # record, so it rides out in `session_end` rather than staying our secret: a
    # reviewer seeing a nonzero count knows the seam log is incomplete and by how
    # many frames. Omitted entirely when zero, so the field's presence is the
    # signal.
    oversize = up_split.dropped_oversize + down_split.dropped_oversize
    obs.session_end(reason=reason, exit_code=code, unanswered=orphans or None,
                    oversize_frames_unlogged=oversize or None)
    return code


def _digest(value) -> str:
    from ._ledger import digest_json
    return digest_json(value)


def _binary_stdin():
    return getattr(sys.stdin, "buffer", sys.stdin)


def _binary_stdout():
    return getattr(sys.stdout, "buffer", sys.stdout)


# -- CLI ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m arcaeon_adapter.proxy",
        description="Record every MCP tool call at the stdio seam, without the agent's help.",
        epilog="Everything after -- is the MCP server command to wrap.")
    ap.add_argument("--ledger", required=True,
                    help="seam ledger path (keep this SEPARATE from any ledger the "
                         "wrapped server writes: one file, one writer, clean provenance)")
    ap.add_argument("--server", default=None,
                    help="label for the wrapped server in every row (default: derived "
                         "from the command)")
    ap.add_argument("--session", default=None,
                    help="session id (default: a fresh uuid4 per proxy process)")
    ap.add_argument("--raw", action="store_true",
                    help="embed raw argument and result payloads in rows. OFF by "
                         "default: digest-only rows are person-free, and an audit "
                         "log that silently accumulates everyone's data is a "
                         "liability. Turn this on only where you own that risk.")
    ap.add_argument("--max-frame", type=int, default=DEFAULT_MAX_FRAME,
                    help="frames larger than this are relayed but not logged "
                         f"(default {DEFAULT_MAX_FRAME})")
    ap.add_argument("--version", action="version", version=IMPL)
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="-- <server command...>")
    args = ap.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        ap.error("no server command given; usage: --ledger PATH -- <server command...>")

    return run(command, args.ledger, server=args.server, session=args.session,
               raw=args.raw, max_frame=args.max_frame)


if __name__ == "__main__":
    sys.exit(main())
