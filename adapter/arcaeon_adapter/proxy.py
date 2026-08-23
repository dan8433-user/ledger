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
import re
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
                        # Observation is never allowed to break transport — but a
                        # swallowed failure must still be a COUNTED failure, or an
                        # observer that raises on every frame produces a session_end
                        # indistinguishable from a clean run.
                        splitter.observe_failures += 1
    except (BrokenPipeError, OSError, ValueError):
        # ValueError = "write to closed file": the other side of the proxy already
        # tore down. Usually a normal shutdown race — but a read-side I/O error
        # lands here too, so it is counted rather than presumed benign. The count
        # rides out in `session_end`; the reader decides what it meant.
        if splitter is not None:
            splitter.relay_errors += 1
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
                    splitter.observe_failures += 1  # same contract as the loop above
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

    # The command line is redacted BEFORE it reaches the row. `command_digest` is
    # taken over the ORIGINAL argv, so the record still pins exactly what was run
    # for anyone who can supply the command and wants to check it, while the file
    # itself carries no credential. Digesting the redacted form instead would have
    # been the quieter bug: the row would verify against nothing real.
    safe_command, redactions = _redact_argv(list(command))
    obs.session_begin(
        adapter_version=VERSION,
        ledger_backend=backend(),
        command=safe_command,
        command_redactions=redactions or None,
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

    # `up` may be a daemon blocked on a stdin read that never returns, so this
    # join is BOUNDED: it exists to close the race between the up thread's last
    # counter increments (a write can complete, then the bookkeeping be preempted
    # past the child's exit) and the counter reads below — not to wait on a client
    # that hasn't hung up. If the timeout expires, the counters are read anyway:
    # best-effort figures beat blocking shutdown on a dead session.
    up.join(timeout=1.0)
    orphans = obs.flush_pending(reason=f"session_ended:{reason}")
    # An oversized frame is relayed but NOT logged. That is a real hole in the
    # record, so it rides out in `session_end` rather than staying our secret: a
    # reviewer seeing a nonzero count knows the seam log is incomplete and by how
    # many frames. Omitted entirely when zero, so the field's presence is the
    # signal. `observe_failures` and `relay_errors` get the identical treatment,
    # because a swallowed exception is the same kind of hole as a dropped frame:
    # survivable, and only honest if declared.
    oversize = up_split.dropped_oversize + down_split.dropped_oversize
    observe_failures = up_split.observe_failures + down_split.observe_failures
    relay_errors = up_split.relay_errors + down_split.relay_errors
    obs.session_end(reason=reason, exit_code=code, unanswered=orphans or None,
                    oversize_frames_unlogged=oversize or None,
                    observe_failures=observe_failures or None,
                    relay_errors=relay_errors or None)
    return code


def _digest(value) -> str:
    from ._ledger import digest_json
    return digest_json(value)


#: A name whose VALUE is a credential. Matched against the NAME half of both
#: `--api-key=X` and the dashless `API_KEY=X`, because a secret is defined by the slot
#: it sits in rather than by how the value looks.
_SECRET_NAME = re.compile(
    r"^(?:key"  # bare `key`, EXACT match only: `--key` is how Google's own docs pass an
                # API key, but the word must not reach into `--keyboard` or `MY_KEY` —
                # substring-matching "key" is how `--no-auth` got eaten by "auth".
    # Every other word must sit at SEPARATOR boundaries: any prefix ends at `_./-`
    # and any suffix begins at one. `auth-token`, `API_TOKEN`, `x-auth` still match;
    # `--authors` and `--oauth` no longer do — the 2026-08-21 audit found "auth"
    # matching INSIDE "authors" and the token after it eaten, the same substring sin
    # the bare-`key` comment above already names. `authorization` is spelled out
    # because the boundary rule would otherwise lose it.
    r"|(?:[\w.-]*[_.-])?"
    r"(?:api[_-]?key|apikey|secret|password|passwd|token|bearer|auth(?:orization)?"
    r"|credentials?|private[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?key)"
    r"(?:[_.-][\w.-]*)?)$", re.I)

#: Names that MATCH _SECRET_NAME but do NOT carry a secret. This list is the fix for the
#: redactor damaging its own record: `--no-auth` contains "auth", so the first cut treated
#: the following token as a credential and blanked it. The result was a row saying a
#: credential had been stripped, sitting next to a destroyed flag, describing a server
#: launched with authentication DISABLED. A wrong record in an evidence file is worse than
#: an unredacted one, because it is confidently wrong.
_NOT_A_SECRET_SLOT = re.compile(
    r"^--?(?:no|not|disable|without|skip|allow|require|use|enable)[_-]"      # --no-auth
    r"|[_-](?:mode|file|path|dir|type|format|env|name|id|header|method|url|scheme"
    r"|source|provider|algorithm|alg|required|enabled|disabled)$", re.I)

#: Values recognizable as credentials wherever they sit. Deliberately shape-based and
#: deliberately a BONUS: the name rules above are the defence. The underscore forms are
#: prefix-sufficient (nothing else on a command line begins `sk_live_`), but the hyphen
#: `sk-` prefix is NOT — every current LLM vendor issues it AND the Python ecosystem
#: publishes package names under it, and the 2026-08-21 audit caught
#: `pip install sk-learn-extras` recorded as credential-stripped. So `sk-` lives in
#: `_SK_CANDIDATE` below and `_looks_like_secret_value` finishes the call, demanding
#: the length and character mixture a real issued key always has.
_SECRET_VALUE = re.compile(
    r"^(?:sk_live_|sk_test_|rk_live_|whsec_"
    r"|ghp_|gho_|ghu_|ghs_|github_pat_"
    r"|xox[baprs]-|glpat-|dop_v1_|shpat_|SG\.[A-Za-z0-9_-]{10,}"
    r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{10,}"                               # Google API key
    r"|eyJ[A-Za-z0-9_-]{10,}\."                              # a JWT
    r"|-----BEGIN)", re.I)

#: An `sk-` token that MIGHT be an OpenAI/Anthropic-style key — or might be a package
#: name. `_looks_like_secret_value` decides which.
_SK_CANDIDATE = re.compile(r"^sk-[A-Za-z0-9_-]{2,}$", re.I)

#: A short plain dictionary-shaped word: letters only, all lowercase after an optional
#: leading capital, twelve characters or fewer — `none`, `basic`, `google`, `oidc`.
#: What a credential-NAMED flag's value must NOT look like before it is eaten:
#: "auth" names a TOPIC as often as it names a secret, and `--auth none` is a server
#: with authentication DISABLED. The first cut blanked that `none` and wrote the exact
#: false record `_NOT_A_SECRET_SLOT`'s comment describes — a credential-stripped row
#: over an auth-off launch. Real credentials carry length, digits, case mixture, or
#: punctuation; a bare short word carries configuration. A password that happens to BE
#: a short dictionary word will now survive in the record, and that is the accepted
#: direction of error: fabricating a redaction is worse than missing one.
_MODE_WORD = re.compile(r"^[A-Za-z][a-z]{0,11}$")

#: Header names whose value is a credential, for `--header "Authorization: Bearer X"`.
_SECRET_HEADER = re.compile(
    r"^\s*(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token"
    r"|x-access-token|cookie|set-cookie|x-amz-security-token|private-token)\s*$", re.I)

#: Query-string parameters carrying a credential inside an otherwise useful URL. `key` is
#: listed explicitly: `?key=` is Google's standard API-key parameter and the first cut's
#: pattern required the literal `apikey`/`api_key`, so a bare `key=` leaked.
_SECRET_QS = re.compile(
    r"([?&](?:key|apikey|api[_-]key|access[_-]?key|secret|client[_-]secret|token"
    r"|private[_-]token|access[_-]token|id[_-]token|refresh[_-]token|password|passwd"
    r"|auth|credential|sig|signature|x-goog-api-key)=)[^&\s]+", re.I)

#: user:password@host in a URL.
#: user:pass@host OR password-only :pass@host in a URL. The username segment is
#: OPTIONAL (`*` not `+`): redis and mongo commonly use `scheme://:password@host`,
#: and an auditor found the with-username form redacted while the password-only
#: form leaked. Both must go.
_URL_USERINFO = re.compile(r"(://)[^/@\s:]*:[^/@\s]+@")

REDACTED = "<redacted>"


def _looks_like_secret_slot(name: str) -> bool:
    """Does a credential belong in the slot called `name`?"""
    if _NOT_A_SECRET_SLOT.search(name):
        return False
    return bool(_SECRET_NAME.match(name.lstrip("-")))


def _looks_like_secret_value(tok: str) -> bool:
    """Is this token, by its own shape, recognizably a credential?

    Most prefixes decide by themselves (`ghp_`, `AKIA`, `AIza`). The `sk-` prefix
    cannot: real issued keys share it with published package names. A real key is
    long (the shortest current vendor form is well past 20 characters) and carries
    digits or mixed case; `sk-learn-extras` is short, lowercase, and digitless.
    Demand the former before calling an sk- token a secret.
    """
    if _SK_CANDIDATE.match(tok):
        return len(tok) >= 20 and (
            any(c.isdigit() for c in tok)
            or (tok.lower() != tok and tok.upper() != tok))
    return bool(_SECRET_VALUE.match(tok))


def _plausible_credential(tok: str) -> bool:
    """May a value sitting in a credential-NAMED slot be redacted as a secret?

    Yes when it is secret-shaped, or when it is anything other than a short
    dictionary word. `--auth none`, `--auth basic`, `--auth=none` keep their mode
    words — see `_MODE_WORD` for why that asymmetry is the honest one.
    """
    return _looks_like_secret_value(tok) or not _MODE_WORD.match(tok)


def _redact_argv(command):
    """Strip credentials out of a wrapped server's command line.

    Why this is not optional. This adapter is wired in by wrapping somebody else's launch
    command, and launch commands routinely carry live secrets. That array is written into
    the `session_begin` row in the DEFAULT digest-only mode, into a file whose whole
    purpose is to be copied into an evidence bundle and handed to a third-party auditor.

    Detection, in descending order of how much it can be trusted:

      1. A value in a credential-NAMED slot, in either form: `--api-key X`,
         `--token=X`, and — the one that matters most in practice — the DASHLESS
         `API_KEY=X`, which is how `docker run -e`, `env`, and most MCP client configs
         actually pass secrets. Names are checked against a negative list first, so a
         flag that merely CONTAINS a credential word without carrying one (`--no-auth`,
         `--auth-mode`, `--api-key-file`) is left alone.
      2. A credential inside an HTTP header argument (`--header "Authorization: ..."`).
      3. A value whose own shape is a known credential kind. A bonus, never the defence.
      4. A credential in a URL query string, or userinfo in a URL, replaced in place so
         the rest of the URL survives and stays useful.

    TWO WAYS THIS CAN BE WRONG, AND ONLY ONE OF THEM IS SAFE. Failing to redact leaks a
    key. Redacting the wrong thing writes a FALSE RECORD: the first version of this
    function saw "auth" inside `--no-auth`, blanked the token after it, and produced a
    row claiming a credential had been stripped from a server that was in fact launched
    with authentication turned off. A confidently wrong evidence file is worse than an
    unredacted one, so the value-consuming path now refuses to eat anything that starts
    with `-`, refuses slots on the negative list, refuses names that only contain a
    credential word as a SUBSTRING (`--authors` is not `--auth`), and refuses values
    that are plain short dictionary words (`--auth none` is a server with auth
    DISABLED, and `none`/`basic`/`google` are configuration, not credentials).

    STATED LIMITS, because a redactor that quietly misses a class manufactures confidence.
    It cannot recognise a credential in an arbitrarily-named slot (`--k9 hunter2`), or a
    bare high-entropy value in no slot at all with no recognisable prefix. It reads only
    `argv`; a secret passed through the actual process environment is never seen by this
    function and is never logged by this adapter either — note that `-e NAME=VALUE` is
    ARGV, not the environment, and IS covered, which is a correction to what an earlier
    version of this docstring claimed. The guidance is unchanged and is the real control:
    **do not put secrets on a command line.** Redaction is a second line, not a licence.

    Returns the cleaned argv and the number of substitutions made, so the row can declare
    that redaction occurred rather than leaving a reader to guess whether a clean-looking
    command was clean or scrubbed.
    """
    out = []
    hits = 0
    expect_secret_for = None
    for tok in command:
        tok = tok if isinstance(tok, str) else str(tok)

        # A pending credential slot from the previous token.
        if expect_secret_for is not None:
            expect_secret_for = None
            # Never consume another flag: `--token --verbose` means the flag took no
            # value, and blanking `--verbose` would delete configuration and invent a
            # credential that was never there. And never consume a MODE WORD:
            # `--auth none` / `--auth basic` / `--oauth google` say HOW a thing is
            # configured, and eating the word records an auth-disabled server as a
            # credential-stripped one — the false-record class again, found live by
            # the 2026-08-21 audit. Only a token that could plausibly BE a
            # credential is eaten; anything spared falls through and is processed
            # like any other token.
            if not tok.startswith("-") and _plausible_credential(tok):
                out.append(REDACTED)
                hits += 1
                continue

        # NAME=VALUE, with or without leading dashes. Covers `--token=X` and the
        # dashless `API_KEY=X` that the first version of this function never inspected.
        if "=" in tok:
            name, _, value = tok.partition("=")
            # The mode-word exemption applies here too: `--auth=none` states the
            # same disabled-auth fact as `--auth none`, and the record must keep it.
            if value and _looks_like_secret_slot(name) and _plausible_credential(value):
                out.append("%s=%s" % (name, REDACTED))
                hits += 1
                continue
            # The NAME is innocent but the VALUE half is a recognisable credential:
            # `MY_KEY=sk_live_...`, `GH_PAT=ghp_...`. The whole-token _SECRET_VALUE
            # check below is anchored at the token's START, so a value sitting after
            # `NAME=` was never inspected at all — which meant the value-shape rule,
            # the one defence that works when the slot name says nothing, went blind
            # exactly where secrets most often sit. Redact the value half only; the
            # name stays, because the name is audit-relevant and not a secret.
            if value and _looks_like_secret_value(value):
                out.append("%s=%s" % (name, REDACTED))
                hits += 1
                continue

        # `Authorization: Bearer x` arriving as one argument.
        if ":" in tok and not tok.startswith("-"):
            hname, _, hvalue = tok.partition(":")
            if hvalue.strip() and _SECRET_HEADER.match(hname):
                out.append("%s: %s" % (hname, REDACTED))
                hits += 1
                continue

        # A bare flag naming a credential: the VALUE is the next token.
        if tok.startswith("-") and "=" not in tok and _looks_like_secret_slot(tok):
            out.append(tok)
            expect_secret_for = tok
            continue

        if _looks_like_secret_value(tok):
            out.append(REDACTED)
            hits += 1
            continue

        cleaned = _URL_USERINFO.sub(r"\1%s:%s@" % (REDACTED, REDACTED), tok)
        cleaned = _SECRET_QS.sub(r"\1%s" % REDACTED, cleaned)
        if cleaned != tok:
            hits += 1
        out.append(cleaned)
    return out, hits


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
