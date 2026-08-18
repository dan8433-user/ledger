# SPDX-License-Identifier: MIT
"""ledger CLI - verify or append from the command line.

    python -m arcaeon_ledger.cli verify agent.log.jsonl
    python -m arcaeon_ledger.cli verify --strict agent.log.jsonl
    python -m arcaeon_ledger.cli append agent.log.jsonl '{"tool":"search","ok":true}'
    python -m arcaeon_ledger.cli --help | --version

Exit codes for `verify` (wire it into CI or a pre-ship gate):
  0 = fully verified — EVERY row checked, chain intact.
  1 = broken (a break was found), or bad usage.
  3 = verified WITHIN SCOPE only: no break found, but unchained `prechain`
      rows were skipped UNVERIFIED (non-strict mode). The JSON report says how
      many (`prechain`) and stamps `verified_scope:
      "bounded_prechain_skipped"`; `ok` is null, not true. A fabricated
      "legacy" prepend lands here, not at 0 — a gate that treats only exit 0
      as green fails loud on it. Pass --strict to make any unchained row a
      hard failure (exit 1) instead.

The nonzero exits are the point: a tampered log fails loud, and a log the
verifier could only PARTIALLY vouch for no longer exits identically to a fully
verified one.
"""
from __future__ import annotations

import json
import sys

from arcaeon_ledger import Ledger, __version__, verify_file


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = (__doc__ or "usage: ledger verify|append <path> [record]").strip()
    # asking for help is not a usage error: it prints usage and exits 0.
    if argv and argv[0] in ("-h", "--help"):
        print(usage)
        return 0
    if argv and argv[0] == "--version":
        print(f"arcaeon-ledger {__version__}")
        return 0
    strict = "--strict" in argv
    argv = [a for a in argv if a != "--strict"]
    if len(argv) < 2 or argv[0] not in ("verify", "append"):
        print(usage)
        return 1
    cmd, path = argv[0], argv[1]
    if cmd == "verify":
        r = verify_file(path, strict=strict)
        print(json.dumps(r.__dict__, indent=1))
        if r.ok is True:
            return 0        # fully verified
        if r.ok is None:
            return 3        # no break, but prechain rows skipped unverified
        return 1            # broken
    # append
    if len(argv) < 3:
        print("append needs a JSON record argument")
        return 1
    try:
        record = json.loads(argv[2])
    except ValueError as e:
        print(f"bad JSON: {e}")
        return 1
    if not isinstance(record, dict):
        print("record must be a JSON object")
        return 1
    chain = Ledger(path).append(record)
    print(chain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
