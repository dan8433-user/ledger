"""ledger CLI — verify or append from the command line.

    python -m ledger.cli verify agent.log.jsonl
    python -m ledger.cli append agent.log.jsonl '{"tool":"search","ok":true}'

Exit code 0 = chain intact, 1 = broken (or bad usage). The nonzero exit is the
point: wire `verify` into CI or a pre-ship gate and a tampered log fails loud.
"""
from __future__ import annotations

import json
import sys

from ledger import Ledger, verify_file


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in ("verify", "append"):
        print((__doc__ or "usage: ledger verify|append <path> [record]").strip())
        return 1
    cmd, path = argv[0], argv[1]
    if cmd == "verify":
        r = verify_file(path)
        print(json.dumps(r.__dict__, indent=1))
        return 0 if r.ok else 1
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
