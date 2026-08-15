"""Property-based / fuzzing hardening for arcaeon_ledger.

Hand-written regression tests check the cases we already thought of. This file
attacks the core promise with thousands of RANDOM ledgers and RANDOM tampers,
hunting for any input where the promise breaks. The promise:

  1. GREEN on honest chains. For ANY sequence of appends (random content, sizes,
     unicode, control chars, huge rows, empty records, nested structures),
     verify() must be ok with breaks == 0 and rows == len(appends).
  2. RED on tamper. Any mutation that changes what the file semantically says —
     edit a chained row, delete a NON-tail row, reorder rows, tear the final
     line (mid-line truncation) — must make verify() ok == False with a named
     first_break.
  3. NEVER crashes. verify_file() must return a VerifyResult (a verdict), never
     raise, for ANY bytes on disk — random noise, bare scalars, NaN literals,
     torn lines, megabyte rows.

HONESTY ABOUT ONE NON-INVARIANT (this is design, not a gap): truncating whole
rows off the TAIL at a line boundary leaves a valid prefix chain that verifies
GREEN — a lone append-only chain cannot catch it (documented in the module
docstring). That gap is closed by external head-anchoring, so we assert the
faithful pair: verify() stays green on tail truncation, but a head pinned before
the truncation (chain_at / Head.rows) detects it. We do NOT assert the false
invariant "tail truncation is RED".

Run standalone for quotable counts:  python test_property_ledger.py
"""
from __future__ import annotations

import functools
import json
import os
import random
import string
import tempfile
from pathlib import Path

from arcaeon_ledger import Ledger, verify_file, chain_at, VerifyResult


def _no_fsync(fn):
    """Run `fn` with os.fsync noop'd, then restore it. fsync is durability, not
    verify-correctness; noop'ing it lets 5000+ on-disk ledgers build in seconds
    instead of minutes, and it changes no emitted bytes. SCOPED to the decorated
    call (restored in finally) so it never leaks into other tests in a shared
    pytest process."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        orig = os.fsync
        os.fsync = lambda _fd: None
        try:
            return fn(*a, **k)
        finally:
            os.fsync = orig
    return wrapper

SEED = int(os.environ.get("LEDGER_PROP_SEED", "20260815"))
N_ITER = int(os.environ.get("LEDGER_PROP_ITERS", "5000"))

_CTRL = [chr(c) for c in range(0, 32)]  # C0 control chars incl. \n \r \t \0
_UNI = ["café", "naïve", "日本語", "emoji🖤ok", "Ω≈ç√∫", "​zero-width",
        "𝕥𝕖𝕩𝕥", "line\nbreak", "tab\there", "null\x00byte", "quote\"inside",
        "back\\slash", "right-to-left‮", "\U0001F600"]


def _rand_text(rng: random.Random, big: bool = False) -> str:
    if big:  # exceed the 8 KB backward-scan window -> exercises _last_chain
        return rng.choice(_UNI) * rng.randint(3000, 6000)
    kind = rng.random()
    if kind < 0.15:
        return ""
    if kind < 0.35:
        return rng.choice(_UNI)
    if kind < 0.45:
        return "".join(rng.choice(_CTRL) for _ in range(rng.randint(1, 6)))
    n = rng.randint(1, 40)
    alphabet = string.printable + "".join(_UNI)
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_value(rng: random.Random, depth: int = 0):
    r = rng.random()
    if r < 0.28:
        return rng.randint(-10 ** 15, 10 ** 15)
    if r < 0.42:
        return round(rng.uniform(-1e9, 1e9), 6)        # finite float only
    if r < 0.55:
        return rng.choice([True, False, None])
    if r < 0.85 or depth >= 2:
        return _rand_text(rng)
    if r < 0.93:
        return [_rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {_rand_text(rng) or f"k{i}": _rand_value(rng, depth + 1)
            for i in range(rng.randint(0, 3))}


def _rand_record(rng: random.Random) -> dict:
    n = rng.randint(0, 5)
    rec: dict = {}
    for i in range(n):
        key = _rand_text(rng) or f"key{i}"
        rec[key] = _rand_value(rng)
    # Occasionally smuggle reserved-ish keys; append() strips 'chain', keeps 'ts'.
    if rng.random() < 0.1:
        rec["chain"] = "attacker-supplied-should-be-ignored"
    if rng.random() < 0.1:
        rec["ts"] = _rand_text(rng)
    return rec


def _build_ledger(rng: random.Random, path: Path) -> int:
    n = rng.randint(1, 8)
    for _ in range(n):
        log = Ledger(path)
        log.append(_rand_record(rng))
    if rng.random() < 0.12:                 # a genuinely huge row now and then
        Ledger(path).append({"blob": _rand_text(rng, big=True)})
        n += 1
    return n


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""),
                    encoding="utf-8", errors="surrogatepass")


def _semantic(lines: list[str]):
    """(row-minus-chain, claimed-chain) sequence — what verify() actually
    checks. Used only to distinguish a genuine content change from a byte flip
    that happens to round-trip to the identical rows (skip those as no-ops)."""
    out = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            out.append(("UNPARSEABLE", raw))
            continue
        if not isinstance(obj, dict):
            out.append(("NOTOBJ", raw))
            continue
        claimed = obj.pop("chain", None)
        out.append((json.dumps(obj, sort_keys=True, ensure_ascii=False), claimed))
    return out


# --- tamper operators: each returns mutated lines or None if inapplicable ----

def _t_edit_chain(lines, rng):
    """Flip one hex char of a chained row's chain value. Always semantic."""
    idxs = [i for i, ln in enumerate(lines) if '"chain":' in ln]
    if not idxs:
        return None
    i = rng.choice(idxs)
    obj = json.loads(lines[i])
    ch = obj.get("chain")
    if not isinstance(ch, str) or not ch:
        return None
    j = rng.randrange(len(ch))
    repl = rng.choice([c for c in "0123456789abcdef" if c != ch[j]])
    mutated = ch[:j] + repl + ch[j + 1:]
    new = lines[:]
    new[i] = lines[i].replace('"' + ch + '"', '"' + mutated + '"', 1)
    return new


def _t_flip_byte(lines, rng):
    """Flip one arbitrary character somewhere in a random line."""
    nonempty = [i for i, ln in enumerate(lines) if ln.strip()]
    if not nonempty:
        return None
    i = rng.choice(nonempty)
    ln = lines[i]
    j = rng.randrange(len(ln))
    repl = rng.choice(string.printable.strip() + "Zx9{}\"")
    if repl == ln[j]:
        repl = "~" if ln[j] != "~" else "Q"
    new = lines[:]
    new[i] = ln[:j] + repl + ln[j + 1:]
    return new


def _t_delete_nontail(lines, rng):
    """Delete a row that is NOT the last (tail deletion is documented-green)."""
    body = [i for i, ln in enumerate(lines) if ln.strip()]
    if len(body) < 2:
        return None
    i = rng.choice(body[:-1])           # never the final row
    return lines[:i] + lines[i + 1:]


def _t_swap(lines, rng):
    """Swap two distinct non-empty rows."""
    body = [i for i, ln in enumerate(lines) if ln.strip()]
    if len(body) < 2:
        return None
    a, b = rng.sample(body, 2)
    if lines[a] == lines[b]:
        return None
    new = lines[:]
    new[a], new[b] = new[b], new[a]
    return new


def _t_tear_last(lines, rng):
    """Mid-line truncation: cut the final row so its line is torn/partial."""
    body = [i for i, ln in enumerate(lines) if ln.strip()]
    if not body:
        return None
    i = body[-1]
    ln = lines[i]
    if len(ln) < 4:
        return None
    cut = rng.randrange(1, len(ln) - 1)  # strictly inside -> partial JSON
    new = lines[:]
    new[i] = ln[:cut]
    return new


_TAMPERS = [_t_edit_chain, _t_flip_byte, _t_delete_nontail, _t_swap, _t_tear_last]


@_no_fsync
def run_seeded_loop(n_iter=N_ITER, seed=SEED, verbose=False):
    rng = random.Random(seed)
    td = tempfile.mkdtemp(prefix="ledger_prop_")
    path = Path(td) / "l.jsonl"
    lock = Path(str(path) + ".lock")
    green = 0
    tampers_caught = 0
    default_caught = 0
    legacy_disguise = 0
    tampers_by_type = {t.__name__: 0 for t in _TAMPERS}
    crashes = 0
    for it in range(n_iter):
        for p in (path, lock):
            if p.exists():
                p.unlink()
        n_rows = _build_ledger(rng, path)
        # (1) honest chain must be GREEN, breaks==0, rows exact, no crash
        try:
            res = verify_file(path)
        except Exception as e:  # noqa: BLE001
            crashes += 1
            raise AssertionError(f"verify CRASHED on honest ledger it={it}: {e!r}")
        assert isinstance(res, VerifyResult)
        assert res.ok and res.breaks == 0, (
            f"honest ledger verified RED it={it}: ok={res.ok} "
            f"breaks={res.breaks} first={res.first_break}")
        assert res.rows == n_rows, f"row miscount it={it}: {res.rows} != {n_rows}"
        green += 1

        # honest genesis-chained ledger must ALSO be green under strict
        # (zero legitimate prechain rows), and never crash under strict.
        rs = verify_file(path, strict=True)
        assert rs.ok and rs.breaks == 0, (
            f"honest ledger RED under strict it={it}: {rs.first_break}")

        honest_lines = _read_lines(path)
        honest_sem = _semantic(honest_lines)

        # (2) each applicable tamper that CHANGES the content must be RED.
        # The real guarantee for a genesis-chained log is strict=True: it is RED
        # on EVERY semantic tamper. Default mode has ONE documented blind spot —
        # a tamper that disguises the LEADING row(s) as unchained "legacy"
        # history (module docstring, fabricated-legacy-prepend) — which strict
        # exists to close. We assert strict catches all, and record whether
        # default caught it too or hit exactly that documented carve-out.
        for t in _TAMPERS:
            mutated = t(honest_lines, rng)
            if mutated is None:
                continue
            if _semantic(mutated) == honest_sem:
                continue  # byte flip round-tripped to identical rows: a no-op
            _write_lines(path, mutated)
            try:
                r_strict = verify_file(path, strict=True)
                r_def = verify_file(path)
            except Exception as e:  # noqa: BLE001
                crashes += 1
                raise AssertionError(
                    f"verify CRASHED on tamper {t.__name__} it={it}: {e!r}")
            assert isinstance(r_strict, VerifyResult)
            assert not r_strict.ok and r_strict.breaks >= 1 and r_strict.first_break, (
                f"TAMPER NOT CAUGHT under strict ({t.__name__}) it={it}: verify "
                f"green on changed file. mutated={mutated!r}")
            tampers_caught += 1
            tampers_by_type[t.__name__] += 1
            if r_def.ok:
                # Permitted ONLY as the documented legacy-disguise: strict's
                # break must be an unchained/prechain rejection, never a real
                # chain mismatch that default somehow missed.
                fb = r_strict.first_break or ""
                assert ("unchained" in fb or "prechain" in fb), (
                    f"DEFAULT missed a non-legacy tamper ({t.__name__}) it={it}:"
                    f" strict break={fb!r} mutated={mutated!r}")
                legacy_disguise += 1
            else:
                assert r_def.breaks >= 1 and r_def.first_break
                default_caught += 1
            _write_lines(path, honest_lines)  # restore for next tamper
        if verbose and it % 1000 == 0:
            print(f"  ...{it}")
    return {"green": green, "tampers_caught": tampers_caught,
            "by_type": tampers_by_type, "crashes": crashes,
            "default_caught": default_caught, "legacy_disguise": legacy_disguise}


def test_property_honest_green_and_tamper_red():
    stats = run_seeded_loop()
    assert stats["crashes"] == 0
    assert stats["green"] == N_ITER
    assert stats["tampers_caught"] >= N_ITER  # many tampers per honest ledger
    # every tamper family must have fired at least once (coverage)
    for name, c in stats["by_type"].items():
        assert c > 0, f"tamper {name} never exercised"
    print(f"\n[ledger] {stats['green']}/{N_ITER} honest ledgers verified GREEN "
          f"(default+strict); {stats['tampers_caught']} tampers caught under "
          f"strict ({stats['by_type']}); of those {stats['default_caught']} "
          f"also caught by default, {stats['legacy_disguise']} were the "
          f"documented legacy-disguise (default-tolerated, strict-caught); "
          f"crashes={stats['crashes']}")


def test_tail_truncation_is_green_but_head_pin_catches_it():
    """The documented non-invariant, asserted faithfully: tail truncation at a
    line boundary verifies GREEN, and an externally-pinned head detects it."""
    rng = random.Random(SEED + 1)
    td = tempfile.mkdtemp(prefix="ledger_trunc_")
    path = Path(td) / "l.jsonl"
    caught_by_pin = green_after_trunc = 0
    for _ in range(300):
        for p in (path, Path(str(path) + ".lock")):
            if p.exists():
                p.unlink()
        n = 0
        for _ in range(rng.randint(3, 8)):
            Ledger(path).append(_rand_record(rng))
            n += 1
        pinned_rows = n
        pinned_chain = chain_at(path, pinned_rows)  # external witness pins this
        lines = _read_lines(path)
        keep = rng.randint(1, n - 1)                # drop >=1 tail row cleanly
        _write_lines(path, lines[:keep])
        res = verify_file(path)
        assert res.ok, "clean prefix must verify green (documented)"
        green_after_trunc += 1
        # the pin catches it: fewer rows now, and chain_at(pinned_rows) is gone
        assert chain_at(path, pinned_rows) != pinned_chain
        assert verify_file(path).rows < pinned_rows
        caught_by_pin += 1
    print(f"[ledger] tail-truncation: {green_after_trunc}/300 stayed green by "
          f"verify(), {caught_by_pin}/300 caught by external head pin")


def test_verify_never_crashes_on_arbitrary_bytes():
    """Fuzz the verifier with adversarial raw files; it must always return a
    verdict, never raise. Includes bare scalars, NaN/Infinity literals, random
    binary noise, torn lines, and huge lines."""
    rng = random.Random(SEED + 2)
    td = tempfile.mkdtemp(prefix="ledger_fuzz_")
    path = Path(td) / "f.jsonl"
    n = 3000
    for _ in range(n):
        pieces = []
        for _ in range(rng.randint(0, 6)):
            kind = rng.randrange(8)
            if kind == 0:
                pieces.append(json.dumps(_rand_record(rng)))
            elif kind == 1:
                pieces.append(rng.choice(["123", "true", "null", '"scalar"',
                                          "[1,2,3]", "NaN", "Infinity",
                                          "-Infinity", "{}"]))
            elif kind == 2:
                pieces.append("{broken json" + _rand_text(rng))
            elif kind == 3:
                pieces.append("")
            elif kind == 4:
                pieces.append(bytes(rng.randrange(256)
                                    for _ in range(rng.randint(0, 40))
                                    ).decode("latin-1"))
            elif kind == 5:
                pieces.append('{"chain":"' + "x" * rng.randint(0, 40) + '"}')
            elif kind == 6:
                pieces.append(_rand_text(rng, big=True))
            else:
                pieces.append('{"a":1,"chain":123}')  # non-string chain
        path.write_text("\n".join(pieces), encoding="utf-8",
                        errors="surrogatepass")
        try:
            res = verify_file(path)
            res2 = verify_file(path, strict=True)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"verify CRASHED on fuzz input {pieces!r}: {e!r}")
        assert isinstance(res, VerifyResult) and isinstance(res2, VerifyResult)
    print(f"[ledger] verify() returned a verdict on {n}/{n} adversarial raw "
          f"files, zero crashes")


if __name__ == "__main__":
    print(f"seed={SEED} iters={N_ITER}")
    s = run_seeded_loop(verbose=True)
    print(f"GREEN honest: {s['green']}/{N_ITER} (default+strict)")
    print(f"tampers caught under strict: {s['tampers_caught']} {s['by_type']}")
    print(f"  also caught by default: {s['default_caught']}; "
          f"documented legacy-disguise (strict-only): {s['legacy_disguise']}")
    print(f"crashes: {s['crashes']}")
    test_tail_truncation_is_green_but_head_pin_catches_it()
    test_verify_never_crashes_on_arbitrary_bytes()
    print("ALL PROPERTY CHECKS PASSED")
