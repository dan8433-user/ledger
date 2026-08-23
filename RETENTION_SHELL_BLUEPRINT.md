# Retention Shell — Architecture Blueprint

**Target:** `C:\Users\USER\arcaeon-ledger` (arcaeon-ledger, stdlib-only, MIT, current `__version__ = "0.5.9"`)

## 0. Patterns & conventions found (grounding the design)

- **Three-valued verdicts, never a bare bool.** Every check result is a dataclass with `ok: bool | None` and a `__bool__` that's truthy *only* on `True` — `VerifyResult` (`C:\Users\USER\arcaeon-ledger\arcaeon_ledger\__init__.py:247-283`), `WitnessVerdict` (`witness.py:45-67`), `WitnessVerify` (`witness.py:74-90`). A container being non-empty/truthy while the verdict inside says no is the recurring class of bug this repo has found and fixed repeatedly (0.5.7, 0.5.8, 0.5.9). Any new result type must follow this shape.
- **Self-chained secondary stores, proven pattern.** `WitnessStore` (`witness.py:92-317`) is exactly "an append-only JSONL sidecar whose own records are hash-chained" — each record carries `prev` (digest of the record before it) *and* `self` (digest of its own content), because a pure back-chain can't protect the tail record (the 0.5.9 fix, born from a demonstrated-red review). This is the mechanism to reuse for the retention manifest, not reinvent.
- **Reserved write-side fields:** `append()` (`__init__.py:313-413`) reserves `ts`, `chain`, `authority` on every row; everything else is caller-defined freeform `dict`. No `kind`/`type` discriminator exists yet anywhere in the core ledger.
- **`authority()` helper** (`__init__.py:221-244`) is the existing "who did this, with what permission" block — reused as-is for "who set this policy" / "what ran this expiry job."
- **Cross-process file locking** via a sidecar `<path>.lock` (`_append_lock`, `witness.py`-adjacent in `__init__.py:158-219`) — `msvcrt` on Windows, `fcntl` on POSIX, bounded 15s wait, degrades to unlocked rather than failing the write. This is the only locking primitive in the repo; new mutating operations should reuse it, not invent a second one.
- **Atomic write + landed-bytes confirmation.** Every write path (`append()`, `WitnessStore.record()`) confirms `tell()` after writing and raises a typed error (`LedgerWriteError(OSError)`) rather than returning a plausible success over a Windows reserved-device-name write-black-hole. New writers (tombstones, manifest records) must do the same.
- **CLI shape:** each capability owns its **own** `python -m arcaeon_ledger.<module>` entry point with a `main(argv)` + `if __name__ == "__main__"` — `cli.py` (verify/append), `bundle.py` (its own exporter CLI), `selftest.py`, `mutation_harness.py`. There is no monolithic subcommand dispatcher. New retention verbs get their own module-level CLI, not a bolt-on to `cli.py`.
- **Export already exists** — `bundle.py` (`C:\Users\USER\arcaeon-ledger\arcaeon_ledger\bundle.py`) builds a self-contained, offline-verifiable auditor bundle (`build_bundle`) for **one** ledger file: verbatim copy + `verify_report.json` + optional witness fetch + `README.txt` (explicitly stating what's proved and what isn't, plus the Art. 19(1)/26(6) legal-context paragraph) + `MANIFEST.json` (sha256 of every bundle file). The Retention Shell's export requirement is "the same idea, multi-segment" — reuse its primitives (`verify_file`, `Head`, the witness fetcher), don't reuse its directory-writing internals (avoid nested-bundle awkwardness), and never touch `bundle.py` itself (zero regression risk on the most externally-relied-on path).
- **Demonstrated-red discipline, twice-shipped.** `selftest.py` plants real tampers and demands the *exact* `first_break` string back (golden vectors, planted unsupported-recipe labels, planted witness truncation/rewrite, planted ledger tampering with a GREEN control run first). `mutation_harness.py` goes further: every claimed check gets a `case_*` function that (1) proves GREEN on a clean fixture, (2) proves the mutation actually mutated (no-op guard), (3) proves RED with the named verdict. The CHANGELOG's own words: *"a check that has never been seen red is a decoration."* The Retention Shell must ship the same two files' worth of coverage for its own new guarantees — this is not optional polish, it's the project's stated bar.
- **"Known limits, stated as limits, not instructions."** Every guarantee ships with an explicit, sometimes uncomfortable, boundary statement (README's "what it proves — and the five things it doesn't"; CHANGELOG's "Known limits, unchanged or newly named"). The Retention Shell must ship its own such section.
- **Stdlib only, Windows-first.** `msvcrt`/`fcntl` dual path, `os.replace` semantics, `pathlib.Path` throughout, no third-party deps (`pyproject.toml:20` — `dependencies = []`).
- **`pyproject.toml`** (`C:\Users\USER\arcaeon-ledger\pyproject.toml`): `[tool.hatch.build.targets.wheel] packages = ["arcaeon_ledger"]`; version lives in two places kept in sync (`pyproject.toml` + `__init__.py:80`), bumped **last**, after upload, per the 0.5.9 CHANGELOG note ("pins deliberately not bumped until the release lands").

## 1. Architecture decision

**The tension (keep ≥6mo / delete promptly) is resolved by operating retention at the *segment* level, never the row level**, and by reusing the ledger's own chain for tamper-evidencing policy and disposal events instead of inventing new chained state:

1. **Policy** is declared as ordinary chained rows *inside* the ledger itself (`kind: "arcaeon.retention.policy"`). No new tamper-evidence mechanism needed — a policy row is just a row, and the existing chain already makes editing it detectable. This is the single biggest simplification available and it's free.
2. **Rotation** seals the live JSONL into an immutable numbered segment file and opens a fresh live file. Segments are **not** row-chained to each other (rejected: would require poking a `genesis` override into `Ledger`/`_chain`/`verify_file`, the most reviewed and fragile code in the repo, for a benefit the manifest already delivers). Instead, a **`RetentionManifestStore`** — a byte-for-byte reuse of `WitnessStore`'s proven `prev`+`self` double-digest pattern — chains the *lifecycle events* (`segment_opened` / `segment_sealed` / `segment_expired`) into one spine. Continuity is proven by cross-checking each manifest-recorded head against the real segment file, which also catches the "whole-file swap" attack that a per-file `verify_file()` alone cannot see (a swapped-in wrong-but-internally-clean file verifies green on its own).
3. **Expiry** deletes a whole sealed segment, never individual rows — row-level deletion inside a hash chain is structurally impossible without breaking everything after it anyway, so the unit of disposal must be the unit of chaining: the segment. Before deletion, a **tombstone row** (`kind: "arcaeon.retention.tombstone"`) is appended to the live ledger, carrying the doomed segment's head/hash/policy citation. Deletion only proceeds after the tombstone is confirmed landed. Absence is then always accompanied by a chained record explaining it — and `verify_all()` treats any segment missing from disk with **no** matching tombstone+manifest-expiry pair as a hard break: *undocumented deletion*, not a silent gap.
4. **Export** composes the existing `verify_file`/`Head`/witness primitives across every present segment plus the manifest plus the reconstructed policy/tombstone history into one offline-verifiable bundle — deliberately *not* reusing `build_bundle()`'s directory-writing internals, so `bundle.py` stays completely untouched.

This buys: additive-only changes (zero edits to `__init__.py`'s `_chain`/`verify_file`/`Ledger` internals), reuse of an already-reviewed chaining pattern (`WitnessStore`), and a verify story that composes cleanly (`verify_file` per segment + `RetentionManifestStore.verify()` for the spine + one new cross-check function) rather than inventing a fourth digest scheme.

**Rejected alternative (documented, not silently dropped):** a literal cross-file chain (segment N+1's first row hashes segment N's tail via a `Ledger(genesis=...)` override). Stronger single-hash-spans-everything story, but touches `_chain`/`_last_chain`/`verify_file` — the code with the most demonstrated-red history in the repo — for a property the manifest already delivers via independent cross-checking. Not worth the risk surface for a v1. Revisit only if an auditor specifically demands a single monotone hash across all history.

## 2. Component design

### 2.1 `arcaeon_ledger/retention.py` — new module (Policy engine + Rotation + Expiry, the mechanical core)

```python
# --- policy -------------------------------------------------------------
_CLOCK_STARTS = {"segment_sealed_at", "segment_oldest_row_ts", "segment_newest_row_ts"}
_ART19_FLOOR_DAYS = 183   # ~6 months — the number Art. 19(1)/26(6) names

class RetentionPolicyError(ValueError): ...   # mirrors LedgerWriteError(OSError)

@dataclass
class RetentionPolicy:
    policy_id: str
    min_keep_days: int
    max_keep_days: int | None = None          # None = no declared ceiling (never auto-expires)
    clock_start: str = "segment_sealed_at"     # one clock governs BOTH bounds (documented tradeoff, see §6)
    category: str | None = None                # None = default/catch-all
    citation: str = "EU AI Act Art. 19(1) / Art. 26(6)"
    rationale: str | None = None
    effective_from: str = field(default_factory=_now_iso)
    supersedes_chain: str | None = None        # chain hash of the policy row this amends

    def validate(self) -> list[str]:
        """Named problems (never raises): 'min_exceeds_max', 'non_positive_min_keep',
        'unknown_clock_start', 'below_art19_floor' (advisory only)."""

def set_policy(ledger: Ledger, policy: RetentionPolicy, *, authority: dict | None = None,
               allow_floor_violation: bool = False) -> str:
    """Appends a `kind: "arcaeon.retention.policy"` row to `ledger`. Returns chain hash.
    Hard-refuses (RetentionPolicyError) on min_exceeds_max / non_positive_min_keep /
    unknown_clock_start ALWAYS. 'below_art19_floor' refuses UNLESS allow_floor_violation=True
    — and when overridden, the row records the caller's literal value, never silently
    clamped back up to 183."""

def current_policy(store: "SegmentStore", *, category: str | None = None,
                    as_of: str | None = None) -> RetentionPolicy | None:
    """Walks manifest-ordered segments (sealed oldest->newest, live last) for policy
    rows matching `category` (falling back to category=None); last-one-wins in ledger
    order, same rule as WitnessStore.latest(). `as_of` reconstructs the policy that
    was ACTUALLY IN FORCE at a past timestamp."""

def policy_history(store: "SegmentStore", *, category: str | None = None) -> list[RetentionPolicy]:
    """Every policy row for `category`, in ledger order — the audit trail of the
    policy itself, tamper-evident for free via the underlying chain."""


# --- rotation -------------------------------------------------------------
_RETENTION_GENESIS = "retention-manifest-genesis"   # distinct seed, mirrors witness's own

class RetentionManifestStore:
    """Chained spine of segment lifecycle events. prev+self double digest,
    copied verbatim from WitnessStore's 0.5.9 mechanism (same reasoning:
    prev catches deletion/reorder, self catches a tail-edit prev can't see)."""
    def __init__(self, path: str | Path): ...
    def record_opened(self, seq: int, segment_path: Path, *, opened_at: str | None = None) -> dict: ...
    def record_sealed(self, seq: int, segment_path: Path, head: Head, *,
                       first_row_ts: str | None, last_row_ts: str | None,
                       sealed_at: str | None = None) -> dict: ...
    def record_expired(self, seq: int, segment_path: Path, *, policy_id: str,
                        policy_row_chain: str, tombstone_chain: str,
                        expired_at: str | None = None) -> dict: ...
    def verify(self) -> "ManifestVerify": ...   # same shape as WitnessStore.verify()
    def segments(self) -> list[dict]: ...        # reconstructed lifecycle table
    def history(self) -> list[dict]: ...

class RotationError(OSError): ...   # mirrors LedgerWriteError

@dataclass
class RotationResult:
    rotated: bool
    sealed_seq: int | None
    sealed_path: Path | None
    new_live_seq: int
    reason: str

class SegmentStore:
    """<base_dir>/live.jsonl, <base_dir>/segments/seg-NNNNNN.jsonl,
    <base_dir>/retention_manifest.jsonl — created on first use."""
    def __init__(self, base_dir: str | Path): ...
    @property
    def live(self) -> Ledger: ...
    @property
    def manifest(self) -> RetentionManifestStore: ...

    def rotate(self, *, reason: str = "scheduled", now: str | None = None,
               witness: "WitnessStore | None" = None,
               witness_namespace: str | None = None) -> RotationResult:
        """Refuses (RotationError) if live.jsonl does not currently verify (ok
        not True and not the legit empty/None-empty case). 0-row live segment
        is a no-op (rotated=False) — an empty seal is manifest noise with no
        reader. Order: verify -> os.replace(live -> segments/seg-NNNNNN) ->
        record_sealed -> create fresh live.jsonl -> record_opened -> (optional)
        publish_head(witness, ...) on the newly sealed segment."""

    def segments(self) -> list["SegmentRecord"]: ...

    def verify_all(self, *, strict: bool = False) -> "SegmentStoreVerify": ...


# --- expiry -----------------------------------------------------------
@dataclass
class ExpiryResult:
    segment_seq: int
    expired: bool
    reason: str
    tombstone_chain: str | None
    dry_run: bool

def expire_due(store: SegmentStore, *, category: str | None = None,
               now: str | None = None, dry_run: bool = False,
               witness: "WitnessStore | None" = None,
               authority: dict | None = None) -> list[ExpiryResult]:
    """For every SEALED (never live) segment: resolve policy -> compute age from
    policy.clock_start (using the manifest's cached first/last_row_ts, no rescan)
    -> if max_keep_days is None: never eligible -> if age >= max_keep_days AND
    age >= min_keep_days (independent, unconditional floor gate, checked here
    regardless of what max_keep_days claims): tombstone, then delete.
    A segment that fails strict verify is SKIPPED with expired=False and the
    reason stated — never raises, never touches an unverifiable segment,
    doesn't abort the whole batch over one bad segment."""

@dataclass
class SegmentStoreVerify:
    ok: bool | None
    segments_checked: int = 0
    manifest_ok: bool | None = None
    breaks: int = 0
    first_break: str | None = None
    unexplained_absences: list[int] = field(default_factory=list)
    def __bool__(self) -> bool: return self.ok is True
```

**Tombstone row schema** (appended to `store.live`, `kind: "arcaeon.retention.tombstone"`):
```json
{
  "kind": "arcaeon.retention.tombstone",
  "segment_seq": 4,
  "segment_path_was": "segments/seg-000004.jsonl",
  "segment_sha256": "<sha256 of full file bytes, computed immediately pre-delete>",
  "segment_head": {"chain": "...", "rows": 812, "as_of": "..."},
  "first_row_ts": "...", "last_row_ts": "...",
  "policy_id": "default", "policy_row_chain": "<chain of the authorizing policy row>",
  "policy_citation": "min_keep satisfied (Art 19(1)/26(6) floor); max_keep ceiling applied",
  "min_keep_days": 183, "max_keep_days": 365, "age_days_at_expiry": 366,
  "clock_start": "segment_sealed_at", "clock_start_value": "2026-02-01T00:00:00Z",
  "expired_at": "..."
}
```
Ordering (crash-safety rule, stated explicitly): **append the tombstone row and confirm it landed *before* deleting the segment file.** A crash between the two leaves an over-cautious state (tombstone exists, file still present — safe, re-checkable). The reverse order would leave a genuine, undetectable gap — exactly what this feature exists to prevent.

**Reserved-field note (new convention, flag explicitly):** the Retention Shell introduces a `kind` discriminator on rows it writes, values namespaced `arcaeon.retention.*`. This is additive (arbitrary caller rows never had a reserved `kind` before) but should be called out in README/CHANGELOG so callers know not to use `kind` values starting with `arcaeon.` for their own rows.

### 2.2 `arcaeon_ledger/retention_bundle.py` — new module (Export)

```python
@dataclass
class RetentionBundleResult:
    out_path: Path
    is_zip: bool
    segments_included: list[int]
    segments_expired: list[int]
    verify_ok: bool | None
    manifest: dict = field(default_factory=dict)

def build_retention_bundle(store: SegmentStore, *, out: str | Path | None = None,
                            namespace_prefix: str | None = None,
                            fetcher: Callable[[str], tuple[int, bytes]] | None = None,
                            generation_command: str | None = None) -> RetentionBundleResult:
    """Self-contained, offline-verifiable bundle:
      live/<copy of live.jsonl (or a stated-empty notice)>
      segments/seg-NNNNNN.jsonl        (every segment still on disk, verbatim)
      retention_manifest.jsonl          (verbatim copy of the chained spine)
      policy_history.json               (policy_history() output, machine+human readable)
      expired_segments.json             (every arcaeon.retention.tombstone row found —
                                          summary fields ONLY, never the deleted content,
                                          since it doesn't exist to include)
      verify_report.json                (per-segment strict verify_file + manifest.verify()
                                          + the cross-segment head-match check, i.e. the
                                          SegmentStoreVerify body)
      witness_<seq>.json (optional, per namespace_prefix:seg-NNNNNN, only when fetched)
      README.txt                        (mirrors bundle.py's style: what's proved, what
                                          isn't, PLUS retention-specific honest boundaries
                                          — see §6)
      MANIFEST.json                     (sha256 of every bundle file — mirrors bundle.py)
    Reuses verify_file / Head / the witness fetcher directly — does NOT call
    bundle.build_bundle() (avoids nested-bundle awkwardness; bundle.py stays untouched)."""

def main(argv: list[str] | None = None) -> int: ...
    # python -m arcaeon_ledger.retention_bundle <base_dir> [--out DIR|ZIP] [--namespace-prefix NS]
    # exit 0 = bundle written (even over a red verdict — evidence of breakage is
    # still evidence); 1 = usage error or bundle could not be written.
```

### 2.3 CLI verbs (own `main(argv)` in `retention.py`, matching `bundle.py`'s self-contained-CLI convention)

```
python -m arcaeon_ledger.retention policy-set <base_dir> --min-keep-days 183 [--max-keep-days 365]
       [--category NAME] [--citation TEXT] [--rationale TEXT] [--clock-start NAME]
       [--allow-floor-violation]
python -m arcaeon_ledger.retention policy-show <base_dir> [--category NAME] [--as-of ISO]
python -m arcaeon_ledger.retention rotate <base_dir> [--reason TEXT]
       [--witness PATH --namespace NS]
python -m arcaeon_ledger.retention expire <base_dir> [--category NAME] [--dry-run]
python -m arcaeon_ledger.retention status <base_dir> [--json]
python -m arcaeon_ledger.retention verify <base_dir> [--strict]
```
Exit codes mirror `cli.py`'s 0/1/3 convention for `verify`/`status`. `expire`: 0 = ran (even if zero segments were eligible), 1 = usage error; a segment that fails strict verify is *skipped and reported*, never a hard failure for the whole run (bounded blast radius, per `ExpiryResult`).

### 2.4 `arcaeon_ledger/__init__.py` — additive re-export block

Appended at the **end**, after `Ledger`/`Head`/`chain_at`/`verify_file` are defined, matching the existing witness/artefact re-export placement (`__init__.py:683-693`) and the reason stated there (avoid partially-initialized-module import order issues):

```python
from arcaeon_ledger.retention import (
    RetentionPolicy, RetentionPolicyError, set_policy, current_policy, policy_history,
    RetentionManifestStore, SegmentStore, SegmentRecord, RotationResult, RotationError,
    ExpiryResult, expire_due, SegmentStoreVerify,
)
```
`__all__` (`__init__.py:81-83`) extended with the same names. `__version__` bumped to `"0.6.0"` — **last commit of the release**, after upload, per the 0.5.9 CHANGELOG's own stated discipline ("pins deliberately not bumped until the release lands").

## 3. Files to create / modify

| Path | Change |
|---|---|
| `C:\Users\USER\arcaeon-ledger\arcaeon_ledger\retention.py` | **new** — Policy engine + `RetentionManifestStore` + `SegmentStore`/rotation + `expire_due` + CLI `main()` |
| `C:\Users\USER\arcaeon-ledger\arcaeon_ledger\retention_bundle.py` | **new** — `build_retention_bundle` + CLI `main()` |
| `C:\Users\USER\arcaeon-ledger\arcaeon_ledger\__init__.py` | **modify** — additive re-export block at EOF, `__all__` extended, `__version__` bump (last step) |
| `C:\Users\USER\arcaeon-ledger\pyproject.toml` | **modify** — version bump only, matching `__init__.py` (last step) |
| `C:\Users\USER\arcaeon-ledger\test_retention_policy.py` | **new** — step 1 |
| `C:\Users\USER\arcaeon-ledger\test_retention_manifest.py` | **new** — step 2 |
| `C:\Users\USER\arcaeon-ledger\test_retention_rotation.py` | **new** — step 3 |
| `C:\Users\USER\arcaeon-ledger\test_retention_expiry.py` | **new** — step 5 |
| `C:\Users\USER\arcaeon-ledger\test_retention_verify_all.py` | **new** — step 6 |
| `C:\Users\USER\arcaeon-ledger\test_retention_cli.py` | **new** — step 7 |
| `C:\Users\USER\arcaeon-ledger\test_retention_bundle.py` | **new** — step 8 |
| `C:\Users\USER\arcaeon-ledger\arcaeon_ledger\selftest.py` | **modify** — additive `"== retention shell planted tampering =="` section, step 9 |
| `C:\Users\USER\arcaeon-ledger\arcaeon_ledger\mutation_harness.py` | **modify** — additive `case_retention_*` functions, step 9 |
| `C:\Users\USER\arcaeon-ledger\README.md` | **modify** — new "Retention Shell" section, step 10 |
| `C:\Users\USER\arcaeon-ledger\CHANGELOG.md` | **modify** — 0.6.0 entry naming every defect found during build, step 10 |

No existing file's *behavior* changes; `__init__.py`'s edit is pure addition at the end of the file.

## 4. Data flow

1. Caller creates `SegmentStore(base_dir)` → `store.live` is a normal `Ledger`, used exactly as today (`log.append(...)`).
2. Caller calls `set_policy(store.live, RetentionPolicy(...))` → a chained `arcaeon.retention.policy` row lands; tamper-evidenced for free.
3. On a cadence (cron/scheduler, outside this library's scope — matches how `publish_head` is "call this on a cadence" today), caller calls `store.rotate(witness=..., witness_namespace=...)` → live segment sealed into `segments/seg-NNNNNN.jsonl`, `RetentionManifestStore` gets a `segment_sealed` record (head + first/last row ts cached), fresh `live.jsonl` opened, `segment_opened` recorded, optional witness pin published on the now-sealed segment.
4. On a cadence, caller calls `expire_due(store)` → for each sealed segment: `current_policy(store, category=...)` resolves the applicable policy → age computed from cached manifest fields (no rescan) → if `age >= max_keep_days and age >= min_keep_days`: tombstone row appended to `store.live` and confirmed landed → segment file deleted → `segment_expired` manifest record written, cross-referencing the tombstone's chain hash.
5. On demand, `store.verify_all()` composes: `RetentionManifestStore.verify()` (spine integrity) + `verify_file(strict=True)` on every segment still present + a head-match cross-check (manifest-recorded head vs. recomputed `head()`/`chain_at()` on the real file, catching whole-file swaps) + a completeness check (every manifest `segment_sealed` seq with no on-disk file must have a matching tombstone+`segment_expired` pair, else `unexplained_absences`).
6. On demand (e.g., regulator ask), `build_retention_bundle(store, out=..., namespace_prefix=...)` produces one offline-checkable directory/zip covering every present segment, the manifest, the reconstructed policy and tombstone history, and a combined verify report.

## 5. Build sequence (each step independently shippable)

- [ ] **Step 1 — Policy engine.** `retention.py`: `RetentionPolicy`, `RetentionPolicyError`, `set_policy`, `current_policy`/`policy_history` operating over a *single* `Ledger` (defer multi-segment walk to step 4). `test_retention_policy.py`. Useful and shippable standalone — you can declare a tamper-evident retention policy today, before rotation exists.
- [ ] **Step 2 — `RetentionManifestStore`.** Copy/adapt `WitnessStore`'s `prev`+`self` mechanism verbatim into the new store, no rotation wiring yet. `test_retention_manifest.py`, including the tail-edit planted case (failure mode #8 below) to prove the copied mechanism actually carries over in the new context.
- [ ] **Step 3 — `SegmentStore` + `rotate()`.** Wire live/segments/manifest together; refuse-on-broken-live-chain; empty-segment no-op. `test_retention_rotation.py`, with the whole-file-swap detection (failure mode #3) as the centerpiece — hardest and most important correctness property in the design, give it real test-writing time.
- [ ] **Step 4 — Extend `current_policy`/`policy_history` to walk all segments via the manifest.** Small diff on step 1+3; completes "policy survives rotation."
- [ ] **Step 5 — Expiry.** `expire_due`, tombstone schema, independent min_keep gate checked at the *mechanical* enforcement point (not just at policy construction), tombstone-before-delete ordering. `test_retention_expiry.py`, including undocumented-deletion detection (#5) and tombstone-vs-manifest cross-check (#6).
- [ ] **Step 6 — `verify_all()` / `SegmentStoreVerify` + `status`/`verify` CLI verbs.** Mostly composition of steps 3+5; still gets its own test file (`test_retention_verify_all.py`) because it's the reader-facing entrypoint an auditor actually calls.
- [ ] **Step 7 — Full CLI.** `policy-set`/`policy-show`/`rotate`/`expire` verbs in `retention.py`'s `main()`. `test_retention_cli.py` (check `test_bundle.py`'s testing pattern first for consistency — not yet read in this pass).
- [ ] **Step 8 — `retention_bundle.py`.** `build_retention_bundle` + CLI, reusing `verify_file`/`Head`/witness primitives directly. `test_retention_bundle.py`, including the no-recoverable-content-leak check (#10).
- [ ] **Step 9 — Port failure modes 1–10 into `selftest.py` + `mutation_harness.py`.** Do this once the real implementation is stable, not earlier — plants must test final behavior, not a moving target. Not optional; it's the bar every other guarantee in this repo already clears.
- [ ] **Step 10 — Docs.** README "Retention Shell" section (code sample + honest-boundary subsection), CHANGELOG 0.6.0 entry naming defects found during 1–9 (matching the existing changelog's practice), version bump in `pyproject.toml` + `__init__.py` together, **last**, after publish.
- [ ] *(Optional, later)* Step 11 — `test_hypothesis_retention.py`: property-fuzz `RetentionPolicy.validate()` and expiry date-math (leap years, min_keep_days=0, DST-adjacent ISO stamps).
- [ ] *(Optional, later)* Step 12 — perf hint: `policy_ids_present` cache field on `segment_sealed` manifest records to bound `current_policy()`'s worst-case O(all rows across all segments) scan — advisory-only, never load-bearing (mirrors how legacy unchained witness pins degrade gracefully). Defer until proven necessary; premature caching is exactly the complexity this codebase's discipline warns against.

## 6. Failure modes + the demonstrated-red plan

Each of these is a required `selftest.py` PLANT / `mutation_harness.py` `case_*` pair (step 9), following the existing GREEN-control-first, no-op-guard, exact-verdict-string discipline:

1. **Policy row edited in place.** Hand-edit a `arcaeon.retention.policy` row's `max_keep_days` in `live.jsonl`. Expect: ordinary `verify_file()` chain mismatch at that line — proves policy rows aren't accidentally routed around the chain (e.g. into an unchained sidecar shortcut).
2. **Policy floor bypass.** `set_policy(min_keep_days=30, max_keep_days=10)` must raise `RetentionPolicyError`. `set_policy(min_keep_days=1, max_keep_days=5)` must raise unless `allow_floor_violation=True`, in which case it must succeed **and** the row must literally record `min_keep_days=1` — not silently clamp back to 183 (a clamp would itself be a silent policy substitution).
3. **Segment swap (the central claim).** After `rotate()`, copy `seg-000002.jsonl`'s bytes over `seg-000001.jsonl` — internally clean, so a bare `verify_file()` on it reports green. Must be caught by `verify_all()`'s manifest-vs-actual-head cross-check: `ok=False`, naming "segment 1: on-disk head does not match manifest record." This is the single most important planted case — it's the "container says yes, verdict says no" bug class this codebase has repeatedly found, applied to whole files instead of rows.
4. **Rotating a broken live chain.** Hand-tamper `live.jsonl` before `rotate()`. Must raise `RotationError`; assert the file is still at `live.jsonl`, unmoved, afterward.
5. **Undocumented deletion.** `os.remove()` a sealed segment directly, bypassing `expire_due()`. `verify_all()` must return `ok=False` with that seq in `unexplained_absences` — proves the tombstone requirement is enforced, not just intended.
6. **Tombstone forgery.** Forge a tombstone claiming `segment_head.rows=999999` for a segment whose independently-earlier-written `segment_sealed` manifest record says `rows=812`. Must be flagged as a mismatch between two independent chained records.
7. **Premature expiry at the mechanical gate.** Bypass `RetentionPolicy.validate()` (simulate a forged/corrupted policy row) and confirm `expire_due()`'s internal eligibility check *still* refuses to delete a segment younger than `min_keep_days`, independent of what `max_keep_days` claims — proves the floor is enforced at the point of action, not only at construction time.
8. **Manifest tail-edit** (same class as the 0.5.9 witness fix). Edit the *last* `RetentionManifestStore` record; must be caught via its `self` digest, not merely `prev` — literally the same test shape as witness's "edited LAST pin" case, ported.
9. **Witness composition regression.** Truncate a sealed-and-witnessed segment; `verify_against_witness` (unchanged, existing function) must still report `"truncated"` — proves rotation didn't accidentally bypass or weaken the pre-existing witness contract.
10. **Bundle content leak.** Plant a distinctive marker string in a row, expire that segment, run `build_retention_bundle`, grep the entire output for the marker — must not appear anywhere except as a tombstone's aggregate summary fields (row count, head, citation), never the original row content.

**Known limits (state plainly, README §, mirroring the existing "five things it doesn't prove" style):**
- **No forensic secure-erase.** `os.remove()` does not shred bytes at the filesystem level on most platforms; true unrecoverable erasure is out of scope and named as the caller's responsibility if that threat model applies.
- **Segments are not literally chained row-to-row across files** — continuity is proven by independent manifest cross-checking, not by one monotone hash spanning all history (the explicitly rejected alternative, §1).
- **A crash between sealing a file and recording `segment_sealed` is detectable but not self-healing in v1** (`verify_all()` reports an "unmanifested segment file" inconsistency; no auto-repair verb yet — named as a future step, not silently ignored).
- **No software artifact discharges a legal retention/erasure obligation on its own** — same line `bundle.py`'s README already uses — and the Shell does not validate that a given `min_keep_days`/`max_keep_days` value is legally correct for any jurisdiction; it makes the *mechanism* tamper-evident and mechanical, not the legal judgment behind the numbers.
- **One clock governs both bounds per policy** (documented tradeoff in §1) — a policy wanting the maximally protective floor *and* the maximally prompt ceiling simultaneously needs two categories, not one clock-start value.

## 7. Critical details

- **Error handling:** `RetentionPolicyError(ValueError)`, `RotationError(OSError)` — typed, catchable subclasses, matching `LedgerWriteError(OSError)`. `expire_due()` never raises on one bad segment; it skips and reports (`ExpiryResult(expired=False, reason=...)`), bounding blast radius the same way `verify_file` continues past one break instead of raising.
- **State management:** no in-memory caching of segment/manifest state across calls — every method re-derives from disk, matching `_last_chain()`'s backward-scan philosophy (recompute from the file, never trust a cached belief).
- **Concurrency:** `rotate()`/`expire_due()` serialize on a lock over `retention_manifest.jsonl.lock` (reusing the existing `_append_lock` primitive); `set_policy()` relies on `Ledger.append()`'s own existing lock since it only touches the live ledger.
- **No new digest recipe.** Policy/tombstone/manifest rows use the same `json.dumps(..., sort_keys=True)` chain body as ordinary rows — no second canonicalization scheme to freeze/version, deliberately.
- **Testing:** `tempfile.TemporaryDirectory()` throughout, matching every existing test file; property-fuzz deferred to optional step 11 rather than gating the core build.
- **Security/regulatory honesty:** every guarantee ships with its boundary stated as loudly as the guarantee itself — this repo's single most consistent convention, and the one most worth protecting in this feature specifically, since its whole premise is regulatory trust.