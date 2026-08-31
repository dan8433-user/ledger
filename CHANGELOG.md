# Changelog

## Unreleased

- **CI (2026-08-30):** added Python 3.13 as a third matrix point in
  `.github/workflows/test.yml` (was `["3.9", "3.12"]`, now
  `["3.9", "3.12", "3.13"]`) — buys coverage of the current stable release
  instead of stopping one behind it. The matrix comment's cost note (previously
  "two points … 4-5 point matrix on repos this small") is updated to describe
  three points, honestly, in-file.
- **Test-only fix:** `test_export_bundle_does_not_crash_on_a_corrupted_witness_file`
  imported `arcaeon_audit` unconditionally, which broke CI collection on the
  single-package runner (first red run: ca5c983, 2026-08-30 — arcaeon-audit
  depends on this package, so the dep is circular and can never be declared).
  Now a loud `pytest.importorskip` with the reason in the skip summary; the test
  still runs everywhere the full line is installed. No shipped code changed;
  the published 0.7.0 wheel is unaffected.


## 0.7.0 — 2026-08-30 — three agent-facing MCP tools

The MCP server's first two tools are OPERATOR tools: append a row, verify a file.
They assume the caller owns the file and reads the result itself. These three
assume something else — that the caller is an agent, and that the output is going
somewhere: to a principal who wants proof, or to a peer who wants to be trusted.
Same machinery, shaped for the conversation it actually shows up in. No new
dependencies; the server still speaks JSON-RPC over stdio directly.

**`prove_my_conduct(namespace, events)` → `{rows, head_hash, chain_verified}`.**
An agent logs a batch of what it just did and gets back ONE chain head it can
hand its principal. `head_hash` is read back off the file after the appends, not
computed for the reply, and `chain_verified` is the verifier's own three-valued
verdict over the agent's own log — so an agent whose ledger has been tampered
with cannot hand out a head hash with a green attached to it. That is the failure
this tool exists to sell against, and reporting the appends as successful without
re-verifying would have walked straight into it.

**`verify_peer_ledger(jsonl_text, strict?)` → `{ok, rows, first_break,
declared_breaks}`.** Judge another agent's exported ledger from its TEXT alone —
no access to their machine, no writes on yours (asserted: the caller's own log is
byte-identical afterwards). `first_break` is an INTEGER LINE NUMBER rather than
the library's human string, because a calling agent needs to point at the row,
not parse a sentence; the sentence still rides along in `first_break_detail`. The
text is verified by writing it to a throwaway temp file and calling `verify_file`
— deliberately, because a second verifier that walked the string directly is a
second verifier that can disagree with the first, and the day they disagree is
the day the tool lies.

**`declare_break(namespace, reason)` → `{declared_line, declared_breaks, ...}`.**
The 0.6.0 repair, wrapped for an agent that does not know its own line numbers:
it runs verification, takes the first break the verifier ALREADY found, and pins
that line. If nothing is broken it REFUSES — declaring a break that verification
did not find would put a false sentence into an append-only record, which is
worse than the silence it replaces. It declares one break at a time, so a second
break can never ride in on one sentence, and it never restores a green: the
verdict stays `ok=None` / `bounded_declared_break` with the break counted forever.

**Two honesty rules extended to the new surface.** An export with no parseable
rows now returns `ok=None` / `verified_scope="bounded_empty"` instead of the
vacuous `true` a zero-row scan would otherwise earn — handing a peer a green for
sending nothing is the cheapest possible forgery, and it is the same standing
rule as prechain and declared breaks: only a scan that checked something returns
True. And every new verdict carries `verified_scope`, `prechain` and `declared`
alongside `ok`, so a client that reads `ok` alone still gets null on a bounded
scan rather than a false pass.

**Namespaces are names, not paths.** Agent ledgers live one file per namespace
under `--ns-dir` (default `ledgers/` beside `--log`). A namespace must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; anything path-shaped is REFUSED rather than
sanitized, with a containment check behind the regex as a belt. Silently
rewriting `../etc/passwd` into `etcpasswd` would create a real ledger under a
name the caller never asked for, and the caller would then hand out a head hash
for a file it can no longer find.

`handle(msg, log)` keeps its 0.6.0 two-argument signature; `ns_dir` is an
optional keyword defaulting to `ledgers/` beside the server's log, so existing
call sites and the 0.6.0 integration tests are untouched.

40 new tests in `test_agent_tools.py`, all watched failing before the
implementation existed (40 failed → 40 passed); the existing 309 stayed green.

## 0.6.0 — 2026-08-28 — declare a break instead of hiding it

A hash-chained log written out of band is broken forever, and that is correct:
the break is the true record. Until now the only two things you could do with one
were live with a permanent red or recompute the chain so the file verified again
— and the second is forging, in a package whose entire argument is that a chain
you can silently re-forge is not evidence of anything.

**`declare_break(path, orphan_line, why, resume_prev=...)`** is the third option
and the only sanctioned repair. It APPENDS (never edits) a row naming the break:
which line, the orphan's exact bytes pinned by a full sha256, a human reason, a
date, and the chain value the record resumed from.

**The break stays a break.** `verify()` reports it forever in `declared` (one
sentence per excused break, reason included) and counts it in `declared_breaks`,
which is deliberately NOT folded into `breaks`. What changes is only that a
known, explained, content-pinned break stops masquerading as an unexplained one.

**It cannot mint a green, and that is the load-bearing design decision.** A
declared break yields `ok=None` with `verified_scope="bounded_declared_break"` —
falsy — not `ok=True`. This is the module's own standing rule from 0.5.7 applied
unchanged: only a scan that CHECKED EVERY ROW returns True. An excused row was
not checked; the chain does not link across it, and what stands in for the link
is a human sentence. Declaring converts an unexplained red into a named, bounded
null. That is the whole of what it does, and it is enough. (Where both apply, the
scope reads `bounded_prechain_skipped+declared_break`.)

**A declaration excuses the exact bytes it pinned and nothing else.** Edit the
orphan afterwards and the sha stops matching and the file goes red again, with a
first_break that says so specifically ("a declaration exists but its
orphan_sha256 does not match these bytes") rather than the generic message — the
difference between "nobody explained this" and "somebody explained this and then
the bytes moved" is the entire point of pinning content. A forged
`orphan_sha256`, a declaration pointing at the wrong line, and a declaration with
a blank `why` all excuse nothing. Only two break classes are declarable at all —
an unchained row after the chain began, and a chain mismatch, the two signatures
of an out-of-band append. Unparseable lines, non-object lines, non-string chain
values and unhashable rows are not declarable: those are malformed bytes, not a
recorded event somebody wrote outside the tool, and there is nothing there to
stand behind.

**`strict=True` ignores declarations entirely.** Strict exists for the caller who
wants no tolerance at all — it already refuses the prechain rows non-strict
accepts as legitimate history. A declaration is an unverified human claim, and
honoring an unverified claim is precisely the tolerance strict was asked to drop.
So strict reports a declared break as a break, in `breaks` and `first_break`,
exactly as before this feature existed: **no strict verdict anywhere gets newly
greener because declarations were added.** Strict also refuses the `resume_prev`
pointer that comes with the declaration, not just the excusal — a mode that
declined the exemption while quietly accepting the pointer would be honoring half
of a claim it had just rejected. Strict does still LIST what it refused
(`"declaration present, NOT honored (strict mode)"`), so the gap between the two
modes is visible rather than silent.

**HONEST LIMITS, stated in the function's own docstring and not only here**,
because understating a tool's limits in its own docs is the failure this package
exists to argue against:

- It is a **record device, not a cryptographic one.** Anyone who can write the
  file can write a declaration, so it raises **no** bar against an attacker who
  already has write access. **It defends against forgetting, not against
  tampering.** Every limit below is one more face of this single fact.
- It cannot tell an honest out-of-band append from a malicious one. `why` is an
  unverified human claim; nothing checks it, and nothing can.
- It only declares breaks `verify()` **already found**. It does nothing about a
  break nobody noticed, and gives no help finding one.
- Honoring is decided in a pre-scan, so the declaring row is checked for one
  cheap structural bar (it must carry a `chain`, i.e. have come through
  `append()` — a raw hand-echoed line hands out no exemptions) but NOT for that
  chain verifying. A hand-written declaration with a bogus chain still excuses,
  and is then reported as a break in its own right at its own line.
- `resume_prev` is taken on trust, but a wrong value fails the very next row, so
  it cannot launder a rewritten tail without showing up immediately.

**Mutation-verified**, four mutants, each watched failing before the tests were
kept: dropping the `orphan_sha256` comparison (2 tests red), honoring
declarations under strict (1 red, and it minted `ok=True` on a broken log — the
exact regression property 6 forbids), letting a declared break mint a green
instead of a bounded null (6 red), and dropping the must-be-chained bar on the
declaring row (1 red). `test_declared_breaks.py`, 20 tests.

Also ships the items below, previously staged as 0.5.10 and never published.

## Also in 0.6.0 (was staged as 0.5.10, never published) — a witness never goes backward, and the docs stop contradicting themselves

- **C3 monotonic guard.** `WitnessStore.record()` now refuses a pin whose
  `rows` is below the namespace's history high-water mark, with the same
  semantics the hosted JS service has enforced since 8/14 ("a witness never
  goes backward"). Before this, truncate-then-re-pin sailed through the
  Python reference: the smaller pin became `latest()`, `verify_against_witness`
  read only `latest()`, and the larger old pin — the standing disproof — sat
  unread in `history()`. The bar is the HIGH-WATER mark, not `latest()`, so
  a legacy file already containing a backward pin cannot anchor the guard to
  the low mark. Equal-rows re-pin (the heartbeat) stays allowed. Honest
  limit, unchanged: this stops a backward pin arriving through the API; an
  actor who can rewrite the store file itself is outside it — that
  protection remains the independence of the host. Mutation-verified.
- **Docstring self-contradiction fixed** (found by independent review
  2026-08-24): the module header called a locally-run store "a witness you
  fully control" — the exact opposite of the module's own opening
  definition (a witness is a party OUTSIDE your control), and the exact
  overclaim phrase the 2026-08-23 audit flagged. Local is for development;
  the protection requires a host the logging party cannot reach.
- **README: read the verdict with its qualifiers.** `witness_self_integrity`
  existed in code since 0.5.9 but no consumer-facing doc said to read it. The
  verify example now shows it and states plainly that a bare `"consistent"`
  from a latest-only hosted client is `unestablished`, not `verified`.

## 0.5.9 — the witness store now has a chain of its own

0.5.8 retracted a false claim: the witness store said it was "tamper-evident by
inspection" because it is written append-only, which described how the class writes,
not a property of the file. An edited pin was undetectable. The retraction shipped
before the mechanism did; this is the mechanism.

**Each pin now carries two digests.** `prev` links it to the pin before it, which
catches deletion and reordering. `self` commits it to its own content, which catches
an edit to the LAST pin — the one a verifier actually reads, and the one a pure
back-chain structurally cannot protect because nothing links forward from it. New
`WitnessStore.verify()` recomputes both and names the first break by line.

**That second digest is here because the first draft shipped without it and a
demonstrated-red run caught the gap.** The reviewer's original attack was editing a
single pin; in a one-pin store that pin is the tail, and a back-chain-only version
reported it clean. The test that runs that exact attack is in the suite.

**Legacy files keep working.** Pins written before 0.5.9 have no `prev`; `verify()`
reports them as `unchained` and does not call them broken, because a witness that
rejects its own history the moment it upgrades turns every real pin into a false
alarm. A file with unchained pins and no breaks returns `ok=None` — falsy, scoped,
and honest about what was checked. Same three-valued shape the ledger uses.

**`verify()` returns a verdict whose truthiness follows the verdict.** Writing the
test exposed that it first returned a plain dict, and a non-empty dict is always
truthy, so `if store.verify():` passed over a broken chain — the same container-says-
yes-while-verdict-says-no defect 0.5.8 fixed in `verify_file`. Now `ok is True` is the
only truthy state.

**What this still does not do**, because it is the part that gets overclaimed: it makes
an edit to a stored pin detectable. It does not stop someone with write access from
discarding the file and minting a fresh consistent one, exactly as the ledger's chain
cannot stop a consistent full rewrite. The protection remains substantially the
independence of the host. And `verify_against_witness` NOW consults `store.verify()`:
two guards run before the comparison, so a forged pin file (`witness_broken`) or a
locally broken log (`local_broken`) can no longer be reported consistent. An earlier
draft of this entry described that as a separate release; an auditor caught the
changelog contradicting the code within the same unreleased 0.5.9, and this is the
correction. What the witness still cannot do is stop a full re-mint by someone with
write access, exactly as the ledger chain cannot stop a consistent full rewrite. Do
not read "the witness has a chain" as "the witness gap is closed."

**And `verify_against_witness` now refuses to bless a broken record.** Once both the
log and the pin file had chains of their own, the cross-check could finally consult
them. Before this it compared row counts and chain values without ever asking whether
either side was internally intact — so a forged pin file, or a log broken elsewhere
than the witnessed row, could still come back `consistent`. Two guards run first:
`witness_broken` if the pin file fails its own chain, `local_broken` if the log fails
its own. Both are falsy. Demonstrated red: against the pre-guard code both attacks
returned `consistent`; the tests that assert otherwise fail there and pass here.

Full suite green including 23 new witness-chain tests; `selftest` and
`mutation_harness` unchanged and passing.

## 0.5.8 — four false greens, and a test file that could not detect the drift it was named for

**Upgrade if you are on 0.5.7 or earlier, and upgrade `arcaeon-adapter` alongside it.** Two of the defects below could leave a record silently incomplete while every integrity check still reported green, which is the one failure mode this library exists to prevent.

These were found by a deliberate internal review pointed at proving the library wrong rather than right. Every one was reproduced before it was fixed, and every fix was confirmed to fail against the code it replaces.

**Two things this entry deliberately does not contain.** The step-by-step reproductions are withheld while installs remain on the older version, because a published method for silently removing a row from an audit log is useful to precisely the wrong reader; ask if you have a concrete need for the detail. And the internal review process, tooling and harness are not described, because that is how we work rather than how the product behaves. What you get instead is every defect stated plainly, its consequence, and the limits that remain. We would rather be specific about being wrong than vague about it.

### A file with zero rows is no longer reported as verified

`verify_file` returned `ok=True, verified_scope="full"` over an empty file — a sentence meaning "every row was checked and the chain holds" said about a file containing nothing. Strict mode did the same. Three things downstream believed it: `bool(verify(...))`, `head()`/`publish_head`, and `build_bundle`, whose auditor-facing README printed *"VERDICT: intact. Every row was checked in strict mode and the hash chain holds end to end"* over zero bytes, with the sha256 of the empty string sitting beside it.

Now `ok=None, verified_scope="empty"` — falsy, so `if verify(...)` stops passing, and deliberately still not a red, because an empty log is an absence of evidence rather than evidence of tampering and the two must not print the same.

The README already warned that automation branching on `.ok` "needs to check `first_break`". Our own bundle generator was that automation and did not. **When the library itself cannot follow its own warning, the verdict is wrong, not the reader.**

### `append()` now confirms the row actually landed

It returned a valid chain hash without ever checking that anything was stored, and on Windows there is a class of path that accepts every write and stores nothing. Combined with the defect above, a log could receive writes, keep nothing, and report intact through the CLI, the witness and the evidence bundle. Not a crash — a confident lie, which for this product is the worst failure available.

`append()` now confirms the bytes are present after the write and raises the new **`LedgerWriteError`** if they are not, with a message naming the likely cause. One extra syscall per row, and it is the difference between "the writer believes it wrote" and "the file contains it". A logger that cannot tell those apart is not an audit logger.

### The verifier can no longer be made to crash instead of returning a verdict

Certain legal-JSON rows produced by ordinary cross-language writers could make `verify`, `head` and `build_bundle` fail permanently on a file, while that file remained writable and iterable. That violates an invariant this module states twice about itself: *"one smuggled line turned the verifier into a crash instead of a verdict."* Those rows now come back as `line N: unhashable row (...)`, a break like any other break.

The write path is unchanged and still refuses such a row before any bytes land. The asymmetry is deliberate: a refused write is honest, whereas an accepted write that can never verify is a slow-motion false alarm.

### The chain formula in the README was wrong

It said `chain = sha256(prev_chain + canonical_json(row_without_chain))`. This package defines exactly one canonical JSON — `json-c14n:v1`, compact separators — and **the chain does not use it.** It uses Python's default `", "` / `": "` spacing. Anyone building a cross-language verifier from the README plus the package's only named canonicalization got a mismatch on every honest row. `_chain`'s docstring now states the separators explicitly and says the chain body is its own unversioned rule. No digest or chain value changes; only the documentation was wrong.

### `test_canonicalization_divergence.py` was rewritten, because all five of its tests were decoration

Added the same day as the finding it documents, the file defined a local helper that re-implemented the canonicalization recipe and then asserted things about the copy. When the real `_canon_json` was altered four ways at once — key ordering, separators, ASCII escaping, and NaN acceptance — every test still passed, with NaN quietly digesting under the `v1` label.

Its docstring had claimed "if one starts failing, the canonicalizer drifted". That was unfalsifiable, because the file never touched the canonicalizer. **It was testing a copy of the thing it was guarding, which is the purest form of a check that cannot go red: a green from it only means the copy still agrees with itself.**

Every test now routes through the real `digest_json` / `_canon_json`, the frozen vectors are hardcoded expected strings rather than recomputed (a vector recomputed with the code under test is a mirror, not a vector), and three properties nothing checked before are now covered: compact separators, `ensure_ascii=False`, and the digest label naming its own recipe and version. Eight tests.

### The shipped selftest now tests the product's central claim

`python -m arcaeon_ledger.selftest` is the proof that ships in the package so you can check your own install rather than trusting our CI. With `verify_file` replaced by a stub returning `ok=True` for every file, it printed **ALL CHECKS PASSED** and exited 0. Tamper detection could be deleted entirely and the health check would not notice: its witness branches compare row counts, and its one chain assertion is satisfied by any truthy stub. A user who ran it and saw green had learned nothing about the property they are paying for.

It now plants eight real tampers in real files — in-place edit, deleted row, reordered rows, torn final row, smuggled non-object line, unchained row after the chain began, empty file, and a write that goes nowhere — and requires the **exact** `first_break` string back for each. Demanding the specific line number is the part that cannot be faked by a constant. Plus a green control on an untouched log, so a verifier that is red-by-default fails too. Both directions pinned, which is the only way a check earns the right to be believed.

### Also fixed in `arcaeon-adapter`, same batch

Two defects in the shipped 0.1.0, both breaking the completeness property the adapter exists to provide. A tool call could be missing from the seam log while the chain still verified green — and the party being audited could influence whether its own call appeared. And the wrapped server's command line, which routinely carries live credentials, was written verbatim into the `session_begin` row in the default person-free mode. See that package's changelog; upgrade both together.

**Verified:** 176 fast tests plus the two slow property suites. `selftest` and `mutation_harness` both green.

**Pins deliberately not bumped until the release lands.** Moving a pin ahead of what is published is the defect 0.5.7 records: `>=0.5.7` was declared while PyPI's newest was 0.5.6, and the documented install command failed. Pins move after the upload, not before it.

### Known limits, unchanged or newly named

Stated as limits rather than as attack paths. These are properties the library does not have, not instructions:

- **The witness store carries no chain of its own.** A witness file that an attacker can write to is not evidence; the independence of the host is the whole protection. Its docstring previously claimed it was "tamper-evident by inspection", which was wrong and has been corrected.
- **A witness pin proves nothing about rows appended after it was taken**, and a pin taken over an empty log constrains nothing at all.
- **`verify_against_witness` answers only the witness question.** It can be consistent while the local chain is broken. Check both; they are separate verdicts.
- **A green verdict covers the decoded content of each row, not the exact bytes of the file.** Undecodable byte sequences are normalised on read, so byte-level equality is not what the chain commits to. If you need byte-level custody, hash the file itself alongside this.
- **Concurrency is safe while the lock can be taken.** Contended writers serialise for up to 15 seconds, after which the append proceeds unlocked rather than fail — so a wedged lock, or a platform with no lock primitive, degrades to a single-writer assumption and concurrent appends can fork.
- **`verify_artefact` without `refetch=True` checks a digest for self-consistency, never that the bytes still match.** Only `refetch=True` does that.
- **A consistent full rewrite of an entire log is undetectable by the chain alone.** That is what the external witness is for, and it is the honest boundary of a hash chain.

## 0.5.7 — PUBLISHED to PyPI 2026-08-19 (the version existed for a day before it shipped)

**The defect this closes.** 0.5.7 was written, tested (99 passing), documented in this file, committed and pushed — and never published. Pushing the source read as shipping it. That single gap produced two downstream failures in files that never mention each other:

1. **`pip install arcaeon-adapter[ledger]` failed hard.** The adapter, published the same morning, declares `arcaeon-ledger>=0.5.7`; PyPI's newest was 0.5.6, so the extra could not resolve: *"No matching distribution found for arcaeon-ledger>=0.5.7."* The bare `pip install arcaeon-adapter` worked, which is the command that got verified and reported. Verifying the path you documented is not verifying the paths you published.
2. **`Dockerfile` pinned `==0.5.6`,** so the image shipped a version behind the repo it claims to package. Fixed by publishing 0.5.7, not by editing the number.

**Packaging fix found while checking the artefacts.** The sdist was sweeping in all 15 files of `adapter/`, including its own `pyproject.toml` — a nested project file inside a source distribution confuses build frontends and makes the tarball claim to contain a package it does not install. The wheel was always clean; only the sdist was wrong, which is exactly the kind of thing that survives when you check one artefact and assume the other. Added `[tool.hatch.build.targets.sdist] exclude`, which also dropped the `.hypothesis` test cache. **Sdist went from 318 entries to 26** — now just source, tests, README, CHANGELOG, LICENSE, Dockerfile and server.json.

**Verified after publishing, with the exact command that had failed:** `pip install arcaeon-adapter[ledger]` now resolves to adapter 0.1.0 + ledger 0.5.7 (needed `--no-cache-dir`; pip had cached the pre-publish index while PyPI's simple index already carried both artefacts). The Dockerfile ENTRYPOINT was also exercised directly against the published 0.5.7: `initialize` returns `serverInfo.version 0.5.7` and `tools/list` returns both tools. Docker itself is still unavailable here (`docker`, `go` and `task` all absent, and the WSL image has none either), so the container layer remains untested and the Dockerfile says so.

Written up internally in full. That path is in a private repo, so it is named here only to record that the write-up exists rather than to send you somewhere you cannot go; ask if the detail would be useful.

## 2026-08-19 — `arcaeon-adapter` moves into this repo, and completeness is named as the fifth gap

Repo-level change, no ledger version bump. Two things landed together because they are the same point.

- **The README's honesty list was incomplete.** It named four things a hash chain does not prove and omitted the structural one: *the agent decides what to call `append` on*, so a tamper-evident log of self-reported calls is still self-report. Nothing inside this library can close that, because anything the agent invokes it can decline to invoke. Gap **#5, Completeness**, now says so plainly and points at the closer. A disclaimer list that omits the biggest disclaimer is worse than no list, because it reads as exhaustive.
- **`arcaeon-adapter` now lives at `adapter/`** rather than in its own repository, and is published to PyPI as `arcaeon-adapter` **0.1.0**. It is a stdio proxy that forwards JSON-RPC byte-for-byte between an MCP client and server and writes one hash-chained row per `tools/call` to its own ledger, in a separate OS process the agent does not own, cannot skip, and cannot see. Wrapping it around *this* package's own MCP server produced the number that makes the argument: the server's own diary wrote **0 rows** while the seam log captured **5**.
- **Why the same repo, deliberately:** the adapter is the companion half of one claim rather than a separate product; several distribution directories key off a single repository URL; and splitting related packages across fresh zero-star repos is the exact pattern curated lists auto-reject as coordinated self-promotion (verbatim from `vinta/awesome-python`'s automatic-rejection rules, checked 2026-08-19). Concentrating is worth more than fragmenting when the scarce asset is credibility, not shelf space.

Gates at the time of publish: ledger suite **99 passed**; adapter **65 passed** from its new location; adapter selftest **6/6 with every check observed failing on its own injected defect**. `pip install arcaeon-adapter` verified against live PyPI, not inferred from the upload receipt.

## 0.5.7 (also) — 2026-08-18 — `python -m arcaeon_ledger.bundle`: one-command auditor evidence bundle

Adapter #3 from the 2026-08-18 AI-Act clause-read (founder directive 12396): "we already hold every ingredient; nothing assembles them." Now something does.

- **New module `arcaeon_ledger.bundle`** — `python -m arcaeon_ledger.bundle <ledger.jsonl> [--out DIR|ZIP] [--namespace NS]` assembles a single directory (or `.zip`, chosen by the `--out` suffix) a provider can hand to an auditor or market-surveillance authority: (1) the ledger file **copied byte-verbatim** (the copy's sha256 is recomputed against the source and the build fails rather than ship a divergent copy); (2) `verify_report.json` — the package's own **strict-mode** verify result in full (`ok/verified_scope/rows/chained/prechain/breaks/first_break`) plus the exact `python -m arcaeon_ledger.cli verify --strict <file>` command a stranger re-runs to reproduce it; (3) with `--namespace`, the hosted witness's `/api/latest` response **byte-verbatim** as `witness_latest.json` plus the public GitHub pin-history URL — and without a namespace, or on a failed fetch, a **stated** "no witness evidence included" line in both README and manifest, never silence (a 404/5xx body is kept as evidence with its status: the witness saying "no pin" is itself a finding); (4) a stated **not-included** line for OTS/anchor receipts (this package ships no anchoring tooling; the witness anchors on its own side — deliberately not built here); (5) `MANIFEST.json` — sha256 + byte count of every file, generation timestamp, package version, and the verbatim generation command, so the bundle itself is checkable (the manifest states plainly that it cannot contain its own hash); (6) auditor-facing `README.txt` in plain English — what each file proves, a **what-this-does-NOT-prove** section (truth, completeness, authorship, truncation-without-witness, and no compliance/classification claims), and the legal-context paragraph worded exactly to the clause-read's honest-pitch scope (Art. 12(1), 19(1), 26(6); integrity + provable retention support for the logs those articles make you keep — no "compliant", no "audit-ready").
- **The input ledger is opened read-only and never modified**; the only network call is the optional witness fetch (10 s timeout, injectable for tests). A ledger that verifies RED still bundles — evidence of a broken chain is evidence, and the README states the verdict as BROKEN with the break count. Exit 0 = bundle written; 1 = usage/IO failure. Refuses to write into a non-empty directory or over an existing zip (evidence never clobbered). Stdlib only, like the rest of the package.
- **New test file `test_bundle.py` (19 tests):** dir + zip creation; byte-identical copy with the sha stated in README/manifest; every manifest hash re-verified from disk and a tampered bundle file detected; strict report inclusion on green AND tampered-red ledgers; witness verbatim inclusion with URL-encoded namespace + history URL; no-namespace and simulated-offline fallbacks both stated-not-silent; HTTP-error body kept as evidence; input-never-mutated; README never contains the must-not-say phrases; CLI exit codes. Full suite: 80 → 99 passed.

Defect class identified by ColonistOne (Colony, 2026-08-17 verdict-field audit); found in our own package by the same lens: *a bare boolean whose scope lives in a separate sibling field — the consumer reads the field named after the answer and misses the field that weakens it.* Our verdict-endpoint self-audit confirmed the ledger carried it twice, once at HIGH severity, and this release closes both by making the verdict inseparable from its scope.

- **HIGH — non-strict `verify()` returned `ok=True` while skipping `prechain` rows unverified, and the honest mode was unreachable from both operational surfaces.** The module docstring admitted it plainly: prepend fabricated unchained "legacy" rows in front of a genuine chain and the file verified GREEN — `prechain` carried the count, but the headline `ok`/`__bool__` ignored it, the CLI's documented CI wiring (`return 0 if r.ok else 1`) exited 0 on it, and `strict=True` existed in the library while neither the CLI nor the MCP server could ask for it. Fixes, all three layers:
  - **`VerifyResult.ok` is three-valued (the continuity-0.2.0 `faithful=None` idiom).** `True` = every row verified; **`None` = no break found but prechain rows were skipped unverified — falsy, never a green**; `False` = broken. A consumer that reads only `ok` (or truthiness) now gets a fail-safe non-green on the bounded case instead of a false green. New in-band field **`verified_scope`**: `"full"` | `"bounded_prechain_skipped"` (stamped on failures too — a red over a bounded scan is still a bounded scan). Chosen over keeping `ok` a bool + sibling scope field because the sibling-field shape IS the defect class; chosen over `ok=False`-on-bounded because adoption-on-existing-log is a documented legitimate use and "unverified" is not "broken". Logs with zero prechain rows — every log this library created from genesis — see no behavior change at all.
  - **Distinct CLI exit code: `0` = fully verified, `3` = verified-within-scope (rows skipped; report says how many), `1` = broken/usage.** A CI gate that treats only 0 as green now fails loud on a fabricated prepend. (`2` deliberately avoided — argparse-convention usage-error code.) Documented in `--help` and the README CI snippet.
  - **`--strict` is reachable from the CLI** (`verify --strict <path>` → hard exit 1 on any unchained row) **and from the MCP server** (`ledger_verify` gains an optional `strict` boolean in its input schema, wired through the handler). The MCP tool description no longer overclaims "the whole log" — it states the three-valued verdict and the prechain toleration.
- **MEDIUM — `verify_artefact`: `digest_ok=True` survived a live `refetch:"mismatch"`.** The response's only boolean stayed green while the live-content disagreement rode in a sibling enum. New top-level **`verdict`** tag minted from the pair, so the one-field read is the honest read: a `FAILURE_REASONS` value (offline leg failed) | `"digest_consistent"` (offline leg passed, no live comparison made) | `"live_match"` | `"live_mismatch"` | `"live_unavailable"`. `digest_ok` is now documented as the offline leg only. No field removed or renamed; additive.
- **Regression tests** (`test_integrity_regressions.py` §7): fabricated prepend under non-strict → `ok=None` + falsy + CLI exit 3 + MCP bounded shape (never a clean green); same input under `--strict` / MCP `strict:true` → hard fail; `verify_artefact` refetch mismatch → `verdict="live_mismatch"` with `digest_ok` still honestly `True`, plus every other tag path. The 0.5.4 prepend test and the property suite's legacy-disguise branch updated to pin the new three-valued shape (`ok is not True` on every semantic tamper).
- Compat note: `bool(VerifyResult)` and `ok` are unchanged for all fully-chained logs and all failures. Only the skipped-rows case changes — from the false green to `None`/falsy/exit 3 — which is the fix.

### Also in 0.5.7 — last mutation survivor fenced (2026-08-17, previously unreleased)

Test-only; no product-logic change.

- **New regression test `test_append_after_a_falsy_chain_row_chains_from_genesis` (2 params: `null` / `""`)** in `test_integrity_regressions.py`, killing mutation survivor L5 from the 2026-08-16 mutation pass — the last of the five ledger survivors without a landed test. `_last_chain()`'s `or _GENESIS` fallback repairs a falsy tail `chain` (a hand-edited or rewritten file can end in `"chain": null`); dropping it made the next `append()` compute `_chain(None, body)` — chaining from the literal string `"None"`, silently forking the log from a value no verifier derives — and the whole fast suite stayed green. The test pins the ACTUAL value chained from (must equal `_chain("genesis", body)`), and was kill-proven directly: mutant applied → both params FAIL (`2 failed in 0.45s`); mutant reverted → fast suite `70 passed in 3.52s`.
- **SPDX:** `# SPDX-License-Identifier: MIT` added as the first line of every `.py` file in the repo (14 files), per the license-header pass at repo touch. — U+2028-class sealed-but-unverifiable bug (property-test pass)

Found while adding a `hypothesis`-driven property suite alongside the existing hand-rolled `test_property_ledger.py` fuzzer, prompted by an identical bug found the same night in `arcaeon-continuity`'s probe-file handoff: rows are written with `json.dumps(..., ensure_ascii=False)`, and every read path (`Ledger.__iter__`, `chain_at`, `verify_file`) split the file with `str.splitlines()`.

- **MEDIUM (honesty) — a row whose content contained U+0085 (NEL), U+2028 (LINE SEPARATOR), or U+2029 (PARAGRAPH SEPARATOR) sealed cleanly on `append()` and then could never verify green again.** `json.dumps(ensure_ascii=False)` only escapes the mandatory U+0000–U+001F control range; those three characters (plus the C0 separators `\x0b \x0c \x1c \x1d \x1e`) sit outside it and round-trip **raw** into the JSONL bytes. `str.splitlines()` treats all of them as row boundaries — a real difference from the literal `"\n"` `append()` actually writes as its delimiter — so a row containing one of them was sliced into fragments, each unparseable, and reported as a tamper that never happened. Proof against the pre-fix build: appending `{"note": "contains U+2028 here"}` (a literal LINE SEPARATOR character in the field value) between two ordinary rows produced `verify() = ok=False, rows=2, breaks=3, first_break='line 2: unparseable'` on a completely untampered log. **Fix:** every read path now splits on `"\n"` only — `read_text()`'s universal-newline handling already folds `\r\n`/`\r` to `\n`, so `"\n"` is the writer's one real delimiter either way. Same input after the fix: `ok=True, rows=3, breaks=0`, content round-trips exactly. No format change; `witness.py`'s pin store was never affected (it writes with the `json.dumps` default `ensure_ascii=True`, which already escapes these characters).
- **New: `test_hypothesis_ledger.py`**, a `hypothesis`-driven property suite (separate from the existing seeded `random`-module fuzzer) with named, adversarially-shrunk coverage of: (1) hash-chain integrity — any single row's content mutated, chain left stale, must break `verify()` starting at exactly that row; (2) append-order determinism — replaying an identical record sequence into two independent fresh ledgers must chain identically at every row; (3) the U+2028-class characters specifically, both in combination and pinned one at a time.
- **New regression tests in `test_integrity_regressions.py`**: `test_u2028_class_content_does_not_break_verify` and `test_u2028_class_content_survives_chain_at_and_head`, written failing against the pre-fix build.
- Full suite: **61 → 67 passed** (2 new regression tests + 4 new property tests; no regressions).
- **Docs: `verify()` on missing-vs-empty ledgers, stated plainly.** A never-created path returns `ok=False, first_break="unreadable: ..."`; an explicitly-created zero-byte file returns `ok=True, rows=0`. Confirmed by direct run tonight, not assumed. New README subsection so automation authors branch on `first_break`, not just `ok`, when the two cases need distinguishing. No behavior change.

## 0.5.5 — 2026-08-15 — non-string chain crash (property-fuzzing)

Found by a new property-based / fuzzing pass (`test_property_ledger.py`): thousands of random ledgers built from random content, then random single mutations, asserting the core promise (green on honest, red on tamper, **never crash — always return a verdict**). It surfaced one real bug that the hand-written suite missed.

- **HIGH — a row with a NON-STRING `chain` value crashed `verify()` instead of returning a verdict.** A chain link is a hex string, but nothing enforced it: a row like `{"a":1,"chain":123}` (int, float, bool, list, or dict — all legal JSON, so all arrive from the wire or a corrupt/tampered file) was popped as `claimed`, correctly flagged as a mismatch, and then assigned into `prev`. The **next** row's `_chain(prev, obj)` does `prev + body` — `int + str` — and raised `TypeError` straight out of `verify_file()`. One malformed row turned the verifier into a crash: a denial-of-verdict, the same class the 0.5.3 bare-scalar guard closes for non-object *lines*, but reachable through a non-object *chain field*. Proof against 0.5.4: `{"a":1,"chain":123}` twice → `TypeError: unsupported operand type(s) for +: 'int' and 'str'`. **Fix:** a present-but-non-string `chain` is now a named break (`line N: non-string chain value`), and continuation uses a safe deterministic string so a following honest row (chained from the real hex head) still fails against it — no false green, no cascade. Defense-in-depth: `_chain` now coerces `prev` with `str()` (a no-op on every honest path, where `prev` is always a hex string or `genesis`) so no future route to a non-string `prev` can crash the hash. Same input after the fix: `ok=False, breaks=3, first_break='line 1: non-string chain value'`. All existing tests still pass.
- **New permanent regression suite — `test_property_ledger.py`.** A seeded 5000-ledger property loop (`green` on every honest chain under default AND strict; `red` on every content-changing tamper — chain-edit, byte-flip, non-tail delete, row-swap, mid-line truncation — under strict, with default's one documented legacy-disguise carve-out recorded not asserted-away), plus a 3000-file `verify()`-never-crashes fuzz (bare scalars, `NaN`/`Infinity` literals, binary noise, torn lines, non-string chains, megabyte rows) and a faithful tail-truncation property (green by `verify()`, caught by an external head pin — the documented non-invariant, asserted honestly rather than as a false RED). Scales via `LEDGER_PROP_ITERS`.

## 0.5.3 — 2026-08-14 — chain-integrity fixes (hostile audit)

Found by a deliberately hostile line-by-line audit of the whole package. The first item is the serious one: **a tampered log could pass `verify()`**, with no attacker cleverness required — only an ordinary large row.

- **CRITICAL — a row bigger than the tail read window silently RESET the chain to genesis, detaching every row before it.** `_last_chain()` read a fixed 8 KB tail to find the previous chain value. A final row longer than 8 KB left no parseable line inside that window, so it returned `"genesis"` and the next `append()` started a fresh chain in the middle of the file. Two consequences, the second much worse than the first: (1) honest appends produced `verify() -> ok=False` on an untampered log — the tamper-evidence tool crying wolf about itself; (2) because the chain restarted, **everything before the reset point became detachable** — delete it all and the remainder verifies clean. Proof, run against 0.5.2: a six-row log (payment, payment, fraud_flag, a 9 KB `web.read`, payment, payment), delete the first four rows including the fraud flag, and `verify_file()` returns `ok=True, rows=2, first_break=None`. Rows over 8 KB are completely ordinary — a fetched page, tool stdout, a base64 blob — so this was reachable by waiting, not by attacking. `_last_chain()` now walks backwards a line at a time (doubling blocks, `_line_start_before`) until it has a complete parseable object row, whatever its length; tested at 8 KB, 9 KB, 40 KB, 300 KB and 2 MB.
- **HIGH — a non-object JSON line turned `verify()` into a crash instead of a verdict.** A line containing a bare scalar or array (`123`, `null`, `[1,2]`, `"x"`) reached `obj.pop("chain")` and raised `AttributeError` / `TypeError` straight out of `verify_file()`, `chain_at()` and `Ledger.append()`. One smuggled line meant the verifier could not answer at all — and a caller doing `if log.verify():` got an exception where it expected a verdict. Non-object lines are now a named break, `line N: not a JSON object`, and are consistently NOT counted as rows by `verify_file` or `chain_at` (so witness row-counts stay aligned).
- **HIGH — `verify_artefact()` raised instead of returning a typed failure on type confusion.** Its whole contract is "typed failure, never a silent pass"; a non-string `digest` (int, None, list, bytes), a non-dict artefact, or a non-dict `subject` / `subject.digest` escaped as `AttributeError`/`TypeError`. All of these now return `digest_ok=False, reason="malformed_digest"`.
- **MEDIUM — an up-cased digest read as a different digest.** The hex gate accepts `[0-9a-fA-F]` but the comparisons were case-sensitive, so the same digest in upper case failed `subject_digest_mismatch`, and a re-fetch of byte-identical content reported `"mismatch"`. Hex is case-insensitive by definition; both comparisons now casefold. A genuinely different hex still fails, unchanged.
- **`VerifyResult.breaks`** — total breaks, not just the first. Added because the documented "verification continues from the CLAIMED value so later damage is counted honestly rather than cascading" promise was **invisible**: a cascading verifier produced the identical `first_break` and was indistinguishable from a correct one. One edited row must now measurably be one break.
- **The mutation harness had a hole big enough to hide a 32-bit chain in.** Planting `if claimed[:8] != want[:8]` in `verify_file` — a one-character "optimization" that drops the chain from 128 bits to 32 (birthday-forgeable in ~2^16 work) — left **all twelve cases green**, because every existing mutation changes the row content and therefore the whole hash; none of them could tell a full-width comparison from a prefix one. Four new named cases close that and the rest of this release: `chain-comparison-full-width` (a chain forged in its LAST character only), `damage-counted-without-cascading` (one edit == one break), `large-row-chain-reset` (green across a 40 KB row, red on deleting the history before it), `non-object-row-typed` (a named break, not an exception). Sixteen cases; all four planted defects — truncated compare, cascade, tolerate-unchained, lenient-recipe-version — are now observed red, quoted in the test suite.
- **Honest limits, two named on the write side** (module docstring): rows containing `NaN`/`Infinity` are written as bare non-JSON tokens that round-trip in Python but that a strict RFC 8259 parser in another language rejects — reading an honest log as damaged; and JSON's duplicate-key ambiguity means a hand-written row with a repeated key can read differently to a first-wins parser while the chain stays green over the last-wins parse. `append()` never produces either; both are boundaries a cross-language verifier will meet.

## 0.5.4 — 2026-08-15 — concurrency lock + strict verify + newline heal (second hostile audit)

Carries tonight's newline-corruption fix (below) plus two findings from internal review: a concurrent-append data-loss race and a fabricated-legacy-prepend non-proof.

- **MEDIUM — concurrent `append()` forked the chain and lost rows.** `append()` is a read-modify-write: it reads the previous chain (`_last_chain()`), then writes a row chaining from it. With no lock, two processes both read the same tail, both chain from it, and the chain forks; on Windows the interleaved `"ab"` writes also drop rows outright. Measured against the pre-fix build: 1 seed + 2×20 concurrent appends (41 expected) → `verify() = ok=False, rows=38, chained=38, breaks=17, first_break='line 4: chain mismatch'` — 3 rows lost, 17 forks. It failed RED (never a silent green-tamper), but it both corrupted and lost data. **Fix:** the read-tail + write critical section is now held under a cross-process file lock — `msvcrt.locking` (byte-range) on Windows, `fcntl.flock` on POSIX — on a sidecar `<path>.lock` file, so the lock never touches the emitted bytes. Acquisition is blocking-with-retry (bounded, 15 s), so concurrent writers serialize instead of erroring; a platform with no lock primitive degrades to the single-writer path rather than failing. Same probe after the fix: `ok=True, rows=41, chained=41, breaks=0` — zero lost rows, zero forks. The happy-path emitted format is unchanged. (Same lock pattern as `arcaeon-once`.)
- **MEDIUM (honesty) — `verify(strict=True)` closes the fabricated-legacy-prepend hole, now named as the fourth non-proof.** Rows with no `chain` field are tolerated before the first chained row (adoption-on-existing-log). The hole: PREPEND fabricated unchained "legacy" rows in front of a genuine chain and the file verifies GREEN — they are counted as `prechain` and skipped, and the headline `ok`/`__bool__` ignore the count. Proof: a real 2-row chain with `{"tool":"INJECTED_fake_history","amount":9999}` prepended → default `verify() = ok=True, rows=3, chained=2, prechain=1`. Two fixes, both honesty-contract: (1) a new `strict=True` flag on `verify()` / `verify_file()` treats any unchained row as a break — the same tampered file now returns `ok=False, prechain=1, breaks=1, first_break='line 1: unchained (prechain) row rejected in strict mode'`; (2) "fabricated-legacy-prepend" is now stated as the **fourth** thing the chain does NOT prove, in both the module docstring and the README's "what it doesn't prove" section. The `Ledger` docstring's "atomic appends" is clarified to state the read-tail + write is lock-guarded so concurrent writers serialize.
- **HIGH — `append()` to a file missing its final newline silently GLUED the new row onto the last line, destroying both.** A ledger can lose its trailing `\n` from a torn write (crash mid-append) or any external tool that touches the file. `append()` opened in `"ab"` and wrote `{row}\n` with no separator, so the new row concatenated onto the newline-less last line into one unparseable blob — and `append()` still returned a valid-looking chain hash, so the corruption was silent until the next `verify()`. Proof against the prior build: a one-row valid ledger with its trailing newline stripped, then one `append()`, verified `ok=False, rows=0` — both the old row and the just-written row lost. `append()` now checks the last byte and writes a single leading `\n` only when one is missing, in the same write call; the torn remnant becomes its own flagged line instead of swallowing the new row. A normally-produced ledger always ends in `\n`, so the branch never fires on the happy path and the **emitted format is unchanged** (all 56 tests still pass; the healed case now verifies `ok=True, rows=2`). Found by a second hostile audit, 2026-08-15.
- **`arcaeon-ledger --help` / `-h` now prints usage and exits 0.** It previously exited **1** and dumped the module docstring, because the CLI hand-rolls its argv check (`argv[0] not in ("verify", "append")`) and every flag fell straight into the usage-error branch. A `--help` that exits nonzero is a broken CLI by convention and by CI: a wrapper script or smoke test that runs `--help` to confirm the tool is installed reads the tool as failing. Found by a live-PyPI QA sweep against the published 0.5.2 wheel.
- **`--version` prints `arcaeon-ledger <version>` and exits 0**, sourced from `arcaeon_ledger.__version__` so it can't drift from the package.
- **`verify` and `append` are untouched** — same output, same JSON shape, same exit codes (0 intact / 1 broken / 1 bad usage), verified before-and-after against a scratch install. A bare invocation still prints usage and still exits 1; that one *is* a usage error. Deliberately not an argparse rewrite: argparse would have changed subcommand parsing and error text, and four other packages depend on this CLI behaving exactly as it does.
- **README: corrected the tamper example's line number.** Block 2 claimed `first_break="line 1: chain mismatch"` after editing the amount; the amount lives in row 2, and `verify()` actually reports `line 2: chain mismatch`. Confirmed by running the example. A doc that misreports which row broke undercuts the one thing the library sells — naming the exact line.

## 0.5.2 — 2026-08-14
- **`verify_artefact()` now REFUSES any digest label it cannot reproduce.** Cause, stated plainly: the 0.5.0 mutation harness printed a standing NOTE that a digest claiming `json-c14n:v9` — a recipe version this build has never shipped and cannot recompute — came back `digest_ok=True` with only a warning note appended. The leniency was written for old rows keeping old recipe versions, but a *future* version cannot be an old row, so the effect was that an unchecked digest was reported as verified. That is the exact overclaim this library exists to refuse, and naming it in a NOTE was not the same as fixing it. It is fixed.
- **Typed failures, not substring-matched notes.** `verify_artefact()` returns a new `reason` key: `None` on success, otherwise exactly one of `unknown_algorithm`, `unknown_recipe`, `unknown_recipe_version`, `malformed_digest`, `subject_digest_mismatch` (exported as `FAILURE_REASONS`). Callers branch on the machine value instead of grepping human prose. The `notes` list is unchanged and still carries the readable explanation.
- **Three holes closed, all previously passing:** (1) an unknown recipe *version* of a known recipe passed with a note — now `unknown_recipe_version`; (2) the algorithm field was never checked at all, so `md5:raw-bytes:v1:<hex>` verified green on the strength of a recipe name — now `unknown_algorithm`; (3) the hex body was never shape-checked, so `sha256:raw-bytes:v1:hello` passed when no `subject` block contradicted it — now `malformed_digest` (must be the right length of hex for the named algorithm). An unknown recipe NAME already failed, but untyped; it now carries `unknown_recipe`.
- **A failed digest never reaches the re-fetch stage**, so `refetch` can never report `"match"` for an artefact whose recipe was never verified.
- **Backward compatible for everything actually minted.** `sha256:raw-bytes:v1` and `sha256:json-c14n:v1` — the only labels `bind_artefact` has ever produced — verify exactly as before, `digest_ok=True` with `reason=None`. The append-only recipe promise is kept by a new `SUPPORTED_RECIPE_VERSIONS` registry, deliberately separate from `RECIPES`: `RECIPES` names the version currently *minted*, `SUPPORTED_RECIPE_VERSIONS` names every version this build can still *reproduce*. When a future `json-c14n:v2` ships, v1 stays listed and old rows keep verifying — the leniency's legitimate purpose, kept, without waving through labels that were never real.
- **Observed, not asserted (mutation-harness discipline).** `python -m arcaeon_ledger.selftest` gained a planted-label block: a clean artefact is verified GREEN first, then four plants — unknown recipe name, unknown version, unknown algorithm, malformed hex — must each be seen going red with their SPECIFIC typed reason. The harness gained two named cases, `unknown-recipe-version` and `unknown-algorithm` (12 cases total), and the standing 0.5.0 NOTE is retired because it is now a case observed red rather than a boundary named and left open.
- **The NOTE slot stays occupied, honestly.** It now reports the leniency that remains: an artefact with a well-formed supported digest but no `subject` block passes, because there is no second copy of the hex to disagree with it. `digest_ok` means "reproducible label, self-consistent string" — never "the bytes were re-checked." Only `refetch=True` does that.

## 0.5.1 — 2026-08-14
- **MCP Registry listing marker.** README now carries `mcp-name: io.arcaeon/ledger` (an HTML comment, invisible on PyPI's rendered page) — the ownership proof the official MCP Registry (registry.modelcontextprotocol.io) checks against the PyPI description before accepting the server under the `io.arcaeon` namespace. No code change to the library.
- **MCP server reports its real version.** `initialize` previously answered `serverInfo.version: "0.1.0"` regardless of the installed package; it now reports the package `__version__`. Cosmetic but honest.

## 0.5.0 — 2026-08-14
- **`python -m arcaeon_ledger.mutation_harness` — every claimed check, observed actually failing.** reticuli (Touchstone) set the standard: a check never observed failing is indistinguishable from decoration, so the harness takes each check the verifier claims, introduces the SPECIFIC defect that check exists to catch, and requires the named red — not "some error somewhere." Ten named cases: byte-edit-in-row, row-reorder, mid-row-delete, unchained-row-after-chain-start (each pinned to the exact `first_break` line), truncation-vs-witness and remint-vs-witness (where the chain deliberately stays green — the forgery self-verifies — and the witness must be the one to go red), artefact-digest-mismatch, canonicalization-recipe-drift (a drifted ascii-escaping canonicalizer must fail the frozen golden vector; an unknown recipe label must fail `verify_artefact`), NaN-rejection, and the guard on the guard.
- **No-op guard, and its own selftest.** Per reticuli's second requirement, a mutation that changes nothing must NOT count as caught: every case captures fixture bytes before and after and fails the harness with "mutation did not mutate" if they match — and the `no-op-guard-self-test` case applies an identity mutation and requires the guard itself to trip. Every case also verifies GREEN on the clean fixture first; a harness that only ever sees red proves nothing.
- **Honest boundary, named not papered:** the harness prints a standing NOTE that `verify_artefact` accepts a digest claiming `json-c14n:v9` (a version this build has never shipped) with `digest_ok=True` and only a note — the leniency exists for old rows keeping old versions, but a future version cannot be an old row. The golden vectors, not that check, are the real version-drift guard.
- Meta-test in the suite: blind the chain verifier and the harness must go red naming the case — the harness is itself catchable, by its own standard.

## 0.4.1 — 2026-08-13
- **`python -m arcaeon_ledger.selftest` — golden vectors + the witness planted fixture.** Two launch-thread asks shipped as one runnable command: (1) holocene's recipe-drift question — frozen `json-c14n:v1`/`raw-bytes:v1` digest vectors that any environment must reproduce exactly, so parser/platform drift fails loudly instead of minting well-formed wrong digests; (2) excelsior's witness-failure fixture — three planted branches (truncate-before-witnessed-head → `truncated`, remint-from-genesis → `rewritten`, untouched → `consistent`) run live in a temp dir on every invocation. Exit 0 only when every check passes.
- **Docs: chain hash named `truncated_sha256_128`.** The chain value was documented as `sha256(...)[:32]` without naming its strength; atomic-raven's review nit stands — 128 bits is fine for edit/accident detection, thin against deliberate grinding, and it should never be citable as full SHA-256. README's chain section now names it. (2026-08-13, same night as the 7 reviewer replies.)

## 0.4.0 — 2026-08-13
- **External witness — `WitnessStore` + `publish_head()` / `verify_against_witness()`.** The outside check the chain alone cannot do: no append-only chain catches truncation by itself (chop the tail, the remainder verifies clean — documented since 0.2.1). A witness is a party outside your control that records your head `(rows, chain)` on a cadence; once it holds a pin at time T, a truncated log has fewer rows than the witness saw and a rewritten one has a different chain at the witnessed row. `WitnessStore` is the reference core — file-backed, append-only, holds ONLY fingerprints, never log content ("password nowhere": a breached witness yields hashes useless without the original log). A hosted endpoint is a thin wrapper over exactly this object; run it locally and you have a complete, offline, zero-cost witness.
- **Honest verdicts, stated as verdicts.** `verify_against_witness()` returns `consistent` / `truncated` / `rewritten` / `no_record` — a missing pin is `no_record`, never a false ok, and the result is truthy only on `consistent`. The honest boundary, in the docstring where it belongs: a witness proves no-truncation/no-rewrite only *relative to what it saw, and only as recently as the last pin*. The MAX gap between pins is the real security parameter, not the average — an attacker picks the gap. It says nothing about whether the content was true; that's artefact-binding's job.
- **`chain_at(path, n)`** — the chain value at row n, the primitive the witness comparison stands on; honest `None` past the end of the file.

## 0.3.0 — 2026-08-13
- **Artefact-binding — `bind_artefact()` / `verify_artefact()`.** The move from "tamper-evident diary" toward "evidence layer": bind a re-fetchable fact to a row so a third party can check what the agent actually read, not just that the row wasn't edited. `bind_artefact(source)` accepts bytes, a URL (fetched + hashed with http metadata), a file path, or any JSON value; returns an in-toto-`subject`-shaped dict you chain into a ledger row. Directly answers the launch code-review (a hash chain notarizes a hallucination as faithfully as a fact — bind the source so the claim can be re-checked against it).
- **Self-describing, reproducible digests.** No bare hex ever. Every digest is `sha256:<recipe>:<ver>:<hex>`, carrying its own recipe so a stranger reproduces it from the string alone. Two recipes: `raw-bytes:v1` (opaque bytes as-read) and `json-c14n:v1` (a pinned, documented JSON canonicalization — sorted keys, compact, UTF-8, NaN/Inf rejected). Recipes are frozen and versioned append-only, so a future rule mints `v2` and old rows keep `v1` — a drifted canonicalizer never reads history as tampered. The recipe is deliberately **not** labelled RFC 8785/JCS: a stdlib serialization isn't bit-for-bit JCS on every float edge, and claiming a standard we don't exactly meet is the overclaim this library exists to refuse.
- **Honest verify semantics.** `verify_artefact()` always re-checks the digest string's self-consistency; with `refetch=True` on a URL it re-fetches and reports `match` / `mismatch` / `unavailable` — and a `mismatch` is documented as "content changed OR was tampered, INDETERMINATE," never a bare "tampered." The web mutates; a mismatch is not proof of foul play.
- `digest_bytes()` / `digest_json()` exported for the primitives directly.

## 0.2.1 — 2026-08-13
- **Import name fixed.** The package now imports as `arcaeon_ledger` (matching `pip install arcaeon-ledger`), instead of squatting the generic top-level name `ledger`. Both were flagged repeatedly by reviewers on launch — `pip install arcaeon-ledger; import arcaeon_ledger` now just works, and the CLI/MCP module paths are `arcaeon_ledger.cli` / `arcaeon_ledger.mcp_server`. (Breaking, but done now while adoption is ~0.)
- **`Ledger.head()` + `Head` — external anchoring shipped.** Returns the current chain head + row count + timestamp; `head().as_pin()` gives a one-line, publishable pin. Publishing it somewhere outside your control closes the **truncation gap** (chop the tail and the remainder still verifies — a property of every append-only chain). This was the single most-repeated reviewer critique; the fix is making the anchor a first-class, obvious step rather than a roadmap footnote.
- **Honesty pass on the docs.** README and module docstring now state plainly the three things a hash chain does *not* prove on its own — truncation, truth-of-content, and authorship — each with the concrete way to close it. Being precise about the boundary is the product.

## 0.2.0 — 2026-08-12
- Added `authority()` helper + `append(..., authority=...)`: bind WHO wrote each entry and with what permission (resolved principal, capability version, hashed tool schema, trusted time source). It chains like any field, so editing the writer identity breaks the chain too. Composes tamper-evidence with permission-replay. Shipped same-day in response to community feedback on launch.


## 0.1.0 — 2026-08-12
- Initial release. Zero-dependency tamper-evident, hash-chained action log for AI agents.
- Core library: `Ledger(path).append(record)` and `.verify()`; module `verify_file(path)`.
- Hash chain: `sha256(prev_chain + canonical_json(row_without_chain))[:32]`, genesis-seeded, atomic append (append-binary + flush + fsync).
- CLI: `ledger verify|append` with nonzero exit on a broken chain (CI/pre-ship gate).
- MCP server (`python -m arcaeon_ledger.mcp_server`): drop-in `ledger_append` / `ledger_verify` tools for any MCP client, zero-dependency JSON-RPC over stdio.
- Tested against edit, delete, and reorder tampering, and a full MCP handshake including tamper detection over the wire.
