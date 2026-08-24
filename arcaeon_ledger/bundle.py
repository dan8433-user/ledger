# SPDX-License-Identifier: MIT
"""arcaeon_ledger.bundle — one-command auditor evidence bundle.

    python -m arcaeon_ledger.bundle <ledger.jsonl> [--out DIR|ZIP] [--namespace NS]

Assembles, into one directory (or one .zip), everything a third party needs to
check a ledger file without trusting the party who handed it over:

  1. the ledger file itself — copied VERBATIM, byte-identical, its sha256 stated;
  2. verify_report.json — the package's own strict-mode verification result in
     full, plus the exact command a stranger can re-run to reproduce it;
  3. witness_latest.json — the hosted witness's latest public pin for the
     ledger's namespace (only when --namespace is given and the fetch succeeds;
     absence is always STATED, never silent);
  4. README.txt — plain-English statement of what each file proves and, just as
     load-bearing, what none of them prove;
  5. MANIFEST.json — sha256 of every file in the bundle, the generation
     timestamp, the package version, and the verbatim generation command, so
     the bundle itself is checkable.

The input ledger is opened read-only and never modified. The only network call
is the optional witness fetch; when it fails the bundle still completes and the
failure is recorded in the manifest and the README (a stated gap, not a silent
one). Stdlib only, like the rest of the package.

Exit codes: 0 = bundle written (even when the ledger verifies RED — evidence of
a broken chain is still evidence, and the verdict is stated in the bundle);
1 = usage error or the bundle could not be written at all.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from arcaeon_ledger import __version__, verify_file

__all__ = ["build_bundle", "BundleResult", "WITNESS_API_BASE", "WITNESS_HISTORY_BASE"]

WITNESS_API_BASE = "https://arcaeon-witness.vercel.app/api/latest?ns="
WITNESS_HISTORY_BASE = "https://github.com/dan8433-user/arcaeon-witness-pins/commits/main/pins/"

_FETCH_TIMEOUT = 10.0
# Names the bundle itself claims; a ledger file that happens to carry one of
# these basenames is copied under a "ledger_" prefix instead of colliding.
_RESERVED_NAMES = {"verify_report.json", "witness_latest.json", "README.txt", "MANIFEST.json"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _default_fetcher(url: str) -> tuple[int, bytes]:
    """GET `url`; returns (http_status, body_bytes). Raises on transport failure.

    An HTTP error status (404 for an unpinned namespace, 5xx, ...) is NOT a
    transport failure: the response body is still the witness speaking, so it
    is returned with its status and included as evidence rather than dropped.
    """
    req = urllib.request.Request(url, headers={"User-Agent": f"arcaeon-ledger-bundle/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:            # non-2xx WITH a body: still evidence
        return e.code, e.read()


@dataclass
class BundleResult:
    """What was written, where, and the manifest that describes it."""
    out_path: Path                       # the bundle directory, or the .zip file
    is_zip: bool
    ledger_name: str                     # basename of the ledger copy inside the bundle
    ledger_sha256: str
    verify_ok: Any                       # the strict verify's three-valued ok
    manifest: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------

def _witness_section(namespace: str | None,
                     fetcher: Callable[[str], tuple[int, bytes]]) -> tuple[dict, bytes | None]:
    """Build the manifest's witness block; returns (block, verbatim_body_or_None)."""
    if namespace is None:
        return {
            "included": False,
            "status": "not_requested",
            "statement": "No witness evidence included: no --namespace was given, "
                         "so no witness lookup was attempted.",
        }, None
    url = WITNESS_API_BASE + urllib.parse.quote(namespace, safe="")
    history_url = WITNESS_HISTORY_BASE + urllib.parse.quote(namespace, safe="")
    try:
        status, body = fetcher(url)
    except Exception as e:  # transport failure: offline, DNS, TLS, timeout
        return {
            "included": False,
            "namespace": namespace,
            "url": url,
            "history_url": history_url,
            "status": f"fetch_failed: {type(e).__name__}: {e}",
            "statement": "No witness evidence included: the witness fetch failed "
                         f"({type(e).__name__}). The pin history remains publicly "
                         f"checkable at {history_url}",
        }, None
    return {
        "included": True,
        "namespace": namespace,
        "url": url,
        "history_url": history_url,
        "http_status": status,
        "status": "included",
        "file": "witness_latest.json",
        "statement": "witness_latest.json is the witness API response, byte-verbatim, "
                     f"HTTP {status}. The full public pin history: {history_url}",
    }, body


def _readme_text(ledger_name: str, ledger_sha: str, verify_report: dict,
                 witness: dict, anchor: dict, generated_at: str,
                 generation_command: str) -> str:
    r = verify_report["result"]
    ok = r.get("ok")
    if ok is True:
        verdict_line = ("VERDICT: intact. Every row was checked in strict mode and the "
                        "hash chain holds end to end.")
    elif verify_report.get("prechain_adoption"):
        lr = verify_report["lenient_result"]
        # HONESTY FIX (pre-invite audit 2026-08-23, C5). This branch used to end
        # "that is not evidence of alteration" — resolving, in the log owner's
        # favour, in the one file an auditor actually reads, a question this
        # package's own docstring says CANNOT BE RESOLVED: "the verifier cannot
        # tell real legacy history from a fabricated prepend." Strict-red plus
        # lenient-null IS the fabricated-prepend signature; it is also the honest
        # adopter's signature, and nothing in the bytes separates them. A critic
        # only had to quote our docstring against our own README.txt.
        # State the undecidability instead of denying it, and quote the counts so
        # the reader can see how much of the file is unverifiable.
        verdict_line = (
            f"VERDICT: verified from adoption onward, over {lr.get('chained')} of "
            f"{lr.get('rows')} row(s). This log was adopted over pre-existing history: "
            f"{lr.get('prechain')} row(s) before the first chained row carry no chain and "
            "are NOT cryptographically verifiable. From the first chained row to the end, "
            f"the hash chain holds (lenient_result: ok=null, scope "
            f"'{lr.get('verified_scope')}').\n\n"
            "WHAT THIS DOES NOT SETTLE, stated plainly: unchained leading rows are the "
            "expected shape of an honest adoption AND the exact shape of a fabricated "
            "prepend. This package cannot tell those apart — nothing in the bytes "
            "distinguishes real legacy history from history invented later and placed "
            "before the first chained row. Strict mode counts those rows as breaks; that "
            "is neither proof of tampering nor evidence against it. Treat the pre-chain "
            "region as UNVERIFIED, not as vouched for. To close it, pin the head to an "
            "external witness at adoption time: rows written from that point forward are "
            "the ones this bundle can actually stand behind.")
    elif ok is False:
        verdict_line = ("VERDICT: BROKEN. Strict verification found "
                        f"{r.get('breaks')} break(s); first break: {r.get('first_break')}. "
                        "This bundle is evidence of a broken chain, stated as such.")
    else:
        verdict_line = ("VERDICT: verified within scope only (ok=null). No break was "
                        "found but some rows could not be verified; see verify_report.json.")
    lines = [
        "ARCAEON LEDGER — EVIDENCE BUNDLE",
        "=" * 60,
        f"Generated:        {generated_at}",
        f"Generator:        arcaeon-ledger {__version__} (stdlib-only Python package)",
        f"Command:          {generation_command}",
        "",
        "This bundle was assembled so that a third party can check the enclosed",
        "log file without trusting whoever handed it over. Every claim below is",
        "re-checkable with the enclosed files and public tooling.",
        "",
        "FILES, AND WHAT EACH ONE PROVES",
        "-" * 60,
        "",
        f"1. {ledger_name}",
        "   The log itself: an append-only JSONL file in which each row carries a",
        "   hash chained to the row before it. Copied into this bundle verbatim,",
        "   byte-identical to the source file at generation time.",
        f"   sha256: {ledger_sha}",
        "   On its own this file proves nothing; it is the subject of the evidence.",
        "",
        "2. verify_report.json",
        "   The complete result of running this package's own verifier over the",
        "   file above, in STRICT mode (every row must chain; unchained rows are",
        "   failures, not skips).",
        f"   {verdict_line}",
        "   Do not take the report's word for it — reproduce it yourself:",
        f"       {verify_report['command']}",
        "   (pip install arcaeon-ledger; exit 0 = fully verified, 1 = broken.)",
        "   A green result proves: the recorded CONTENT of each row was not edited,",
        "   or reordered IN PLACE after they were written. An edit anywhere in",
        "   the middle of the file breaks every later link and the verifier",
        "   names the exact line.",
        "",
        "3. Witness evidence",
        f"   {witness['statement']}",
    ]
    if witness.get("included"):
        lines += [
            "   A witness pin is a (row count, chain head) fingerprint recorded on a",
            "   public, third-party-timestamped store OUTSIDE the log owner's",
            "   control. Comparing the pinned head against this file proves the log",
            "   was not silently truncated or rewritten relative to what the witness",
            "   saw — a guarantee the hash chain alone cannot give. The pin history",
            "   URL above is a public GitHub commit history; check it directly.",
            "   This bundle includes the pin as fetched; it does not itself perform",
            "   or assert that comparison — checking the pin against the ledger is",
            "   the auditor's step.",
        ]
    lines += [
        "",
        "4. Timestamp anchoring (OpenTimestamps / blockchain anchors)",
        f"   {anchor['statement']}",
        "",
        "5. MANIFEST.json",
        "   sha256 of every file in this bundle, the generation timestamp, package",
        "   version, and the generation command. To check the bundle itself,",
        "   re-hash each listed file and compare. MANIFEST.json cannot contain its",
        "   own hash; if you received this bundle through an untrusted channel,",
        "   obtain the expected manifest hash out of band.",
        "",
        "WHAT THIS BUNDLE DOES NOT PROVE",
        "-" * 60,
        "- It does not prove the logged statements are TRUE. The chain notarizes",
        "  whatever was written, accurate or not.",
        "- It does not prove COMPLETENESS: that everything which should have been",
        "  logged was logged. The verifier checks integrity of what is present,",
        "  never the presence of what is absent.",
        "- It does not prove AUTHORSHIP. Authority fields are data in the rows,",
        "  not cryptographic signatures.",
        "- Without witness evidence, it does not rule out TRUNCATION: a log cut",
        "  at the tail still verifies green. Only an external pin closes that gap,",
        "  and only up to the time of the last pin.",
        "- It does not make anyone compliant with any law or regulation, and it",
        "  does not classify any AI system as high-risk or otherwise. Legal",
        "  duties bind providers and deployers — organizations, not files; no",
        "  software artifact can discharge them on its own.",
        "",
        "LEGAL CONTEXT (stated precisely, claiming no more than the text)",
        "-" * 60,
        "The EU AI Act requires high-risk AI systems to technically allow",
        "automatic recording of events over the system's lifetime (Art. 12(1)),",
        "and requires both providers and deployers to keep those logs, to the",
        "extent under their control, for at least six months (Art. 19(1),",
        "Art. 26(6)). arcaeon-ledger gives you an ownable, portable event record",
        "you can independently prove was never altered, and the witness makes",
        "silent truncation of a retained log detectable by a stranger —",
        "integrity and provable retention support for the logs those articles",
        "make you keep. Nothing in this bundle asserts conformity with that",
        "regulation or any other.",
        "",
    ]
    return "\n".join(lines)


def build_bundle(ledger_path: str | Path, *, out: str | Path | None = None,
                 namespace: str | None = None,
                 fetcher: Callable[[str], tuple[int, bytes]] | None = None,
                 generation_command: str | None = None) -> BundleResult:
    """Assemble the evidence bundle. Never modifies the input ledger.

    `out` ending in ".zip" (case-insensitive) produces a single zip archive;
    anything else (or None) produces a directory. A None `out` creates
    `<stem>_evidence_bundle_<UTC timestamp>` in the current directory.
    `fetcher` is injectable for tests; it must return (http_status, body_bytes)
    or raise on transport failure.
    """
    src = Path(ledger_path)
    if not src.is_file():
        raise FileNotFoundError(f"ledger file not found: {src}")
    fetcher = fetcher or _default_fetcher
    generated_at = _now_iso()
    if generation_command is None:
        parts = ["python -m arcaeon_ledger.bundle", str(ledger_path)]
        if out is not None:
            parts += ["--out", str(out)]
        if namespace is not None:
            parts += ["--namespace", namespace]
        generation_command = " ".join(parts)

    if out is None:
        out = Path.cwd() / f"{src.stem}_evidence_bundle_{generated_at.replace(':', '').replace('-', '')}"
    out = Path(out)
    as_zip = out.suffix.lower() == ".zip"

    ledger_name = src.name if src.name not in _RESERVED_NAMES else "ledger_" + src.name

    # Verify read-only over the source file. Strict is the headline check, but an
    # honestly-adopted log (legacy pre-chain rows before the first chained row — a
    # first-class feature per the package docstring) fails strict for a reason that
    # is NOT tampering. Running non-strict alongside lets the bundle tell the two
    # apart instead of branding an adopter's log "BROKEN" (external audit 2026-08-23:
    # the bundle's strict brand contradicted the verifier's own three-valued honesty
    # on the exact workflow the README sells).
    result = verify_file(src, strict=True)
    lenient = verify_file(src, strict=False)
    # strict-broken but lenient-clean-modulo-prechain = adoption, not tampering.
    # `lenient.chained > 0` is load-bearing (pre-invite audit C5/F3). Without it a
    # log with ZERO chained rows — every link stripped — took the adoption branch,
    # and the bundle asserted "the hash chain holds" over a file with no verified
    # links at all, while MANIFEST.json honestly carried verify.ok=false. The
    # machine-readable field was right and the human-readable verdict, which is
    # the artifact's whole purpose, was not. No first chained row means no
    # adoption claim: fall through to BROKEN.
    prechain_only = (result.ok is False and lenient.ok is None
                     and lenient.verified_scope == "bounded_prechain_skipped"
                     and (lenient.chained or 0) > 0)
    verify_report = {
        "package": "arcaeon-ledger",
        "package_version": __version__,
        "mode": "strict",
        "ledger_file": ledger_name,
        "command": f"python -m arcaeon_ledger.cli verify --strict {ledger_name}",
        "exit_code_semantics": {"0": "fully verified", "1": "broken or usage error",
                                "3": "verified within scope only (non-strict mode only)"},
        "result": dict(result.__dict__),
        "lenient_result": dict(lenient.__dict__),
        "prechain_adoption": prechain_only,
        "generated_at": generated_at,
    }

    witness, witness_body = _witness_section(namespace, fetcher)
    anchor = {
        "included": False,
        "statement": "Not included: this package ships no timestamp-anchoring "
                     "(OpenTimestamps) tooling of its own. The hosted witness "
                     "service anchors its pin store daily on its own side; those "
                     "receipts live with the witness, not in this bundle.",
    }

    def _write_all(dest: Path) -> dict[str, dict]:
        """Write every bundle file into `dest`; returns {name: {sha256, bytes}}."""
        dest.mkdir(parents=True, exist_ok=True)
        if any(dest.iterdir()):
            raise FileExistsError(f"refusing to write into non-empty directory: {dest}")
        files: dict[str, dict] = {}

        def _put(name: str, data: bytes) -> None:
            (dest / name).write_bytes(data)
            files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

        # 1. the ledger, verbatim — copy then prove the copy matches the source.
        shutil.copyfile(src, dest / ledger_name)
        copy_sha = _sha256_file(dest / ledger_name)
        src_sha = _sha256_file(src)
        if copy_sha != src_sha:  # pragma: no cover - a live concurrent writer
            raise RuntimeError("ledger changed while being copied; re-run the bundle")
        files[ledger_name] = {"sha256": copy_sha, "bytes": (dest / ledger_name).stat().st_size}

        # 2. verify report
        _put("verify_report.json",
             (json.dumps(verify_report, indent=2) + "\n").encode("utf-8"))
        # 3. witness response, byte-verbatim, only when actually fetched
        if witness_body is not None:
            _put("witness_latest.json", witness_body)
        # 4. README
        readme = _readme_text(ledger_name, copy_sha, verify_report, witness,
                              anchor, generated_at, generation_command)
        _put("README.txt", readme.encode("utf-8"))
        # 5. manifest — last, over everything already written
        manifest = {
            "format": "arcaeon-ledger-evidence-bundle/1",
            "generated_at": generated_at,
            "package_version": __version__,
            "generation_command": generation_command,
            "ledger_file": ledger_name,
            "ledger_sha256": copy_sha,
            "verify": {"mode": "strict", "ok": result.ok, "file": "verify_report.json"},
            "witness": witness,
            "anchor": anchor,
            "files": files,
            "manifest_note": "MANIFEST.json cannot include its own hash. Check the "
                             "bundle by re-hashing every file listed under 'files'.",
        }
        (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                            encoding="utf-8")
        files_and_manifest = dict(files)
        files_and_manifest["__manifest__"] = manifest
        return files_and_manifest

    if as_zip:
        if out.exists():
            raise FileExistsError(f"refusing to overwrite existing file: {out}")
        with tempfile.TemporaryDirectory(prefix="arcaeon_bundle_") as tmp:
            staged = Path(tmp) / "bundle"
            written = _write_all(staged)
            out.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for p in sorted(staged.iterdir()):
                    zf.write(p, arcname=p.name)
    else:
        written = _write_all(out)

    manifest = written.pop("__manifest__")
    return BundleResult(out_path=out, is_zip=as_zip, ledger_name=ledger_name,
                        ledger_sha256=manifest["ledger_sha256"],
                        verify_ok=result.ok, manifest=manifest)


# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = (__doc__ or "usage: python -m arcaeon_ledger.bundle <ledger.jsonl> "
                        "[--out DIR|ZIP] [--namespace NS]").strip()
    if argv and argv[0] in ("-h", "--help"):
        print(usage)
        return 0
    out: str | None = None
    namespace: str | None = None
    positional: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--out", "--namespace"):
            if i + 1 >= len(argv):
                print(f"{a} needs a value")
                return 1
            if a == "--out":
                out = argv[i + 1]
            else:
                namespace = argv[i + 1]
            i += 2
        elif a.startswith("--"):
            print(f"unknown option: {a}")
            return 1
        else:
            positional.append(a)
            i += 1
    if len(positional) != 1:
        print(usage)
        return 1
    command = "python -m arcaeon_ledger.bundle " + " ".join(argv)
    try:
        res = build_bundle(positional[0], out=out, namespace=namespace,
                           generation_command=command)
    except (FileNotFoundError, FileExistsError, RuntimeError, OSError) as e:
        print(f"bundle failed: {e}")
        return 1
    kind = "zip" if res.is_zip else "directory"
    print(json.dumps({
        "bundle": str(res.out_path),
        "kind": kind,
        "ledger_file": res.ledger_name,
        "ledger_sha256": res.ledger_sha256,
        "verify_ok": res.verify_ok,
        "witness": res.manifest["witness"]["status"],
        "files": sorted(res.manifest["files"]) + ["MANIFEST.json"],
    }, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
