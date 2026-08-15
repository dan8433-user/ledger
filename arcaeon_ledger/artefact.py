"""arcaeon_ledger.artefact — bind a re-fetchable fact to a ledger row.

A hash chain proves a *record* wasn't altered. It does NOT prove the record was
ever *true* — it will notarize a hallucination as faithfully as a fact. To make
a row speak about the world, you bind an ARTEFACT: hash the actual bytes the
agent read (a URL's content, a file, tool stdout, a JSON object), store that
digest in the row, and let a third party re-fetch and compare.

Two honest limits, stated up front because being precise about them IS the point:

  1. A digest binds *the bytes as-read at time T*, nothing more. `verify_artefact`
     re-computes the digest from the recipe (always) and, for a URL, can re-fetch
     and compare — but a re-fetch MISMATCH means "the content changed OR was
     tampered, indeterminate," NEVER a bare "tampered." The web mutates, 404s,
     paywalls, and personalizes; a mismatch is not proof of foul play.

  2. A digest is meaningless without its canonicalization rule. We never emit a
     bare hex hash. Every digest is a SELF-DESCRIBING string that carries its own
     recipe and version, so a stranger reconstructs it from the string alone:

         sha256:raw-bytes:v1:<hex>     # opaque bytes, hashed as-read
         sha256:json-c14n:v1:<hex>     # a JSON value, canonicalized (see below)

     The `json-c14n` v1 recipe is defined EXACTLY as, and reproducible in any
     language by, following these steps:
         canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False)
         digest    = sha256(canonical.encode("utf-8"))
     i.e. object keys sorted, no inter-token whitespace, non-ASCII kept as UTF-8,
     NaN/Infinity rejected. Keep numbers within I-JSON safe range (integers with
     abs value <= 2**53-1; avoid arbitrary-precision decimals) so the serialization
     is unambiguous across languages. This is our own pinned, versioned recipe — it
     is deliberately NOT labelled RFC 8785 (JCS), because a stdlib serialization is
     not bit-for-bit JCS on every float edge case, and claiming a standard we don't
     exactly meet is the kind of overclaim this whole library exists to refuse. The
     recipe is frozen: `v1` never changes; a future rule would mint `v2`, and old
     rows keep `v1` forever, so a drifted canonicalizer never reads history as
     tampered.

     The other half of a self-describing digest is that the verifier must REFUSE
     labels it cannot reproduce. `verify_artefact` accepts a digest only when its
     algorithm, recipe name, and recipe version are all in the supported registry
     (`SUPPORTED_ALGOS`, `RECIPES`, `SUPPORTED_RECIPE_VERSIONS`); anything else is a
     hard typed failure — `unknown_algorithm` / `unknown_recipe` /
     `unknown_recipe_version` — never a pass with a warning attached. A digest we
     cannot recompute is a digest we did not check, and "did not check" must not be
     reported as "verified."

The result of `bind_artefact` is a plain dict, shaped after the in-toto
attestation `subject`, ready to drop into a ledger row (chain it like any field):

    from arcaeon_ledger import Ledger, bind_artefact
    log = Ledger("agent.log.jsonl")
    art = bind_artefact("https://example.com/pricing")   # or bytes / a dict / a path
    log.append({"tool": "web.read", "url": "https://example.com/pricing",
                "artefact": art})

Stdlib only. The URL path uses urllib (network); everything else is offline.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["bind_artefact", "verify_artefact", "digest_bytes", "digest_json", "RECIPES",
           "SUPPORTED_RECIPE_VERSIONS", "SUPPORTED_ALGOS", "FAILURE_REASONS"]

# The frozen recipe registry. A recipe name maps to (version, description). Append
# only: never repurpose or renumber an existing entry, or old digests stop
# reproducing. New rule -> new name or bumped version, old rows keep their label.
# This maps to the CURRENT version minted for each recipe — what `bind_artefact`
# stamps today. It is NOT the set of versions verification accepts; that is
# SUPPORTED_RECIPE_VERSIONS below, and the two are deliberately separate.
RECIPES = {
    "raw-bytes": ("v1", "sha256 of the artefact's raw bytes, exactly as read"),
    "json-c14n": ("v1", "sha256 of json.dumps(value, sort_keys=True, "
                        "separators=(',',':'), ensure_ascii=False, allow_nan=False) "
                        "encoded UTF-8"),
}

# Every (recipe, version) pair THIS BUILD can actually reproduce. `verify_artefact`
# accepts a digest only if its recipe AND version appear here — a label this build
# cannot reproduce is a typed failure, never a note-only pass.
#
# This is also how the documented "old rows keep v1 forever" promise is kept: when
# a future rule mints json-c14n v2, RECIPES flips to "v2" (new digests get the new
# label) while this tuple becomes ("v1", "v2") — old v1 rows keep verifying,
# because a version we still ship the code for is still reproducible. Append here;
# only remove a version if the build genuinely loses the ability to compute it,
# and say so in the changelog when you do.
SUPPORTED_RECIPE_VERSIONS = {
    "raw-bytes": ("v1",),
    "json-c14n": ("v1",),
}

# Digest algorithms this build can reproduce, and the hex length each must present.
# An algo outside this table is a typed failure: "sha256:" is not decoration, and a
# digest string claiming md5/blake3/whatever is not something we verified.
SUPPORTED_ALGOS = {"sha256": 64}

# The typed failure vocabulary of `verify_artefact`. `reason` is exactly one of
# these on failure, and None on success — so a caller can branch on the machine
# value instead of substring-matching the human-readable notes.
FAILURE_REASONS = (
    "malformed_digest",       # not algo:recipe:ver:hex, or hex is not the algo's hex
    "unknown_algorithm",      # algo not in SUPPORTED_ALGOS
    "unknown_recipe",         # recipe name not in the registry
    "unknown_recipe_version", # recipe known, version this build cannot reproduce
    "subject_digest_mismatch",# embedded hex disagrees with subject.digest.sha256
)

_ALGO = "sha256"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_FETCH_CAP = 25 * 1024 * 1024  # 25 MB ceiling on a fetched artefact — refuse to hash more


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canon_json(value: Any) -> bytes:
    """The json-c14n v1 canonicalization. Reproducible from the recipe string alone."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest_string(recipe: str, raw: bytes) -> str:
    """Build the self-describing digest: sha256:<recipe>:<ver>:<hex>."""
    ver = RECIPES[recipe][0]
    return f"{_ALGO}:{recipe}:{ver}:{hashlib.sha256(raw).hexdigest()}"


def digest_bytes(data: bytes) -> str:
    """Self-describing raw-bytes digest of opaque data."""
    return _digest_string("raw-bytes", data)


def digest_json(value: Any) -> str:
    """Self-describing json-c14n digest of a JSON-serializable value."""
    return _digest_string("json-c14n", _canon_json(value))


def _looks_like_url(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def bind_artefact(source: Any, *, canon: str = "auto",
                  fetch_cap: int = _FETCH_CAP) -> dict:
    """Bind a re-fetchable fact to a ledger-row-embeddable dict.

    `source` may be:
      - bytes                      -> hashed raw (recipe raw-bytes)
      - a URL str (http/https)     -> fetched, raw response body hashed (raw-bytes),
                                      with http metadata captured for re-fetch
      - a filesystem path (Path,
        or str to an existing file)-> file bytes hashed (raw-bytes)
      - any JSON-serializable value-> canonicalized + hashed (recipe json-c14n)

    `canon="auto"` picks by type as above. Force it with canon="raw-bytes" (hash
    the value's bytes / its UTF-8 if a str) or canon="json-c14n" (canonicalize).

    Returns an in-toto-`subject`-shaped dict:
        {"subject": {"name": <str>, "digest": {"sha256": "<hex>"}},
         "recipe":  "<algo>:<recipe>:<ver>",       # the self-describing prefix
         "digest":  "<algo>:<recipe>:<ver>:<hex>", # the full self-describing string
         "bound_at": "<iso8601 Z>",
         "source_meta": {...}}                       # http status/type/len for URLs

    The dict chains like any other row field, so binding it into a ledger entry
    makes the artefact digest tamper-evident alongside the action.
    """
    if canon not in ("auto", "raw-bytes", "json-c14n"):
        raise ValueError("canon must be 'auto', 'raw-bytes', or 'json-c14n'")

    name = None
    source_meta: dict[str, Any] = {}
    recipe: str
    raw_for_hash: bytes

    # --- URL: fetch and hash the raw response body ------------------------------
    if isinstance(source, str) and _looks_like_url(source) and canon != "json-c14n":
        name = source
        req = urllib.request.Request(source, headers={"User-Agent": "arcaeon-ledger/artefact"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(fetch_cap + 1)
            if len(body) > fetch_cap:
                raise ValueError(f"artefact exceeds fetch_cap ({fetch_cap} bytes); refusing to bind a truncated read")
            source_meta = {
                "kind": "url",
                "http_status": getattr(r, "status", None) or r.getcode(),
                "content_type": r.headers.get("Content-Type"),
                "content_length": len(body),
                "final_url": r.geturl(),
            }
        recipe, raw_for_hash = "raw-bytes", body

    # --- existing file path: hash the file bytes --------------------------------
    elif isinstance(source, Path) or (isinstance(source, str) and canon != "json-c14n"
                                      and Path(source).is_file()):
        p = Path(source)
        data = p.read_bytes()
        if len(data) > fetch_cap:
            raise ValueError(f"artefact exceeds fetch_cap ({fetch_cap} bytes)")
        name = p.name
        source_meta = {"kind": "file", "path": str(p), "content_length": len(data)}
        recipe, raw_for_hash = "raw-bytes", data

    # --- raw bytes --------------------------------------------------------------
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        source_meta = {"kind": "bytes", "content_length": len(data)}
        recipe, raw_for_hash = "raw-bytes", data

    # --- explicit raw-bytes on a str: hash its UTF-8 ----------------------------
    elif canon == "raw-bytes" and isinstance(source, str):
        data = source.encode("utf-8")
        source_meta = {"kind": "text", "content_length": len(data)}
        recipe, raw_for_hash = "raw-bytes", data

    # --- JSON-serializable value: canonicalize ----------------------------------
    else:
        recipe = "json-c14n"
        raw_for_hash = _canon_json(source)
        source_meta = {"kind": "json", "content_length": len(raw_for_hash)}

    hex_digest = hashlib.sha256(raw_for_hash).hexdigest()
    ver = RECIPES[recipe][0]
    return {
        "subject": {"name": name, "digest": {"sha256": hex_digest}},
        "recipe": f"{_ALGO}:{recipe}:{ver}",
        "digest": f"{_ALGO}:{recipe}:{ver}:{hex_digest}",
        "bound_at": _now_iso(),
        "source_meta": source_meta,
    }


def _parse_digest(s: str) -> tuple[str, str, str, str]:
    """Split a self-describing digest 'algo:recipe:ver:hex' into its parts."""
    if not isinstance(s, str):
        raise ValueError(f"digest must be a string, got {type(s).__name__}")
    parts = s.split(":")
    if len(parts) != 4:
        raise ValueError(f"malformed digest string: {s!r}")
    return parts[0], parts[1], parts[2], parts[3]


def verify_artefact(artefact: dict, *, refetch: bool = False,
                    fetch_cap: int = _FETCH_CAP) -> dict:
    """Verify an artefact dict produced by `bind_artefact`.

    Always: re-parses the self-describing digest, confirms this build can actually
    REPRODUCE the recipe it names (algorithm + recipe + version all in the supported
    registry), and confirms the string is internally consistent (the embedded hex
    matches subject.digest).

    An unsupported label is a HARD, TYPED failure — `digest_ok=False` plus a
    machine-readable `reason` from `FAILURE_REASONS`. It is never a pass and never a
    silent skip: a digest we cannot recompute is a digest we did not check, and
    reporting an unchecked digest as verified is the exact overclaim this library
    exists to refuse. (Before 0.5.2 an unknown VERSION of a known recipe passed with
    only a note; the mutation harness carried that hole as a standing NOTE. It is
    now a case, observed red.)

    If `refetch=True` and the artefact is a URL, also re-fetches and re-hashes,
    reporting the comparison HONESTLY:
      - "match"       — re-fetched bytes reproduce the digest
      - "mismatch"    — they do NOT. This means the content CHANGED or was tampered,
                        INDETERMINATE. It is NOT proof of tampering (the web mutates).
      - "unavailable" — the URL could not be fetched (404, network, cap exceeded).
    A failed digest never reaches the re-fetch stage, so `refetch` can never report
    "match" for an artefact whose recipe was not verified.

    Returns:
        {"digest_ok": bool,               # recipe reproducible + string self-consistent
         "reason": None | <one of FAILURE_REASONS>,   # typed failure, None when ok
         "recipe": "<algo:recipe:ver>",
         "refetch": "match|mismatch|unavailable|skipped",
         "notes": [<str>, ...]}
    """
    notes: list[str] = []
    out = {"digest_ok": False, "reason": None, "recipe": None,
           "refetch": "skipped", "notes": notes}

    def fail(reason: str, note: str) -> dict:
        out["reason"] = reason
        notes.append(note)
        return out

    # Type confusion is a MALFORMED artefact, not an exception. Through 0.5.2 a
    # non-str digest (or a non-dict artefact) escaped as AttributeError/TypeError
    # from a function whose entire contract is "typed failure, never a crash",
    # so a caller branching on `reason` got an exception instead. (0.5.3)
    if not isinstance(artefact, dict):
        return fail("malformed_digest",
                    f"artefact must be an object, got {type(artefact).__name__}")
    try:
        ds = artefact["digest"]
        algo, recipe, ver, hexd = _parse_digest(ds)
    except (KeyError, ValueError, TypeError) as e:
        return fail("malformed_digest", f"unparseable artefact: {e}")

    out["recipe"] = f"{algo}:{recipe}:{ver}"

    # 1. algorithm — "sha256:" is a claim about what was computed, not decoration.
    if algo not in SUPPORTED_ALGOS:
        return fail("unknown_algorithm",
                    f"unknown digest algorithm {algo!r} — this build reproduces only "
                    f"{sorted(SUPPORTED_ALGOS)}; cannot verify this digest")

    # 2. recipe name — an unregistered canonicalization rule is unreproducible.
    if recipe not in RECIPES:
        return fail("unknown_recipe",
                    f"unknown recipe {recipe!r} — cannot reproduce this digest")

    # 3. recipe VERSION — a version this build never shipped cannot be an old row.
    #    Old versions stay verifiable by remaining listed in
    #    SUPPORTED_RECIPE_VERSIONS; anything else we simply cannot recompute.
    supported = SUPPORTED_RECIPE_VERSIONS.get(recipe, ())
    if ver not in supported:
        return fail("unknown_recipe_version",
                    f"recipe {recipe} version {ver} is not reproducible by this build "
                    f"(it reproduces {list(supported)}) — cannot verify this digest")

    # 4. hex shape — the right length of hex for the named algorithm, or the string
    #    is not a digest at all and nothing below it means anything.
    want_len = SUPPORTED_ALGOS[algo]
    if len(hexd) != want_len or not _HEX_RE.match(hexd):
        return fail("malformed_digest",
                    f"digest hex is not {want_len} hex characters for {algo}")

    # 5. internal consistency: embedded hex must equal subject.digest.sha256.
    #    Compared case-insensitively — hex is case-insensitive by definition, and
    #    an up-cased copy of the SAME digest is not a disagreement (0.5.3).
    subj = artefact.get("subject")
    if subj is not None and not isinstance(subj, dict):
        return fail("malformed_digest", "subject is present but is not an object")
    subj_digest = (subj or {}).get("digest")
    if subj_digest is not None and not isinstance(subj_digest, dict):
        return fail("malformed_digest", "subject.digest is present but is not an object")
    subj_hex = (subj_digest or {}).get("sha256")
    if subj_hex is not None and not isinstance(subj_hex, str):
        return fail("malformed_digest", "subject.digest.sha256 is not a string")
    if subj_hex is not None and subj_hex.casefold() != hexd.casefold():
        return fail("subject_digest_mismatch",
                    "subject.digest.sha256 does not match the digest string's hex")

    out["digest_ok"] = True

    if not refetch:
        return out

    name = (subj or {}).get("name")
    if not isinstance(name, str):
        name = ""
    if not _looks_like_url(name):
        notes.append("refetch requested but artefact is not a URL; nothing to re-fetch")
        out["refetch"] = "skipped"
        return out
    if recipe != "raw-bytes":
        notes.append("refetch only meaningful for raw-bytes URL artefacts")
        out["refetch"] = "skipped"
        return out

    try:
        req = urllib.request.Request(name, headers={"User-Agent": "arcaeon-ledger/artefact"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(fetch_cap + 1)
        if len(body) > fetch_cap:
            out["refetch"] = "unavailable"
            notes.append("re-fetched artefact exceeds fetch_cap; cannot compare")
            return out
        now_hex = hashlib.sha256(body).hexdigest()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        out["refetch"] = "unavailable"
        notes.append(f"could not re-fetch ({e}); mismatch NOT implied")
        return out

    if now_hex.casefold() == hexd.casefold():
        out["refetch"] = "match"
    else:
        out["refetch"] = "mismatch"
        notes.append("re-fetched bytes differ from the bound digest. This means the "
                     "content CHANGED or was tampered — INDETERMINATE. Not proof of tampering.")
    return out
