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
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["bind_artefact", "verify_artefact", "digest_bytes", "digest_json", "RECIPES"]

# The frozen recipe registry. A recipe name maps to (version, description). Append
# only: never repurpose or renumber an existing entry, or old digests stop
# reproducing. New rule -> new name or bumped version, old rows keep their label.
RECIPES = {
    "raw-bytes": ("v1", "sha256 of the artefact's raw bytes, exactly as read"),
    "json-c14n": ("v1", "sha256 of json.dumps(value, sort_keys=True, "
                        "separators=(',',':'), ensure_ascii=False, allow_nan=False) "
                        "encoded UTF-8"),
}

_ALGO = "sha256"
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
    parts = s.split(":")
    if len(parts) != 4:
        raise ValueError(f"malformed digest string: {s!r}")
    return parts[0], parts[1], parts[2], parts[3]


def verify_artefact(artefact: dict, *, refetch: bool = False,
                    fetch_cap: int = _FETCH_CAP) -> dict:
    """Verify an artefact dict produced by `bind_artefact`.

    Always: re-parses the self-describing digest and confirms the string is
    well-formed and internally consistent (the embedded hex matches subject.digest).

    If `refetch=True` and the artefact is a URL, also re-fetches and re-hashes,
    reporting the comparison HONESTLY:
      - "match"       — re-fetched bytes reproduce the digest
      - "mismatch"    — they do NOT. This means the content CHANGED or was tampered,
                        INDETERMINATE. It is NOT proof of tampering (the web mutates).
      - "unavailable" — the URL could not be fetched (404, network, cap exceeded).

    Returns:
        {"digest_ok": bool,               # digest string well-formed + self-consistent
         "recipe": "<algo:recipe:ver>",
         "refetch": "match|mismatch|unavailable|skipped",
         "notes": [<str>, ...]}
    """
    notes: list[str] = []
    out = {"digest_ok": False, "recipe": None, "refetch": "skipped", "notes": notes}

    try:
        ds = artefact["digest"]
        algo, recipe, ver, hexd = _parse_digest(ds)
    except (KeyError, ValueError) as e:
        notes.append(f"unparseable artefact: {e}")
        return out

    out["recipe"] = f"{algo}:{recipe}:{ver}"

    if recipe not in RECIPES:
        notes.append(f"unknown recipe {recipe!r} — cannot reproduce this digest")
        return out
    if RECIPES[recipe][0] != ver:
        notes.append(f"recipe {recipe} is at {RECIPES[recipe][0]}, digest claims {ver} "
                     f"(old rows keep their version; this is not itself tampering)")

    # internal consistency: embedded hex must equal subject.digest.sha256
    subj_hex = (((artefact.get("subject") or {}).get("digest") or {}).get("sha256"))
    if subj_hex is not None and subj_hex != hexd:
        notes.append("subject.digest.sha256 does not match the digest string's hex")
        return out

    out["digest_ok"] = True

    if not refetch:
        return out

    name = ((artefact.get("subject") or {}).get("name")) or ""
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

    if now_hex == hexd:
        out["refetch"] = "match"
    else:
        out["refetch"] = "mismatch"
        notes.append("re-fetched bytes differ from the bound digest. This means the "
                     "content CHANGED or was tampered — INDETERMINATE. Not proof of tampering.")
    return out
