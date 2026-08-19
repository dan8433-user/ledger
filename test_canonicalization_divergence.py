"""Pin the KNOWN divergences between `json-c14n:v1` and RFC 8785 (JCS).

Why this file exists: the IETF 126 hackathon (July 2026) ran a SCITT interop table
across seven independent implementations, and one of the three defects it surfaced was
**JSON canonicalization divergence**. Several agent-audit drafts now carry a MUST-level
RFC 8785 requirement because of it, and at least one implementer has publicly retracted
a JCS conformance claim after discovering their sort was not actually JCS.

We do not claim JCS, and `artefact.py` says so in the docstring. But "we are not JCS"
is a weak statement without a named, tested instance of HOW we differ. This file turns
the disclaimer into a measurement.

These are limits of `json-c14n:v1`, not bugs to fix. Fixing them would change every
historical digest ever emitted. A JCS-exact rule mints `v2` and leaves `v1` alone.

WHY THIS FILE WAS REWRITTEN, and it is the more useful half of the lesson
------------------------------------------------------------------------
The first version of this file defined its own local `c14n_v1()` helper that
re-implemented the recipe, then asserted things about that helper. Every test passed.
An adversarial review then drifted the REAL `_canon_json` to `sort_keys=False`,
`separators=(", ", ": ")`, `ensure_ascii=True`, `allow_nan=True` — four simultaneous
changes to the recipe this file is named after — and all five tests still passed. NaN
was silently digesting under the `v1` label and nothing here noticed.

The docstring had claimed: "if one starts failing, the canonicalizer drifted." That
sentence was unfalsifiable, because the file never touched the canonicalizer. It was
testing a copy of the thing it was guarding, which is the purest form of a check that
cannot go red: a green from it means the copy still agrees with itself.

So every test below now goes through `digest_json` / `_canon_json` — the real, shipped
functions. The frozen vectors are hardcoded expected STRINGS rather than recomputed,
because a vector recomputed with the code under test is not a vector, it is a mirror.
Verified to go red against each of the four drifts individually and all four together.
"""

import hashlib
import json

from arcaeon_ledger.artefact import _canon_json, digest_json


def jcs_key_order(keys):
    """RFC 8785 sorts keys by UTF-16 code units, not by code point."""
    return sorted(keys, key=lambda k: k.encode("utf-16-be"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -- the divergence, measured against the REAL canonicalizer -------------------

def test_supplementary_plane_keys_order_differently_than_jcs():
    """The likeliest divergence to actually hit: an emoji in a key.

    U+1F600 encodes in UTF-16 as a surrogate pair (D83D DE00). Those code units sort
    BELOW the BMP range E000-FFFF, so JCS puts the emoji first. Python sorts by code
    point, so U+FB00 comes first. Opposite orders, same object.

    Read out of the real canonical bytes, so a change to `sort_keys` fails here.
    """
    obj = {"\U0001F600": 1, "ﬀ": 2}
    canon = _canon_json(obj).decode("utf-8")

    assert canon.index("ﬀ") < canon.index("\U0001F600"), (
        f"v1 must order U+FB00 before U+1F600 (code-point order); got {canon!r}")
    assert jcs_key_order(obj.keys()) == ["\U0001F600", "ﬀ"], (
        "JCS reference ordering changed")


def test_the_divergence_actually_changes_the_digest():
    """Ordering only matters if it reaches the hash. Prove that it does."""
    obj = {"\U0001F600": 1, "ﬀ": 2}

    ours = digest_json(obj)
    jcs_bytes = json.dumps({k: obj[k] for k in jcs_key_order(obj.keys())},
                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    assert ours.endswith(sha256_hex(_canon_json(obj))), (
        "digest_json must hash exactly what _canon_json produced")
    assert sha256_hex(_canon_json(obj)) != sha256_hex(jcs_bytes), (
        "same logical object must produce different digests under v1 vs JCS ordering; "
        "if these are equal the divergence is gone and the artefact.py docstring is "
        "now wrong")


def test_bmp_only_keys_agree_with_jcs():
    """The boundary of the problem: below U+10000 the two orderings agree.

    This is the half that makes the limitation tolerable — ordinary ASCII and BMP keys,
    which is essentially every real log row, canonicalize identically to JCS.
    """
    obj = {"zebra": 1, "alpha": 2, "éclair": 3, "ﬀ": 4}
    jcs_bytes = json.dumps({k: obj[k] for k in jcs_key_order(obj.keys())},
                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    assert _canon_json(obj) == jcs_bytes, (
        "BMP-only keys must canonicalize byte-identically to JCS; this agreement is "
        "what bounds the divergence to the supplementary planes")


# -- the recipe's own frozen properties ---------------------------------------

def test_recipe_rejects_nan_and_infinity():
    """`allow_nan=False` is load-bearing: NaN is not JSON and is not canonicalizable.

    This test is the reason the file imports the real function. When the reviewer
    flipped `allow_nan=True`, NaN began digesting happily under the `v1` label and the
    old local-copy version of this test never noticed.
    """
    for bad in (float("nan"), float("inf"), float("-inf")):
        try:
            _canon_json({"x": bad})
        except ValueError:
            continue
        raise AssertionError(f"json-c14n:v1 must refuse {bad!r}, not serialize it")


def test_recipe_emits_no_inter_token_whitespace():
    """`separators=(",", ":")` — compact form, verified on the real output."""
    canon = _canon_json({"b": 1, "a": [1, 2], "c": {"d": True}}).decode("utf-8")
    assert canon == '{"a":[1,2],"b":1,"c":{"d":true}}', canon
    assert ", " not in canon and ": " not in canon


def test_recipe_keeps_non_ascii_as_utf8():
    """`ensure_ascii=False` — a literal character, never a `\\uXXXX` escape."""
    canon = _canon_json({"k": "café 日"})
    assert "café 日".encode("utf-8") in canon
    assert b"\\u" not in canon, (
        "ensure_ascii must stay False, or every non-ASCII digest ever emitted changes")


def test_frozen_vectors_still_reproduce():
    """Guard the recipe itself against drift in any of its four parameters.

    The expected values are HARDCODED, not recomputed. A vector recomputed with the
    code under test cannot detect that code changing — that was the original defect in
    this file. These strings were produced by 0.5.7 and must never move for `v1`.
    """
    vectors = [
        ({}, "sha256:json-c14n:v1:"
             "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
        ({"a": 1}, "sha256:json-c14n:v1:"
                   "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"),
        ({"b": 1, "a": 2}, "sha256:json-c14n:v1:"
                          "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772"),
    ]
    for value, expected in vectors:
        got = digest_json(value)
        if got != expected:
            # Print both so a legitimate v2 migration can read the new value off a
            # failure instead of guessing, while v1 drift still fails loudly.
            raise AssertionError(
                f"json-c14n:v1 changed for {value!r}\n  expected {expected}\n  got      {got}")


def test_the_digest_label_names_the_recipe_and_version():
    """A digest that does not carry its recipe is not self-describing.

    Cheap, and it is the property the whole `verify_artefact` refusal path rests on:
    a verifier must be able to tell from the string alone whether it can reproduce it.
    """
    d = digest_json({"a": 1})
    algo, recipe, version, hexpart = d.split(":")
    assert (algo, recipe, version) == ("sha256", "json-c14n", "v1")
    assert len(hexpart) == 64 and int(hexpart, 16) >= 0
