"""Pin the KNOWN divergences between `json-c14n:v1` and RFC 8785 (JCS).

Why this file exists: the IETF 126 hackathon (July 2026) ran a SCITT interop table
across seven independent implementations, and one of the three defects it surfaced was
**JSON canonicalization divergence**. Several agent-audit drafts now carry a MUST-level
RFC 8785 requirement because of it, and at least one implementer has publicly retracted
a JCS conformance claim after discovering their sort was not actually JCS.

We do not claim JCS, and `artefact.py` says so in the docstring. But "we are not JCS"
is a weak statement without a named, tested instance of HOW we differ. This file turns
the disclaimer into a measurement. Every test here asserts a divergence is REAL and
STABLE — if one starts failing, the canonicalizer drifted, and drift is the thing that
silently reclassifies honest history as tampered.

These are limits of `json-c14n:v1`, not bugs to fix. Fixing them would change every
historical digest ever emitted. A JCS-exact rule mints `v2` and leaves `v1` alone.
"""

import hashlib
import json


def c14n_v1(value) -> str:
    """The frozen v1 recipe, exactly as artefact.py documents it."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def jcs_key_order(keys):
    """RFC 8785 sorts keys by UTF-16 code units, not by code point."""
    return sorted(keys, key=lambda k: k.encode("utf-16-be"))


def digest(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_supplementary_plane_keys_order_differently_than_jcs():
    """The likeliest divergence to actually hit: an emoji in a key.

    U+1F600 encodes in UTF-16 as a surrogate pair (D83D DE00). Those code units sort
    BELOW the BMP range E000-FFFF, so JCS puts the emoji first. Python sorts by code
    point, so U+FB00 (0xFB00) comes first here. Opposite orders, same object.
    """
    obj = {"\U0001F600": 1, "ﬀ": 2}

    ours = sorted(obj.keys())
    theirs = jcs_key_order(obj.keys())

    assert ours == ["ﬀ", "\U0001F600"], "v1 recipe changed its key order"
    assert theirs == ["\U0001F600", "ﬀ"], "JCS reference ordering changed"
    assert ours != theirs, "the divergence disappeared — recipe or reference drifted"


def test_the_divergence_actually_changes_the_digest():
    """Ordering only matters if it reaches the hash. Prove that it does."""
    obj = {"\U0001F600": 1, "ﬀ": 2}

    ours = c14n_v1(obj)
    theirs = json.dumps({k: obj[k] for k in jcs_key_order(obj.keys())},
                        separators=(",", ":"), ensure_ascii=False)

    assert digest(ours) != digest(theirs), (
        "same logical object must produce different digests under v1 vs JCS ordering; "
        "if this passes-as-equal the divergence is gone and the docstring is now wrong")


def test_bmp_only_keys_agree_with_jcs():
    """The boundary of the problem: below U+10000 the two orderings agree.

    This is the half that makes the limitation tolerable — ordinary ASCII and BMP keys,
    which is essentially every real log row, canonicalize identically to JCS.
    """
    obj = {"zebra": 1, "alpha": 2, "éclair": 3, "ﬀ": 4}
    assert sorted(obj.keys()) == jcs_key_order(obj.keys())
    assert digest(c14n_v1(obj)) == digest(
        json.dumps({k: obj[k] for k in jcs_key_order(obj.keys())},
                   separators=(",", ":"), ensure_ascii=False))


def test_recipe_rejects_nan_and_infinity():
    """allow_nan=False is load-bearing: NaN is not JSON and is not canonicalizable."""
    for bad in (float("nan"), float("inf"), float("-inf")):
        try:
            c14n_v1({"x": bad})
        except ValueError:
            continue
        raise AssertionError("v1 recipe must refuse %r, not serialize it" % bad)


def test_frozen_vectors_still_reproduce():
    """Guard the recipe itself. If these digests move, v1 drifted and history breaks."""
    vectors = [
        ({}, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
        ({"a": 1}, digest('{"a":1}')),
        ({"b": 1, "a": 2}, digest('{"a":2,"b":1}')),
    ]
    for value, expected in vectors:
        assert digest(c14n_v1(value)) == expected, "json-c14n:v1 changed for %r" % (value,)
