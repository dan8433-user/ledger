# SPDX-License-Identifier: MIT
"""The credential redactor's corpus. Both directions, because both directions failed.

WHY THIS FILE EXISTS AS ITS OWN FILE. `_redact_argv` shipped with eleven tests in
`test_record_survives_hostile_content.py` and an adversarial audit still found eighteen
defects in it within hours. Those eleven tests were not wrong; they were narrow. They
covered the shapes I had thought of, which is the failure mode a corpus exists to close.

The two classes they missed:

**It leaked the dominant real shape.** `-e OPENAI_API_KEY=sk-proj-...` has no leading
dash, and the first version only inspected a token's `=` split when the token started
with one. So the single most common way an MCP server actually receives a secret — from
`docker run -e`, from `env`, from most client configs — passed through untouched into a
file whose purpose is to be handed to an auditor. It also carried Stripe's underscore
prefix and none of the hyphen forms that every current LLM vendor issues, which for a
product sold to agent operators meant missing the two likeliest real secrets on any
command line it would ever see.

**It wrote a false record.** `--no-auth` contains "auth", so the flag matched, the next
token was blanked unconditionally, and the row came out as `--no-auth <redacted>
a.jsonl` with `command_redactions=1`. A server launched with authentication DISABLED,
recorded as one that had a credential stripped, with a fabricated count beside it. That
is worse than an unredacted leak, because it is confidently wrong in an evidence file.
`--token --verbose` ate the next flag the same way; `--api-key-file /etc/keys/prod.pem`
blanked a path.

So the corpus has two halves and neither is optional. MUST_REDACT asserts no marker
survives. MUST_NOT_TOUCH asserts the argv comes back byte-identical with a count of
zero. A redactor that passes only the first half is a shredder.

Every case here was confirmed FAILING against the implementation it was written to
catch, except three MUST_REDACT guards deliberately written green (marked in the case
list) — fifty-four cases in the two lists, thirty-four observed red: eighteen against
the 0.1.0 redactor, three (the password-only userinfo shapes) against the first 0.1.1
cut, seven (NAME=VALUE tokens whose VALUE half is secret-shaped, plus the bare
`--key`/AIza shapes) against 0.1.1 as shipped, and six (the `--auth none` /
`--authors` / `sk-learn-extras` false-record probes) against the post-0.1.1 tree the
2026-08-21 audit ran them on. A regression corpus whose red has never been observed
is decoration.
"""
import sys

import pytest

from arcaeon_adapter.proxy import REDACTED, _redact_argv

#: The placeholder, pinned as a LITERAL in this file on purpose. Asserting against the
#: imported constant would let a mutant `REDACTED = ""` pass its own corpus: every
#: "was it replaced?" check would compare empty-to-empty and agree with itself.
PLACEHOLDER = "<redacted>"

#: Substrings that must never survive. Deliberately distinctive so a partial redaction
#: cannot pass as a full one.
SECRET_MARKERS = ("REALSECRET", "sk-proj-", "sk-ant-api03-", "sk_live_", "ghp_",
                  "hunter2", "AKIAIOSFODNN7EXAMPLE", "glpat-", "xoxb-", "AIzaSy")

MUST_REDACT = [
    # NAME=VALUE with no leading dash. The shape that leaked, and the common one.
    ["docker", "run", "-e", "OPENAI_API_KEY=sk-proj-REALSECRET123", "img"],
    ["docker", "run", "-e", "STRIPE_SECRET_KEY=sk_live_REALSECRET", "img"],
    ["env", "GITHUB_TOKEN=ghp_REALSECRET", "server"],
    ["npx", "-y", "srv", "--env", "API_KEY=REALSECRET"],
    ["srv", "ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET"],
    ["srv", "AWS_SECRET_ACCESS_KEY=REALSECRETvalue"],
    ["srv", "CLIENT_SECRET=REALSECRET"],
    # NAME=VALUE where the NAME is innocent but the VALUE half is secret-shaped. The
    # audit found all four leaking untouched with hits=0: the NAME check declined and
    # the whole-token _SECRET_VALUE match is anchored at the token's START, so a value
    # sitting after `NAME=` was never inspected at all.
    ["srv", "STRIPE_KEY=sk_live_REALSECRET"],
    ["srv", "OPENAI_KEY=sk-proj-REALSECRET123"],
    ["srv", "GH_PAT=ghp_REALSECRET"],
    ["srv", "MY_KEY=eyJhbGciOiJIUzI1NiJ9REALSECRET.payload.sig"],   # a JWT
    # Bare `key` as a slot name, and Google's AIza prefix. Both were missing:
    # `--key AIzaSy...` leaked with hits=0.
    ["srv", "--key", "AIzaSyREALSECRET-abc123xyz"],
    ["srv", "--key=AIzaSyREALSECRETabc123xyz"],
    ["srv", "AIzaSyREALSECRETbarevalue00"],
    # Credentials inside a header argument: the value does not START with Bearer.
    ["srv", "--header", "Authorization: Bearer REALSECRET"],
    ["srv", "-H", "X-Api-Key: REALSECRET"],
    ["srv", "--header", "Proxy-Authorization: Basic REALSECRET"],
    # Hyphen-form key prefixes: every current LLM vendor.
    ["srv", "sk-proj-REALSECRETabc"],
    ["srv", "sk-ant-api03-REALSECRETabc"],
    # Query-string parameters. `key=` is Google's standard and needed naming explicitly.
    ["srv", "--url", "https://api.google.com/v1?key=REALSECRET"],
    ["srv", "--url", "https://x/v1?access-key=REALSECRET&page=2"],
    ["srv", "--url", "https://x/v1?private_token=REALSECRET"],
    # Guards proving the word-boundary and mode-word fixes did not over-correct:
    # a credential-named COMPOUND slot still consumes a secret-shaped value, and
    # secret-shaped values still redact whether separate, glued, or dashless.
    # These were written GREEN on purpose — they pin the redactions the fix for
    # the --auth/--authors/sk-learn false-record class was required to preserve.
    ["srv", "--auth-token", "REALSECRETx91"],
    ["srv", "--api-key=sk-ant-api03-REALSECRET123"],
    ["srv", "API_TOKEN=ghp_REALSECRET"],
    # Shapes the first version DID catch. Kept so the fix cannot regress them.
    ["srv", "--api-key", "sk_live_REALSECRET", "--log", "a.jsonl"],
    ["srv", "--token=REALSECRET"],
    ["srv", "--password", "hunter2"],
    ["srv", "AKIAIOSFODNN7EXAMPLE"],
    ["srv", "glpat-REALSECRET"],
    ["srv", "postgres://user:hunter2@db.internal/x"],
    # Password-only userinfo (redis/mongo standard shape). An auditor found the
    # with-username form redacted while these leaked: the username segment was
    # required non-empty. Both must be redacted.
    ["srv", "redis://:hunter2@cache.internal:6379/0"],
    ["srv", "mongodb://:hunter2@host/db"],
    ["srv", "--url", "redis://:hunter2@h:6379"],
]

MUST_NOT_TOUCH = [
    # The 2026-08-21 audit's live probes, permanent. All six came back damaged with
    # hits=1: `--auth none` is a server with authentication DISABLED — the exact scar
    # class this file's header describes — recorded as credential-stripped; `basic`
    # and `google` are MODE/PROVIDER words in an auth-topic slot, not credentials;
    # `--authors` matched because "auth" was found as a SUBSTRING of the name; and
    # the sk- value shape ate a package name. A short dictionary word after an
    # auth-ish flag stays, because fabricating a redaction is worse than missing one.
    ["srv", "--auth", "none"],
    ["srv", "--auth", "basic"],
    ["srv", "--auth=none"],
    ["srv", "--oauth", "google"],
    ["srv", "--authors", "Jane"],
    ["pip", "install", "sk-learn-extras"],
    # The false-record class. Each of these was damaged by the first version.
    ["srv", "--no-auth", "--log", "a.jsonl"],
    ["srv", "--token", "--verbose", "--log", "a.jsonl"],
    ["srv", "--auth-mode", "oidc"],
    ["srv", "--api-key-file", "/etc/keys/prod.pem"],
    ["srv", "--no-auth"],
    ["srv", "--disable-auth", "--port", "8080"],
    # Ordinary launches, which are the overwhelming majority of real input.
    [sys.executable, "-m", "arcaeon_ledger.mcp_server", "--log", "a.jsonl"],
    ["docker", "run", "-e", "LOG_LEVEL=debug", "img"],
    ["srv", "--url", "https://api.example.com/v1?page=2&limit=10"],
    ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    # Guards on the NAME=VALUE value-shape check and on bare `key` as a slot name.
    # A value that is not secret-shaped must survive even next to a key-ish NAME,
    # and `key` must be word-bounded: `--keyboard` is not a credential slot.
    ["srv", "MY_KEY=not-a-secret-word"],
    ["srv", "--keyboard=qwerty"],
    ["srv", "--keyboard", "qwerty"],
    ["srv", "COUNT=12345"],
]


@pytest.mark.parametrize("argv", MUST_REDACT, ids=lambda a: " ".join(a)[:60])
def test_credential_does_not_survive(argv):
    out, hits = _redact_argv(argv)
    joined = " ".join(out)
    survived = [m for m in SECRET_MARKERS if m in joined]
    assert not survived, (
        "a live credential reached the record: %s\n  in: %s" % (survived, joined))
    assert hits >= 1, "something was redacted, so the count must say so: %s" % joined
    # The other half of the same property: redaction must be SURGICAL. Every position
    # whose token carries no secret marker must come back byte-identical — a redactor
    # that shreds the innocent parts of a hot argv writes a false record just as
    # surely as one that misses the secret.
    assert len(out) == len(argv), "argv length changed: %s -> %s" % (argv, out)
    for before, after in zip(argv, out):
        if not any(m in before for m in SECRET_MARKERS):
            assert after == before, (
                "a non-secret token was altered: %r -> %r\n  in: %s" % (
                    before, after, argv))


@pytest.mark.parametrize("argv", MUST_NOT_TOUCH, ids=lambda a: " ".join(a)[:60])
def test_ordinary_argv_is_returned_unchanged(argv):
    """Byte-identical, and a count of zero.

    Two distinct harms if this fails. Destroying a flag makes the record wrong about how
    the server was configured — and the worst instance was a SECURITY setting, since
    `--no-auth` was the flag whose successor got blanked. Reporting a redaction that did
    not happen makes `command_redactions` a fabrication, and that field exists precisely
    so a reader does not have to guess whether a clean-looking command was scrubbed.
    """
    out, hits = _redact_argv(argv)
    assert out == argv, "argv was altered with no credential present:\n  %s\n  %s" % (
        argv, out)
    assert hits == 0, "a redaction was reported that did not happen: hits=%d" % hits


def test_the_placeholder_is_the_agreed_literal():
    """Pin the placeholder to the literal string readers of the ledger expect.

    Everything below asserts against PLACEHOLDER, defined in THIS file, precisely so a
    mutant `REDACTED = ""` in the module under test cannot grade its own homework. This
    test is where the module's constant and the corpus's literal are forced to agree.
    """
    assert REDACTED == PLACEHOLDER


def test_the_count_is_exact_across_multiple_secrets():
    """`hits` must be a COUNT, not a boolean in a trench coat.

    Three secrets in, exactly three redactions reported. An implementation that
    redacted one and said "yes, redaction happened" would pass every `hits >= 1`
    assertion while under-reporting how much of the record was altered.
    """
    argv = ["docker", "run", "-e", "OPENAI_API_KEY=sk-proj-REALSECRET",
            "--api-key", "sk_live_REALSECRET",
            "--url", "https://x/v1?key=REALSECRET&page=2", "img"]
    out, hits = _redact_argv(argv)
    assert hits == 3, "three secrets in, hits must be exactly 3, got %d: %s" % (hits, out)
    assert out == ["docker", "run", "-e", "OPENAI_API_KEY=%s" % PLACEHOLDER,
                   "--api-key", PLACEHOLDER,
                   "--url", "https://x/v1?key=%s&page=2" % PLACEHOLDER, "img"]


def test_the_count_is_honest_when_the_marker_was_already_there():
    """An argv that already contains the marker string must not be counted as redacted."""
    argv = ["srv", "--flag", PLACEHOLDER]
    out, hits = _redact_argv(argv)
    assert out == argv
    assert hits == 0


def test_a_redacted_flag_keeps_its_name():
    """The name is audit-relevant even when the value cannot be kept.

    Blanking the whole token would lose the fact that an api-key was passed at all,
    which is information an auditor wants and which costs nothing to keep.
    """
    out, _ = _redact_argv(["srv", "--api-key=sk_live_X"])
    assert out == ["srv", "--api-key=%s" % PLACEHOLDER]
    out, _ = _redact_argv(["srv", "OPENAI_API_KEY=sk-proj-X"])
    assert out == ["srv", "OPENAI_API_KEY=%s" % PLACEHOLDER]
    # Same rule on the value-shape path: the NAME half survives, the VALUE half goes.
    out, _ = _redact_argv(["srv", "MY_KEY=eyJhbGciOiJIUzI1NiJ9xx.p.s"])
    assert out == ["srv", "MY_KEY=%s" % PLACEHOLDER]


def test_the_useful_part_of_a_url_survives():
    """Redact the credential in place, keep the endpoint. A blanked URL loses the target."""
    out, hits = _redact_argv(["srv", "--url", "https://api.example.com/v1?key=SEK&page=2"])
    joined = " ".join(out)
    assert "SEK" not in joined
    assert "api.example.com/v1" in joined and "page=2" in joined
    assert hits == 1


def test_non_string_argv_entries_do_not_crash():
    """Nothing should be able to turn observation into a transport failure."""
    out, _ = _redact_argv(["srv", 8080, None, "--api-key", "sk_live_X"])
    assert PLACEHOLDER in out
    assert "8080" in out and "None" in out
