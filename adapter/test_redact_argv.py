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

Every case here was confirmed FAILING against the previous implementation: eighteen of
these thirty-one. A regression corpus whose red has never been observed is decoration.
"""
import sys

import pytest

from arcaeon_adapter.proxy import REDACTED, _redact_argv

#: Substrings that must never survive. Deliberately distinctive so a partial redaction
#: cannot pass as a full one.
SECRET_MARKERS = ("REALSECRET", "sk-proj-", "sk-ant-api03-", "sk_live_", "ghp_",
                  "hunter2", "AKIAIOSFODNN7EXAMPLE", "glpat-", "xoxb-")

MUST_REDACT = [
    # NAME=VALUE with no leading dash. The shape that leaked, and the common one.
    ["docker", "run", "-e", "OPENAI_API_KEY=sk-proj-REALSECRET123", "img"],
    ["docker", "run", "-e", "STRIPE_SECRET_KEY=sk_live_REALSECRET", "img"],
    ["env", "GITHUB_TOKEN=ghp_REALSECRET", "server"],
    ["npx", "-y", "srv", "--env", "API_KEY=REALSECRET"],
    ["srv", "ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET"],
    ["srv", "AWS_SECRET_ACCESS_KEY=REALSECRETvalue"],
    ["srv", "CLIENT_SECRET=REALSECRET"],
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
    # Shapes the first version DID catch. Kept so the fix cannot regress them.
    ["srv", "--api-key", "sk_live_REALSECRET", "--log", "a.jsonl"],
    ["srv", "--token=REALSECRET"],
    ["srv", "--password", "hunter2"],
    ["srv", "AKIAIOSFODNN7EXAMPLE"],
    ["srv", "glpat-REALSECRET"],
    ["srv", "postgres://user:hunter2@db.internal/x"],
]

MUST_NOT_TOUCH = [
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
]


@pytest.mark.parametrize("argv", MUST_REDACT, ids=lambda a: " ".join(a)[:60])
def test_credential_does_not_survive(argv):
    out, hits = _redact_argv(argv)
    joined = " ".join(out)
    survived = [m for m in SECRET_MARKERS if m in joined]
    assert not survived, (
        "a live credential reached the record: %s\n  in: %s" % (survived, joined))
    assert hits >= 1, "something was redacted, so the count must say so: %s" % joined


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


def test_the_count_is_honest_when_the_marker_was_already_there():
    """An argv that already contains the marker string must not be counted as redacted."""
    argv = ["srv", "--flag", REDACTED]
    out, hits = _redact_argv(argv)
    assert out == argv
    assert hits == 0


def test_a_redacted_flag_keeps_its_name():
    """The name is audit-relevant even when the value cannot be kept.

    Blanking the whole token would lose the fact that an api-key was passed at all,
    which is information an auditor wants and which costs nothing to keep.
    """
    out, _ = _redact_argv(["srv", "--api-key=sk_live_X"])
    assert out == ["srv", "--api-key=%s" % REDACTED]
    out, _ = _redact_argv(["srv", "OPENAI_API_KEY=sk-proj-X"])
    assert out == ["srv", "OPENAI_API_KEY=%s" % REDACTED]


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
    assert REDACTED in out
    assert "8080" in out and "None" in out
