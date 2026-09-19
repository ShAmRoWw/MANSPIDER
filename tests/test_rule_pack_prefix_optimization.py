"""Preserve exact evidence when token boundaries move behind literal prefixes.

The reference expressions intentionally retain the pre-optimization spelling.
For fixed-width P, (?<!C)P and P(?<!CP) have the same accepted match spans.
These checks include Unicode word boundaries and all provider-format fixtures.
"""

import random
import re

import pytest

from man_spider.rules import load_builtin_rules, regex_flags
from tests.rule_pack_expansion_content_cases import CONTENT_CASES, NEGATIVE_CASES


REFERENCE_PATTERNS = {
    "age-secret-identity": "(?<![A-Za-z0-9_-])AGE-SECRET-KEY-(?:1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}|PQ-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58,4096})(?![A-Za-z0-9_-])",
    "digitalocean-access-token": "(?<![A-Za-z0-9_-])do[por]_v1_[a-f0-9]{32,128}(?![A-Za-z0-9_-])",
    "grafana-cloud-access-token": "(?<![A-Za-z0-9_-])glc_[A-Za-z0-9+/]{32,4096}={0,2}(?![A-Za-z0-9_+/=-])",
    "grafana-service-account-token": "(?<![A-Za-z0-9_-])glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}(?![A-Za-z0-9_-])",
    "huggingface-access-token": "(?<![A-Za-z0-9_-])hf_[A-Za-z0-9]{20,255}(?![A-Za-z0-9_-])",
    "nats-nkey-seed": "(?<![A-Za-z0-9_-])S[UAONC][A-Z2-7]{56}(?![A-Za-z0-9_-])",
    "postgresql-scram-verifier": "(?<![A-Za-z0-9_-])SCRAM-SHA-256\\$[1-9][0-9]{0,9}:[A-Za-z0-9+/]{4,256}={0,2}\\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=(?![A-Za-z0-9_+/=])",
    "supabase-secret-api-key": "(?<![A-Za-z0-9_-])sb_secret_[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])",
    "tailscale-access-token": "(?<![A-Za-z0-9_-])tskey-(?:auth|api|client|app|scim|webhook)-[A-Za-z0-9]{5,32}-[A-Za-z0-9]{16,128}(?![A-Za-z0-9_-])",
    "jfrog-reference-or-api-token": "(?<![A-Za-z0-9_-])(?:cmVmd[A-Za-z0-9]{59}|AKCp[A-Za-z0-9]{69})(?![A-Za-z0-9_-])",
    "telegram-bot-credential": "(?:https://api\\.telegram\\.org/(?:file/)?bot|\\b(?i:TELEGRAM[_-](?:BOT[_-])?TOKEN)[\"']?[ \\t]{0,16}[:=][ \\t]{0,16}[\"']?)[0-9]{5,16}:[A-Za-z0-9_-]{30,64}(?![A-Za-z0-9_-])",
    "datadog-api-key-assignment": "\\b(?i:(?:DD|DATADOG)[_-]API[_-]KEY)[\"']?[ \\t]{0,16}[:=][ \\t]{0,16}[\"']?[a-fA-F0-9]{32}(?![A-Za-z0-9_-])",
    "dns-tsig-shared-secret": '\\b(?i:key)[ \\t]{1,32}"[^"\\r\\n]{1,255}"[ \\t\\r\\n]{0,32}\\{(?=[^{}]{0,512}\\b(?i:algorithm)[ \\t]{1,32}(?i:hmac-(?:md5|sha1|sha224|sha256|sha384|sha512))(?:-[0-9]{1,3})?[ \\t]{0,16};)[^{}]{0,512}\\b(?i:secret)[ \\t]{1,32}"[A-Za-z0-9+/]{16,256}={0,2}"[ \\t]{0,16};',
}

BUILTIN = {rule["id"]: rule for rule in load_builtin_rules()}
BOUNDARIES = (
    "",
    " ",
    "\n",
    "\t",
    '"',
    "'",
    "[",
    "]",
    ":",
    "_",
    "-",
    "/",
    "a",
    "Z",
    "0",
    "é",
    "Ж",
    "中",
    "İ",
    "ı",
    "ſ",
    "K",
    "\x00",
    "\u0301",
    "😀",
)


def evidence(expression, content):
    return [(match.span(), match.group(0)) for match in expression.finditer(content)]


@pytest.mark.parametrize("rule_id", sorted(REFERENCE_PATTERNS))
def test_literal_prefix_optimization_preserves_exact_matches(rule_id):
    reference = re.compile(REFERENCE_PATTERNS[rule_id])
    action = BUILTIN[rule_id]["actions"][0]
    actual = re.compile(action["pattern"], regex_flags(action["flags"]))
    fixtures = [content for _, content, expected_id in CONTENT_CASES + NEGATIVE_CASES if expected_id == rule_id]
    assert fixtures
    # Check boundaries adjacent to the token itself as well as surrounding JSON,
    # assignments, directives and URLs from full configuration fixtures.
    atoms = list(
        dict.fromkeys(fixtures + [match.group(0) for content in fixtures for match in reference.finditer(content)])
    )

    for atom in atoms:
        for left in BOUNDARIES:
            for right in BOUNDARIES:
                content = left + atom + right
                assert evidence(actual, content) == evidence(reference, content), content

    randomizer = random.Random(20260905)
    for _ in range(256):
        content = randomizer.choice(atoms)
        position = randomizer.randrange(len(content) + 1)
        mutation = randomizer.randrange(4)
        if mutation == 0:
            content = content[:position] + randomizer.choice(BOUNDARIES) + content[position:]
        elif mutation == 1:
            content = content[:position] + content[position + 1 :]
        elif mutation == 2:
            content = content.swapcase()
        else:
            content += randomizer.choice(BOUNDARIES) + randomizer.choice(atoms)
        assert evidence(actual, content) == evidence(reference, content), content
