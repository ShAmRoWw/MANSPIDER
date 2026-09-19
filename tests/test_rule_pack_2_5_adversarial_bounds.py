"""Regression guard against repeated-line whitespace backtracking explosions."""

import json
import subprocess
import sys
from pathlib import Path


def test_indented_nonsensitive_blocks_have_bounded_matching_time():
    # A dozen ordinary indented lines made each original pattern exceed a second.
    # The child deadline protects the test runner if an ambiguous lexer returns.
    pack_path = Path(__file__).parents[1] / "man_spider" / "builtin_rules_v3.json"
    code = r"""
import json, re, sys
pack = json.loads(open(sys.argv[1]).read())
rules = {rule["id"]: rule for rule in pack["rules"]}
cases = {
    "bruno-api-key-auth-value": "auth:apikey {\n" + "                key: label\n" * 24 + "}\n",
    "kubernetes-secret-manifest": "kind: Secret\ndata:\n" + "                public: label\n" * 24,
    "web-deployment-password": ("<publishProfile" + ' public="ordinary value"' * 30 + "/>\n") * 2048,
}
for rule_id, content in cases.items():
    for action in rules[rule_id]["actions"]:
        if action["type"] == "scan":
            flags = sum(getattr(re, name.upper()) for name in action.get("flags", []))
            assert re.search(action["pattern"], content, flags) is None
print(json.dumps(sorted(cases)))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(pack_path)],
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    )
    assert json.loads(result.stdout) == [
        "bruno-api-key-auth-value",
        "kubernetes-secret-manifest",
        "web-deployment-password",
    ]
