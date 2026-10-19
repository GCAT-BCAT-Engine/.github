"""Every workflow `uses:` is pinned to a full 40-hex commit sha.

A tag or branch ref can be moved after review; a commit sha cannot. Local
`./` actions live in this repository and are reviewed with it, so they are
exempt.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^'\"\s#]+)")
PINNED = re.compile(r"@[0-9a-f]{40}$")


def unpinned_uses():
    found = []
    for path in sorted(WORKFLOWS.rglob("*")):
        if path.suffix not in (".yml", ".yaml"):
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = USES.match(line)
            if not match:
                continue
            ref = match.group(1)
            if ref.startswith("./") or PINNED.search(ref):
                continue
            found.append(f"{path.relative_to(ROOT)}:{number}: {ref}")
    return found


class WorkflowActionPinsTest(unittest.TestCase):
    def test_every_uses_is_pinned_to_a_commit_sha(self):
        unpinned = unpinned_uses()
        self.assertEqual(
            unpinned,
            [],
            json.dumps(
                {
                    "failure_code": "WORKFLOW_ACTION_NOT_PINNED",
                    "failed_predicate": "EVERY_WORKFLOW_USES_PINNED_TO_40_HEX_SHA",
                    "required_evidence_or_repair": (
                        "pin each listed uses: to the commit sha its tag resolves to "
                        "(git ls-remote https://github.com/<owner>/<action> refs/tags/<tag>, "
                        "peeling annotated tags with ^{}), keeping the tag as a trailing comment: "
                        + "; ".join(unpinned)
                    ),
                    "retry_entrypoint": "python -m unittest tests.test_workflow_action_pins -v",
                    "owning_existing_goal": "SVORG-LLM-ORG-FOUNDATION-001",
                    "next_attempt": "re-run the retry_entrypoint after pinning",
                },
                sort_keys=True,
            ),
        )


if __name__ == "__main__":
    unittest.main()
