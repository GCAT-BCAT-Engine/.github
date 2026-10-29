"""B-P40 (R-DISPATCH 19:25Z): every action is a manifest-bound attempted state transition.

No workflow in this tree is started by hand or by a timer: there is no
`workflow_dispatch` and no `schedule` trigger. A workflow runs on a
pull_request, a push, or a workflow_run, so each run follows a committed
state transition. Read as text, standard library only.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
FORBIDDEN = ("workflow_dispatch", "schedule")
ALLOWED = {"pull_request", "push", "workflow_run"}


def workflows():
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def yaml_lines(text):
    """The lines that carry YAML, with comments removed."""
    return [line.split(" #")[0].rstrip() for line in text.splitlines() if not line.lstrip().startswith("#")]


def triggers(text):
    """The top-level keys of the workflow's `on:` block (block or flow form)."""
    lines = yaml_lines(text)
    start = next(index for index, line in enumerate(lines) if re.match(r"^(on|\"on\"|'on'):", line))
    inline = lines[start].split(":", 1)[1].strip()
    if inline:
        return [name.strip() for name in inline.strip("[]").split(",") if name.strip()]
    found = []
    for line in lines[start + 1:]:
        if line and not line.startswith(" "):
            break
        match = re.match(r"^  ([A-Za-z_]+)\s*:", line)
        if match:
            found.append(match.group(1))
    return found


class WorkflowTriggerTests(unittest.TestCase):
    def test_the_tree_has_workflows(self):
        self.assertTrue(workflows())

    def test_no_workflow_is_started_by_hand_or_by_a_timer(self):
        for path in workflows():
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                for word in FORBIDDEN:
                    self.assertNotIn(word, triggers(text))
                    self.assertFalse(any(re.match(r"^\s*" + word + r"\s*:", line) for line in yaml_lines(text)),
                                     word + " key in " + path.name)
                self.assertFalse(any(re.match(r"^\s*-?\s*cron\s*:", line) for line in yaml_lines(text)),
                                 "cron in " + path.name)

    def test_every_trigger_follows_a_committed_state_transition(self):
        for path in workflows():
            with self.subTest(workflow=path.name):
                found = triggers(path.read_text(encoding="utf-8"))
                self.assertTrue(found, path.name)
                self.assertLessEqual(set(found), ALLOWED, path.name)

    def test_the_reader_sees_a_dispatch_or_schedule_trigger(self):
        for text in ("on:\n  push:\n  workflow_dispatch:\njobs:\n", "on: [push, workflow_dispatch]\njobs:\n",
                     "on:\n  schedule:\n    - cron: '0 * * * *'\njobs:\n"):
            with self.subTest(text=text):
                found = triggers(text)
                self.assertTrue(set(found) & set(FORBIDDEN), found)


if __name__ == "__main__":
    unittest.main()
