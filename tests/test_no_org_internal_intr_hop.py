"""No InTr hop inside this organization (Rigel's rule, 2026-10-25).

InTr paths exist only between distinct organizations; there is never an InTr hop inside one organization. The
intr-destination self-closure addressed this organization's own InTr destination, so its carrier
(.github/workflows/organization-ledger-transition.yml, resident-runtime/self_closure_packet.py and the committed
.stegverse/intr-destination/self-closure-packet.json) is retired by the InTr path owner (Lane B,
StegVerse-org/.github#162; the same removal as SV-LLM/.github#62 and StegVerse-org/.github#251). The ledger's
historical receipts are append-only and stay as they are.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORGANIZATION = "GCAT-BCAT-Engine"
RETIRED = (".github/workflows/organization-ledger-transition.yml", "resident-runtime/self_closure_packet.py",
           ".stegverse/intr-destination/self-closure-packet.json")
MARKERS = ("--self-close", "self_close(", "self-closure-packet", "self_closure_packet", "--verify-self-closure")


class NoOrgInternalHop(unittest.TestCase):
    def test_the_self_closure_carrier_is_absent(self):
        for path in RETIRED:
            self.assertFalse((ROOT / path).exists(), path)

    def test_no_workflow_runs_a_self_closure(self):
        for workflow in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            text = workflow.read_text(encoding="utf-8")
            for marker in MARKERS:
                self.assertNotIn(marker, text, workflow.name)

    def test_no_declared_path_names_this_organization_as_its_destination(self):
        for name in ("transfers.json", "inbound.json"):
            path = ROOT / ".stegverse/intr-path-transfer" / name
            if not path.exists():
                continue
            for row in json.loads(path.read_text()).get("transfers", []):
                source, _, destination = row["path_id"].split(":")[0].partition("->")
                self.assertNotEqual(source, destination, row["path_id"])


if __name__ == "__main__":
    unittest.main()
