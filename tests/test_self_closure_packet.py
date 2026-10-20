"""self_closure_packet: the committed packet that replaces the writer's dispatch inputs."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("self_closure_packet_t", ROOT / "resident-runtime/self_closure_packet.py")
scp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scp)
WRITER = ROOT / ".github/workflows/organization-ledger-transition.yml"
VALIDATION = ROOT / ".github/workflows/organization-ledger-transition-validation.yml"


def source(path):
    """The workflow without its comment lines."""
    return "\n".join(line for line in path.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#")) + "\n"
GOOD = {"schema": scp.SCHEMA, "communication_id": "cid-001", "packet_id": "p-001", "hb_epoch": 7}


class Packet(unittest.TestCase):
    def read(self, body, require=True, raw=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            if body is not None or raw is not None:
                path.write_text(raw if raw is not None else json.dumps(body), encoding="utf-8")
            return scp.read_packet(path, require_hb_epoch=require)

    def assertRefused(self, result, code):
        self.assertEqual(result["disposition"], "FAIL_CLOSED", result)
        self.assertEqual(result["failure_code"], code)
        for field in ("failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
                      "owning_existing_goal", "next_attempt"):
            self.assertTrue(result[field], field)

    def test_a_well_formed_packet_supplies_the_inputs(self):
        self.assertEqual(self.read(GOOD), {"disposition": "ALLOW", "communication_id": "cid-001",
                                           "packet_id": "p-001", "hb_epoch": 7})

    def test_packet_id_is_optional(self):
        body = {k: v for k, v in GOOD.items() if k != "packet_id"}
        self.assertIsNone(self.read(body)["packet_id"])

    def test_absent_unreadable_and_foreign_packets_fail_closed(self):
        self.assertRefused(self.read(None), "SELF_CLOSURE_PACKET_ABSENT")
        self.assertRefused(self.read(None, raw="{not json"), "SELF_CLOSURE_PACKET_UNREADABLE")
        self.assertRefused(self.read({**GOOD, "schema": "other"}), "SELF_CLOSURE_PACKET_SCHEMA_MISMATCH")
        self.assertRefused(self.read({**GOOD, "extra": 1}), "SELF_CLOSURE_PACKET_SCHEMA_MISMATCH")
        self.assertRefused(self.read([GOOD]), "SELF_CLOSURE_PACKET_SCHEMA_MISMATCH")

    def test_tokens_must_be_single_visible_tokens(self):
        for bad in ("", "two words", None, 5):
            self.assertRefused(self.read({**GOOD, "communication_id": bad}), "SELF_CLOSURE_INPUT_INVALID")
        self.assertRefused(self.read({**GOOD, "packet_id": "a b"}), "SELF_CLOSURE_INPUT_INVALID")

    def test_the_epoch_is_supplied_never_sampled(self):
        body = {k: v for k, v in GOOD.items() if k != "hb_epoch"}
        self.assertRefused(self.read(body, require=True), "SELF_CLOSURE_HB_EPOCH_UNSUPPLIED")
        self.assertIsNone(self.read(body, require=False)["hb_epoch"])
        for bad in (-1, "7", True, 1.5):
            self.assertRefused(self.read({**GOOD, "hb_epoch": bad}), "SELF_CLOSURE_HB_EPOCH_INVALID")

    def test_the_cli_writes_the_inputs_to_the_job_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet, env = Path(tmp) / "p.json", Path(tmp) / "env"
            packet.write_text(json.dumps(GOOD), encoding="utf-8")
            self.assertEqual(scp.main(["--packet", str(packet), "--require-hb-epoch", "--github-env", str(env)]), 0)
            self.assertEqual(env.read_text().splitlines(),
                             ["CLOSURE_COMMUNICATION_ID=cid-001", "CLOSURE_PACKET_ID=p-001", "HB_EPOCH=7"])
            self.assertEqual(scp.main(["--packet", str(Path(tmp) / "absent.json"), "--github-env", str(env)]), 1)
            self.assertEqual(len(env.read_text().splitlines()), 3)


class Triggers(unittest.TestCase):
    def test_the_writer_runs_on_push_to_main_for_the_packet_only(self):
        text = source(WRITER)
        head = text.split("\njobs:\n", 1)[0]
        for word in ("workflow_dispatch", "pull_request", "schedule", "repository_dispatch", "workflow_run",
                     "github.event.inputs"):
            self.assertNotIn(word, text, word)
        self.assertIn("on:\n  push:\n    branches: [main]\n    paths:\n      - '" + scp.PACKET_PATH + "'\n", head)
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", text)
        self.assertIn("resident-runtime/self_closure_packet.py", text)

    def test_the_validation_workflow_is_read_only_and_unconditional(self):
        text = source(VALIDATION)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("workflow_dispatch", text)
        self.assertNotIn("    if:", text)
        self.assertIn("pull_request:", text)
        self.assertIn("'" + scp.PACKET_PATH + "'", text)


if __name__ == "__main__":
    unittest.main()
