"""The organization ledger stack records transition evidence.

Redirected POSIX roots and temporary git repositories are not the published
ref ``refs/stegverse/organization-ledger`` in ``GCAT-BCAT-Engine/.github``.
Nothing in this module is a production receipt.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED_REF = "refs/stegverse/organization-ledger"
NAMESPACE = "repository-ledger/GCAT-BCAT-Engine/.github"
FEDERATION_ORGANIZATIONS = (
    "AaCT-E",
    "Admissible-Existence",
    "AdmittedCode",
    "Data-Continuation",
    "ECAT-ICAT-Formal",
    "formalism-tests",
    "GCAT-BCAT-Engine",
    "Infrastructure-Continuity-Ventures",
    "master-records",
    "StegGhost",
    "StegVerse-002",
    "StegVerse-Labs",
    "StegVerse-org",
    "Triad-Test",
)
LEDGER_ROOTS = ("STEGVERSE_REPO_LEDGER_ROOT", "STEGVERSE_ORG_LEDGER_ROOT")
GRANT_SCAN = (
    ".stegverse/transition-ledger/contract.json",
    ".stegverse/transition-ledger/org-contract.json",
    ".stegverse/transition-ledger/emit.py",
    "resident-runtime/ledger_store.py",
    "resident-runtime/aggregate_repo_transition.py",
    "resident-runtime/organization_ledger_readback.py",
    "resident-runtime/dual_ledger.py",
    "resident-runtime/intr_destination_ingress.py",
    "org-kernel/kernel.py",
    "org-runtime/interlock-intr.json",
    "data/organization-role-runtime-reality-deployment.json",
    "docs/ORGANIZATION_TRANSITION_LEDGER_MIRROR_HANDOFF.md",
    "docs/TRANSITION_LEDGER_MIRROR_HANDOFF.md",
    "docs/INTR_DESTINATION_CAPABILITY_MIRROR_HANDOFF.md",
    ".github/workflows/organization-ledger-transition.yml",
)


def _module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def diagnostic(communication_id):
    return {
        "message_class": "ecosystem.communication",
        "communication_id": communication_id,
        "subject": "purpose-neutral mesh diagnostic",
        "body": {
            "schema": "stegverse.org-intr-destination-diagnostic/v1",
            "probe": "diagnostic-crossing",
        },
    }


class ContractAndBoundaryTests(unittest.TestCase):
    def test_the_contract_names_the_published_ref_and_not_a_placeholder(self):
        org_text = (ROOT / ".stegverse/transition-ledger/org-contract.json").read_text(encoding="utf-8")
        self.assertNotIn("ORGANIZATION_LEDGER_ROOT", org_text)
        org = json.loads(org_text)
        repo = json.loads((ROOT / ".stegverse/transition-ledger/contract.json").read_text(encoding="utf-8"))
        deployment = json.loads(
            (ROOT / "data/organization-role-runtime-reality-deployment.json").read_text(encoding="utf-8"))
        self.assertEqual(org["organization"], "GCAT-BCAT-Engine")
        self.assertEqual(org["organization_ledger_ref"], PUBLISHED_REF)
        self.assertEqual(org["organization_ledger_repository"], "GCAT-BCAT-Engine/.github")
        self.assertEqual(org["ledger_lock"], "ORGANIZATION_LEDGER_LOCK")
        self.assertIn("stegverse.repo-transition-receipt/v1", org["consumes"])
        self.assertEqual(org["emits"], "stegverse.organization-transition-receipt/v1")
        location = repo["repository_ledger_location"]
        self.assertEqual(location["ref"], PUBLISHED_REF)
        self.assertEqual(location["namespace"], NAMESPACE)
        self.assertIs(location["new_ledger_root"], False)
        self.assertEqual(repo["repository"], "GCAT-BCAT-Engine/.github")
        self.assertEqual(deployment["reality_locus"], PUBLISHED_REF)
        binding = json.loads((ROOT / "org-runtime/interlock-intr.json").read_text(encoding="utf-8"))
        receipt_append = binding["ingress"]["capability_endpoint_bindings"][0]["receiving_operation"]["receipt_append"]
        self.assertEqual(receipt_append, "resident-runtime/aggregate_repo_transition.py::append")
        self.assertNotIn("capability_destination_bindings", binding["egress"])

    def test_federation_peer_list_is_unchanged(self):
        federation = json.loads((ROOT / "org-boundary/registry/federation.json").read_text(encoding="utf-8"))
        names = tuple(entry["organization"] for entry in federation["organizations"])
        self.assertEqual(names, FEDERATION_ORGANIZATIONS)
        self.assertEqual(len(names), 14)
        self.assertEqual(federation["denominator"], 14)
        for entry in federation["organizations"]:
            self.assertNotIn("intr-destination", str(entry.get("org_control_service") or ""))
            self.assertNotIn("addressed_service", entry)

    def test_added_and_modified_ledger_files_avoid_prohibited_wording(self):
        for relative in GRANT_SCAN:
            text = (ROOT / relative).read_text(encoding="utf-8").lower()
            self.assertNotIn("grant", text, relative)

    def test_a_supplied_epoch_does_not_change_the_clock_reference_shape(self):
        kernel = _module("kernel_epoch_shape", "org-kernel/kernel.py")
        sample = kernel.HB_ANCHOR_UNIX_NS + 1_000_000_000
        clock = kernel.hb_reference(sample)
        self.assertEqual(set(clock), {
            "epoch", "generation", "heartbeat_id", "sampled_unix_ns",
            "phase_offset_ns", "frequency_hz", "progression_dependency",
            "authority_effect",
        })
        supplied = kernel.hb_reference(epoch=32)
        self.assertEqual(supplied["epoch"], 32)
        self.assertIs(supplied["derived_from_clock"], False)
        self.assertNotIn("sampled_unix_ns", supplied)
        with self.assertRaises(ValueError):
            kernel.hb_reference(sample, epoch=32)


class RedirectedStoreTests(unittest.TestCase):
    def setUp(self):
        self._work = tempfile.TemporaryDirectory()
        self.addCleanup(self._work.cleanup)
        self.work = Path(self._work.name)
        previous = {name: os.environ.get(name) for name in LEDGER_ROOTS}

        def restore():
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore)
        for name in LEDGER_ROOTS:
            os.environ.pop(name, None)

    def test_a_missing_location_fails_closed(self):
        ledger = _module("dual_ledger_missing", "resident-runtime/dual_ledger.py")
        with self.assertRaises(ValueError) as raised:
            ledger.append_repository(
                "missing", "CLASS", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                {}, "NONE", hb_epoch=32)
        self.assertIn("ledger_location_required_from_materializer", str(raised.exception))

    def test_redirected_roots_are_not_the_published_repository(self):
        os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(self.work / "repo")
        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(self.work / "org")
        self.assertNotIn("GCAT-BCAT-Engine/.github", os.environ["STEGVERSE_ORG_LEDGER_ROOT"])
        self.assertFalse(os.environ["STEGVERSE_ORG_LEDGER_ROOT"].startswith("git+"))
        ingress = _module("ingress_redirected", "resident-runtime/intr_destination_ingress.py")
        registry = json.loads((ROOT / "org-boundary/registry/services.json").read_text(encoding="utf-8"))
        result = ingress.self_close("redirected-diagnostic", registry=registry, hb_epoch=32)
        self.assertEqual(result["disposition"], "ALLOW", result.get("detail"))
        self.assertIs(result["self_closure"], True)
        self.assertEqual(result["communication_id"], "redirected-diagnostic")
        self.assertIs(result["organization_receipt_preserves_repository_receipt"], True)
        replay = ingress.self_close("redirected-diagnostic", registry=registry, hb_epoch=40)
        self.assertIs(replay["transition_replayed"], True)
        self.assertEqual(result["repository_receipt_sha256"], replay["repository_receipt_sha256"])
        self.assertEqual(result["organization_receipt_sha256"], replay["organization_receipt_sha256"])
        collided = ingress.receive(
            diagnostic("other-diagnostic"), registry=registry,
            packet_id="intr-destination-self-closure:redirected-diagnostic", hb_epoch=32)
        self.assertEqual(collided["disposition"], "FAIL_CLOSED")
        self.assertEqual(collided["failed_predicate"], "ONE_PACKET_ID_BINDS_ONE_DIAGNOSTIC")
        self.assertIs(collided["repository_receipt_observed"], False)
        ledger = _module("dual_ledger_redirected", "resident-runtime/dual_ledger.py")
        found = ledger.find_repository(
            "ORGANIZATION_INTR_DESTINATION_INGRESS:intr-destination-self-closure:redirected-diagnostic")
        self.assertIsNotNone(found)
        self.assertEqual(found["evidence"]["communication_id"], "redirected-diagnostic")
        self.assertEqual(found["hb_reference"]["epoch"], 32)


    SIX_FIELDS = ("failure_code", "failed_predicate", "required_evidence_or_repair",
                  "retry_entrypoint", "owning_existing_goal", "next_attempt")

    def _refused_before_the_store_opens(self, name, **epoch):
        os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(self.work / "repo")
        emit = _module(name, ".stegverse/transition-ledger/emit.py")

        def untouched(*_args, **_kwargs):
            raise AssertionError("reached before the epoch was checked")

        emit.ledger_store.open_store = untouched
        emit.kernel.hb_reference = untouched
        with self.assertRaises(emit.RepoLedgerEpochRefused) as raised:
            emit.append("epoch-refused", "CLASS", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                        {}, "NONE", **epoch)
        refusal = raised.exception.refusal
        for field in self.SIX_FIELDS:
            self.assertTrue(refusal[field], field)
        self.assertEqual(refusal["disposition"], "FAIL_CLOSED")
        self.assertEqual(refusal["failed_predicate"], "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(refusal["owning_existing_goal"],
                         "INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001")
        self.assertIs(refusal["consequence_committed"], False)
        self.assertEqual(refusal, emit.kernel.writer_epoch_refusal(
            epoch.get("hb_epoch"), retry_entrypoint=emit.EPOCH_RETRY_ENTRYPOINT))
        self.assertFalse((self.work / "repo").exists())
        return refusal

    def test_an_append_without_a_supplied_epoch_fails_closed_before_the_store_opens(self):
        refusal = self._refused_before_the_store_opens("emit_epoch_absent")
        self.assertEqual(refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")

    def test_an_append_with_an_invalid_epoch_fails_closed_before_the_store_opens(self):
        for index, epoch in enumerate(("33.0", True, 31, "+33", 33.0, " 33", "3_3")):
            with self.subTest(epoch=epoch):
                refusal = self._refused_before_the_store_opens(
                    "emit_epoch_invalid_%d" % index, hb_epoch=epoch)
                self.assertEqual(refusal["failure_code"], "HB_EPOCH_INVALID")

    def test_the_emitter_command_refuses_without_an_epoch_and_writes_nothing(self):
        self._command_refuses(None, "HB_EPOCH_NOT_SUPPLIED")

    def test_the_emitter_command_refuses_an_invalid_epoch_and_writes_nothing(self):
        for epoch in ("33.0", "31", "+33"):
            with self.subTest(epoch=epoch):
                self._command_refuses(epoch, "HB_EPOCH_INVALID")

    def _command_refuses(self, epoch, failure_code):
        env = {**os.environ, "STEGVERSE_REPO_LEDGER_ROOT": str(self.work / "repo")}
        args = ["python3", str(ROOT / ".stegverse/transition-ledger/emit.py"),
                "--transition-id", "epoch-refused", "--transition-class", "CLASS",
                "--predecessor-state-sha256", "sha256:" + "a" * 64,
                "--successor-state-sha256", "sha256:" + "b" * 64]
        if epoch is not None:
            args += ["--hb-epoch", epoch]
        run = subprocess.run(args, env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 1, run.stderr)
        refusal = json.loads(run.stdout)
        self.assertEqual(refusal["failure_code"], failure_code)
        self.assertEqual(refusal["failed_predicate"], "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(refusal["retry_entrypoint"],
                         ".stegverse/transition-ledger/emit.py::append (hb_epoch=, or --hb-epoch)")
        self.assertFalse((self.work / "repo").exists())


    INVALID_EPOCHS = ("33.0", True, 31, "+33")

    def _aggregate_refused_before_the_store_opens(self, name, **epoch):
        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(self.work / "org")
        aggregate = _module(name, "resident-runtime/aggregate_repo_transition.py")

        def untouched(*_args, **_kwargs):
            raise AssertionError("reached before the epoch was checked")

        aggregate.open_store = untouched
        aggregate.kernel.hb_reference = untouched
        with self.assertRaises(aggregate.OrgLedgerEpochRefused) as raised:
            aggregate.append({}, "REPO_STATE_PROPAGATION", "sha256:" + "a" * 64,
                             "sha256:" + "b" * 64, {}, "NONE", **epoch)
        refusal = raised.exception.refusal
        for field in self.SIX_FIELDS:
            self.assertTrue(refusal[field], field)
        self.assertEqual(refusal["disposition"], "FAIL_CLOSED")
        self.assertEqual(refusal["failed_predicate"], "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(refusal["retry_entrypoint"], aggregate.EPOCH_RETRY_ENTRYPOINT)
        self.assertIs(refusal["consequence_committed"], False)
        self.assertEqual(refusal, aggregate.epoch_refusal(epoch.get("hb_epoch")))
        self.assertFalse((self.work / "org").exists())
        return refusal

    def test_an_organization_append_without_a_supplied_epoch_fails_closed_before_the_store_opens(self):
        refusal = self._aggregate_refused_before_the_store_opens("aggregate_epoch_absent")
        self.assertEqual(refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")

    def test_an_organization_append_with_an_invalid_epoch_fails_closed_before_the_store_opens(self):
        for index, epoch in enumerate(self.INVALID_EPOCHS):
            with self.subTest(epoch=epoch):
                refusal = self._aggregate_refused_before_the_store_opens(
                    "aggregate_epoch_invalid_%d" % index, hb_epoch=epoch)
                self.assertEqual(refusal["failure_code"], "HB_EPOCH_INVALID")

    def test_a_propagated_receipt_without_an_epoch_writes_neither_ledger(self):
        # A caller that propagates a repository receipt through the dual
        # ledger is refused by the organization append too, not only by the
        # repository emitter in front of it.
        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = str(self.work / "org")
        ledger = _module("dual_ledger_epoch_absent", "resident-runtime/dual_ledger.py")
        for index, epoch in enumerate((None, *self.INVALID_EPOCHS)):
            with self.subTest(epoch=epoch):
                with self.assertRaises(ValueError) as raised:
                    ledger.append_organization(
                        {"schema": "stegverse.repo-transition-receipt/v1"},
                        "REPO_STATE_PROPAGATION", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                        {}, "NONE", hb_epoch=epoch)
                self.assertEqual(raised.exception.failed_predicate,
                                 "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
                self.assertFalse((self.work / "org").exists())

    def test_the_aggregator_command_refuses_without_an_epoch_and_writes_nothing(self):
        self._aggregate_command_refuses(None, "HB_EPOCH_NOT_SUPPLIED")

    def test_the_aggregator_command_refuses_an_invalid_epoch_and_writes_nothing(self):
        for epoch in ("33.0", "31", "+33"):
            with self.subTest(epoch=epoch):
                self._aggregate_command_refuses(epoch, "HB_EPOCH_INVALID")

    def _aggregate_command_refuses(self, epoch, failure_code):
        source = self.work / "source.json"
        source.write_text("{}", encoding="utf-8")
        env = {**os.environ, "STEGVERSE_ORG_LEDGER_ROOT": str(self.work / "org")}
        args = ["python3", str(ROOT / "resident-runtime/aggregate_repo_transition.py"),
                "--repo-receipt", str(source),
                "--predecessor-org-state-sha256", "sha256:" + "a" * 64,
                "--successor-org-state-sha256", "sha256:" + "b" * 64]
        if epoch is not None:
            args += ["--hb-epoch", epoch]
        run = subprocess.run(args, env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 1, run.stderr)
        refusal = json.loads(run.stdout)
        self.assertEqual(refusal["failure_code"], failure_code)
        self.assertEqual(refusal["failed_predicate"], "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(refusal["retry_entrypoint"],
                         "resident-runtime/aggregate_repo_transition.py::append (hb_epoch=, or --hb-epoch)")
        self.assertFalse((self.work / "org").exists())

class TemporaryGitRefTests(unittest.TestCase):
    def setUp(self):
        self._work = tempfile.TemporaryDirectory()
        self.addCleanup(self._work.cleanup)
        self.work = Path(self._work.name)
        previous = {name: os.environ.get(name) for name in LEDGER_ROOTS}

        def restore():
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore)

    def test_self_closure_pushes_a_temporary_ref_and_reads_it_back(self):
        checkout = self.work / "checkout"
        remote = self.work / "remote.git"
        fresh = self.work / "fresh.git"
        _git("init", "--bare", "-q", str(remote))
        _git("init", "-q", str(checkout))
        _git("-C", str(checkout), "config", "user.email", "ledger@example.invalid")
        _git("-C", str(checkout), "config", "user.name", "ledger-test")
        (checkout / "README").write_text("checkout\n", encoding="utf-8")
        _git("-C", str(checkout), "add", "README")
        _git("-C", str(checkout), "commit", "-q", "-m", "init")
        _git("-C", str(checkout), "remote", "add", "origin", str(remote))
        _git("-C", str(checkout), "push", "-q", "origin", "HEAD:refs/heads/main")

        os.environ["STEGVERSE_ORG_LEDGER_ROOT"] = f"git+{checkout}#{PUBLISHED_REF}"
        os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = f"git+{checkout}#{PUBLISHED_REF}:{NAMESPACE}"
        self.assertNotEqual(str(checkout), "GCAT-BCAT-Engine/.github")
        self.assertIn(str(self.work), str(checkout))

        ingress = _module("ingress_git_ref", "resident-runtime/intr_destination_ingress.py")
        registry = json.loads((ROOT / "org-boundary/registry/services.json").read_text(encoding="utf-8"))
        result = ingress.self_close("git-ref-diagnostic", registry=registry, hb_epoch=32)
        self.assertEqual(result["disposition"], "ALLOW", result.get("detail"))
        self.assertEqual(result["communication_id"], "git-ref-diagnostic")
        self.assertIs(result["self_closure"], True)
        self.assertEqual(result["addressed_service"], "gcat-bcat-engine.intr-destination")

        _git("-C", str(checkout), "push", "origin", f"{PUBLISHED_REF}:{PUBLISHED_REF}")
        _git("init", "--bare", "-q", str(fresh))
        _git("--git-dir", str(fresh), "fetch", "-q", str(remote), f"+{PUBLISHED_REF}:{PUBLISHED_REF}")
        self.assertNotEqual(str(fresh), "GCAT-BCAT-Engine/.github")

        readback = _module("organization_ledger_readback_git", "resident-runtime/organization_ledger_readback.py")
        location = f"git+{fresh}#{PUBLISHED_REF}"
        verified = readback.readback(location, result)
        self.assertEqual(verified["disposition"], "ALLOW")
        self.assertIs(verified["communication_id_on_organization_receipt"], True)
        self.assertEqual(verified["ingress_communication_id"], "git-ref-diagnostic")
        self.assertEqual(verified["chain_length"], 1)
        repository = readback.repository_readback(location, NAMESPACE, verified, result)
        self.assertIs(repository["ingress_repository_receipt_in_chain"], True)
        self.assertIs(repository["communication_id_on_repository_receipt"], True)
        self.assertEqual(repository["chain_length"], 1)
        self.assertIs(repository["replay_read_organization_receipts"], False)


if __name__ == "__main__":
    unittest.main()
