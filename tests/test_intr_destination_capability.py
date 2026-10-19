"""``intr-destination`` is a universal ingress capability, not a purpose route.

GCAT-BCAT-Engine advertises it. A peer address is derived as
``organization_slug + "." + "intr-destination"``. A purpose-neutral diagnostic
can be emitted and closed. Peer installation is not proven at resolution.
Closure, when a fabricated far side answers, shows that a boundary ran this
packet. It does not show which organization that boundary belongs to. No
answer stays ``PENDING`` and writes nothing.

Authority and time are constraint variables. A disposition is transition
evidence only. Both ledger roots and the mesh are redirected. Nothing here is
an authentic production receipt or a live peer installation.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PROFILE_ID = "intr-destination"
PROFILE_NAME = "InTr:Destination"
OPERATION = "DIAGNOSTIC_CROSSING"
OPERATION_ID = "ORGANIZATION_INTR_DESTINATION_INGRESS"
ADDRESS = "gcat-bcat-engine." + PROFILE_ID
PAYLOAD_SCHEMA = "stegverse.org-intr-destination-diagnostic/v1"
THIS = "GCAT-BCAT-Engine"
PEER = "StegVerse-org"
CONSTRAINT = "CONSTRAINT_VARIABLE"
DISPOSITION_ROLE = "TRANSITION_EVIDENCE_ONLY"
CONSTRAINT_FIELDS = (
    "routing_authority_constraint",
    "admission_authority_constraint",
    "execution_authority_constraint",
    "time_constraint",
)
STANDING = {"mode": "ESTABLISH_GENESIS", "node_ref": "intr-destination-test", "predecessor": None}


def _module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kernel = _module("kernel", "org-kernel/kernel.py")
capability = _module("capability_ingress", "org-boundary/runtime/capability_ingress.py")
egress = _module("organization_egress_boundary",
                 "resident-runtime/organization_egress_boundary.py")
ingress = _module("intr_destination_ingress", "resident-runtime/intr_destination_ingress.py")
runtime_boundary = _module("runtime_boundary", "org-runtime/runtime_boundary.py")

REGISTRY = json.loads((ROOT / "org-boundary/registry/services.json").read_text(encoding="utf-8"))
BOUNDARY = json.loads((ROOT / "org-runtime/interlock-intr.json").read_text(encoding="utf-8"))
FEDERATION = json.loads((ROOT / "org-boundary/registry/federation.json").read_text(encoding="utf-8"))


def binding(profile_id, document=None):
    matches = [entry for entry in (document or BOUNDARY)["ingress"]["capability_endpoint_bindings"]
               if entry.get("profile_id") == profile_id]
    if len(matches) != 1:
        raise AssertionError(profile_id)
    return matches[0]


def row(service_id):
    return next(item for item in REGISTRY["services"] if item["service_id"] == service_id)


def diagnostic(communication_id="intr-destination-diagnostic-001", schema=PAYLOAD_SCHEMA):
    return {
        "message_class": "ecosystem.communication",
        "communication_id": communication_id,
        "subject": "purpose-neutral mesh diagnostic",
        "body": {"schema": schema, "probe": "diagnostic-crossing"},
    }


def assert_constraints(test, record):
    for name in CONSTRAINT_FIELDS:
        test.assertEqual(record[name], CONSTRAINT, name)
    test.assertEqual(record["disposition_role"], DISPOSITION_ROLE)


class DeclarationTests(unittest.TestCase):
    def test_the_overlay_advertises_the_capability_and_sets_no_constraint(self):
        declared = binding(PROFILE_ID)
        self.assertEqual(declared["profile_name"], PROFILE_NAME)
        self.assertEqual(declared["operation"], OPERATION)
        self.assertEqual(declared["payload_schema"], PAYLOAD_SCHEMA)
        self.assertEqual(declared["submission_reader"], capability.COMMUNICATION_READER)
        self.assertEqual(declared["authority_effect"], "NONE_BINDING_ONLY")
        self.assertIs(declared["environment_selected_ingress"], False)
        assert_constraints(self, declared)
        receiving = declared["receiving_operation"]
        self.assertEqual(receiving["operation_id"], OPERATION_ID)
        self.assertEqual(receiving["addressed_service"], ADDRESS)
        self.assertEqual(receiving["addressed_service_boundary_role"], capability.ROLE)
        self.assertIs(receiving["selects_processing_at_the_capability_address"], False)
        self.assertIs(receiving["host_required"], False)
        self.assertIs(receiving["environment_url_required"], False)
        assert_constraints(self, receiving)
        self.assertTrue((ROOT / receiving["operation"]).is_file())

    def test_the_registry_row_is_an_address_and_not_an_admission(self):
        served = row(ADDRESS)
        self.assertEqual(served["boundary_role"], "BOUNDARY_LOCAL_CAPABILITY_INGRESS")
        self.assertEqual(served["capability_profile_id"], PROFILE_ID)
        self.assertEqual(served["admission_authority_constraint"], CONSTRAINT)
        self.assertEqual(served["time_constraint"], CONSTRAINT)
        self.assertEqual(served["disposition_role"], DISPOSITION_ROLE)
        self.assertIs(served["selects_processing_at_this_address"], False)
        self.assertNotIn("endpoint_adapter", served)
        self.assertNotIn("admits_processing", served)
        self.assertIn("ecosystem.communication", served["accepts"])
        self.assertIn(PAYLOAD_SCHEMA, served["accepts"])

    def test_the_served_address_is_named_and_no_peer_address_is(self):
        proven = BOUNDARY["egress"]["peer_capability_resolution"]["proven_on_this_organization"]
        served = {entry["receiving_operation"]["addressed_service"]
                  for entry in BOUNDARY["ingress"]["capability_endpoint_bindings"]}
        self.assertEqual(served, {ADDRESS})
        self.assertEqual(proven, ADDRESS)
        self.assertNotIn("stegverse-org.intr-destination", (proven,))
        report = runtime_boundary.validate()
        self.assertIs(report["valid"], True, report["checks"])
        self.assertIs(report["checks"]["capability_addresses_resolve"], True)
        self.assertIs(report["checks"]["peer_capability_addresses_derive"], True)

    def test_naming_a_proper_subset_of_served_addresses_is_refused(self):
        document = json.loads(json.dumps(BOUNDARY))
        extra = json.loads(json.dumps(binding(PROFILE_ID)))
        extra["profile_id"] = "sdk-manifest-ingress"
        extra["receiving_operation"] = dict(extra["receiving_operation"])
        extra["receiving_operation"]["addressed_service"] = "gcat-bcat-engine.sdk-manifest-ingress"
        document["ingress"]["capability_endpoint_bindings"].append(extra)
        document["egress"]["peer_capability_resolution"]["proven_on_this_organization"] = ADDRESS
        self.assertIs(runtime_boundary.peer_capability_addresses_derive(document), False)

    def test_a_peer_address_in_the_proven_field_is_refused(self):
        document = json.loads(json.dumps(BOUNDARY))
        document["egress"]["peer_capability_resolution"]["proven_on_this_organization"] = [
            ADDRESS, "stegverse-org.intr-destination"]
        self.assertIs(runtime_boundary.peer_capability_addresses_derive(document), False)

    def test_a_single_served_address_may_still_be_named_as_a_string(self):
        self.assertIsInstance(
            BOUNDARY["egress"]["peer_capability_resolution"]["proven_on_this_organization"], str)
        self.assertIs(runtime_boundary.peer_capability_addresses_derive(BOUNDARY), True)

    def test_peer_services_are_not_written_into_the_federation_directory(self):
        for entry in FEDERATION["organizations"]:
            for key in ("org_control_service", "addressed_service"):
                self.assertNotIn(PROFILE_ID, str(entry.get(key) or ""))

    def test_no_governance_or_remediation_destination_binding_was_added(self):
        self.assertNotIn("capability_destination_bindings", BOUNDARY["egress"])


class OverlayAuthorityTests(unittest.TestCase):
    def test_resolution_names_the_overlay_and_the_bound_operation(self):
        resolved = capability.resolve(ROOT, row(ADDRESS))
        self.assertEqual(resolved["resolution_source"], "ORGANIZATION_CAPABILITY_OVERLAY")
        self.assertIs(resolved["resolved_from_the_addressed_row_alone"], False)
        self.assertEqual(resolved["receiving_operation_id"], OPERATION_ID)
        self.assertEqual(resolved["capability_operation"], OPERATION)
        self.assertEqual(ingress.OPERATION_ID, OPERATION_ID)

    def test_a_row_the_overlay_does_not_name_resolves_nothing(self):
        with self.assertRaises(SystemExit) as refused:
            capability.resolve(ROOT, {"service_id": "gcat-bcat-engine.not-bound-anywhere"})
        self.assertIn("ADDRESS_SERVES_A_CAPABILITY_THE_OVERLAY_BINDS_HERE",
                      str(refused.exception))

    def test_a_module_that_is_not_the_bound_operation_is_refused(self):
        resolved = dict(capability.resolve(ROOT, row(ADDRESS)))
        resolved["receiving_operation_path"] = ROOT / "resident-runtime/organization_egress_boundary.py"
        with self.assertRaises(SystemExit) as refused:
            capability.load_operation(resolved)
        self.assertIn("MODULE_IDENTIFIES_ITSELF_AS_THE_BOUND_OPERATION",
                      str(refused.exception))

    def test_an_operation_outside_this_organization_is_refused(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "org-runtime").mkdir(parents=True)
        document = json.loads(json.dumps(BOUNDARY))
        receiving = binding(PROFILE_ID, document)["receiving_operation"]
        receiving["operation"] = "../outside.py"
        (root / "org-runtime/interlock-intr.json").write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(SystemExit) as refused:
            capability.resolve(root, row(ADDRESS))
        self.assertIn("RECEIVING_OPERATION_IS_OWNED_INSIDE_THIS_ORGANIZATION",
                      str(refused.exception))

    def test_the_readers_do_not_cross(self):
        manifest_binding = {"operation": "SUBMIT_MANIFEST"}
        with self.assertRaises(SystemExit) as manifest_refused:
            capability.submission_for(manifest_binding, diagnostic())
        self.assertIn("SUBMISSION_CARRIES_A_MANIFEST", str(manifest_refused.exception))
        with self.assertRaises(SystemExit) as diagnostic_refused:
            capability.submission_for(binding(PROFILE_ID), {"manifest": {"probe": True}})
        self.assertIn("SUBMISSION_DECLARES_A_RESPONDED_REQUEST_CLASS",
                      str(diagnostic_refused.exception))

    def test_a_diagnostic_body_under_another_schema_is_refused(self):
        with self.assertRaises(SystemExit) as refused:
            capability.submission_for(
                binding(PROFILE_ID), diagnostic(schema="stegverse.org-governance-decision/v1"))
        self.assertIn("SUBMISSION_BODY_DECLARES_THE_BOUND_PAYLOAD_SCHEMA", str(refused.exception))


class RedirectedLedgers(unittest.TestCase):
    LEDGER_ROOTS = ("STEGVERSE_REPO_LEDGER_ROOT", "STEGVERSE_ORG_LEDGER_ROOT")

    def setUp(self):
        self._work = tempfile.TemporaryDirectory()
        self.addCleanup(self._work.cleanup)
        previous = {name: os.environ.get(name) for name in self.LEDGER_ROOTS}
        for name in self.LEDGER_ROOTS:
            os.environ[name] = str(Path(self._work.name) / name.lower())
        self.mesh = Path(self._work.name) / "mesh"

        def restore():
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.addCleanup(restore)

    def receipts(self, variable, schema, transition_class=None):
        found = []
        root = Path(os.environ[variable])
        if not root.exists():
            return found
        for path in root.rglob("*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("schema") != schema:
                continue
            if transition_class is not None and record.get("transition_class") != transition_class:
                continue
            found.append(record)
        return found


class OperationReceiptTests(RedirectedLedgers):
    def test_a_diagnostic_is_acknowledged_at_both_ledger_levels(self):
        result = ingress.receive(diagnostic(), registry=REGISTRY, packet_id="direct-diagnostic",
                                 hb_epoch=32)
        self.assertEqual(result["disposition"], "ALLOW", result.get("detail"))
        self.assertIs(result["received"], True)
        self.assertIs(result["communication_acknowledged"], True)
        self.assertIs(result["repository_receipt_observed"], True)
        self.assertIs(result["organization_receipt_observed"], True)
        self.assertIs(result["organization_receipt_preserves_repository_receipt"], True)
        self.assertEqual(result["authority_effect"], "NONE_DIAGNOSTIC_ACK_ONLY")
        assert_constraints(self, result)
        for flag in ("selects_processing", "purpose_specific_route", "standing_rechecked_here"):
            self.assertIs(result[flag], False, flag)
        repository, = self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                    "stegverse.repo-transition-receipt/v1", OPERATION_ID)
        self.assertEqual(repository["evidence"]["profile_id"], PROFILE_ID)
        self.assertEqual(repository["evidence"]["receiving_operation"], OPERATION_ID)
        assert_constraints(self, repository["evidence"])
        organization, = self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                                      "stegverse.organization-transition-receipt/v1")
        self.assertEqual(organization["repo_receipt_sha256"], repository["receipt_sha256"])

    def test_a_replay_of_the_same_diagnostic_does_not_mint_a_second_pair(self):
        first = ingress.receive(diagnostic(), registry=REGISTRY, packet_id="replayed-diagnostic",
                                hb_epoch=32)
        second = ingress.receive(diagnostic(), registry=REGISTRY, packet_id="replayed-diagnostic",
                                 hb_epoch=32)
        self.assertIs(second["transition_replayed"], True)
        self.assertEqual(first["repository_receipt_sha256"], second["repository_receipt_sha256"])
        self.assertEqual(len(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                           "stegverse.repo-transition-receipt/v1", OPERATION_ID)), 1)

    def test_a_payload_that_is_not_the_diagnostic_is_refused_and_recorded(self):
        result = ingress.receive(
            {"message_class": "ecosystem.work.request", "communication_id": "not-a-diagnostic",
             "body": {"schema": "stegverse.org-governance-decision-request/v1"}},
            registry=REGISTRY, packet_id="refused-diagnostic", hb_epoch=32)
        self.assertEqual(result["disposition"], "DENY")
        self.assertIs(result["communication_acknowledged"], False)
        self.assertIs(result["refusal_recorded"], True)
        self.assertEqual(result["failed_predicate"], "SUBMISSION_DECLARES_A_RESPONDED_REQUEST_CLASS")
        self.assertEqual(result["authority_effect"], "NONE_REFUSAL_ONLY")
        assert_constraints(self, result)
        self.assertEqual(len(self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1",
            ingress.REFUSED_CLASS)), 1)
        self.assertEqual(self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1", OPERATION_ID), [])


class AddressedAndClosedTests(RedirectedLedgers):
    def publish(self, payload, service, packet_id, origin=PEER, epoch=4096):
        packet = kernel.build_packet(
            origin_org=origin,
            origin_service=kernel.organization_slug(origin) + "." + PROFILE_ID,
            destination_org=THIS, destination_service=service,
            payload=payload,
            transition_reference="intr:transition:" + packet_id,
            authority_effect="NONE", packet_id=packet_id)
        # Place the frame in the temporary mesh. This is not an emission record
        # and not an authentic receipt. The frame carries a supplied epoch, so
        # ingest admits it and the receiving operation decides. epoch=None
        # stands for a sender whose frame time is a clock reading.
        if epoch is None:
            kernel.publish_packet(packet, root=self.mesh, now_ns=kernel.HB_ANCHOR_UNIX_NS)
        else:
            kernel.publish_packet(packet, root=self.mesh, epoch=epoch)
        return packet

    def consume(self):
        return kernel.consume_addressed_frames(ROOT, mesh_root=self.mesh)

    def frames_to(self, organization):
        directory = self.mesh / "frames.d"
        if not directory.is_dir():
            return []
        frames = []
        for path in directory.glob("*.json"):
            frame = json.loads(path.read_text(encoding="utf-8"))
            if frame.get("destination_org") == organization:
                frames.append(frame)
        return frames

    def test_a_peer_frame_at_the_address_without_a_supplied_epoch_is_not_receipted(self):
        # A frame whose time is a clock reading carries no supplied epoch. The
        # repository emitter used to read the host clock in its place; ingest
        # now refuses the frame before either ledger is opened.
        self.publish(diagnostic("addressed-diagnostic"), ADDRESS, "addressed-diagnostic", epoch=None)
        with self.assertRaises(ValueError) as refused:
            self.consume()
        self.assertEqual(getattr(refused.exception, "failed_predicate", None),
                         "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1"), [])
        self.assertEqual(self.receipts(
            "STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1"), [])

    def _emit_refused_before_anything_is_published(self, **epoch):
        def untouched(*_args, **_kwargs):
            raise AssertionError("reached before the epoch was checked")

        for name in ("publish_packet", "publish_frame", "carrier_frame", "hb_reference"):
            patcher = mock.patch.object(egress.kernel, name, untouched)
            patcher.start()
            self.addCleanup(patcher.stop)
        with self.assertRaises(egress.EgressEpochRefused) as raised:
            egress.emit(PEER, diagnostic("epoch-refused-diagnostic"), standing=STANDING,
                        capability=PROFILE_ID, mesh_root=self.mesh, **epoch)
        refusal = raised.exception.refusal
        for field in ("failure_code", "failed_predicate", "required_evidence_or_repair",
                      "retry_entrypoint", "owning_existing_goal", "next_attempt"):
            self.assertTrue(refusal[field], field)
        self.assertEqual(refusal["disposition"], "FAIL_CLOSED")
        self.assertEqual(refusal["failed_predicate"], "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(refusal["retry_entrypoint"], egress.EPOCH_RETRY_ENTRYPOINT)
        self.assertIs(refusal["consequence_committed"], False)
        self.assertFalse((self.mesh / "frames.d").exists())
        self.assertEqual(self.frames_to(PEER), [])
        for variable in self.LEDGER_ROOTS:
            self.assertFalse(Path(os.environ[variable]).exists(), variable)
        return refusal

    def test_an_emission_without_a_supplied_epoch_publishes_nothing(self):
        refusal = self._emit_refused_before_anything_is_published()
        self.assertEqual(refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")

    def test_an_emission_with_an_invalid_epoch_publishes_nothing(self):
        for epoch in ("33.0", True, 31, "+33"):
            with self.subTest(epoch=epoch):
                refusal = self._emit_refused_before_anything_is_published(hb_epoch=epoch)
                self.assertEqual(refusal["failure_code"], "HB_EPOCH_INVALID")

    def test_the_emission_command_refuses_without_an_epoch_and_publishes_nothing(self):
        work = Path(self._work.name)
        (work / "payload.json").write_text(json.dumps(diagnostic("command-diagnostic")),
                                           encoding="utf-8")
        (work / "standing.json").write_text(json.dumps(STANDING), encoding="utf-8")
        for epoch in (None, "33.0", "31", "+33"):
            with self.subTest(epoch=epoch):
                args = ["python3", str(ROOT / "resident-runtime/organization_egress_boundary.py"),
                        "--destination-organization", PEER, "--capability", PROFILE_ID,
                        "--payload", str(work / "payload.json"),
                        "--standing", str(work / "standing.json"), "--mesh-root", str(self.mesh)]
                if epoch is not None:
                    args += ["--hb-epoch", epoch]
                run = subprocess.run(args, env=dict(os.environ), capture_output=True, text=True)
                self.assertEqual(run.returncode, 1, run.stderr)
                refusal = json.loads(run.stdout)
                self.assertEqual(refusal["failure_code"],
                                 "HB_EPOCH_NOT_SUPPLIED" if epoch is None else "HB_EPOCH_INVALID")
                self.assertFalse((self.mesh / "frames.d").exists())
                for variable in self.LEDGER_ROOTS:
                    self.assertFalse(Path(os.environ[variable]).exists(), variable)

    def test_a_supplied_epoch_is_the_published_frames_heartbeat_reference(self):
        emitted = egress.emit(PEER, diagnostic("epoch-frame-diagnostic"), standing=STANDING,
                              capability=PROFILE_ID, mesh_root=self.mesh, hb_epoch="40")
        self.assertEqual(emitted["disposition"], "ALLOW", emitted.get("detail"))
        frame, = self.frames_to(PEER)
        self.assertEqual(frame["heartbeat_reference"], kernel.hb_reference(epoch=40))
        self.assertIs(frame["heartbeat_reference"]["derived_from_clock"], False)
        self.assertNotIn("sampled_unix_ns", frame["heartbeat_reference"])

    def test_a_manifest_addressed_to_this_capability_is_not_a_diagnostic(self):
        self.publish({"manifest": {"probe": True}}, ADDRESS, "not-a-diagnostic")
        with self.assertRaises(ValueError) as refused:
            self.consume()
        self.assertIn("SUBMISSION_DECLARES_A_RESPONDED_REQUEST_CLASS", str(refused.exception))
        self.assertEqual(self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1", OPERATION_ID), [])

    def test_outbound_resolution_derives_the_peer_address_and_does_not_prove_it_serves(self):
        resolved = egress.resolve_destination(PEER, capability=PROFILE_ID)
        self.assertEqual(resolved["destination_service"],
                         kernel.organization_slug(PEER) + "." + PROFILE_ID)
        self.assertEqual(resolved["destination_service"], "stegverse-org.intr-destination")
        self.assertNotEqual(resolved["destination_service"],
                            resolved["destination_org_control_service"])
        self.assertIs(resolved["peer_serves_this_capability_is_proven_here"], False)
        self.assertIs(resolved["destination_capability_declared_by_the_peer_directory"], False)
        self.assertEqual(egress.peer_capability_service(THIS, PROFILE_ID), ADDRESS)

    def test_an_undeclared_capability_is_still_refused(self):
        with self.assertRaises(egress.EgressRefused) as refused:
            egress.resolve_destination(PEER, capability="not-a-declared-capability")
        self.assertEqual(refused.exception.failed_predicate,
                         "CAPABILITY_IS_DECLARED_IN_THIS_ORGANIZATIONS_OVERLAY")

    def test_an_undeclared_peer_is_still_refused(self):
        with self.assertRaises(egress.EgressRefused) as refused:
            egress.resolve_destination("Not-A-Declared-Peer", capability=PROFILE_ID)
        self.assertEqual(refused.exception.failed_predicate,
                         "DESTINATION_IS_A_DECLARED_PEER_OF_THIS_ORGANIZATION")

    def answer(self, packet):
        """Answer as a boundary does: the kernel's own receipt chain and control response.

        The chain is fabricated in this temporary mesh. It is not an authentic
        receipt and not a live peer installation.
        """
        chain, previous = [], None
        for kind in egress.FAR_SIDE_RECEIPT_KINDS:
            receipt = kernel.receipt(kind, packet["packet_id"], packet["destination"]["service"],
                                     previous, {"payload_hash": kernel.sha(packet["payload"])})
            chain.append(receipt["receipt_id"])
            previous = receipt["receipt_id"]
        response = kernel.build_control_response(
            packet, {"application_result": {
                "schema": ingress.RESULT_SCHEMA, "disposition": "ALLOW",
                "authority_effect": "NONE_DIAGNOSTIC_ACK_ONLY"},
                "reconstruction": {"terminal_receipt_id": chain[-1]}})
        kernel.publish_packet(response, root=self.mesh,
                              now_ns=kernel.HB_ANCHOR_UNIX_NS + 2 * kernel.HB_PERIOD_NS)
        return chain[-1]

    def test_a_diagnostic_crossing_closes_only_when_the_far_side_answers(self):
        emitted = egress.emit(PEER, diagnostic("closable-diagnostic"), standing=STANDING,
                              capability=PROFILE_ID, mesh_root=self.mesh, hb_epoch=32)
        self.assertEqual(emitted["disposition"], "ALLOW", emitted.get("detail"))
        self.assertIs(emitted["emitted"], True)
        self.assertEqual(emitted["destination_service"], "stegverse-org.intr-destination")
        self.assertIs(emitted["peer_serves_this_capability_is_proven_here"], False)
        self.assertEqual(emitted["emission_record"]["far_side_service_id"],
                         emitted["destination_service"])
        pending = egress.close(PEER, emitted["packet_id"], "closable-diagnostic",
                               mesh_root=self.mesh, hb_epoch=33)
        self.assertEqual(pending["disposition"], "PENDING")
        self.assertIs(pending["closed"], False)
        self.assertIs(pending["closure_recorded"], False)
        self.assertIs(pending["absence_is_not_a_transition"], True)
        self.assertEqual(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                       "stegverse.repo-transition-receipt/v1",
                                       egress.CLOSED_CLASS), [])

        frame, = self.frames_to(PEER)
        packet = kernel.recover_packet(frame)
        self.assertEqual(packet["destination"]["service"], "stegverse-org.intr-destination")
        self.assertEqual(packet["payload"]["message_class"], "ecosystem.communication")
        self.assertEqual(packet["payload"]["communication_id"], "closable-diagnostic")
        terminal = self.answer(packet)
        closed = egress.close(PEER, emitted["packet_id"], "closable-diagnostic",
                              mesh_root=self.mesh, hb_epoch=34)
        self.assertEqual(closed["disposition"], "ALLOW", closed.get("closure_findings"))
        self.assertIs(closed["closed"], True)
        self.assertEqual(closed["far_side_terminal_receipt"], terminal)
        self.assertEqual(closed["communication_id"], "closable-diagnostic")
        self.assertEqual(closed["closure_record"]["response_message_class"],
                         "ecosystem.communication.ack")
        # Closure shows a boundary ran this packet. It does not show which
        # organization that boundary belongs to, and resolution did not claim
        # the peer serves the capability.
        self.assertIs(closed["closure_record"]["reconstruction_proves_the_boundary_ran_this_packet"], True)
        self.assertIs(closed["closure_record"]["reconstruction_proves_who_the_far_side_is"], False)
        self.assertIs(emitted["peer_serves_this_capability_is_proven_here"], False)
        self.assertEqual(len(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                           "stegverse.repo-transition-receipt/v1",
                                           egress.CLOSED_CLASS)), 1)
        self.assertTrue(self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                                      "stegverse.organization-transition-receipt/v1"))



class SuppliedEpochParsingTests(RedirectedLedgers):
    """--hb-epoch and publish_packet(epoch=) are read by the shared rule, not coerced."""

    REFUSED = (None, "+33", " 33", "\u0663\u0663", "\uff13\uff13", "True", "abc", "33.7", "-1", "31")
    SIX_FIELDS = ("failure_code", "failed_predicate", "required_evidence_or_repair",
                  "retry_entrypoint", "owning_existing_goal", "next_attempt")

    def assert_six_field_refusal(self, refusal, epoch, retry_entrypoint):
        for field in self.SIX_FIELDS:
            self.assertTrue(refusal.get(field), field)
        self.assertEqual(refusal["disposition"], "FAIL_CLOSED")
        self.assertEqual(refusal["failed_predicate"], "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assertEqual(refusal["failure_code"],
                         "HB_EPOCH_NOT_SUPPLIED" if epoch is None else "HB_EPOCH_INVALID")
        self.assertEqual(refusal["retry_entrypoint"], retry_entrypoint)
        self.assertIs(refusal["consequence_committed"], False)

    def nothing_written(self):
        for variable in self.LEDGER_ROOTS:
            self.assertFalse(Path(os.environ[variable]).exists(), variable)
        self.assertFalse(self.mesh.exists())

    def command(self, mode, epoch, out):
        work = Path(self._work.name)
        args = ["python3", str(ROOT / "resident-runtime/intr_destination_ingress.py"),
                "--registry", str(ROOT / "org-boundary/registry/services.json"),
                "--out", str(out)]
        if mode == "self-close":
            args += ["--self-close", "--communication-id", "epoch-parsing-diagnostic"]
        else:
            (work / "payload.json").write_text(json.dumps(diagnostic("epoch-parsing-diagnostic")),
                                               encoding="utf-8")
            args += ["--payload", str(work / "payload.json")]
        if epoch is not None:
            args.append("--hb-epoch=" + epoch)
        return subprocess.run(args, env=dict(os.environ), capture_output=True, text=True)

    def test_the_ingress_command_refuses_an_unparsed_epoch_and_writes_nothing(self):
        for mode in ("payload", "self-close"):
            for epoch in self.REFUSED:
                with self.subTest(mode=mode, epoch=epoch):
                    out = Path(self._work.name) / "out.json"
                    run = self.command(mode, epoch, out)
                    self.assertEqual(run.returncode, 1, run.stderr)
                    self.assertNotIn("Traceback", run.stderr)
                    self.assert_six_field_refusal(json.loads(run.stdout), epoch,
                                                  ingress.EPOCH_RETRY_ENTRYPOINT)
                    self.assertFalse(out.exists())
                    self.nothing_written()

    def test_the_ingress_command_accepts_a_large_ascii_epoch(self):
        for mode in ("payload", "self-close"):
            with self.subTest(mode=mode):
                out = Path(self._work.name) / (mode + ".json")
                run = self.command(mode, "4096", out)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                result = json.loads(out.read_text(encoding="utf-8"))
                self.assertEqual(result["disposition"], "ALLOW")
                receipts = self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                         "stegverse.repo-transition-receipt/v1")
                self.assertTrue(receipts)
                self.assertEqual({r["hb_reference"]["epoch"] for r in receipts}, {4096})

    def packet(self):
        return kernel.build_packet(
            origin_org=THIS, origin_service=ADDRESS, destination_org=PEER,
            destination_service=kernel.organization_slug(PEER) + "." + PROFILE_ID,
            payload=diagnostic("publish-epoch-diagnostic"),
            transition_reference="intr:transition:publish-epoch",
            authority_effect="NONE", packet_id="publish-epoch")

    def test_publish_packet_refuses_an_unparsed_epoch_and_publishes_nothing(self):
        # epoch=None keeps the clock-sampled reference (WU-B13); the absent
        # case here is an empty supplied value.
        for epoch in ("",) + self.REFUSED[1:] + (True, -1, 31, 33.7):
            with self.subTest(epoch=epoch):
                with self.assertRaises(kernel.SuppliedEpochRefused) as raised:
                    kernel.publish_packet(self.packet(), root=self.mesh, epoch=epoch)
                refusal = raised.exception.refusal
                for field in self.SIX_FIELDS:
                    self.assertTrue(refusal.get(field), field)
                self.assertEqual(refusal["failure_code"], "HB_EPOCH_INVALID")
                self.assertEqual(refusal["retry_entrypoint"],
                                 "org-kernel/kernel.py::publish_packet")
                self.nothing_written()

    def test_publish_packet_accepts_a_supplied_ascii_epoch(self):
        for epoch in ("4096", 4096, "32"):
            with self.subTest(epoch=epoch):
                published = kernel.publish_packet(self.packet(), root=self.mesh, epoch=epoch)
                self.assertEqual(published["frame"]["heartbeat_reference"],
                                 kernel.hb_reference(epoch=int(str(epoch))))
                self.assertTrue(Path(published["path"]).exists())


if __name__ == "__main__":
    unittest.main()


def _kernel_instances(*modules):
    """Every loaded copy of the kernel reachable from these modules' attributes."""
    found, seen, pending = [], set(), list(modules)
    while pending:
        module = pending.pop()
        if id(module) in seen:
            continue
        seen.add(id(module))
        if Path(getattr(module, "__file__", "") or "").resolve() == ROOT / "org-kernel/kernel.py":
            found.append(module)
        for value in vars(module).values():
            if isinstance(value, type(kernel)):
                pending.append(value)
    return found


class EpochProvenanceTests(RedirectedLedgers):
    """B-P36f: an ingress forwards only the epoch it was supplied, never one read back.

    The clock is patched to a fixed sample on every loaded kernel copy. With the
    epoch absent nothing is written. A replay that returns a recorded repository
    receipt does not lend that receipt's epoch to the organization receipt.
    """

    CLOCK_NS = kernel.HB_ANCHOR_UNIX_NS + 777 * kernel.HB_PERIOD_NS + kernel.HB_PERIOD_NS // 2
    CLOCK_EPOCH = kernel.HB_ANCHOR_EPOCH + 777

    def setUp(self):
        super().setUp()
        fixed = datetime.fromtimestamp(self.CLOCK_NS / 1_000_000_000, timezone.utc)
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(return_value=fixed)
        self.kernels = _kernel_instances(ingress, egress, capability, kernel)
        self.assertGreaterEqual(len(self.kernels), 4)
        for copy in self.kernels:
            patcher = mock.patch.object(copy, "datetime", clock)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.assertEqual(self.kernels[0].hb_reference()["epoch"], self.CLOCK_EPOCH)

    def all_receipts(self):
        return (self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1"),
                self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                              "stegverse.organization-transition-receipt/v1"))

    def assert_nothing_written(self):
        self.assertEqual(self.all_receipts(), ([], []))

    def assert_no_laundered_epoch(self, supplied):
        for receipt in sum(self.all_receipts(), []):
            reference = receipt["hb_reference"]
            if reference.get("derived_from_clock") is False:
                self.assertIn(reference["epoch"], supplied, receipt["receipt_sha256"])

    def assert_absent_epoch_refused(self, call):
        with self.assertRaises(kernel.SuppliedEpochRefused.__mro__[1]) as refused:
            call()
        self.assertEqual(getattr(refused.exception, "failed_predicate", None),
                         "SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH")
        self.assert_nothing_written()

    def test_intr_destination_receive_without_an_epoch_writes_nothing(self):
        self.assert_absent_epoch_refused(lambda: ingress.receive(
            diagnostic("probe-receive"), registry=REGISTRY, packet_id="probe-receive"))

    def test_intr_destination_self_close_without_an_epoch_writes_nothing(self):
        self.assert_absent_epoch_refused(lambda: ingress.self_close(
            "probe-self-close", registry=REGISTRY))

    def test_capability_ingress_without_an_epoch_writes_nothing(self):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + "." + PROFILE_ID,
            destination_org=THIS, destination_service=ADDRESS,
            payload=diagnostic("probe-capability"), transition_reference="intr:transition:probe",
            authority_effect="NONE", packet_id="probe-capability")
        kernel.publish_packet(packet, root=self.mesh)
        self.assert_absent_epoch_refused(
            lambda: kernel.consume_addressed_frames(ROOT, mesh_root=self.mesh))

    def test_egress_emit_and_close_without_an_epoch_write_nothing(self):
        self.assert_absent_epoch_refused(lambda: egress.emit(
            PEER, diagnostic("probe-emit"), standing=STANDING, capability=PROFILE_ID,
            mesh_root=self.mesh))
        self.assertFalse((self.mesh / "frames.d").exists())
        closed = egress.close(PEER, "probe-emit", "probe-emit", mesh_root=self.mesh)
        self.assertEqual(closed["disposition"], "PENDING")
        self.assert_nothing_written()

    def test_the_supplied_epoch_is_carried_at_both_levels(self):
        received = ingress.receive(diagnostic("probe-4096"), registry=REGISTRY,
                                   packet_id="probe-4096", hb_epoch="4096")
        self.assertEqual(received["disposition"], "ALLOW", received.get("detail"))
        emitted = egress.emit(PEER, diagnostic("probe-emit-4096"), standing=STANDING,
                              capability=PROFILE_ID, mesh_root=self.mesh, hb_epoch="4096")
        self.assertEqual(emitted["disposition"], "ALLOW", emitted.get("detail"))
        repository, organization = self.all_receipts()
        self.assertEqual(len(repository), 2)
        self.assertEqual(len(organization), 2)
        for receipt in repository + organization:
            self.assertEqual(receipt["hb_reference"]["epoch"], 4096)
            self.assertIs(receipt["hb_reference"]["derived_from_clock"], False)
            self.assertNotIn("sampled_unix_ns", receipt["hb_reference"])

    def _seed_clock_receipt(self, transition_id, transition_class, predecessor, successor, evidence,
                            reference=None):
        """A repository receipt as an unsupplied writer recorded it: the clock sample.

        Written through the emitter with its epoch check bypassed, to stand for
        a receipt recorded before the supplied-epoch rule. ``reference`` replaces
        the clock sample with another unsupplied reference. Not an authentic receipt.
        """
        emit = ingress.ledger.emit
        with mock.patch.object(emit.kernel, "supplied_hb_reference",
                               lambda *_a, **_k: dict(reference) if reference is not None
                               else emit.kernel.hb_reference()):
            seeded = emit.append(transition_id, transition_class, predecessor, successor,
                                 dict(evidence), "NONE")
        if reference is None:
            self.assertEqual(seeded["hb_reference"]["epoch"], self.CLOCK_EPOCH)
            self.assertIn("sampled_unix_ns", seeded["hb_reference"])
        return seeded

    def organization_ledger_files(self):
        root = Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"])
        return sorted(path for path in root.rglob("*") if path.is_file()) if root.exists() else []

    def assert_source_refused(self, call, failure_code):
        with self.assertRaises(ValueError) as refused:
            call()
        refusal = refused.exception.refusal
        self.assertEqual(refusal["failure_code"], failure_code)
        self.assertEqual(refusal["failed_predicate"], "SOURCE_RECEIPT_REFERENCES_A_SUPPLIED_HB_EPOCH")
        self.assertTrue(refusal["required_evidence_or_repair"].startswith("a WU-B13 migration transition"))
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        self.assertIs(refusal["consequence_committed"], False)
        # No organization receipt, no retained source copy, no HEAD.
        self.assertEqual(self.organization_ledger_files(), [])
        self.assert_no_laundered_epoch({4096})

    def _ingress_replay_over(self, reference=None):
        packet_id = "probe-replay"
        evidence = ingress._evidence(diagnostic("probe-replay"), packet_id, "ALLOW",
                                     failed_predicate=None, detail=None)
        successor = kernel.sha({"disposition": "ALLOW", "packet_id": packet_id,
                                "communication_id": evidence.get("communication_id"),
                                "payload_sha256": evidence["payload_sha256"]})
        self._seed_clock_receipt(OPERATION_ID + ":" + packet_id, OPERATION_ID,
                                 evidence["payload_sha256"], successor, evidence, reference)
        return lambda: ingress.receive(diagnostic("probe-replay"), registry=REGISTRY,
                                       packet_id=packet_id, hb_epoch=4096)

    def test_an_ingress_replay_over_a_clock_receipt_writes_no_organization_receipt(self):
        # Before B-P36f the replay lent the clock epoch (809) to an organization
        # receipt marked derived_from_clock false; B-P36f forwarded 4096 over the
        # clock source instead. The source itself is now refused.
        self.assert_source_refused(self._ingress_replay_over(), "SOURCE_RECEIPT_IS_CLOCK_PROVENANCE")

    def test_an_ingress_replay_over_an_unmarked_receipt_writes_no_organization_receipt(self):
        unmarked = {"epoch": 4096, "generation": 4096, "heartbeat_id": "HB:4096",
                    "phase_offset_ns": 0, "frequency_hz": 100,
                    "progression_dependency": "OSCILLATOR_ONLY", "authority_effect": "NONE"}
        self.assert_source_refused(self._ingress_replay_over(unmarked), "HB_EPOCH_PROVENANCE_UNMARKED")

    def test_an_egress_replay_over_a_clock_receipt_writes_no_organization_receipt(self):
        record = {"intended_action": "probe", "disposition": "DENY",
                  "crossed_an_organization_boundary": False,
                  "frame_sha256": None, "payload_sha256": kernel.sha({"probe": 1})}
        transition_id = egress.EMIT_REFUSED_CLASS + ":probe-replay"
        self._seed_clock_receipt(transition_id, egress.EMIT_REFUSED_CLASS,
                                 record["payload_sha256"], kernel.sha(record), record)
        self.assert_source_refused(
            lambda: egress._record(transition_id, egress.EMIT_REFUSED_CLASS,
                                   record["payload_sha256"], kernel.sha(record), record, 4096),
            "SOURCE_RECEIPT_IS_CLOCK_PROVENANCE")


class CopiedRepository(RedirectedLedgers):
    """Ledgers, mesh and a copy of this repository, all in a temporary directory."""

    CLOCK_NS = EpochProvenanceTests.CLOCK_NS
    CLOCK_EPOCH = EpochProvenanceTests.CLOCK_EPOCH

    def setUp(self):
        super().setUp()
        self.copy = Path(self._work.name) / "repo"
        shutil.copytree(ROOT, self.copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        previous = os.environ.get("STEGVERSE_ORG_FEDERATION_ROOT")
        os.environ["STEGVERSE_ORG_FEDERATION_ROOT"] = str(self.mesh)
        self.addCleanup(lambda: os.environ.__setitem__("STEGVERSE_ORG_FEDERATION_ROOT", previous)
                        if previous is not None else os.environ.pop("STEGVERSE_ORG_FEDERATION_ROOT", None))
        gateway = os.environ.pop("STEGVERSE_ORG_FEDERATION_GATEWAY_URL", None)
        if gateway is not None:
            self.addCleanup(os.environ.__setitem__, "STEGVERSE_ORG_FEDERATION_GATEWAY_URL", gateway)

    def runtime(self):
        module = _module("organization_runtime_probe", "runtime/organization_runtime.py")
        for name in ("ACTIVATIONS", "INGRESS", "EGRESS"):
            patcher = mock.patch.object(module, name, Path(self._work.name) / "runtime" / name.lower())
            patcher.start()
            self.addCleanup(patcher.stop)
        return module

    def written(self, directory):
        root = Path(self._work.name) / "runtime" / directory
        return sorted(root.glob("*.json")) if root.is_dir() else []

    def publish(self, service, payload, packet_id, epoch=4096):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        kernel.publish_packet(packet, root=self.mesh, epoch=epoch)


class ClockMarkerAndRuntimeEpochTests(CopiedRepository):
    """B-P36g: no receipt is stamped from the clock, and a clock value is always marked.

    `runtime/organization_runtime.py` stamps its ingress and activation receipts
    from the supplied epoch, or refuses six-field before writing. The federation
    cycle reports a receiving operation's epoch refusal as six fields, not a
    traceback. With the clock patched, every clock value a route writes sits in
    a reference that says so: `derived_from_clock` true or `sampled_unix_ns`.
    """

    def test_runtime_ingress_and_activation_without_an_epoch_write_nothing(self):
        runtime = self.runtime()
        envelope = runtime.egress("probe-message", "PROBE", {"boundary": "B", "subsystem": "S"}, b"x")
        for call in (lambda: runtime.ingress(envelope),
                     lambda: runtime.activate("probe-activation", "probe-node")):
            with self.assertRaises(runtime.kernel.SuppliedEpochRefused) as refused:
                call()
            self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
            self.assertIs(refused.exception.refusal["consequence_committed"], False)
        self.assertEqual(self.written("ingress"), [])
        self.assertEqual(self.written("activations"), [])

    def test_runtime_receipts_reference_the_supplied_epoch_and_no_clock(self):
        runtime = self.runtime()
        envelope = runtime.egress("probe-message", "PROBE", {"boundary": "B", "subsystem": "S"}, b"x")
        received = runtime.ingress(envelope, "4096")
        activated = runtime.activate("probe-activation", "probe-node", "4096")
        for receipt, clock_field in ((received, "validated_at"), (activated, "requested_at")):
            self.assertNotIn(clock_field, receipt)
            self.assertEqual(receipt["hb_reference"]["epoch"], 4096)
            self.assertIs(receipt["hb_reference"]["derived_from_clock"], False)
            self.assertNotIn("sampled_unix_ns", receipt["hb_reference"])
        self.assertEqual(len(self.written("ingress")), 1)
        self.assertEqual(len(self.written("activations")), 1)

    def test_the_runtime_command_refuses_without_an_epoch_and_writes_nothing(self):
        run = subprocess.run(
            ["python3", str(self.copy / "runtime/organization_runtime.py"), "activate",
             "--activation-id", "probe-activation", "--node-ref", "probe-node"],
            capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 1, run.stderr)
        refusal = json.loads(run.stdout)
        self.assertEqual(refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        self.assertFalse((self.copy / "runtime/activations").exists())

    def test_the_federation_cycle_reports_its_own_epoch_refusal_as_six_fields(self):
        self.publish(ADDRESS, diagnostic("probe-cycle"), "probe-cycle")
        run = subprocess.run(["python3", str(self.copy / "resident-runtime/federation_cycle.py")],
                             capture_output=True, text=True, check=False,
                             env={k: v for k, v in os.environ.items() if k != "HB_EPOCH"})
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertNotIn("Traceback", run.stderr)
        refusal = json.loads(run.stdout)
        self.assertEqual(refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        self.assertFalse((self.copy / "resident-runtime/federation/latest-cycle.json").exists())
        self.assertEqual(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                       "stegverse.repo-transition-receipt/v1"), [])

    def test_every_clock_value_a_route_writes_is_marked(self):
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_probe", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        fixed = datetime.fromtimestamp(self.CLOCK_NS / 1_000_000_000, timezone.utc)
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(return_value=fixed)
        for module in (cycle, cycle.K, cycle.GW):
            if getattr(module, "datetime", None) is datetime:
                patcher = mock.patch.object(module, "datetime", clock)
                patcher.start()
                self.addCleanup(patcher.stop)
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        for role in ("BOUNDARY_LOCAL_DIAGNOSTIC", "BOUNDARY_LOCAL_CONTROL"):
            self.publish(services[role], {"communication_id": "probe-" + role.lower(),
                                          "message_class": "ecosystem.monitor.request",
                                          "subject": "probe", "body": {}}, "probe-" + role.lower())
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        # A supplied cycle epoch leaves no route a reason to read the clock.
        self.assertFalse(clock.now.called)
        runtime = self.runtime()
        runtime.ingress(runtime.egress("probe-message", "PROBE",
                                       {"boundary": "B", "subsystem": "S"}, b"x"), "4096")
        runtime.activate("probe-activation", "probe-node", "4096")

        clock_values = {self.CLOCK_EPOCH, self.CLOCK_NS, fixed.isoformat(),
                        fixed.replace(microsecond=0).isoformat().replace("+00:00", "Z")}
        unmarked, seen = [], 0

        def walk(value, where):
            nonlocal seen
            if isinstance(value, dict):
                marked = value.get("derived_from_clock") is True or "sampled_unix_ns" in value
                for key, item in value.items():
                    if not isinstance(item, (dict, list)) and item in clock_values:
                        seen += 1
                        if not marked:
                            unmarked.append(where + "." + key)
                    walk(item, where + "." + key)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, where + "[" + str(index) + "]")

        written = [self.copy / "resident-runtime/federation/latest-cycle.json",
                   *sorted((self.copy / "resident-runtime/federation/seen.d").glob("*.json")),
                   *sorted((self.mesh / "frames.d").glob("*.json")),
                   *self.written("ingress"), *self.written("activations"), *self.written("egress")]
        for path in written:
            document = json.loads(path.read_text(encoding="utf-8"))
            walk(document, path.name)
            if "packet_base64" in document:
                walk(kernel.recover_packet(document), path.name + "#packet")
        self.assertEqual(unmarked, [])


def _forged_frame(frame, **reference):
    """A carrier frame whose heartbeat reference is replaced and whose digest is recomputed."""
    body = dict(frame)
    body.pop("frame_sha256")
    body["heartbeat_reference"] = {**frame["heartbeat_reference"], **reference}
    return {**body, "frame_sha256": kernel.sha(body)}


class CarriedEpochAndCollisionTests(CopiedRepository):
    """B-P36h and the VALIDATOR repair rows on GCAT#15.

    P/G1: the shared rule refuses a reference that does not mark itself supplied,
    and ingest refuses a frame whose time is a clock reading. G2/G4: a response
    frame and the monitor status carry the request frame's epoch. G3: the cycle
    takes the supplied epoch. Row 3: a replayed emission at another epoch is
    refused before it is published.
    """

    def unavailable_clock(self, *modules):
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(side_effect=RuntimeError("clock unavailable"))
        for module in modules:
            if getattr(module, "datetime", None) is datetime:
                patcher = mock.patch.object(module, "datetime", clock)
                patcher.start()
                self.addCleanup(patcher.stop)
        return clock

    def cycle(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_carried", self.copy / "resident-runtime/federation_cycle.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def monitor_request(self, role, packet_id):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        self.publish(services[role], {"communication_id": packet_id,
                                      "message_class": "ecosystem.monitor.request",
                                      "subject": "probe", "body": {}}, packet_id)

    def frames(self):
        directory = self.mesh / "frames.d"
        return sorted(directory.glob("*.json")) if directory.is_dir() else []

    def responses(self):
        found = []
        for path in self.frames():
            frame = json.loads(path.read_text(encoding="utf-8"))
            if ":response:" in frame["packet_id"]:
                found.append((frame, kernel.recover_packet(frame)))
        return found

    def test_the_shared_rule_refuses_a_reference_that_does_not_mark_itself_supplied(self):
        self.assertEqual(kernel.supplied_epoch_failure(4096, {})[0], "HB_EPOCH_PROVENANCE_UNMARKED")
        # Order: present and not false, then a clock sample, then absent.
        self.assertEqual(kernel.supplied_epoch_failure(
            4096, {"derived_from_clock": False, "sampled_unix_ns": 1})[0], "HB_EPOCH_INVALID")
        self.assertEqual(kernel.supplied_epoch_failure(4096, {"sampled_unix_ns": 1})[0], "HB_EPOCH_INVALID")
        self.assertEqual(kernel.supplied_epoch_failure(4096, {"derived_from_clock": True})[0],
                         "HB_EPOCH_INVALID")
        self.assertEqual(kernel.supplied_epoch_failure(
            4096, {"derived_from_clock": True, "sampled_unix_ns": 1})[1],
            kernel.supplied_epoch_failure(4096, {"derived_from_clock": True})[1])
        self.assertIsNone(kernel.supplied_epoch_failure(4096, {"derived_from_clock": False}))
        self.assertIsNone(kernel.supplied_epoch_failure(4096))
        refusal = kernel.writer_epoch_refusal(4096, retry_entrypoint="probe", reference={})
        self.assertEqual(refusal["failure_code"], "HB_EPOCH_PROVENANCE_UNMARKED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)

    def test_ingest_refuses_a_frame_whose_time_is_a_clock_reading(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=services["BOUNDARY_LOCAL_DIAGNOSTIC"],
            payload={"probe": "ping"}, transition_reference="probe", authority_effect="NONE",
            packet_id="probe-clock-frame")
        supplied = kernel.carrier_frame(packet, epoch=4096)
        cases = (
            (_forged_frame(supplied, sampled_unix_ns=self.CLOCK_NS), "HB_EPOCH_INVALID"),
            (_forged_frame({**supplied, "heartbeat_reference": {
                key: value for key, value in supplied["heartbeat_reference"].items()
                if key != "derived_from_clock"}}), "HB_EPOCH_PROVENANCE_UNMARKED"),
        )
        for frame, failure_code in cases:
            with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
                kernel.ingest_frame(ROOT, frame, mesh_root=self.mesh)
            self.assertEqual(refused.exception.refusal["failure_code"], failure_code)
        self.assertEqual(kernel.ingest_frame(ROOT, supplied, mesh_root=self.mesh)["carried_hb_epoch"], 4096)
        # NARROW S1 (07:48Z, 08:10Z): a CLOCK frame -- flagged true, or the legacy
        # bare sample -- is consumed and lends no epoch.
        for clock_frame in (_forged_frame(supplied, derived_from_clock=True),
                            kernel.carrier_frame(packet, now_ns=self.CLOCK_NS)):
            consumed = kernel.ingest_frame(ROOT, clock_frame, mesh_root=self.mesh)
            self.assertEqual((consumed["status"], consumed["carried_hb_epoch"], consumed["hb_epoch"]),
                             ("CONSUMED", None, None))

    def test_a_response_and_the_monitor_status_carry_the_request_frames_epoch(self):
        self.unavailable_clock(kernel)
        self.monitor_request("BOUNDARY_LOCAL_CONTROL", "probe-carried-monitor")
        self.monitor_request("BOUNDARY_LOCAL_DIAGNOSTIC", "probe-carried-diagnostic")
        results = kernel.consume_and_respond(self.copy, mesh_root=self.mesh)
        self.assertEqual(len(results), 2)
        responses = self.responses()
        self.assertEqual(len(responses), 2)
        for frame, packet in responses:
            self.assertEqual(frame["heartbeat_reference"]["epoch"], 4096)
            self.assertIs(frame["heartbeat_reference"]["derived_from_clock"], False)
            status = (packet["payload"]["body"]["application_result"] or {}).get("monitor_status")
            if status is not None:
                self.assertEqual(status["heartbeat_reference"]["epoch"], 4096)
                self.assertIs(status["heartbeat_reference"]["derived_from_clock"], False)
        self.assertTrue(any((p["payload"]["body"]["application_result"] or {}).get("monitor_status")
                            for _f, p in responses))

    def test_the_monitor_status_refuses_without_an_epoch(self):
        with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
            kernel.resident_status(ROOT)
        self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")

    def test_the_cycle_refuses_an_absent_or_invalid_epoch_and_writes_nothing(self):
        self.monitor_request("BOUNDARY_LOCAL_CONTROL", "probe-cycle-refused")
        before = self.frames()
        for argv, environment, failure_code in (
                ([], {}, "HB_EPOCH_NOT_SUPPLIED"),
                (["--hb-epoch", "+33"], {}, "HB_EPOCH_INVALID"),
                ([], {"HB_EPOCH": "31"}, "HB_EPOCH_INVALID"),
                ([], {"HB_EPOCH": ""}, "HB_EPOCH_INVALID")):
            run = subprocess.run(
                ["python3", str(self.copy / "resident-runtime/federation_cycle.py"), *argv],
                capture_output=True, text=True, check=False,
                env={**{k: v for k, v in os.environ.items() if k != "HB_EPOCH"}, **environment})
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertNotIn("Traceback", run.stderr)
            refusal = json.loads(run.stdout)
            self.assertEqual(refusal["failure_code"], failure_code, argv)
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, refusal)
        self.assertFalse((self.copy / "resident-runtime/federation/latest-cycle.json").exists())
        self.assertFalse((self.copy / "resident-runtime/federation/seen.d").exists())
        self.assertEqual(self.frames(), before)

    def test_the_cycle_stamps_its_record_and_responses_from_the_supplied_epoch(self):
        cycle = self.cycle()
        clock = self.unavailable_clock(cycle, cycle.K, cycle.GW)
        self.monitor_request("BOUNDARY_LOCAL_CONTROL", "probe-cycle-monitor")
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        self.assertFalse(clock.now.called)
        record = json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())
        self.assertEqual(record["heartbeat_reference"]["epoch"], 4096)
        self.assertIs(record["heartbeat_reference"]["derived_from_clock"], False)
        self.assertEqual(record["responses_emitted"], 1)
        (frame, packet), = self.responses()
        self.assertEqual(frame["heartbeat_reference"]["epoch"], 4096)
        status = packet["payload"]["body"]["application_result"]["monitor_status"]
        self.assertEqual(status["heartbeat_reference"]["epoch"], 4096)

    def test_an_emission_replayed_at_another_epoch_publishes_and_writes_nothing(self):
        first = egress.emit(PEER, diagnostic("probe-collision"), standing=STANDING,
                            capability=PROFILE_ID, mesh_root=self.mesh, hb_epoch=4096)
        self.assertEqual(first["disposition"], "ALLOW", first.get("detail"))
        frames, ledgers = self.frames(), self.all_ledger_files()
        replay = egress.emit(PEER, diagnostic("probe-collision"), standing=STANDING,
                             capability=PROFILE_ID, mesh_root=self.mesh, hb_epoch=4096)
        self.assertEqual(replay["emission_repository_receipt_sha256"],
                         first["emission_repository_receipt_sha256"])
        self.assertEqual((self.frames(), self.all_ledger_files()), (frames, ledgers))
        with self.assertRaises(egress.EmissionCollisionRefused) as refused:
            egress.emit(PEER, diagnostic("probe-collision"), standing=STANDING,
                        capability=PROFILE_ID, mesh_root=self.mesh, hb_epoch=4097)
        refusal = refused.exception.refusal
        self.assertEqual(refusal["failure_code"], "LEDGER_RECEIPT_COLLISION")
        self.assertIn("4096", refusal["required_evidence_or_repair"])
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        self.assertEqual((self.frames(), self.all_ledger_files()), (frames, ledgers))

        payload = Path(self._work.name) / "payload.json"
        payload.write_text(json.dumps(diagnostic("probe-collision")), encoding="utf-8")
        standing = Path(self._work.name) / "standing.json"
        standing.write_text(json.dumps(STANDING), encoding="utf-8")
        argv = ["organization_egress_boundary.py", "--destination-organization", PEER,
                "--payload", str(payload), "--standing", str(standing), "--capability", PROFILE_ID,
                "--mesh-root", str(self.mesh), "--hb-epoch", "4097"]
        with mock.patch("sys.argv", argv), mock.patch("builtins.print") as printed:
            self.assertEqual(egress.main(), 1)
        self.assertEqual(json.loads(printed.call_args.args[0])["failure_code"], "LEDGER_RECEIPT_COLLISION")
        self.assertEqual((self.frames(), self.all_ledger_files()), (frames, ledgers))

    def all_ledger_files(self):
        found = []
        for variable in self.LEDGER_ROOTS:
            root = Path(os.environ[variable])
            if root.exists():
                found.extend(sorted(str(path) for path in root.rglob("*") if path.is_file()))
        return found


class MarkerVocabularyTests(CopiedRepository):
    """07:17Z marker vocabulary: a supplied epoch is SUPPLIED, and no clock is read for it.

    SUPPLIED is derived_from_clock exactly false with no sampled_unix_ns. Every
    kernel path that stamps a supplied 4096 does so with the clock patched to
    raise, and the clock is never called.
    """

    def test_a_supplied_epoch_is_marked_supplied_and_reads_no_clock(self):
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(side_effect=RuntimeError("clock unavailable"))
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_vocabulary", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        for module in (kernel, cycle.K, cycle.GW):
            if hasattr(module, "datetime"):
                patcher = mock.patch.object(module, "datetime", clock)
                patcher.start()
                self.addCleanup(patcher.stop)
        packet = kernel.build_packet(
            origin_org=THIS, origin_service=kernel.organization_slug(THIS) + ".org-control",
            destination_org=PEER, destination_service=kernel.organization_slug(PEER) + ".org-control",
            payload={"probe": "vocabulary"}, transition_reference="probe", authority_effect="NONE",
            packet_id="probe-vocabulary")
        references = [
            kernel.hb_reference(epoch=4096),
            kernel.supplied_hb_reference("4096", retry_entrypoint="probe"),
            kernel.carrier_frame(packet, epoch=4096)["heartbeat_reference"],
            kernel.publish_packet(packet, root=self.mesh, epoch="4096")["frame"]["heartbeat_reference"],
        ]
        self.publish(next(row["service_id"] for row in REGISTRY["services"]
                          if row["boundary_role"] == "BOUNDARY_LOCAL_CONTROL"),
                     {"communication_id": "probe-vocabulary-monitor",
                      "message_class": "ecosystem.monitor.request", "subject": "probe", "body": {}},
                     "probe-vocabulary-monitor")
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        record = json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())
        references.append(record["heartbeat_reference"])
        for path in sorted((self.mesh / "frames.d").glob("*.json")):
            references.append(json.loads(path.read_text(encoding="utf-8"))["heartbeat_reference"])
        self.assertGreaterEqual(len(references), 7)
        for reference in references:
            self.assertEqual(reference["epoch"], 4096)
            self.assertIs(reference["derived_from_clock"], False)
            self.assertNotIn("sampled_unix_ns", reference)
        self.assertEqual(clock.now.call_count, 0)


class FrameEpochReachesTheOperationTests(CopiedRepository):
    """07:36Z rows on GCAT#15: G2 publisher epoch, G4 capability epoch, quarantined refusals."""

    def unavailable_clock(self, *modules):
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(side_effect=RuntimeError("clock unavailable"))
        for module in modules:
            if getattr(module, "datetime", None) is datetime:
                patcher = mock.patch.object(module, "datetime", clock)
                patcher.start()
                self.addCleanup(patcher.stop)
        return clock

    def cycle(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_g4", self.copy / "resident-runtime/federation_cycle.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def clock_frame(self, service, payload, packet_id):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        kernel.publish_packet(packet, root=self.mesh, now_ns=self.CLOCK_NS)

    def ledger_receipts(self):
        return (self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1"),
                self.receipts("STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1"))

    def test_a_capability_frame_at_4096_is_consumed_at_4096_without_the_clock(self):
        self.publish(ADDRESS, diagnostic("probe-g4-ingest"), "probe-g4-ingest")
        frame_path, = (self.mesh / "frames.d").glob("*.json")
        clocks = [self.unavailable_clock(module) for module in _kernel_instances(ingress, capability, kernel)]
        result = kernel.ingest_frame(ROOT, json.loads(frame_path.read_text(encoding="utf-8")),
                                     mesh_root=self.mesh)
        self.assertEqual(result["status"], "CONSUMED")
        self.assertEqual(result["execution_result"]["application_result"]["receiving_operation_result"]["disposition"], "ALLOW")
        repository, organization = self.ledger_receipts()
        self.assertEqual((len(repository), len(organization)), (1, 1))
        for receipt in repository + organization:
            self.assertEqual(receipt["hb_reference"]["epoch"], 4096)
            self.assertIs(receipt["hb_reference"]["derived_from_clock"], False)
        self.assertEqual(sum(clock.now.call_count for clock in clocks), 0)

    def test_the_cycle_carries_a_capability_frames_epoch_to_the_operation(self):
        self.publish(ADDRESS, diagnostic("probe-g4-cycle"), "probe-g4-cycle")
        cycle = self.cycle()
        clock = self.unavailable_clock(cycle, cycle.K, cycle.GW)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        self.assertFalse(clock.now.called)
        record = json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())
        self.assertEqual((record["frames_consumed"], record["frames_refused"]), (1, 0))
        repository, organization = self.ledger_receipts()
        self.assertEqual((len(repository), len(organization)), (1, 1))
        for receipt in repository + organization:
            self.assertEqual(receipt["hb_reference"]["epoch"], 4096)
            self.assertIs(receipt["hb_reference"]["derived_from_clock"], False)

    def test_a_refused_frame_is_quarantined_and_does_not_hold_back_the_next_cycle(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        self.publish(services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": "valid"}, "probe-batch-valid")
        # A legacy CLOCK frame is consumed without an epoch (08:10Z); an unmarked one is refused.
        self.clock_frame(services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": "clock"}, "probe-batch-clock")
        unmarked = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=services["BOUNDARY_LOCAL_DIAGNOSTIC"],
            payload={"probe": "unmarked"}, transition_reference="intr:transition:probe-batch-unmarked",
            authority_effect="NONE", packet_id="probe-batch-unmarked")
        supplied = kernel.carrier_frame(unmarked, epoch=4096)
        kernel.publish_frame(_forged_frame({**supplied, "heartbeat_reference": {
            key: value for key, value in supplied["heartbeat_reference"].items()
            if key != "derived_from_clock"}}), root=self.mesh)
        cycle = self.cycle()
        clock = self.unavailable_clock(cycle, cycle.K, cycle.GW)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        record = json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())
        self.assertEqual((record["frames_seen"], record["frames_consumed"], record["frames_refused"]),
                         (3, 2, 1))
        markers = [json.loads(path.read_text(encoding="utf-8"))
                   for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json")]
        quarantined, = [marker for marker in markers if marker["status"] == "REFUSED"]
        self.assertEqual(quarantined["packet_id"], "probe-batch-unmarked")
        refusal = quarantined["refusal"]
        self.assertEqual(refusal["failure_code"], "FRAME_REFUSED_QUARANTINED")
        self.assertEqual(refusal["refused_failure_code"], "HB_EPOCH_PROVENANCE_UNMARKED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        consumed, = [marker for marker in markers if marker["packet_id"] == "probe-batch-clock"]
        self.assertEqual(consumed["status"], "CONSUMED")

        self.publish(services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": "next"}, "probe-batch-next", epoch=4097)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4097"]), 0)
        record = json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())
        self.assertEqual((record["frames_seen"], record["frames_consumed"], record["frames_refused"]),
                         (1, 1, 0))
        self.assertFalse(clock.now.called)
        for path in [self.copy / "resident-runtime/federation/latest-cycle.json",
                     *(self.copy / "resident-runtime/federation/seen.d").glob("*.json")]:
            text = path.read_text(encoding="utf-8")
            # No clock sample is written as a value; the refusal's detail may name the field.
            self.assertNotIn('"sampled_unix_ns":', text)
            self.assertNotIn(str(self.CLOCK_NS), text)

    def run_publisher(self, *argv):
        return subprocess.run(
            ["python3", str(self.copy / "resident-runtime/ecosystem_control.py"), "send-message",
             "--subject", "probe", "--body-json", "{}", *argv],
            capture_output=True, text=True, check=False, env=dict(os.environ))

    def test_the_publisher_refuses_an_absent_or_invalid_epoch_and_publishes_nothing(self):
        for argv, failure_code in (([], "HB_EPOCH_NOT_SUPPLIED"),
                                   (["--hb-epoch", ""], "HB_EPOCH_INVALID"),
                                   (["--hb-epoch", "+33"], "HB_EPOCH_INVALID"),
                                   (["--hb-epoch", "\uff13\uff13"], "HB_EPOCH_INVALID")):
            run = self.run_publisher(*argv)
            self.assertEqual(run.returncode, 1, (argv, run.stderr))
            self.assertNotIn("Traceback", run.stderr)
            refusal = json.loads(run.stdout)
            self.assertEqual(refusal["failure_code"], failure_code, argv)
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, refusal)
        self.assertFalse((self.mesh / "frames.d").exists())

    def test_the_publisher_stamps_every_frame_from_the_supplied_epoch(self):
        run = self.run_publisher("--hb-epoch", "4096")
        self.assertEqual(run.returncode, 0, run.stderr)
        frames = [json.loads(path.read_text(encoding="utf-8"))
                  for path in (self.mesh / "frames.d").glob("*.json")]
        self.assertTrue(frames)
        for frame in frames:
            self.assertEqual(frame["heartbeat_reference"]["epoch"], 4096)
            self.assertIs(frame["heartbeat_reference"]["derived_from_clock"], False)
            self.assertNotIn("sampled_unix_ns", frame["heartbeat_reference"])


class CarriedProvenanceTests(CopiedRepository):
    """B-P36k / G5: a CARRIED claim is verified against the organization head, never stripped.

    A carrier reference that names `source` or `head_receipt_sha` is admitted
    only when it is the current verified organization ledger head at that
    epoch. Otherwise ingest refuses six-field CARRIED_PROVENANCE_UNVERIFIED and
    writes nothing; within a cycle the only write is the B-P36j quarantine.
    """

    FORGED = "sha256:" + "f" * 64

    def snapshot(self):
        files = set()
        for root in (self.copy, *(Path(os.environ[name]) for name in self.LEDGER_ROOTS)):
            if root.exists():
                files.update(str(path) for path in root.rglob("*")
                             if path.is_file() and "__pycache__" not in path.parts)
        return files

    def carried_frame(self, service, payload, packet_id, *, epoch=4096, **claim):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        return _forged_frame(kernel.carrier_frame(packet, epoch=epoch), **claim)

    def routes(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        return (
            (services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": "carried"}),
            (services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-carried-work",
                                                  "message_class": "ecosystem.work.request",
                                                  "subject": "probe", "body": {}}),
            (services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-carried-monitor",
                                                  "message_class": "ecosystem.monitor.request",
                                                  "subject": "probe", "body": {}}),
            (ADDRESS, diagnostic("probe-carried-capability")),
        )

    def organization_head(self):
        received = ingress.receive(diagnostic("probe-head"), registry=REGISTRY,
                                   packet_id="probe-head", hb_epoch=4096)
        self.assertEqual(received["disposition"], "ALLOW", received.get("detail"))
        head = json.loads((Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / "HEAD.json").read_text())
        return head["receipt_sha256"]

    def assert_unverified(self, frame):
        before = self.snapshot()
        with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
            kernel.ingest_frame(self.copy, frame, mesh_root=self.mesh)
        refusal = refused.exception.refusal
        self.assertEqual(refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        self.assertEqual(self.snapshot(), before)
        return refusal

    def test_a_forged_head_sha_is_refused_on_every_route_and_writes_nothing(self):
        for index, (service, payload) in enumerate(self.routes()):
            self.assert_unverified(self.carried_frame(
                service, payload, "probe-forged-" + str(index),
                source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=self.FORGED))
        self.assertFalse((self.copy / "resident-runtime/control/inbox").exists()
                         and any((self.copy / "resident-runtime/control/inbox").iterdir()))

    def test_a_claim_is_refused_when_it_is_not_the_current_verified_head(self):
        head = self.organization_head()
        service = self.routes()[0][0]
        for index, claim in enumerate((
                {"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": self.FORGED},
                {"source": "SOMEWHERE_ELSE", "head_receipt_sha": head},
                {"head_receipt_sha": head},
                {"source": "ORGANIZATION_LEDGER_HEAD"})):
            self.assert_unverified(self.carried_frame(service, {"probe": index},
                                                      "probe-claim-" + str(index), **claim))
        # The current head, at an epoch that is not the head's own.
        self.assert_unverified(self.carried_frame(
            service, {"probe": "epoch"}, "probe-claim-epoch", epoch=4097,
            source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=head))

    def test_a_claim_of_the_current_verified_head_is_admitted(self):
        head = self.organization_head()
        frame = self.carried_frame(self.routes()[0][0], {"probe": "verified"}, "probe-verified",
                                   source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=head)
        result = kernel.ingest_frame(self.copy, frame, mesh_root=self.mesh)
        self.assertEqual(result["status"], "CONSUMED")
        self.assertEqual(result["carried_hb_epoch"], 4096)

    def test_a_forged_claim_in_a_cycle_is_quarantined_and_nothing_else_is_written(self):
        for index, (service, payload) in enumerate(self.routes()):
            frame = self.carried_frame(service, payload, "probe-cycle-forged-" + str(index),
                                       source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=self.FORGED)
            kernel.publish_frame(frame, root=self.mesh)
        before = self.snapshot()
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_carried_claim", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        written = self.snapshot() - before
        seen = self.copy / "resident-runtime/federation/seen.d"
        latest = self.copy / "resident-runtime/federation/latest-cycle.json"
        self.assertEqual({Path(path).parent for path in written - {str(latest)}}, {seen})
        markers = [json.loads(path.read_text(encoding="utf-8")) for path in seen.glob("*.json")]
        self.assertEqual(len(markers), len(self.routes()))
        for marker in markers:
            self.assertEqual(marker["status"], "REFUSED")
            self.assertEqual(marker["refusal"]["failure_code"], "FRAME_REFUSED_QUARANTINED")
            self.assertEqual(marker["refusal"]["refused_failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        record = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual((record["frames_consumed"], record["frames_refused"]), (0, len(self.routes())))
        self.assertEqual(self.ledger_files(), [])

    def ledger_files(self):
        found = []
        for name in self.LEDGER_ROOTS:
            root = Path(os.environ[name])
            if root.exists():
                found.extend(path for path in root.rglob("*") if path.is_file())
        return found


class SharedValidatorPinTests(unittest.TestCase):
    """The #3282 FINAL supplied_epoch_failure, pinned byte for byte by its source digest."""

    def test_the_shared_rule_is_the_pinned_final_text(self):
        digest = hashlib.sha256(inspect.getsource(kernel.supplied_epoch_failure).encode()).hexdigest()
        self.assertEqual(digest, kernel.SHARED_VALIDATOR_SHA256)
        self.assertEqual(kernel.SHARED_VALIDATOR_SHA256,
                         "ad8ff52936d5bcd9a2ad6caceb2d9a637a099518989b34bbb3370301c7a4cce2")

    def test_every_loaded_copy_of_the_rule_is_the_pinned_text(self):
        copies = _kernel_instances(ingress, egress, capability, kernel)
        self.assertGreaterEqual(len(copies), 4)
        for copy in copies:
            self.assertEqual(hashlib.sha256(inspect.getsource(copy.supplied_epoch_failure).encode())
                             .hexdigest(), kernel.SHARED_VALIDATOR_SHA256)

    def test_the_final_rule_on_carrier_references(self):
        rule = kernel.supplied_epoch_failure
        self.assertEqual(rule(4096, {"sampled_unix_ns": 1})[0], "HB_EPOCH_INVALID")
        self.assertEqual(rule(4096, {"source": "ORGANIZATION_LEDGER_HEAD",
                                     "head_receipt_sha": "sha256:" + "f" * 64})[0],
                         "HB_EPOCH_PROVENANCE_UNMARKED")
        self.assertEqual(rule(4096, {"derived_from_clock": False, "sampled_unix_ns": 1})[0],
                         "HB_EPOCH_INVALID")
        self.assertIsNone(rule(4096, {"derived_from_clock": False, "source": "X"}))


class NarrowClockFlagAndEpochConflictTests(CopiedRepository):
    """NARROW S1 (07:48Z), B-P36l (07:52Z) and G8 on GCAT#15.

    A clock-flagged frame is consumed and lends no epoch; a route that needs
    one refuses NOT_SUPPLIED. A supplied epoch that differs from the frame's is
    HB_EPOCH_CONFLICT and nothing is written. The gateway acknowledgement is
    stamped from the cycle epoch, never the clock.
    """

    def frame(self, service, payload, packet_id, *, epoch=4096, **reference):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        frame = kernel.carrier_frame(packet, epoch=epoch)
        return _forged_frame(frame, **reference) if reference else frame

    def services(self):
        return {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}

    def snapshot(self):
        files = set()
        for root in (self.copy, *(Path(os.environ[name]) for name in self.LEDGER_ROOTS)):
            if root.exists():
                files.update(str(path) for path in root.rglob("*")
                             if path.is_file() and "__pycache__" not in path.parts)
        return files

    def unavailable_clock(self, *modules):
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(side_effect=RuntimeError("clock unavailable"))
        for module in modules:
            if getattr(module, "datetime", None) is datetime:
                patcher = mock.patch.object(module, "datetime", clock)
                patcher.start()
                self.addCleanup(patcher.stop)
        return clock

    def test_a_clock_flagged_frame_is_consumed_and_its_epoch_needing_routes_refuse(self):
        clock = self.unavailable_clock(*_kernel_instances(ingress, capability, kernel))
        services = self.services()
        diagnostic_frame = self.frame(services["BOUNDARY_LOCAL_DIAGNOSTIC"],
                                      {"communication_id": "probe-flagged-communication",
                                       "message_class": "ecosystem.communication",
                                       "subject": "probe", "body": {}},
                                      "probe-flagged-communication", derived_from_clock=True)
        consumed = kernel.ingest_frame(self.copy, diagnostic_frame, mesh_root=self.mesh)
        self.assertEqual((consumed["status"], consumed["hb_epoch"]), ("CONSUMED", None))
        for service, payload, packet_id in (
                (services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-flagged-monitor",
                                                      "message_class": "ecosystem.monitor.request",
                                                      "subject": "probe", "body": {}},
                 "probe-flagged-monitor"),
                (ADDRESS, diagnostic("probe-flagged-capability"), "probe-flagged-capability")):
            with self.assertRaises(ValueError) as refused:
                kernel.ingest_frame(self.copy, self.frame(service, payload, packet_id,
                                                          derived_from_clock=True),
                                    mesh_root=self.mesh)
            self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        self.assertEqual(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                       "stegverse.repo-transition-receipt/v1"), [])
        # Its response needs an epoch: with none supplied it is refused, never clock-stamped.
        kernel.publish_frame(diagnostic_frame, root=self.mesh)
        results = kernel.consume_and_respond(self.copy, mesh_root=self.mesh)
        (item,) = results
        self.assertEqual(item["result"]["status"], "CONSUMED")
        self.assertIsNone(item["response_publication"])
        self.assertEqual(item["result"]["response_refusal"]["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        marker = json.loads(Path(item["seen_marker"]).read_text(encoding="utf-8"))
        self.assertEqual(marker["response_refusal"]["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        self.assertEqual(clock.now.call_count, 0)

    def test_a_legacy_clock_frame_is_consumed_and_its_epoch_needing_routes_refuse(self):
        services = self.services()
        clocked = []
        for service, payload, packet_id in (
                (services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": "legacy"}, "probe-legacy-diagnostic"),
                (services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-legacy-monitor",
                                                      "message_class": "ecosystem.monitor.request",
                                                      "subject": "probe", "body": {}}, "probe-legacy-monitor"),
                (ADDRESS, diagnostic("probe-legacy-capability"), "probe-legacy-capability")):
            packet = kernel.build_packet(
                origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
                destination_org=THIS, destination_service=service, payload=payload,
                transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
                packet_id=packet_id)
            clocked.append(kernel.carrier_frame(packet, now_ns=self.CLOCK_NS))
        self.assertNotIn("derived_from_clock", clocked[0]["heartbeat_reference"])
        clock = self.unavailable_clock(*_kernel_instances(ingress, capability, kernel))
        consumed = kernel.ingest_frame(self.copy, clocked[0], mesh_root=self.mesh)
        self.assertEqual((consumed["status"], consumed["hb_epoch"]), ("CONSUMED", None))
        for frame in clocked[1:]:
            with self.assertRaises(ValueError) as refused:
                kernel.ingest_frame(self.copy, frame, mesh_root=self.mesh)
            self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        self.assertEqual(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                       "stegverse.repo-transition-receipt/v1"), [])
        self.assertEqual(clock.now.call_count, 0)

    def test_a_supplied_epoch_answers_a_clock_flagged_frame(self):
        services = self.services()
        frame = self.frame(services["BOUNDARY_LOCAL_DIAGNOSTIC"],
                           {"communication_id": "probe-flagged-answered",
                            "message_class": "ecosystem.communication", "subject": "probe", "body": {}},
                           "probe-flagged-answered", derived_from_clock=True)
        kernel.publish_frame(frame, root=self.mesh)
        (item,) = kernel.consume_and_respond(self.copy, mesh_root=self.mesh, hb_epoch="4096")
        reference = item["response_publication"]["frame"]["heartbeat_reference"]
        self.assertEqual((reference["epoch"], reference["derived_from_clock"]), (4096, False))

    def test_an_invalid_supplied_epoch_is_invalid_whatever_the_frame_carries(self):
        frame = self.frame(self.services()["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": 1}, "probe-invalid")
        before = self.snapshot()
        for value in ("+33", "", "31"):
            with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
                kernel.ingest_frame(self.copy, frame, mesh_root=self.mesh, hb_epoch=value)
            self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_INVALID")
        self.assertEqual(self.snapshot(), before)

    def test_a_supplied_epoch_that_differs_from_the_frames_is_a_conflict(self):
        services = self.services()
        before = self.snapshot()
        for service, payload in ((services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": 1}),
                                 (services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-conflict-work",
                                                                      "message_class": "ecosystem.work.request",
                                                                      "subject": "probe", "body": {}}),
                                 (ADDRESS, diagnostic("probe-conflict-capability"))):
            with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
                kernel.ingest_frame(self.copy, self.frame(service, payload, "probe-conflict", epoch=77),
                                    mesh_root=self.mesh, hb_epoch="4096")
            refusal = refused.exception.refusal
            self.assertEqual(refusal["failure_code"], "HB_EPOCH_CONFLICT")
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, refusal)
        self.assertEqual(self.snapshot(), before)
        # In a cycle the conflicting frame is quarantined and nothing is stamped at either epoch.
        self.publish(ADDRESS, diagnostic("probe-conflict-cycle"), "probe-conflict-cycle", epoch=77)
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_conflict", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        marker, = [json.loads(path.read_text(encoding="utf-8"))
                   for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json")]
        self.assertEqual(marker["refusal"]["refused_failure_code"], "HB_EPOCH_CONFLICT")
        self.assertEqual(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                       "stegverse.repo-transition-receipt/v1"), [])
        self.assertFalse(any(":response:" in json.loads(path.read_text(encoding="utf-8"))["packet_id"]
                             for path in (self.mesh / "frames.d").glob("*.json")))

    def gateway(self, fetched):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_probe", self.copy / "resident-runtime/federation_gateway_transport.py"))
        module.__spec__.loader.exec_module(module)
        sent = []
        patchers = [mock.patch.object(module, "fetch_frame", return_value=fetched),
                    mock.patch.object(module, "submit_frame", side_effect=lambda frame: sent.append(frame) or {}),
                    mock.patch.object(module, "_json_request",
                                      side_effect=lambda method, path, body=None, headers=None:
                                      sent.append(body) or {"state": (body or {}).get("state")})]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        return module, sent

    def test_the_gateway_acknowledgement_is_stamped_from_the_cycle_epoch(self):
        services = self.services()
        frame = self.frame(services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-gateway",
                                                                "message_class": "ecosystem.monitor.request",
                                                                "subject": "probe", "body": {}},
                           "probe-gateway")
        gateway, sent = self.gateway({"state": "FRAME_AVAILABLE", "frame": frame})
        clock = self.unavailable_clock(gateway, gateway.K)
        result = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
        self.assertEqual((result["state"], result["responses_emitted"]), ("CONSUMED", 1))
        response, ack = sent
        self.assertEqual(response["heartbeat_reference"]["epoch"], 4096)
        self.assertNotIn("observed_at", ack)
        self.assertEqual((ack["hb_reference"]["epoch"], ack["hb_reference"]["derived_from_clock"]), (4096, False))
        self.assertFalse(clock.now.called)

    def test_a_refused_gateway_frame_is_acknowledged_terminal_without_the_clock(self):
        frame = self.frame(self.services()["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": 1}, "probe-gateway-refused",
                           sampled_unix_ns=self.CLOCK_NS)
        gateway, sent = self.gateway({"state": "FRAME_AVAILABLE", "frame": frame})
        result = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
        self.assertEqual(result["state"], "REFUSED")
        self.assertEqual(result["refusal"]["failure_code"], "FRAME_REFUSED_QUARANTINED")
        ack, = sent
        self.assertEqual(ack["state"], "BLOCKED")
        self.assertEqual(ack["refusal"]["refused_failure_code"], "HB_EPOCH_INVALID")
        self.assertEqual(ack["hb_reference"]["epoch"], 4096)
        self.assertNotIn(str(self.CLOCK_NS), json.dumps(ack))

    def test_the_gateway_cycle_refuses_without_an_epoch_before_fetching(self):
        gateway, sent = self.gateway({"state": "NO_FRAME"})
        with self.assertRaises(gateway.K.SuppliedEpochRefused) as refused:
            gateway.resident_gateway_cycle(self.copy)
        self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_NOT_SUPPLIED")
        gateway.fetch_frame.assert_not_called()
        self.assertEqual(sent, [])


class CarriedProvenanceDownstreamTests(CopiedRepository):
    """B-P36m: a verified CARRIED claim reaches every receipt and status made in response.

    Once ingest verifies a frame's claim against the current organization head,
    the repository and organization receipts and the monitor status keep
    `source`, `head_receipt_sha` and `derived_from_clock` false, so they read
    as CARRIED. A writer handed a provenance re-verifies it (07:08Z) and
    refuses CARRIED_PROVENANCE_UNVERIFIED, writing nothing.
    """

    FORGED = CarriedProvenanceTests.FORGED

    def head(self):
        received = ingress.receive(diagnostic("probe-downstream-head"), registry=REGISTRY,
                                   packet_id="probe-downstream-head", hb_epoch=4096)
        self.assertEqual(received["disposition"], "ALLOW", received.get("detail"))
        return json.loads((Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / "HEAD.json").read_text())["receipt_sha256"]

    def claimed(self, service, payload, packet_id, head):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        return _forged_frame(kernel.carrier_frame(packet, epoch=4096),
                             source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=head)

    def assert_carried(self, reference, head):
        self.assertEqual(reference["epoch"], 4096)
        self.assertIs(reference["derived_from_clock"], False)
        self.assertEqual(reference["source"], "ORGANIZATION_LEDGER_HEAD")
        self.assertEqual(reference["head_receipt_sha"], head)
        self.assertNotIn("sampled_unix_ns", reference)

    def test_receipts_made_for_a_verified_carried_frame_read_as_carried(self):
        head = self.head()
        frame = self.claimed(ADDRESS, diagnostic("probe-downstream-capability"),
                             "probe-downstream-capability", head)
        result = kernel.ingest_frame(self.copy, frame, mesh_root=self.mesh)
        self.assertEqual(result["status"], "CONSUMED")
        operation = result["execution_result"]["application_result"]["receiving_operation_result"]
        repository_sha = operation["repository_receipt_sha256"]
        organization_sha = operation["organization_receipt_sha256"]
        repository, = [receipt for receipt in self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
            if receipt["receipt_sha256"] == repository_sha]
        organization, = [receipt for receipt in self.receipts(
            "STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1")
            if receipt["receipt_sha256"] == organization_sha]
        self.assert_carried(repository["hb_reference"], head)
        self.assert_carried(organization["hb_reference"], head)

    def test_the_monitor_status_for_a_verified_carried_frame_reads_as_carried(self):
        head = self.head()
        control = next(row["service_id"] for row in REGISTRY["services"]
                       if row["boundary_role"] == "BOUNDARY_LOCAL_CONTROL")
        frame = self.claimed(control, {"communication_id": "probe-downstream-monitor",
                                       "message_class": "ecosystem.monitor.request",
                                       "subject": "probe", "body": {}},
                             "probe-downstream-monitor", head)
        result = kernel.ingest_frame(self.copy, frame, mesh_root=self.mesh)
        self.assert_carried(result["execution_result"]["application_result"]["monitor_status"]
                            ["heartbeat_reference"], head)

    def test_a_writer_handed_an_unverified_provenance_refuses_and_writes_nothing(self):
        self.head()
        before = sorted(str(path) for name in self.LEDGER_ROOTS
                        for path in Path(os.environ[name]).rglob("*") if path.is_file())
        emit = ingress.ledger.emit
        forged = {"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": self.FORGED}
        with self.assertRaises(ValueError) as refused:
            emit.append("probe:forged", "PROBE", kernel.sha({"p": 1}), kernel.sha({"p": 2}), {},
                        "NONE", hb_epoch=4096, hb_provenance=forged)
        self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        repository, = [receipt for receipt in self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")]
        with self.assertRaises(ValueError) as refused:
            ingress.ledger.aggregate.append(repository, "REPO_STATE_PROPAGATION", "FROM_HEAD",
                                            kernel.sha({"p": 3}), {}, "NONE", hb_epoch=4096,
                                            hb_provenance=forged)
        self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refused.exception.refusal)
        after = sorted(str(path) for name in self.LEDGER_ROOTS
                       for path in Path(os.environ[name]).rglob("*") if path.is_file())
        self.assertEqual(after, before)


class ManifestEpochBindingTests(unittest.TestCase):
    """B-P36n: every epoch-requiring entrypoint the activation manifest names declares a binding."""

    MANIFEST = ROOT / "resident-runtime/activation-manifest.json"
    SOURCES = {"dispatch_input", "CARRIED:ORGANIZATION_LEDGER_HEAD"}

    def declared(self):
        manifest = json.loads(self.MANIFEST.read_text(encoding="utf-8"))
        paths = {value for value in manifest.values()
                 if isinstance(value, str) and value.endswith(".py") and (ROOT / value).is_file()}
        return manifest, paths

    @staticmethod
    def requires_epoch(path):
        return '"--hb-epoch"' in (ROOT / path).read_text(encoding="utf-8")

    def test_every_epoch_requiring_entrypoint_has_a_binding(self):
        manifest, paths = self.declared()
        bindings = manifest.get("epoch_bindings", {})
        requiring = {path for path in paths if self.requires_epoch(path)}
        self.assertTrue({"resident-runtime/federation_cycle.py",
                         "resident-runtime/ecosystem_control.py"} <= requiring)
        self.assertEqual(manifest["resident_cycle_entrypoint"], "resident-runtime/federation_cycle.py")
        for path in requiring:
            self.assertIn(path, bindings, path + " requires an epoch and declares no binding")
            binding = bindings[path]["hb_epoch"]
            self.assertIn(binding["from"], self.SOURCES)
            source = (ROOT / path).read_text(encoding="utf-8")
            self.assertIn('"' + binding["argument"] + '"', source)
            if "environment" in binding:
                self.assertIn('"' + binding["environment"] + '"', source)
            self.assertIs(bindings[path]["never_derived_from_clock"], True)

    def test_a_binding_or_an_exemption_names_only_declared_entrypoints(self):
        manifest, paths = self.declared()
        for path in manifest.get("epoch_bindings", {}):
            self.assertIn(path, paths)
            self.assertTrue(self.requires_epoch(path))
        for path in manifest.get("epoch_free_entrypoints", {}):
            self.assertIn(path, paths)
            self.assertFalse(self.requires_epoch(path), path)


class MalformedClockFrameTests(CopiedRepository):
    """F-S1a: a CLOCK frame's epoch field must be well formed; otherwise six fields and quarantine."""

    def clock_frame(self, packet_id, **reference):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS,
            destination_service=next(row["service_id"] for row in REGISTRY["services"]
                                     if row["boundary_role"] == "BOUNDARY_LOCAL_DIAGNOSTIC"),
            payload={"probe": packet_id}, transition_reference="intr:transition:" + packet_id,
            authority_effect="NONE", packet_id=packet_id)
        frame = kernel.carrier_frame(packet, epoch=4096)
        body = dict(frame)
        body.pop("frame_sha256")
        body["heartbeat_reference"] = {"derived_from_clock": True, **reference}
        return {**body, "frame_sha256": kernel.sha(body)}

    CASES = (({"epoch": "abc"}, "HB_EPOCH_INVALID"),
             ({}, "HB_EPOCH_NOT_SUPPLIED"),
             ({"epoch": 5}, "HB_EPOCH_INVALID"),
             ({"sampled_unix_ns": 1}, "HB_EPOCH_NOT_SUPPLIED"))

    def test_a_malformed_clock_epoch_is_refused_six_field(self):
        for index, (reference, failure_code) in enumerate(self.CASES):
            with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
                kernel.ingest_frame(self.copy, self.clock_frame("probe-malformed-" + str(index), **reference),
                                    mesh_root=self.mesh)
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, refused.exception.refusal)
            self.assertEqual(refused.exception.refusal["failure_code"], failure_code, reference)
        # The legacy bare sample with a malformed epoch is CLOCK too, and refused the same way.
        legacy = self.clock_frame("probe-malformed-legacy")
        body = dict(legacy)
        body.pop("frame_sha256")
        body["heartbeat_reference"] = {"epoch": "abc", "sampled_unix_ns": 1}
        with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
            kernel.ingest_frame(self.copy, {**body, "frame_sha256": kernel.sha(body)}, mesh_root=self.mesh)
        self.assertEqual(refused.exception.refusal["failure_code"], "HB_EPOCH_INVALID")

    def test_a_cycle_quarantines_malformed_clock_frames_and_does_not_raise(self):
        for index, (reference, _failure_code) in enumerate(self.CASES):
            kernel.publish_frame(self.clock_frame("probe-cycle-malformed-" + str(index), **reference),
                                 root=self.mesh)
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_malformed", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        markers = {json.loads(path.read_text(encoding="utf-8"))["packet_id"]:
                   json.loads(path.read_text(encoding="utf-8"))
                   for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json")}
        for index, (_reference, failure_code) in enumerate(self.CASES):
            marker = markers["probe-cycle-malformed-" + str(index)]
            self.assertEqual(marker["status"], "REFUSED")
            self.assertEqual(marker["refusal"]["failure_code"], "FRAME_REFUSED_QUARANTINED")
            self.assertEqual(marker["refusal"]["refused_failure_code"], failure_code)
