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
import importlib.machinery
import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
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


class AnyFrameFailureIsTerminalTests(CopiedRepository):
    """B-P36o: any error ingesting one frame of a cycle is that frame's terminal refusal."""

    def packet(self, service, payload, packet_id):
        return kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)

    def diagnostic_frame(self, packet_id):
        service = next(row["service_id"] for row in REGISTRY["services"]
                       if row["boundary_role"] == "BOUNDARY_LOCAL_DIAGNOSTIC")
        return kernel.carrier_frame(self.packet(service, {"probe": packet_id}, packet_id), epoch=4096)

    @staticmethod
    def rebound(frame, **fields):
        body = dict(frame)
        body.pop("frame_sha256")
        body.update(fields)
        return {**body, "frame_sha256": kernel.sha(body)}

    def bad_frames(self):
        generation = self.diagnostic_frame("probe-bad-generation")
        heartbeat = self.diagnostic_frame("probe-bad-heartbeat-id")
        frame_hash = self.diagnostic_frame("probe-bad-frame-hash")
        packet_hash = self.diagnostic_frame("probe-bad-packet-hash")
        epoch_value = self.diagnostic_frame("probe-bad-epoch-value")
        unknown = kernel.carrier_frame(self.packet("gcat-bcat-engine.no-such-service", {"probe": 1},
                                                   "probe-bad-adapter"), epoch=4096)
        return {
            "probe-bad-generation": (self.rebound(generation, heartbeat_reference={
                **generation["heartbeat_reference"], "generation": 4097}), "HB_REFERENCE_INVALID"),
            "probe-bad-heartbeat-id": (self.rebound(heartbeat, heartbeat_reference={
                **heartbeat["heartbeat_reference"], "heartbeat_id": "HB:4097"}), "HB_REFERENCE_INVALID"),
            "probe-bad-frame-hash": ({**frame_hash, "frame_sha256": "sha256:" + "0" * 64},
                                     "FRAME_INTEGRITY_INVALID"),
            "probe-bad-packet-hash": (self.rebound(packet_hash, packet_sha256="sha256:" + "0" * 64),
                                      "FRAME_INTEGRITY_INVALID"),
            "probe-bad-epoch-value": (self.rebound(epoch_value, heartbeat_reference={
                **epoch_value["heartbeat_reference"], "epoch": "abc"}), "HB_EPOCH_INVALID"),
            "probe-bad-adapter": (unknown, "FRAME_INGEST_FAILED"),
        }

    def test_a_reference_naming_another_epoch_is_refused_at_ingest(self):
        frame = self.diagnostic_frame("probe-direct-generation")
        with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
            kernel.ingest_frame(self.copy, self.rebound(frame, heartbeat_reference={
                **frame["heartbeat_reference"], "generation": 4097}), mesh_root=self.mesh)
        self.assertEqual(refused.exception.refusal["failure_code"], "HB_REFERENCE_INVALID")

    def test_a_mixed_batch_quarantines_each_bad_frame_and_ledgers_the_valid_one(self):
        bad = self.bad_frames()
        for frame, _code in bad.values():
            kernel.publish_frame(frame, root=self.mesh)
        (self.mesh / "frames.d" / "unreadable.json").write_text("{not json", encoding="utf-8")
        self.publish(ADDRESS, diagnostic("probe-batch-valid-capability"), "probe-batch-valid-capability")
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_b36o", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(side_effect=RuntimeError("clock unavailable"))
        for module in (cycle.K, kernel):
            patcher = mock.patch.object(module, "datetime", clock)
            patcher.start()
            self.addCleanup(patcher.stop)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        latest = self.copy / "resident-runtime/federation/latest-cycle.json"
        record = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual((record["frames_seen"], record["frames_consumed"], record["frames_refused"]),
                         (len(bad) + 2, 1, len(bad) + 1))
        markers = [json.loads(path.read_text(encoding="utf-8"))
                   for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json")]
        refused = {marker.get("packet_id"): marker for marker in markers if marker["status"] == "REFUSED"}
        for packet_id, (_frame, code) in bad.items():
            self.assertEqual(refused[packet_id]["refusal"]["failure_code"], "FRAME_REFUSED_QUARANTINED")
            self.assertEqual(refused[packet_id]["refusal"]["refused_failure_code"], code, packet_id)
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, refused[packet_id]["refusal"])
        self.assertEqual(refused[None]["refusal"]["refused_failure_code"], "FRAME_INGEST_FAILED")
        self.assertEqual(refused[None]["refusal"]["failed_predicate"], "JSONDecodeError")
        self.assertEqual(refused[None]["frame_name"], "unreadable.json")
        self.assertEqual(refused["probe-bad-adapter"]["refusal"]["failed_predicate"], "ValueError")
        # Only the valid frame reached the ledgers.
        repository = self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
        self.assertEqual([receipt["evidence"]["communication_id"] for receipt in repository],
                         ["probe-batch-valid-capability"])
        self.assertEqual(len(self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                                           "stegverse.organization-transition-receipt/v1")), 1)
        self.assertFalse(clock.now.called)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        record = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual(record["frames_seen"], 0)


def _workflow_jobs(text):
    """{job name: its block of lines} for a workflow file, read as text (no YAML dependency)."""
    lines = text.splitlines()
    start = next(index for index, line in enumerate(lines) if line.rstrip() == "jobs:")
    jobs, name = {}, None
    for line in lines[start + 1:]:
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if header:
            name = header.group(1)
            jobs[name] = []
        elif name is not None:
            jobs[name].append(line)
    return {key: "\n".join(value) for key, value in jobs.items()}


def _workflow_triggers(text):
    lines = text.splitlines()
    start = next(index for index, line in enumerate(lines) if line.rstrip() == "on:")
    triggers = []
    for line in lines[start + 1:]:
        if line and not line.startswith(" "):
            break
        match = re.match(r"^  ([A-Za-z_]+):", line)
        if match:
            triggers.append(match.group(1))
    return triggers


def _run_blocks(job):
    """The shell scripts of a job's `run: |` steps, dedented, in order."""
    lines, blocks, index = job.splitlines(), [], 0
    while index < len(lines):
        match = re.match(r"^(\s*)run: \|\s*$", lines[index])
        if match:
            indent, body, index = len(match.group(1)), [], index + 1
            while index < len(lines) and (not lines[index].strip()
                                          or len(lines[index]) - len(lines[index].lstrip()) > indent):
                body.append(lines[index])
                index += 1
            blocks.append(textwrap.dedent("\n".join(body)))
            continue
        index += 1
    return blocks


def _epoch_requiring_scripts():
    return {str(path.relative_to(ROOT)) for path in ROOT.rglob("*.py")
            if "tests" not in path.parts and ".git" not in path.parts
            and '"--hb-epoch"' in path.read_text(encoding="utf-8")}


class InTreeDispatcherTests(CopiedRepository):
    """MANIFEST_DISPATCHER_NOT_IN_TREE (08:32Z): the manifest's dispatcher is a workflow in this tree."""

    MANIFEST = ROOT / "resident-runtime/activation-manifest.json"

    def bindings(self):
        return json.loads(self.MANIFEST.read_text(encoding="utf-8"))["epoch_bindings"]

    def test_every_binding_names_an_in_tree_dispatcher_that_invokes_it_with_the_epoch(self):
        for entrypoint, binding in self.bindings().items():
            dispatcher = ROOT / binding["dispatcher"]
            self.assertTrue(dispatcher.is_file(), binding["dispatcher"])
            self.assertEqual(dispatcher.parent, ROOT / ".github/workflows")
            self.assertEqual(binding["dispatcher_authority_effect"], "NONE")
            text = dispatcher.read_text(encoding="utf-8")
            self.assertEqual(_workflow_triggers(text), ["workflow_dispatch"])
            self.assertRegex(text, r"hb_epoch:\n\s+description: [^\n]+\n\s+required: true")
            self.assertNotIn("default:", text.split("jobs:")[0])
            invocation = "python " + entrypoint + " "
            invoking = [job for job in _workflow_jobs(text).values() if invocation in job]
            self.assertTrue(invoking, entrypoint + " is not invoked by " + binding["dispatcher"])
            for job in invoking:
                gate, call = job.index("writer_epoch_refusal"), job.index(invocation)
                self.assertLess(gate, call)
                self.assertIn(binding["hb_epoch"]["argument"] + ' "$HB_EPOCH"', job[call:].split("\n")[0])

    def run_dispatcher(self, hb_epoch):
        dispatcher = ROOT / next(iter(self.bindings().values()))["dispatcher"]
        job, = _workflow_jobs(dispatcher.read_text(encoding="utf-8")).values()
        environment = {**os.environ, "HB_EPOCH": hb_epoch,
                       "STEGVERSE_ORG_FEDERATION_ROOT": str(self.mesh)}
        outputs = []
        for script in _run_blocks(job):
            run = subprocess.run(["bash", "-e", "-c", script], cwd=self.copy, env=environment,
                                 capture_output=True, text=True, check=False)
            outputs.append(run)
            if run.returncode != 0:
                break
        return outputs

    def test_the_dispatcher_passes_the_epoch_through(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        self.publish(services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-dispatcher",
                                                          "message_class": "ecosystem.monitor.request",
                                                          "subject": "probe", "body": {}}, "probe-dispatcher")
        gate, cycle, status = self.run_dispatcher("4096")
        for run in (gate, cycle, status):
            self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("DISPATCH_HB_EPOCH=SUPPLIED", gate.stdout)
        record = json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())
        self.assertEqual((record["heartbeat_reference"]["epoch"], record["frames_consumed"]), (4096, 1))
        self.assertIs(record["heartbeat_reference"]["derived_from_clock"], False)
        self.assertEqual(json.loads(status.stdout)["heartbeat_reference"]["epoch"], 4096)

    def test_the_dispatcher_refuses_an_empty_or_invalid_epoch_before_any_entrypoint(self):
        for value, failure_code in (("", "HB_EPOCH_NOT_SUPPLIED"), ("+33", "HB_EPOCH_INVALID")):
            runs = self.run_dispatcher(value)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0].returncode, 1)
            self.assertEqual(json.loads(runs[0].stdout)["failure_code"], failure_code)
        self.assertFalse((self.copy / "resident-runtime/federation/latest-cycle.json").exists())

    def test_no_trigger_but_a_gated_dispatch_invokes_an_epoch_requiring_entrypoint(self):
        scripts = _epoch_requiring_scripts()
        self.assertTrue({"resident-runtime/federation_cycle.py", "resident-runtime/ecosystem_control.py",
                         "resident-runtime/intr_destination_ingress.py"} <= scripts)
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            dispatch_only = _workflow_triggers(text) == ["workflow_dispatch"]
            for name, job in _workflow_jobs(text).items():
                for call in re.finditer(r"python3? (\S+\.py)", job):
                    if call.group(1) not in scripts:
                        continue
                    where = workflow.name + ":" + name + ":" + call.group(1)
                    self.assertTrue(dispatch_only or "if: github.event_name == 'workflow_dispatch'" in job, where)
                    self.assertIn("writer_epoch_refusal", job[:call.start()], where)
                    self.assertIn("--hb-epoch", job, where)


class ClockFrameCarriedClaimTests(CopiedRepository):
    """G5-R (VALIDATOR 6262338014): a CLOCK frame that asserts a CARRIED claim is refused, never consumed."""

    FORGED = "sha256:" + "f" * 64

    def frame(self, service, payload, packet_id, reference):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=service, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        frame = kernel.carrier_frame(packet, epoch=4096)
        body = dict(frame)
        body.pop("frame_sha256")
        body["heartbeat_reference"] = {"epoch": 4096, "source": "ORGANIZATION_LEDGER_HEAD",
                                       "head_receipt_sha": self.FORGED, **reference}
        return {**body, "frame_sha256": kernel.sha(body)}

    CLOCK_FORMS = ({"sampled_unix_ns": 1}, {"derived_from_clock": True},
                   {"derived_from_clock": True, "sampled_unix_ns": 1})

    def routes(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        return ((services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"probe": "carried-clock"}),
                (services["BOUNDARY_LOCAL_CONTROL"], {"communication_id": "probe-carried-clock-work",
                                                      "message_class": "ecosystem.work.request",
                                                      "subject": "probe", "body": {}}),
                (services["BOUNDARY_LOCAL_DIAGNOSTIC"], {"communication_id": "probe-carried-clock-comm",
                                                         "message_class": "ecosystem.communication",
                                                         "subject": "probe", "body": {}}))

    def written(self):
        files = set()
        for root in (self.copy, *(Path(os.environ[name]) for name in self.LEDGER_ROOTS)):
            if root.exists():
                files.update(str(path) for path in root.rglob("*")
                             if path.is_file() and "__pycache__" not in path.parts)
        return files

    def test_a_clock_frame_asserting_a_claim_is_refused_with_nothing_written(self):
        before = self.written()
        for form_index, form in enumerate(self.CLOCK_FORMS):
            for route_index, (service, payload) in enumerate(self.routes()):
                with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
                    kernel.ingest_frame(self.copy, self.frame(
                        service, payload, "probe-cc-" + str(form_index) + "-" + str(route_index), form),
                        mesh_root=self.mesh)
                self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
                for field in SuppliedEpochParsingTests.SIX_FIELDS:
                    self.assertIn(field, refused.exception.refusal)
        self.assertEqual(self.written(), before)

    def test_a_cycle_quarantines_them_and_writes_no_intake(self):
        for form_index, form in enumerate(self.CLOCK_FORMS):
            for route_index, (service, payload) in enumerate(self.routes()):
                kernel.publish_frame(self.frame(service, payload,
                                                "probe-cycle-cc-" + str(form_index) + "-" + str(route_index),
                                                form), root=self.mesh)
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_g5r", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        markers = [json.loads(path.read_text(encoding="utf-8"))
                   for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json")]
        self.assertEqual(len(markers), len(self.CLOCK_FORMS) * len(self.routes()))
        for marker in markers:
            self.assertEqual(marker["status"], "REFUSED")
            self.assertEqual(marker["refusal"]["refused_failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        inbox = self.copy / "resident-runtime/control/inbox"
        self.assertFalse(inbox.exists() and any(inbox.iterdir()))
        self.assertEqual([path for name in self.LEDGER_ROOTS
                          for path in Path(os.environ[name]).rglob("*") if path.is_file()], [])

    def test_collection_skips_a_frame_whose_digests_do_not_bind_its_packet(self):
        directory = self.mesh / "frames.d"
        directory.mkdir(parents=True)
        (directory / "unreadable.json").write_text("{not json", encoding="utf-8")
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=kernel.organization_slug(THIS) + ".org-control",
            payload={"communication_id": "probe-collect", "message_class": "ecosystem.communication.ack",
                     "body": {}}, transition_reference="probe", authority_effect="NONE",
            packet_id="probe-collect")
        frame = kernel.carrier_frame(packet, epoch=4096)
        kernel.publish_frame({**frame, "packet_sha256": "sha256:" + "0" * 64}, root=self.mesh)
        self.assertEqual(kernel.collect_ecosystem_responses(THIS, "probe-collect", mesh_root=self.mesh)
                         ["response_count"], 0)


class ScanGuardTests(CopiedRepository):
    """F-SCAN: a malformed frames.d file is guarded on its own and quarantined by name."""

    def test_malformed_files_do_not_block_the_cycle(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        self.publish(ADDRESS, diagnostic("probe-behind-malformed"), "probe-behind-malformed")
        directory = self.mesh / "frames.d"
        (directory / "0-malformed.json").write_text("{not json", encoding="utf-8")
        (directory / "1-not-an-object.json").write_text("[1, 2]", encoding="utf-8")
        (directory / "2-not-utf8.json").write_bytes(b"\xff\xfe\x00")
        (directory / "3-oversized.json").write_text(
            json.dumps({"pad": "x" * kernel.MAX_CARRIER_FRAME_BYTES}), encoding="utf-8")
        (directory / "4-read-error.json").mkdir()
        cycle = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_scan", self.copy / "resident-runtime/federation_cycle.py"))
        cycle.__spec__.loader.exec_module(cycle)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        latest = self.copy / "resident-runtime/federation/latest-cycle.json"
        record = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual((record["frames_seen"], record["frames_consumed"], record["frames_refused"]), (6, 1, 5))
        markers = {json.loads(path.read_text(encoding="utf-8"))["frame_name"]: json.loads(path.read_text(encoding="utf-8"))
                   for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json")}
        expected = {"0-malformed.json": "JSONDecodeError", "1-not-an-object.json": "ValueError",
                    "2-not-utf8.json": "UnicodeDecodeError", "3-oversized.json": "ValueError",
                    "4-read-error.json": "IsADirectoryError"}
        for name, exception_class in expected.items():
            self.assertEqual(markers[name]["status"], "REFUSED")
            self.assertEqual(markers[name]["refusal"]["failed_predicate"], exception_class, name)
            self.assertEqual(markers[name]["refusal"]["refused_failure_code"], "FRAME_INGEST_FAILED")
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, markers[name]["refusal"])
        self.assertIn("size_cap", markers["3-oversized.json"]["refusal"]["detail"])
        # The valid frame behind them was ledgered; the corrupt files wrote no ledger file.
        self.assertEqual(markers[next(name for name in markers if name not in expected)]["status"], "CONSUMED")
        repository = self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
        self.assertEqual([receipt["evidence"]["communication_id"] for receipt in repository],
                         ["probe-behind-malformed"])
        self.assertEqual(len(self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                                           "stegverse.organization-transition-receipt/v1")), 1)
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        self.assertEqual(json.loads(latest.read_text(encoding="utf-8"))["frames_seen"], 0)
        # A scan that is not a consuming cycle skips them without raising.
        self.assertEqual(kernel.scan_addressed_frames(THIS, root=self.mesh, seen=set())[0]["frame"]["packet_id"],
                         "probe-behind-malformed")


class TotalGuardAndDispatchIoTests(CopiedRepository):
    """F-TYPE and its IO addendum: the per-frame guard is total; this boundary's own IO failure defers."""

    def capability_frame(self, packet_id, epoch=4096):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=ADDRESS, payload=diagnostic(packet_id),
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        return kernel.carrier_frame(packet, epoch=epoch)

    @staticmethod
    def rebound(frame, **fields):
        body = dict(frame)
        body.pop("frame_sha256")
        body.update(fields)
        return {**body, "frame_sha256": kernel.sha(body)}

    def cycle(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_total", self.copy / "resident-runtime/federation_cycle.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def run_cycle(self, cycle):
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        return json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())

    def markers(self):
        return {marker.get("packet_id"): marker for marker in
                (json.loads(path.read_text(encoding="utf-8"))
                 for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json"))}

    def test_wrong_typed_fields_are_quarantined_and_the_valid_frames_are_ledgered(self):
        bad = {}
        for index, value in enumerate((123, None, ["x"], {"x": 1})):
            packet_id = "probe-type-" + str(index)
            bad[packet_id] = self.rebound(self.capability_frame(packet_id), packet_base64=value)
        bad["probe-type-hash"] = {**self.capability_frame("probe-type-hash"), "frame_sha256": 7}
        bad["probe-type-reference"] = self.rebound(self.capability_frame("probe-type-reference"),
                                                   heartbeat_reference="x")
        directory = self.mesh / "frames.d"
        directory.mkdir(parents=True, exist_ok=True)
        for packet_id, frame in bad.items():
            # Written directly: a wrong-typed field need not survive publish_frame.
            (directory / (packet_id + ".json")).write_text(json.dumps(frame), encoding="utf-8")
        for packet_id in ("probe-type-valid-a", "probe-type-valid-b"):
            kernel.publish_frame(self.capability_frame(packet_id), root=self.mesh)
        cycle = self.cycle()
        clock = mock.Mock(wraps=datetime)
        clock.now = mock.Mock(side_effect=RuntimeError("clock unavailable"))
        for module in (cycle.K, kernel):
            patcher = mock.patch.object(module, "datetime", clock)
            patcher.start()
            self.addCleanup(patcher.stop)
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_refused"]), (2, len(bad)))
        markers = self.markers()
        for packet_id in bad:
            self.assertEqual(markers[packet_id]["status"], "REFUSED", packet_id)
            for field in SuppliedEpochParsingTests.SIX_FIELDS:
                self.assertIn(field, markers[packet_id]["refusal"])
        for index in range(4):
            refusal = markers["probe-type-" + str(index)]["refusal"]
            self.assertEqual(refusal["refused_failure_code"], "FRAME_INGEST_FAILED")
            self.assertIn(refusal["failed_predicate"], {"AttributeError", "TypeError"})
        repository = self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
        self.assertEqual(sorted(receipt["evidence"]["communication_id"] for receipt in repository),
                         ["probe-type-valid-a", "probe-type-valid-b"])
        self.assertFalse(clock.now.called)
        self.assertEqual(self.run_cycle(cycle)["frames_seen"], 0)

    def test_the_gateway_guard_is_total_too(self):
        gateway = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_total", self.copy / "resident-runtime/federation_gateway_transport.py"))
        gateway.__spec__.loader.exec_module(gateway)
        frame = self.rebound(self.capability_frame("probe-gateway-type"), packet_base64=123)
        sent = []
        with mock.patch.object(gateway, "fetch_frame", return_value={"state": "FRAME_AVAILABLE", "frame": frame}), \
                mock.patch.object(gateway, "_json_request",
                                  side_effect=lambda method, path, body=None, headers=None:
                                  sent.append(body) or {"state": (body or {}).get("state")}):
            result = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
        self.assertEqual(result["state"], "REFUSED")
        self.assertEqual(result["refusal"]["refused_failure_code"], "FRAME_INGEST_FAILED")
        self.assertEqual(sent[0]["state"], "BLOCKED")

    def test_an_io_failure_writing_this_boundarys_ledger_defers_the_frame_and_it_is_consumed_once(self):
        kernel.publish_frame(self.capability_frame("probe-io"), root=self.mesh)
        organization_root = str(Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]).resolve())
        real_replace, failed = os.replace, []

        def failing_replace(source, destination, *args, **kwargs):
            if not failed and str(Path(destination).resolve()).startswith(organization_root):
                failed.append(destination)
                raise OSError(28, "No space left on device")
            return real_replace(source, destination, *args, **kwargs)

        cycle = self.cycle()
        with mock.patch("os.replace", side_effect=failing_replace):
            record = self.run_cycle(cycle)
        self.assertTrue(failed)
        self.assertEqual((record["frames_consumed"], record["frames_refused"], record["frames_deferred"]),
                         (0, 0, 1))
        self.assertNotIn("probe-io", self.markers())
        self.assertEqual(self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                                       "stegverse.organization-transition-receipt/v1"), [])
        # The next cycle offers it again and consumes it exactly once.
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_deferred"]), (1, 0))
        self.assertEqual(self.markers()["probe-io"]["status"], "CONSUMED")
        self.assertEqual(len(self.receipts("STEGVERSE_REPO_LEDGER_ROOT",
                                           "stegverse.repo-transition-receipt/v1")), 1)
        self.assertEqual(len(self.receipts("STEGVERSE_ORG_LEDGER_ROOT",
                                           "stegverse.organization-transition-receipt/v1")), 1)
        self.assertEqual(self.run_cycle(cycle)["frames_seen"], 0)

    def test_the_gateway_defers_on_its_own_io_failure_without_acknowledging(self):
        gateway = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_io", self.copy / "resident-runtime/federation_gateway_transport.py"))
        gateway.__spec__.loader.exec_module(gateway)
        sent = []
        with mock.patch.object(gateway, "fetch_frame",
                               return_value={"state": "FRAME_AVAILABLE", "frame": self.capability_frame("probe-gw-io")}), \
                mock.patch.object(gateway, "_json_request", side_effect=lambda *a, **k: sent.append(a) or {}), \
                mock.patch.object(gateway.K, "ingest_frame", side_effect=OSError(5, "I/O error")):
            result = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
        self.assertEqual(result["state"], "DEFERRED")
        self.assertEqual(result["refusal"]["failure_code"], "FRAME_DISPATCH_IO_FAILED")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, result["refusal"])
        self.assertEqual(sent, [])


class DispatcherFindingTests(unittest.TestCase):
    """08:43Z bar: the manifest that denies GitHub Actions runtime authority records its dispatcher finding."""

    def test_the_manifest_records_the_pending_substrate_finding_six_field(self):
        manifest = json.loads((ROOT / "resident-runtime/activation-manifest.json").read_text(encoding="utf-8"))
        self.assertIs(manifest["github_actions_is_runtime_authority"], False)
        finding, = [row for row in manifest["dispatcher_findings"]
                    if row["failure_code"] == "RUNTIME_DISPATCHER_PENDING_SUBSTRATE"]
        for field in ("disposition", "failed_predicate", "required_evidence_or_repair",
                      "retry_entrypoint", "owning_existing_goal", "next_attempt"):
            self.assertTrue(finding[field], field)
        self.assertIs(finding["blocking"], False)
        self.assertIn("WU-B13", finding["owning_existing_goal"])


class TransientWriterFaultTests(CopiedRepository):
    """F-TRANSIENT-RT: a lost comparison on a ledger append defers the frame; it is consumed exactly once later."""

    def setUp(self):
        super().setUp()
        self.losing = None
        test = self

        def lose(original):
            def append_transaction(store, *args, **kwargs):
                if test.losing is not None and str(Path(store.root).resolve()).startswith(test.losing):
                    return False
                return original(store, *args, **kwargs)
            append_transaction.__wrapped_original__ = original
            return append_transaction

        def patch_store_classes(module):
            store = getattr(module, "PosixLedgerStore", None)
            if store is not None and not hasattr(store.append_transaction, "__wrapped_original__"):
                original = store.append_transaction
                store.append_transaction = lose(original)
                self.addCleanup(setattr, store, "append_transaction", original)

        for module in list(sys.modules.values()):
            patch_store_classes(module)
        real_exec = importlib.machinery.SourceFileLoader.exec_module

        def exec_module(loader, module):
            real_exec(loader, module)
            patch_store_classes(module)
        patcher = mock.patch.object(importlib.machinery.SourceFileLoader, "exec_module", exec_module)
        patcher.start()
        self.addCleanup(patcher.stop)

    def cycle(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_transient", self.copy / "resident-runtime/federation_cycle.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def run_cycle(self, cycle):
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        return json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())

    def marker(self, packet_id):
        for path in (self.copy / "resident-runtime/federation/seen.d").glob("*.json"):
            marker = json.loads(path.read_text(encoding="utf-8"))
            if marker.get("packet_id") == packet_id:
                return marker
        return None

    def ledgers(self):
        return (self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1"),
                self.receipts("STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1"))

    def assert_deferred_then_once(self, losing_root, packet_id, repository_after_first):
        self.publish(ADDRESS, diagnostic(packet_id), packet_id)
        cycle = self.cycle()
        self.losing = str(Path(losing_root).resolve())
        results = []
        real_consume = cycle.K.consume_and_respond
        with mock.patch.object(cycle.K, "consume_and_respond",
                               side_effect=lambda *a, **k: results.extend(real_consume(*a, **k)) or results):
            record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_refused"], record["frames_deferred"]),
                         (0, 0, 1))
        refusal = results[0]["result"]["refusal"]
        self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("FRAME_DISPATCH_WRITE_FAILED", False))
        self.assertIn("CONTENTION_EXHAUSTED", refusal["detail"])
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)
        self.assertIsNone(self.marker(packet_id))
        repository, organization = self.ledgers()
        self.assertEqual((len(repository), len(organization)), (repository_after_first, 0))
        self.losing = None
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_deferred"]), (1, 0))
        self.assertEqual(self.marker(packet_id)["status"], "CONSUMED")
        repository, organization = self.ledgers()
        self.assertEqual((len(repository), len(organization)), (1, 1))
        self.assertEqual(organization[0]["repo_receipt_sha256"], repository[0]["receipt_sha256"])
        self.assertEqual(self.run_cycle(cycle)["frames_seen"], 0)

    def test_a_lost_comparison_on_every_append_defers_and_writes_nothing(self):
        self.assert_deferred_then_once(Path(self._work.name), "probe-lost-every", 0)

    def test_a_lost_comparison_on_the_organization_append_defers_and_the_replay_lands_once(self):
        self.assert_deferred_then_once(os.environ["STEGVERSE_ORG_LEDGER_ROOT"], "probe-lost-org", 1)


class CarriedWriterVerificationTests(CopiedRepository):
    """B-P36m writers (lead 09:00Z, VALIDATOR V-P11): outside an admitted crossing, every writer
    verifies a carried claim against the current organization head, as ingest does; no
    caller-supplied head widens it. Inside one, writers verify against the crossing's durable
    admission record (CarriedCrossingAdmissionRecordTests).
    """

    def ledger_files(self):
        return sorted(str(path) for name in self.LEDGER_ROOTS if Path(os.environ[name]).exists()
                      for path in Path(os.environ[name]).rglob("*") if path.is_file())

    def head(self):
        return json.loads((Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / "HEAD.json").read_text())["receipt_sha256"]

    def receive(self, packet_id, hb_epoch, provenance=None):
        return ingress.receive(diagnostic(packet_id), registry=REGISTRY, packet_id=packet_id,
                               hb_epoch=hb_epoch, hb_provenance=provenance)

    def test_a_verified_crossing_keeps_source_and_sha_on_both_receipts(self):
        self.assertEqual(self.receive("probe-writer-head", 4096)["disposition"], "ALLOW")
        admitted = self.head()
        provenance = {"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": admitted}
        result = self.receive("probe-writer-crossing", 4096, provenance)
        self.assertEqual(result["disposition"], "ALLOW", result.get("detail"))
        receipts = {receipt["receipt_sha256"]: receipt for receipt in
                    self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
                    + self.receipts("STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1")}
        for digest in (result["repository_receipt_sha256"], result["organization_receipt_sha256"]):
            reference = receipts[digest]["hb_reference"]
            self.assertEqual((reference["source"], reference["head_receipt_sha"]),
                             ("ORGANIZATION_LEDGER_HEAD", admitted))
            self.assertEqual((reference["epoch"], reference["derived_from_clock"]), (4096, False))

    def test_a_caller_supplied_older_chain_member_is_refused_at_every_writer(self):
        self.assertEqual(self.receive("probe-older", 1000)["disposition"], "ALLOW")
        older = self.head()
        self.assertEqual(self.receive("probe-current", 4096)["disposition"], "ALLOW")
        self.assertNotEqual(self.head(), older)
        before = self.ledger_files()
        provenance = {"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": older,
                      "admission_head_receipt_sha": older}
        repository, = [receipt for receipt in self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
            if receipt["evidence"]["communication_id"] == "probe-current"]
        calls = (
            lambda: kernel.supplied_hb_reference(1000, retry_entrypoint="probe", provenance=provenance),
            lambda: ingress.ledger.emit.append("probe:older", "PROBE", kernel.sha({"p": 1}), kernel.sha({"p": 2}),
                                               {}, "NONE", hb_epoch=1000, hb_provenance=provenance),
            lambda: ingress.ledger.append_repository("probe:older", "PROBE", kernel.sha({"p": 1}),
                                                     kernel.sha({"p": 2}), {}, "NONE", hb_epoch=1000,
                                                     hb_provenance=provenance),
            lambda: ingress.ledger.append_organization(repository, "REPO_STATE_PROPAGATION", "FROM_HEAD",
                                                       kernel.sha({"p": 3}), {}, "NONE", hb_epoch=1000,
                                                       hb_provenance=provenance),
            lambda: ingress.ledger.aggregate.append(repository, "REPO_STATE_PROPAGATION", "FROM_HEAD",
                                                    kernel.sha({"p": 3}), {}, "NONE", hb_epoch=1000,
                                                    hb_provenance=provenance),
            lambda: self.receive("probe-older-crossing", 1000, provenance),
        )
        for call in calls:
            with self.assertRaises(ValueError) as refused:
                call()
            self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        self.assertEqual(self.ledger_files(), before)

    def test_a_forged_sha_is_refused_with_nothing_written(self):
        self.assertEqual(self.receive("probe-forged-head", 4096)["disposition"], "ALLOW")
        before = self.ledger_files()
        with self.assertRaises(ValueError) as refused:
            self.receive("probe-forged-writer", 4096, {"source": "ORGANIZATION_LEDGER_HEAD",
                                                       "head_receipt_sha": "sha256:" + "f" * 64})
        self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        self.assertEqual(self.ledger_files(), before)


class ReceiptCollisionTests(RedirectedLedgers):
    """09:14Z: a content collision is refused before any write, six fields; a byte-identical replay is idempotent."""

    def ledger_files(self):
        return sorted(str(path) for name in self.LEDGER_ROOTS if Path(os.environ[name]).exists()
                      for path in Path(os.environ[name]).rglob("*") if path.is_file())

    def test_a_collision_is_refused_before_any_write_and_a_replay_is_idempotent(self):
        first = ingress.receive(diagnostic("probe-collision-a"), registry=REGISTRY,
                                packet_id="probe-collision", hb_epoch=4096)
        self.assertEqual(first["disposition"], "ALLOW")
        before = self.ledger_files()
        replay = ingress.receive(diagnostic("probe-collision-a"), registry=REGISTRY,
                                 packet_id="probe-collision", hb_epoch=4096)
        self.assertIs(replay["transition_replayed"], True)
        self.assertEqual(replay["repository_receipt_sha256"], first["repository_receipt_sha256"])
        self.assertEqual(self.ledger_files(), before)
        collided = ingress.receive(diagnostic("probe-collision-b"), registry=REGISTRY,
                                   packet_id="probe-collision", hb_epoch=4096)
        self.assertEqual(collided["disposition"], "FAIL_CLOSED")
        self.assertEqual(collided["failure_code"], "LEDGER_RECEIPT_COLLISION")
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, collided)
        self.assertIs(collided["consequence_committed"], False)
        self.assertEqual(self.ledger_files(), before)


class ResponsePublishedOnceTests(CopiedRepository):
    """F-REPUB: a fault after a response is published leaves the frame pending; it never gets a second response."""

    def response_frames(self):
        frames = []
        for path in sorted((self.mesh / "frames.d").glob("*.json")):
            frame = json.loads(path.read_text(encoding="utf-8"))
            if ":response:" in frame["packet_id"]:
                frames.append(frame)
        return frames

    def cycle(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_repub", self.copy / "resident-runtime/federation_cycle.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def test_a_marker_failure_after_the_response_gives_exactly_one_response(self):
        self.publish(ADDRESS, diagnostic("probe-repub-marker"), "probe-repub-marker")
        cycle = self.cycle()
        real_mark, failed = cycle.K.mark_federation_frame_seen, []

        def failing_mark(*args, **kwargs):
            if not failed:
                failed.append(True)
                raise OSError(28, "No space left on device")
            return real_mark(*args, **kwargs)

        with mock.patch.object(cycle.K, "mark_federation_frame_seen", side_effect=failing_mark), \
                mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        latest = self.copy / "resident-runtime/federation/latest-cycle.json"
        record = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual((record["frames_deferred"], record["responses_emitted"]), (1, 1))
        self.assertEqual(len(self.response_frames()), 1)
        first = self.response_frames()[0]
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        record = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual((record["frames_consumed"], record["responses_emitted"]), (1, 0))
        self.assertEqual(self.response_frames(), [first])
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), 0)
        self.assertEqual(json.loads(latest.read_text(encoding="utf-8"))["frames_seen"], 0)
        self.assertEqual(len(self.response_frames()), 1)

    def test_an_ack_failure_after_the_gateway_response_gives_exactly_one_response(self):
        gateway = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_repub", self.copy / "resident-runtime/federation_gateway_transport.py"))
        gateway.__spec__.loader.exec_module(gateway)
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=ADDRESS, payload=diagnostic("probe-repub-ack"),
            transition_reference="intr:transition:probe-repub-ack", authority_effect="NONE",
            packet_id="probe-repub-ack")
        frame = kernel.carrier_frame(packet, epoch=4096)
        submitted, acks = [], []

        def json_request(method, path, body=None, headers=None):
            if path.endswith("/acknowledgements"):
                acks.append(body)
                if len(acks) == 1:
                    raise OSError(104, "Connection reset by peer")
                return {"state": body["state"]}
            submitted.append(body)
            return {"state": "PENDING"}

        with mock.patch.object(gateway, "fetch_frame", return_value={"state": "FRAME_AVAILABLE", "frame": frame}), \
                mock.patch.object(gateway, "_json_request", side_effect=json_request):
            first = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
            self.assertEqual(first["state"], "DEFERRED")
            self.assertEqual((first["refusal"]["failure_code"], first["refusal"]["terminal"]),
                             ("FRAME_DISPATCH_IO_FAILED", False))
            second = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
        self.assertEqual((second["state"], second["responses_emitted"]), ("CONSUMED", 0))
        self.assertEqual(len(submitted), 1)
        self.assertEqual(len(acks), 2)
        self.assertEqual(second["response_frame_sha256"], submitted[0]["frame_sha256"])


class TornHeadWriteTests(CopiedRepository):
    """IO-TORN (VALIDATOR V-P11): an OSError writing HEAD after the receipt is published leaves the
    ledger appendable; the next cycle consumes the frame once, with no orphan."""

    def setUp(self):
        super().setUp()
        self.tear = None
        test = self

        def tearing(original):
            def put(store, key, value):
                if (test.tear is not None and key == "HEAD.json"
                        and str(Path(store.root).resolve()).startswith(test.tear)):
                    test.tear = None
                    raise OSError(5, "I/O error writing HEAD")
                return original(store, key, value)
            put.__torn_original__ = original
            return put

        def patch_store_classes(module):
            store = getattr(module, "PosixLedgerStore", None)
            if store is not None and not hasattr(store.put, "__torn_original__"):
                original = store.put
                store.put = tearing(original)
                self.addCleanup(setattr, store, "put", original)

        for module in list(sys.modules.values()):
            patch_store_classes(module)
        real_exec = importlib.machinery.SourceFileLoader.exec_module

        def exec_module(loader, module):
            real_exec(loader, module)
            patch_store_classes(module)
        patcher = mock.patch.object(importlib.machinery.SourceFileLoader, "exec_module", exec_module)
        patcher.start()
        self.addCleanup(patcher.stop)

    cycle = TransientWriterFaultTests.cycle
    run_cycle = TransientWriterFaultTests.run_cycle
    marker = TransientWriterFaultTests.marker
    ledgers = TransientWriterFaultTests.ledgers

    def assert_chain_has_no_orphan(self, variable):
        root = Path(os.environ[variable])
        cursor = json.loads((root / "HEAD.json").read_text())["receipt_sha256"]
        reachable = set()
        while cursor:
            name = cursor.split(":", 1)[1] + ".json"
            reachable.add(name)
            cursor = json.loads((root / "receipts" / name).read_text()).get("previous_receipt_sha256")
        self.assertEqual({path.name for path in (root / "receipts").glob("*.json")}, reachable)

    def torn_then_once(self, variable, prime):
        cycle = self.cycle()
        if prime:
            self.publish(ADDRESS, diagnostic("probe-torn-prime"), "probe-torn-prime")
            self.assertEqual(self.run_cycle(cycle)["frames_consumed"], 1)
        packet_id = "probe-torn-" + variable.lower().replace("_", "-") + ("" if prime else "-genesis")
        self.publish(ADDRESS, diagnostic(packet_id), packet_id)
        self.tear = str(Path(os.environ[variable]).resolve())
        record = self.run_cycle(cycle)
        self.assertIsNone(self.tear)
        self.assertEqual((record["frames_consumed"], record["frames_refused"], record["frames_deferred"]), (0, 0, 1))
        self.assertIsNone(self.marker(packet_id))
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_refused"], record["frames_deferred"]), (1, 0, 0))
        self.assertEqual(self.marker(packet_id)["status"], "CONSUMED")
        expected = 2 if prime else 1
        repository, organization = self.ledgers()
        self.assertEqual((len(repository), len(organization)), (expected, expected))
        for name in self.LEDGER_ROOTS:
            self.assert_chain_has_no_orphan(name)
        # Later frames are unaffected.
        self.publish(ADDRESS, diagnostic(packet_id + "-later"), packet_id + "-later")
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_refused"]), (1, 0))
        repository, organization = self.ledgers()
        self.assertEqual((len(repository), len(organization)), (expected + 1, expected + 1))

    def test_a_torn_organization_head_write_is_recovered(self):
        self.torn_then_once("STEGVERSE_ORG_LEDGER_ROOT", prime=True)

    def test_a_torn_organization_genesis_head_write_is_recovered(self):
        self.torn_then_once("STEGVERSE_ORG_LEDGER_ROOT", prime=False)

    def test_a_torn_repository_head_write_is_recovered(self):
        self.torn_then_once("STEGVERSE_REPO_LEDGER_ROOT", prime=True)


class MultiStepWriteResumableTests(CopiedRepository):
    """B-P36q: every multi-step durable write is atomic or idempotently resumable; a fault at any
    step leaves state the next run completes exactly once, never state that refuses itself."""

    def cycle(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "federation_cycle_resumable", self.copy / "resident-runtime/federation_cycle.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def run_cycle(self, cycle, expected=0):
        with mock.patch("builtins.print") as printed:
            self.assertEqual(cycle.main(["--hb-epoch", "4096"]), expected)
        return printed

    def latest(self):
        return json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text())

    def failing_replace_once(self, predicate):
        real_replace, failed = os.replace, []

        def replace(source, destination, *args, **kwargs):
            if not failed and predicate(str(destination)):
                failed.append(destination)
                raise OSError(28, "No space left on device")
            return real_replace(source, destination, *args, **kwargs)
        return mock.patch("os.replace", side_effect=replace), failed

    def responses(self):
        return [json.loads(path.read_text(encoding="utf-8")) for path in (self.mesh / "frames.d").glob("*.json")
                if ":response:" in json.loads(path.read_text(encoding="utf-8"))["packet_id"]]

    def monitor(self, packet_id):
        control = next(row["service_id"] for row in REGISTRY["services"]
                       if row["boundary_role"] == "BOUNDARY_LOCAL_CONTROL")
        self.publish(control, {"communication_id": packet_id, "message_class": "ecosystem.monitor.request",
                               "subject": "probe", "body": {}}, packet_id)

    def test_a_fault_at_each_local_cycle_write_is_completed_once_by_the_next_run(self):
        steps = {
            "response frame": lambda destination: "frames.d" in destination,
            "seen marker": lambda destination: "seen.d" in destination,
            "cycle record": lambda destination: destination.endswith("latest-cycle.json"),
        }
        for index, (step, predicate) in enumerate(steps.items()):
            packet_id = "probe-step-" + str(index)
            self.monitor(packet_id)
            cycle = self.cycle()
            patcher, failed = self.failing_replace_once(predicate)
            with patcher:
                self.run_cycle(cycle, expected=1 if step == "cycle record" else 0)
            self.assertTrue(failed, step)
            self.run_cycle(cycle)
            if step == "cycle record":
                # The frame was already marked; the next run redoes nothing.
                self.assertEqual(self.latest()["frames_seen"], 0)
            else:
                self.assertEqual(self.latest()["frames_consumed"], 1, step)
            self.run_cycle(cycle)
            self.assertEqual(self.latest()["frames_seen"], 0, step)
            mine = [frame for frame in self.responses()
                    if kernel.recover_packet(frame)["payload"]["body"]["request_packet_id"] == packet_id]
            self.assertEqual(len(mine), 1, step)

    def test_torn_documents_from_an_earlier_write_are_replaced_not_refused_forever(self):
        self.monitor("probe-torn-marker")
        work = next(row["service_id"] for row in REGISTRY["services"]
                    if row["boundary_role"] == "BOUNDARY_LOCAL_CONTROL")
        self.publish(work, {"communication_id": "probe-torn-intake", "message_class": "ecosystem.work.request",
                            "subject": "probe", "body": {}}, "probe-torn-intake")
        frames = {json.loads(path.read_text(encoding="utf-8"))["packet_id"]: path
                  for path in (self.mesh / "frames.d").glob("*.json")}
        seen = self.copy / "resident-runtime/federation/seen.d"
        seen.mkdir(parents=True, exist_ok=True)
        marker = seen / (hashlib.sha256(frames["probe-torn-marker"].name.encode()).hexdigest() + ".json")
        marker.write_text('{"schema_version": "stegverse.federation-frame', encoding="utf-8")
        inbox = self.copy / "resident-runtime/control/inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        intake = inbox / (hashlib.sha256(("probe-torn-intake|probe-torn-intake").encode()).hexdigest() + ".json")
        intake.write_text('{"schema_version": "stegverse.ecosystem-work', encoding="utf-8")
        cycle = self.cycle()
        self.run_cycle(cycle)
        self.assertEqual((self.latest()["frames_consumed"], self.latest()["frames_refused"]), (2, 0))
        self.assertEqual(json.loads(marker.read_text(encoding="utf-8"))["status"], "CONSUMED")
        self.assertEqual(json.loads(intake.read_text(encoding="utf-8"))["communication_id"], "probe-torn-intake")
        self.run_cycle(cycle)
        self.assertEqual(self.latest()["frames_seen"], 0)

    def test_the_cycle_record_fault_is_six_field_and_non_terminal(self):
        self.monitor("probe-record-fault")
        cycle = self.cycle()
        patcher, _failed = self.failing_replace_once(lambda destination: destination.endswith("latest-cycle.json"))
        with patcher:
            printed = self.run_cycle(cycle, expected=1)
        refusal = json.loads(printed.call_args.args[0])
        self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("CYCLE_RECORD_WRITE_FAILED", False))
        for field in SuppliedEpochParsingTests.SIX_FIELDS:
            self.assertIn(field, refusal)

    def gateway(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_resumable", self.copy / "resident-runtime/federation_gateway_transport.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def test_a_fault_at_each_gateway_response_step_submits_one_response(self):
        steps = ("record before submit", "submit", "record after submit")
        for index, step in enumerate(steps):
            gateway = self.gateway()
            packet = kernel.build_packet(
                origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
                destination_org=THIS, destination_service=ADDRESS,
                payload=diagnostic("probe-gw-step-" + str(index)),
                transition_reference="intr:transition:gw-step", authority_effect="NONE",
                packet_id="probe-gw-step-" + str(index))
            frame = kernel.carrier_frame(packet, epoch=4096)
            submitted, writes = [], {"count": 0}
            real_write = gateway.K.write_json_atomic

            def write(path, value, step=step):
                if "gateway-responses.d" in str(path):
                    writes["count"] += 1
                    if (step == "record before submit" and writes["count"] == 1) or \
                            (step == "record after submit" and writes["count"] == 2):
                        raise OSError(5, "I/O error")
                return real_write(path, value)

            def json_request(method, path, body=None, headers=None, step=step):
                if path.endswith("/frames"):
                    submitted.append(body)
                    if step == "submit" and len(submitted) == 1:
                        raise gateway.FederationGatewayTransportError("gateway request failed: reset")
                    return {"state": "PENDING"}
                return {"state": body["state"]}

            with mock.patch.object(gateway, "fetch_frame", return_value={"state": "FRAME_AVAILABLE", "frame": frame}), \
                    mock.patch.object(gateway, "_json_request", side_effect=json_request), \
                    mock.patch.object(gateway.K, "write_json_atomic", side_effect=write):
                first = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
                self.assertEqual(first["state"], "DEFERRED", step)
                self.assertIs(first["refusal"]["terminal"], False)
                second = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
                third = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
            self.assertEqual(second["state"], "CONSUMED", step)
            self.assertEqual(third["state"], "CONSUMED", step)
            # One distinct response; a retried submission is the same bytes.
            self.assertEqual(len({json.dumps(body, sort_keys=True) for body in submitted}), 1, step)
            self.assertEqual(sum(1 for body in submitted if body) - (1 if step != "record before submit" else 0), 1, step)

    def test_a_torn_runtime_receipt_is_replaced_not_a_permanent_collision(self):
        runtime = _module("organization_runtime_torn", "runtime/organization_runtime.py")
        for name in ("ACTIVATIONS", "INGRESS", "EGRESS"):
            patcher = mock.patch.object(runtime, name, Path(self._work.name) / "runtime" / name.lower())
            patcher.start()
            self.addCleanup(patcher.stop)
        envelope = runtime.egress("probe-torn-runtime", "PROBE", {"boundary": "B", "subsystem": "S"}, b"x")
        torn = Path(self._work.name) / "runtime" / "ingress" / "probe-torn-runtime.json"
        torn.parent.mkdir(parents=True, exist_ok=True)
        torn.write_text('{"schema": "stegverse.organization-interlock', encoding="utf-8")
        received = runtime.ingress(envelope, "4096")
        self.assertEqual(json.loads(torn.read_text(encoding="utf-8"))["receipt_hash"], received["receipt_hash"])
        self.assertEqual(runtime.ingress(envelope, "4096"), received)


class ResponseIdKeyingTests(CopiedRepository):
    """Response-once keying (Lane B 09:40Z): a response is reused only for the same request, the same
    packet id and the same digest. A different request under that response id is six-field
    RESPONSE_ID_COLLISION, quarantined before any ledger write, and never handed the earlier response."""

    def ledger_files(self):
        return sorted(str(path) for name in self.LEDGER_ROOTS
                      for path in Path(os.environ[name]).rglob("*") if path.is_file())

    def response_frames(self):
        return ResponsePublishedOnceTests.response_frames(self)

    def cycle(self):
        return ResponsePublishedOnceTests.cycle(self)

    def run_cycle(self, cycle, epoch="4096"):
        with mock.patch("builtins.print"):
            self.assertEqual(cycle.main(["--hb-epoch", epoch]), 0)
        return json.loads((self.copy / "resident-runtime/federation/latest-cycle.json").read_text(encoding="utf-8"))

    def refused_markers(self):
        markers = self.copy / "resident-runtime/federation/seen.d"
        found = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(markers.glob("*.json"))]
        return [marker for marker in found if marker.get("status") == "REFUSED"]

    def assert_collision(self, refusal):
        self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("FRAME_REFUSED_QUARANTINED", True))
        self.assertEqual(refusal["refused_failure_code"], "RESPONSE_ID_COLLISION")
        for field in ("failed_predicate", "detail", "required_evidence_or_repair", "retry_entrypoint",
                      "owning_existing_goal", "next_attempt"):
            self.assertTrue(refusal[field], field)
        self.assertIs(refusal["consequence_committed"], False)

    def collide(self, second_packet_id, second_payload):
        cycle = self.cycle()
        self.publish(ADDRESS, diagnostic("probe-keying"), "probe-keying-a")
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["responses_emitted"]), (1, 1))
        first = self.response_frames()
        self.assertEqual(len(first), 1)
        before = self.ledger_files()
        self.publish(ADDRESS, second_payload, second_packet_id)
        record = self.run_cycle(cycle)
        self.assertEqual(record["responses_emitted"], 0)
        self.assertEqual(self.response_frames(), first)
        self.assertEqual(self.ledger_files(), before)
        body = kernel.recover_packet(first[0])["payload"]["body"]
        self.assertEqual(body["request_packet_id"], "probe-keying-a")
        return cycle

    def test_another_request_under_the_same_communication_id_is_a_collision(self):
        payload = diagnostic("probe-keying")
        payload["subject"] = "a different request"
        cycle = self.collide("probe-keying-b", payload)
        refused = self.refused_markers()
        self.assertEqual([marker["packet_id"] for marker in refused], ["probe-keying-b"])
        self.assert_collision(refused[0]["refusal"])
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_seen"], record["responses_emitted"]), (0, 0))
        self.assertEqual(len(self.response_frames()), 1)

    def test_the_same_request_id_with_other_content_is_a_collision_not_the_earlier_response(self):
        payload = diagnostic("probe-keying")
        payload["body"] = {**payload["body"], "probe": "other-content"}
        self.collide("probe-keying-a", payload)
        refused = self.refused_markers()
        self.assertEqual([marker["packet_id"] for marker in refused], ["probe-keying-a"])
        self.assert_collision(refused[0]["refusal"])

    def test_the_same_request_resent_reuses_its_response(self):
        cycle = self.cycle()
        self.publish(ADDRESS, diagnostic("probe-keying"), "probe-keying-a")
        self.run_cycle(cycle)
        first = self.response_frames()
        self.publish(ADDRESS, diagnostic("probe-keying"), "probe-keying-a", epoch=8192)
        record = self.run_cycle(cycle, "8192")
        self.assertEqual((record["frames_consumed"], record["responses_emitted"]), (1, 0))
        self.assertEqual(self.response_frames(), first)
        self.assertEqual(self.refused_markers(), [])

    def gateway(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_keying", self.copy / "resident-runtime/federation_gateway_transport.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def gateway_frame(self, payload, packet_id):
        packet = kernel.build_packet(
            origin_org=PEER, origin_service=kernel.organization_slug(PEER) + ".org-control",
            destination_org=THIS, destination_service=ADDRESS, payload=payload,
            transition_reference="intr:transition:" + packet_id, authority_effect="NONE",
            packet_id=packet_id)
        return kernel.carrier_frame(packet, epoch=4096)

    def test_the_gateway_refuses_another_request_under_a_submitted_response_id(self):
        gateway = self.gateway()
        other = diagnostic("probe-gw-keying")
        other["body"] = {**other["body"], "probe": "other-content"}
        cases = [(self.gateway_frame(diagnostic("probe-gw-keying"), "probe-gw-a"), "CONSUMED"),
                 (self.gateway_frame(other, "probe-gw-a"), "REFUSED"),
                 (self.gateway_frame(diagnostic("probe-gw-keying"), "probe-gw-b"), "REFUSED")]
        submitted, acks = [], []

        def json_request(method, path, body=None, headers=None):
            if path.endswith("/acknowledgements"):
                acks.append(body)
                return {"state": body["state"]}
            submitted.append(body)
            return {"state": "PENDING"}

        before = None
        for frame, state in cases:
            with mock.patch.object(gateway, "fetch_frame", return_value={"state": "FRAME_AVAILABLE", "frame": frame}), \
                    mock.patch.object(gateway, "_json_request", side_effect=json_request):
                result = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
            self.assertEqual(result["state"], state)
            if state == "REFUSED":
                self.assert_collision(result["refusal"])
                self.assertEqual(result["responses_emitted"], 0)
                self.assertEqual(acks[-1]["state"], "BLOCKED")
                self.assertEqual(self.ledger_files(), before)
            before = self.ledger_files()
        self.assertEqual(len(submitted), 1)


class WriterTraceTests(CopiedRepository):
    """F-WRITER-TRACE (Lane B 09:50Z, V-P11): every epoch-taking writer CLI prints a non-terminal
    six-field record when its own write faults, never a raw OSError or traceback. The fault is
    injected at each write in turn (every durable write is an os.replace), and the next run
    completes, leaving exactly the documents a run without a fault leaves."""

    def setUp(self):
        super().setUp()
        self.out = Path(self._work.name) / "out"
        self.inputs = Path(self._work.name) / "inputs"
        self.inputs.mkdir()
        (self.inputs / "payload.json").write_text(json.dumps(diagnostic("probe-writer-trace")), encoding="utf-8")
        (self.inputs / "standing.json").write_text(json.dumps(STANDING), encoding="utf-8")

    def state_roots(self):
        return [Path(os.environ[name]) for name in self.LEDGER_ROOTS] + [
            self.mesh, self.out, Path(self._work.name) / "runtime",
            self.copy / "resident-runtime/federation", self.copy / "resident-runtime/control"]

    def reset(self):
        for root in self.state_roots():
            shutil.rmtree(root, ignore_errors=True)

    def documents(self):
        """Every document left, with a response frame named by its response id: a resumed run's
        response truthfully says transition_replayed, but it is still the one response."""
        found = []
        for root in self.state_roots():
            for path in (sorted(root.rglob("*")) if root.is_dir() else []):
                if not path.is_file():
                    continue
                if path.parent.name == "frames.d":
                    packet_id = json.loads(path.read_text(encoding="utf-8"))["packet_id"]
                    if ":response:" in packet_id:
                        found.append("response " + packet_id)
                        continue
                found.append(str(path))
        return sorted(found)

    def invoke(self, main, argv, fail_at=None, fail_after_head=None):
        """Run one CLI in this process: (exit code, printed lines, os.replace calls).

        `fail_at` faults the Nth os.replace before it lands; `fail_after_head`
        faults just after the Nth HEAD.json replace has landed (the directory
        sync step), so HEAD is already published."""
        real_replace, calls, heads = os.replace, [], []

        def replace(*args, **kwargs):
            calls.append(args)
            if fail_at is not None and len(calls) == fail_at:
                raise OSError(28, "No space left on device")
            result = real_replace(*args, **kwargs)
            if str(args[1]).endswith("HEAD.json"):
                heads.append(args[1])
                if fail_after_head is not None and len(heads) == fail_after_head:
                    raise OSError(5, "I/O error syncing the directory after HEAD")
            return result

        with mock.patch("sys.argv", argv), mock.patch("os.replace", side_effect=replace), \
                mock.patch("builtins.print") as printed:
            try:
                code = main()
            except SystemExit as exc:
                code = exc.code
        self.heads_replaced = len(heads)
        return code, [call.args[0] for call in printed.call_args_list], len(calls)

    def assert_each_write_fault_is_six_field_and_resumable(self, load, argv, expected=0):
        self.reset()
        main = load()
        code, _, writes = self.invoke(main, argv)
        self.assertEqual(code if code is not None else 0, expected)
        self.assertGreater(writes, 0)
        clean = self.documents()
        for fail_at in range(1, writes + 1):
            with self.subTest(fail_at=fail_at):
                self.reset()
                main = load()
                code, printed, _ = self.invoke(main, argv, fail_at)
                record = json.loads(printed[-1])
                if code == 0 and record.get("deferrals"):
                    # A cycle that deferred a frame completes; the frame's record is six-field.
                    self.assertEqual(len(record["deferrals"]), 1)
                    refusal = record["deferrals"][0]
                else:
                    self.assertEqual(code, 1)
                    refusal = record
                self.assertEqual((refusal["disposition"], refusal["terminal"]), ("FAIL_CLOSED", False))
                self.assertIn(refusal["failure_code"], ("WRITER_IO_FAILED", "CYCLE_RECORD_WRITE_FAILED",
                                                        "FRAME_DISPATCH_IO_FAILED"))
                for field in ("failed_predicate", "detail", "required_evidence_or_repair",
                              "retry_entrypoint", "owning_existing_goal", "next_attempt"):
                    self.assertTrue(refusal[field], field)
                code, _, _ = self.invoke(main, argv)
                self.assertEqual(code if code is not None else 0, expected)
                self.assertEqual(self.documents(), clean)

    def cli(self, name, relative):
        def load():
            module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
                name, self.copy / relative))
            module.__spec__.loader.exec_module(module)
            return module.main
        return load

    def test_the_repository_emitter(self):
        self.assert_each_write_fault_is_six_field_and_resumable(
            self.cli("emit_trace", ".stegverse/transition-ledger/emit.py"),
            ["emit.py", "--transition-id", "probe-writer-trace", "--transition-class", "CLASS",
             "--predecessor-state-sha256", "sha256:" + "a" * 64,
             "--successor-state-sha256", "sha256:" + "b" * 64, "--hb-epoch", "4096"])

    def test_the_organization_aggregate(self):
        receipt = self.inputs / "repo-receipt.json"

        def load():
            emit = _module("emit_trace_source", ".stegverse/transition-ledger/emit.py")
            if not receipt.exists():
                root = os.environ["STEGVERSE_REPO_LEDGER_ROOT"]
                os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(self.inputs / "source-ledger")
                try:
                    receipt.write_text(json.dumps(emit.append(
                        "probe-writer-trace", "CLASS", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                        {}, "NONE", 4096)), encoding="utf-8")
                finally:
                    os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = root
            return self.cli("aggregate_trace", "resident-runtime/aggregate_repo_transition.py")()

        self.assert_each_write_fault_is_six_field_and_resumable(
            load, ["aggregate_repo_transition.py", "--transition-receipt", str(receipt),
                   "--predecessor-org-state-sha256", "GENESIS",
                   "--successor-org-state-sha256", "sha256:" + "c" * 64, "--hb-epoch", "4096"])

    def test_the_ingress_receive_and_self_close_commands(self):
        registry = str(self.copy / "org-boundary/registry/services.json")
        load = self.cli("ingress_trace", "resident-runtime/intr_destination_ingress.py")
        self.assert_each_write_fault_is_six_field_and_resumable(
            load, ["intr_destination_ingress.py", "--registry", registry,
                   "--payload", str(self.inputs / "payload.json"), "--hb-epoch", "4096",
                   "--out", str(self.out / "receive.json")])
        self.assert_each_write_fault_is_six_field_and_resumable(
            load, ["intr_destination_ingress.py", "--registry", registry, "--self-close",
                   "--communication-id", "probe-writer-trace", "--hb-epoch", "4096",
                   "--out", str(self.out / "self-close.json")])

    def test_the_egress_emit_command(self):
        self.assert_each_write_fault_is_six_field_and_resumable(
            self.cli("egress_trace", "resident-runtime/organization_egress_boundary.py"),
            ["organization_egress_boundary.py", "--destination-organization", PEER,
             "--payload", str(self.inputs / "payload.json"), "--standing", str(self.inputs / "standing.json"),
             "--capability", PROFILE_ID, "--mesh-root", str(self.mesh), "--hb-epoch", "4096",
             "--out", str(self.out / "egress.json")])

    def test_the_organization_runtime_activation(self):
        def load():
            return self.runtime().main
        self.assert_each_write_fault_is_six_field_and_resumable(
            load, ["organization_runtime.py", "activate", "--activation-id", "probe-writer-trace",
                   "--node-ref", "probe-node", "--hb-epoch", "4096"])

    def test_the_ecosystem_publisher(self):
        self.assert_each_write_fault_is_six_field_and_resumable(
            self.cli("ecosystem_trace", "resident-runtime/ecosystem_control.py"),
            ["ecosystem_control.py", "send-message", "--subject", "probe", "--body-json", "{}",
             "--communication-id", "probe-writer-trace", "--hb-epoch", "4096"])

    def test_the_federation_cycle(self):
        def load():
            if not (self.mesh / "frames.d").is_dir():
                self.publish(ADDRESS, diagnostic("probe-writer-trace-cycle"), "probe-writer-trace-cycle")
            return self.cli("cycle_trace", "resident-runtime/federation_cycle.py")()
        self.assert_each_write_fault_is_six_field_and_resumable(
            load, ["federation_cycle.py", "--hb-epoch", "4096"])

    # F-POST-HEAD (VALIDATOR V-P11): a fault after HEAD's replace landed must not lead the rerun
    # to a second receipt; the rerun returns the recorded one.

    def assert_post_head_fault_is_idempotent(self, load, argv, prepare=None, same_output=False):
        self.reset()
        if prepare:
            prepare()
        code, clean_printed, _ = self.invoke(load(), argv)
        self.assertEqual(code if code is not None else 0, 0)
        heads = self.heads_replaced
        self.assertGreater(heads, 0)
        clean = self.documents()
        for fail_after_head in range(1, heads + 1):
            with self.subTest(fail_after_head=fail_after_head):
                self.reset()
                if prepare:
                    prepare()
                main = load()
                code, printed, _ = self.invoke(main, argv, fail_after_head=fail_after_head)
                record = json.loads(printed[-1])
                refusal = record["deferrals"][0] if code == 0 and record.get("deferrals") else record
                if code != 0:
                    self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("WRITER_IO_FAILED", False))
                    self.assertIn("may already be committed", refusal["next_attempt"])
                    self.assertNotEqual(refusal["consequence_committed"], False)
                code, rerun, _ = self.invoke(main, argv)
                self.assertEqual(code if code is not None else 0, 0)
                self.assertEqual(self.documents(), clean)
                if same_output:
                    self.assertEqual(json.loads(rerun[-1]), json.loads(clean_printed[-1]))

    EMIT_ARGV = ["emit.py", "--transition-id", "probe-post-head", "--transition-class", "CLASS",
                 "--predecessor-state-sha256", "sha256:" + "a" * 64,
                 "--successor-state-sha256", "sha256:" + "b" * 64, "--hb-epoch", "4096"]

    def test_post_head_the_repository_emitter_returns_the_recorded_receipt(self):
        self.assert_post_head_fault_is_idempotent(
            self.cli("emit_post_head", ".stegverse/transition-ledger/emit.py"), self.EMIT_ARGV, same_output=True)
        receipts = [r for r in self.receipts("STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
                    if r["transition_id"] == "probe-post-head"]
        self.assertEqual(len(receipts), 1)

    def source_receipt(self, name, transition_id):
        path = self.inputs / (name + ".json")
        if not path.exists():
            emit = _module("emit_post_head_source", ".stegverse/transition-ledger/emit.py")
            root = os.environ["STEGVERSE_REPO_LEDGER_ROOT"]
            os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = str(self.inputs / ("source-ledger-" + name))
            try:
                path.write_text(json.dumps(emit.append(
                    transition_id, "CLASS", "sha256:" + "a" * 64, "sha256:" + "b" * 64, {}, "NONE", 4096)),
                    encoding="utf-8")
            finally:
                os.environ["STEGVERSE_REPO_LEDGER_ROOT"] = root
        return path

    def aggregate_argv(self, receipt, predecessor):
        return ["aggregate_repo_transition.py", "--transition-receipt", str(receipt),
                "--predecessor-org-state-sha256", predecessor,
                "--successor-org-state-sha256", "sha256:" + "c" * 64, "--hb-epoch", "4096"]

    def org_receipts(self):
        return self.receipts("STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1")

    def test_post_head_the_organization_aggregate_at_genesis_returns_the_recorded_receipt(self):
        receipt = self.source_receipt("genesis", "probe-post-head-genesis")
        self.assert_post_head_fault_is_idempotent(
            self.cli("aggregate_post_head", "resident-runtime/aggregate_repo_transition.py"),
            self.aggregate_argv(receipt, "GENESIS"), same_output=True)
        self.assertEqual(len(self.org_receipts()), 1)

    def test_post_head_the_organization_aggregate_from_head_returns_the_recorded_receipt(self):
        first = self.source_receipt("first", "probe-post-head-first")
        second = self.source_receipt("second", "probe-post-head-second")
        load = self.cli("aggregate_post_head_from", "resident-runtime/aggregate_repo_transition.py")

        def prepare():
            code, _, _ = self.invoke(load(), self.aggregate_argv(first, "GENESIS"))
            self.assertIn(code, (None, 0))
        self.assert_post_head_fault_is_idempotent(load, self.aggregate_argv(second, "FROM_HEAD"),
                                                  prepare=prepare, same_output=True)
        self.assertEqual(len(self.org_receipts()), 2)

    def test_post_head_the_ingress_egress_runtime_and_cycle_commands(self):
        registry = str(self.copy / "org-boundary/registry/services.json")
        self.assert_post_head_fault_is_idempotent(
            self.cli("ingress_post_head", "resident-runtime/intr_destination_ingress.py"),
            ["intr_destination_ingress.py", "--registry", registry,
             "--payload", str(self.inputs / "payload.json"), "--hb-epoch", "4096",
             "--out", str(self.out / "receive.json")])
        self.assert_post_head_fault_is_idempotent(
            self.cli("egress_post_head", "resident-runtime/organization_egress_boundary.py"),
            ["organization_egress_boundary.py", "--destination-organization", PEER,
             "--payload", str(self.inputs / "payload.json"), "--standing", str(self.inputs / "standing.json"),
             "--capability", PROFILE_ID, "--mesh-root", str(self.mesh), "--hb-epoch", "4096",
             "--out", str(self.out / "egress.json")])

        def load_cycle():
            if not (self.mesh / "frames.d").is_dir():
                self.publish(ADDRESS, diagnostic("probe-post-head-cycle"), "probe-post-head-cycle")
            return self.cli("cycle_post_head", "resident-runtime/federation_cycle.py")()
        self.assert_post_head_fault_is_idempotent(load_cycle, ["federation_cycle.py", "--hb-epoch", "4096"])

    def test_a_changed_rerun_of_a_recorded_transition_is_a_terminal_collision(self):
        load = self.cli("emit_collision", ".stegverse/transition-ledger/emit.py")
        self.reset()
        self.assertIn(self.invoke(load(), self.EMIT_ARGV)[0], (None, 0))
        before = self.documents()
        changed = self.EMIT_ARGV[:-2] + ["--evidence-json", '{"other": true}', "--hb-epoch", "4096"]
        code, printed, _ = self.invoke(load(), changed)
        self.assertEqual(code, 1)
        refusal = json.loads(printed[-1])
        self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("LEDGER_RECEIPT_COLLISION", True))
        self.assertEqual(self.documents(), before)


class InputTraceTests(WriterTraceTests):
    """F-INPUT-TRACE (VALIDATOR V-P11): a missing, unreadable, non-UTF-8, non-JSON or wrong-type input
    on any CLI argument is a TERMINAL six-field CLI_INPUT_INVALID, non-zero, with nothing written and
    no traceback. Inputs are read before any write, outside the own-state fault classifier."""

    BAD_INPUTS = ("missing", "directory", "not-utf-8", "not-json", "wrong-type")

    def bad_input(self, kind):
        path = self.inputs / ("bad-" + kind)
        if kind == "directory":
            path.mkdir(exist_ok=True)
        elif kind == "not-utf-8":
            path.write_bytes(b"\xff\xfe{")
        elif kind == "not-json":
            path.write_text("{not json", encoding="utf-8")
        elif kind == "wrong-type":
            path.write_text("[1, 2]", encoding="utf-8")
        return path

    def bad_inline(self, kind):
        return {"not-json": "{not json", "wrong-type": "[1, 2]"}.get(kind)

    def assert_terminal_input_refusal(self, load, argv, argument):
        self.reset()
        before = self.documents()
        code, printed, writes = self.invoke(load(), argv)
        self.assertEqual(code, 1, printed)
        refusal = json.loads(printed[-1])
        self.assertEqual((refusal["disposition"], refusal["failure_code"], refusal["terminal"]),
                         ("FAIL_CLOSED", "CLI_INPUT_INVALID", True))
        self.assertTrue(refusal["detail"].startswith(argument + ": "), refusal["detail"])
        for field in ("failed_predicate", "required_evidence_or_repair", "retry_entrypoint",
                      "owning_existing_goal", "next_attempt"):
            self.assertTrue(refusal[field], field)
        self.assertIs(refusal["consequence_committed"], False)
        self.assertEqual(writes, 0)
        self.assertEqual(self.documents(), before)

    def each_bad_file(self, load, argv_for, argument, *, any_json=False):
        for kind in self.BAD_INPUTS:
            if any_json and kind == "wrong-type":
                continue
            with self.subTest(argument=argument, kind=kind):
                self.assert_terminal_input_refusal(load, argv_for(str(self.bad_input(kind))), argument)

    def each_bad_inline(self, load, argv_for, argument):
        for kind in ("not-json", "wrong-type"):
            with self.subTest(argument=argument, kind=kind):
                self.assert_terminal_input_refusal(load, argv_for(self.bad_inline(kind)), argument)

    def test_the_repository_emitter_inputs(self):
        load = self.cli("emit_input", ".stegverse/transition-ledger/emit.py")
        self.each_bad_inline(load, lambda value: self.EMIT_ARGV + ["--evidence-json", value], "--evidence-json")

    def test_the_organization_aggregate_inputs(self):
        load = self.cli("aggregate_input", "resident-runtime/aggregate_repo_transition.py")
        good = self.source_receipt("input", "probe-input")
        for flag in ("--transition-receipt", "--repo-receipt"):
            self.each_bad_file(load, lambda path: ["aggregate_repo_transition.py", flag, path,
                                                   "--predecessor-org-state-sha256", "GENESIS",
                                                   "--successor-org-state-sha256", "sha256:" + "c" * 64,
                                                   "--hb-epoch", "4096"], flag)
        self.each_bad_inline(load, lambda value: self.aggregate_argv(good, "GENESIS")
                             + ["--boundary-evidence-json", value], "--boundary-evidence-json")

    def test_the_ingress_inputs(self):
        load = self.cli("ingress_input", "resident-runtime/intr_destination_ingress.py")
        registry = str(self.copy / "org-boundary/registry/services.json")
        payload = str(self.inputs / "payload.json")
        self.each_bad_file(load, lambda path: ["intr_destination_ingress.py", "--registry", path,
                                               "--payload", payload, "--hb-epoch", "4096"], "--registry")
        self.each_bad_file(load, lambda path: ["intr_destination_ingress.py", "--registry", path,
                                               "--self-close", "--communication-id", "probe-input",
                                               "--hb-epoch", "4096"], "--registry")
        self.each_bad_file(load, lambda path: ["intr_destination_ingress.py", "--registry", registry,
                                               "--payload", path, "--hb-epoch", "4096"], "--payload", any_json=True)

    def test_the_egress_inputs(self):
        load = self.cli("egress_input", "resident-runtime/organization_egress_boundary.py")
        payload, standing = str(self.inputs / "payload.json"), str(self.inputs / "standing.json")

        def argv(payload_path, standing_path):
            return ["organization_egress_boundary.py", "--destination-organization", PEER,
                    "--payload", payload_path, "--standing", standing_path, "--capability", PROFILE_ID,
                    "--mesh-root", str(self.mesh), "--hb-epoch", "4096"]
        self.each_bad_file(load, lambda path: argv(path, standing), "--payload", any_json=True)
        self.each_bad_file(load, lambda path: argv(payload, path), "--standing")

    def test_the_ecosystem_publisher_inputs(self):
        load = self.cli("ecosystem_input", "resident-runtime/ecosystem_control.py")
        self.each_bad_inline(load, lambda value: ["ecosystem_control.py", "send-message", "--subject", "probe",
                                                  "--body-json", value, "--hb-epoch", "4096"], "--body-json")

    def test_the_organization_runtime_ingress_input(self):
        load = lambda: self.runtime().main
        self.each_bad_file(load, lambda path: ["organization_runtime.py", "ingress", "--file", path,
                                               "--hb-epoch", "4096"], "--file")


class CarriedCrossingAdmissionRecordTests(CopiedRepository):
    """B-P36m race (VALIDATOR V-P11 @330970f): another writer can move the organization head
    between a CARRIED crossing's repository and organization writes. Ingest writes a durable
    admission record before any write; the crossing's later writers verify against it (the
    admitted head and epoch, on the chain the live head reaches, by digest), not the live head.
    So a crossing is never left with a repository receipt and no organization receipt."""

    FORGED = "sha256:" + "f" * 64

    def setUp(self):
        super().setUp()
        self.before_put = None
        self.after_append = None
        test = self

        def hooked_put(original):
            def put(store, key, value):
                if test.before_put is not None:
                    test.before_put(str(Path(store.root).resolve()), key)
                return original(store, key, value)
            put.__hooked_original__ = original
            return put

        def hooked_append(original):
            def append_transaction(store, *args, **kwargs):
                result = original(store, *args, **kwargs)
                # After the transaction returns its lock is released: the gap
                # between a crossing's repository and organization writes.
                if test.after_append is not None:
                    test.after_append(str(Path(store.root).resolve()))
                return result
            append_transaction.__hooked_original__ = original
            return append_transaction

        def patch_store_classes(module):
            store = getattr(module, "PosixLedgerStore", None)
            if store is not None and not hasattr(store.put, "__hooked_original__"):
                for name, hook in (("put", hooked_put), ("append_transaction", hooked_append)):
                    original = getattr(store, name)
                    setattr(store, name, hook(original))
                    self.addCleanup(setattr, store, name, original)

        for module in list(sys.modules.values()):
            patch_store_classes(module)
        real_exec = importlib.machinery.SourceFileLoader.exec_module

        def exec_module(loader, module):
            real_exec(loader, module)
            patch_store_classes(module)
        patcher = mock.patch.object(importlib.machinery.SourceFileLoader, "exec_module", exec_module)
        patcher.start()
        self.addCleanup(patcher.stop)

    cycle = TransientWriterFaultTests.cycle
    run_cycle = TransientWriterFaultTests.run_cycle
    carried_frame = CarriedProvenanceTests.carried_frame
    organization_head = CarriedProvenanceTests.organization_head
    assert_chain_has_no_orphan = TornHeadWriteTests.assert_chain_has_no_orphan

    def root_of(self, variable):
        return str(Path(os.environ[variable]).resolve())

    def head(self):
        return json.loads((Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / "HEAD.json").read_text())["receipt_sha256"]

    def other_writer(self):
        """A second writer, in its own process: one organization receipt appended FROM_HEAD."""
        source = Path(self._work.name) / "other-writer-source.json"
        if not source.exists():
            emitted = ingress.ledger.emit.append(
                "probe:other-writer", "PROBE", kernel.sha({"other": 1}), kernel.sha({"other": 2}),
                {}, "NONE", hb_epoch=4096)
            source.write_text(json.dumps(emitted), encoding="utf-8")
        run = subprocess.run(
            ["timeout", "60", "python3", str(self.copy / "resident-runtime/aggregate_repo_transition.py"),
             "--transition-receipt", str(source), "--predecessor-org-state-sha256", "FROM_HEAD",
             "--successor-org-state-sha256", kernel.sha({"other": 3}), "--hb-epoch", "4096"],
            env=dict(os.environ), capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def crossing_receipts(self, packet_id):
        repository = [receipt for receipt in self.receipts(
            "STEGVERSE_REPO_LEDGER_ROOT", "stegverse.repo-transition-receipt/v1")
            if (receipt.get("evidence") or {}).get("communication_id") == packet_id]
        organization = [receipt for receipt in self.receipts(
            "STEGVERSE_ORG_LEDGER_ROOT", "stegverse.organization-transition-receipt/v1")
            if (receipt.get("boundary_evidence") or receipt.get("evidence") or {}).get("communication_id")
            == packet_id]
        return repository, organization

    def admissions(self):
        directory = self.copy / "resident-runtime/federation/admissions.d"
        return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))]

    def assert_crossing_landed(self, packet_id, admitted):
        repository, organization = self.crossing_receipts(packet_id)
        self.assertEqual((len(repository), len(organization)), (1, 1))
        for receipt in repository + organization:
            reference = receipt["hb_reference"]
            self.assertEqual((reference["source"], reference["head_receipt_sha"], reference["epoch"]),
                             ("ORGANIZATION_LEDGER_HEAD", admitted, 4096))
            self.assertNotIn("admission_id", reference)
        for variable in self.LEDGER_ROOTS:
            self.assert_chain_has_no_orphan(variable)
        records = self.admissions()
        self.assertEqual([(record["packet_id"], record["head_receipt_sha"], record["closed"])
                          for record in records], [(packet_id, admitted, True)])

    def test_a_concurrent_organization_append_between_the_crossings_writes(self):
        admitted = self.organization_head()
        frame = self.carried_frame(ADDRESS, diagnostic("probe-race"), "probe-race",
                                   source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=admitted)
        kernel.publish_frame(frame, root=self.mesh)
        repository_root, raced = self.root_of("STEGVERSE_REPO_LEDGER_ROOT"), []

        def after_append(root):
            if root == repository_root and not raced:
                raced.append(True)
                self.other_writer()
        self.after_append = after_append
        record = self.run_cycle(self.cycle())
        self.after_append = None
        self.assertEqual(raced, [True])
        self.assertEqual((record["frames_consumed"], record["frames_refused"]), (1, 0))
        self.assertNotEqual(self.head(), admitted)
        self.assert_crossing_landed("probe-race", admitted)

    def test_a_deferred_crossing_resumes_after_another_writer_moved_the_head(self):
        admitted = self.organization_head()
        frame = self.carried_frame(ADDRESS, diagnostic("probe-race-resume"), "probe-race-resume",
                                   source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=admitted)
        kernel.publish_frame(frame, root=self.mesh)
        organization_root, torn = self.root_of("STEGVERSE_ORG_LEDGER_ROOT"), []

        def before_put(root, key):
            # The first organization write of the crossing: nothing of it is
            # written, so the other writer is not held back by a torn copy.
            if root == organization_root and not torn:
                torn.append(True)
                raise OSError(5, "I/O error writing the organization receipt")
        self.before_put = before_put
        cycle = self.cycle()
        first = self.run_cycle(cycle)
        self.before_put = None
        self.assertEqual((first["frames_deferred"], first["frames_refused"]), (1, 0))
        self.assertEqual([record["closed"] for record in self.admissions()], [False])
        self.other_writer()
        self.assertNotEqual(self.head(), admitted)
        second = self.run_cycle(cycle)
        self.assertEqual((second["frames_consumed"], second["frames_refused"]), (1, 0))
        self.assert_crossing_landed("probe-race-resume", admitted)
        self.assertEqual(self.run_cycle(cycle)["frames_seen"], 0)

    def copy_ledger(self):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "dual_ledger_admission_probe", self.copy / "resident-runtime/dual_ledger.py"))
        module.__spec__.loader.exec_module(module)
        return module

    def test_an_admission_id_admits_nothing_once_closed_forged_or_off_chain(self):
        admitted = self.organization_head()
        frame = self.carried_frame(ADDRESS, diagnostic("probe-admission-closed"), "probe-admission-closed",
                                   source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=admitted)
        kernel.publish_frame(frame, root=self.mesh)
        self.assertEqual(self.run_cycle(self.cycle())["frames_consumed"], 1)
        self.other_writer()
        closed = kernel.admission_id(frame)
        off_chain = "0" * 64
        directory = self.copy / "resident-runtime/federation/admissions.d"
        token = json.loads((directory / (closed + ".json")).read_text(encoding="utf-8"))["admission_token"]
        (directory / (off_chain + ".json")).write_text(json.dumps({
            "schema": kernel.ADMISSION_SCHEMA, "admission_id": off_chain, "admission_token": token,
            "packet_id": "probe-off-chain", "frame_sha256": self.FORGED, "head_receipt_sha": self.FORGED,
            "epoch": 4096, "closed": False}), encoding="utf-8")
        ledger = self.copy_ledger()
        before = sorted(str(path) for name in self.LEDGER_ROOTS for path in Path(os.environ[name]).rglob("*"))
        for identifier, head in ((closed, admitted), ("a" * 64, admitted), ("../" + closed, admitted),
                                 (off_chain, self.FORGED)):
            # Even holding the right token, a closed, never-written, path-escaping or off-chain
            # record admits nothing.
            provenance = {"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": head,
                          "admission_id": identifier, "admission_token": token}
            for call in (
                    lambda: kernel.supplied_hb_reference(4096, retry_entrypoint="probe", provenance=provenance,
                                                         admission_root=self.copy),
                    lambda: ledger.append_repository("probe:admission", "PROBE", kernel.sha({"p": 1}),
                                                     kernel.sha({"p": 2}), {}, "NONE", hb_epoch=4096,
                                                     hb_provenance=provenance)):
                with self.subTest(identifier=identifier):
                    with self.assertRaises(ValueError) as refused:
                        call()
                    self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        self.assertEqual(sorted(str(path) for name in self.LEDGER_ROOTS
                                for path in Path(os.environ[name]).rglob("*")), before)

    def test_a_gateway_frame_offered_again_after_its_crossing_landed_is_replayed_not_refused(self):
        gateway = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "gateway_admission", self.copy / "resident-runtime/federation_gateway_transport.py"))
        gateway.__spec__.loader.exec_module(gateway)
        admitted = self.organization_head()
        frame = self.carried_frame(ADDRESS, diagnostic("probe-admission-ack"), "probe-admission-ack",
                                   source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=admitted)
        submitted, acks = [], []

        def json_request(method, path, body=None, headers=None):
            if path.endswith("/acknowledgements"):
                acks.append(body)
                if len(acks) == 1:
                    raise OSError(104, "Connection reset by peer")
                return {"state": body["state"]}
            submitted.append(body)
            return {"state": "PENDING"}

        with mock.patch.object(gateway, "fetch_frame", return_value={"state": "FRAME_AVAILABLE", "frame": frame}), \
                mock.patch.object(gateway, "_json_request", side_effect=json_request):
            self.assertEqual(gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)["state"], "DEFERRED")
            self.other_writer()
            again = gateway.resident_gateway_cycle(self.copy, hb_epoch=4096)
        self.assertEqual((again["state"], again["responses_emitted"]), ("CONSUMED", 0), again.get("refusal"))
        self.assertEqual(acks[-1]["state"], "CONSUMED")
        self.assertEqual(len(submitted), 1)
        self.assert_crossing_landed("probe-admission-ack", admitted)

    def deferred_crossing(self, packet_id):
        """A CARRIED crossing admitted at H0 and deferred with its record open; the head then moves."""
        admitted = self.organization_head()
        frame = self.carried_frame(ADDRESS, diagnostic(packet_id), packet_id,
                                   source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=admitted)
        kernel.publish_frame(frame, root=self.mesh)
        organization_root, torn = self.root_of("STEGVERSE_ORG_LEDGER_ROOT"), []

        def before_put(root, key):
            if root == organization_root and not torn:
                torn.append(True)
                raise OSError(5, "I/O error writing the organization receipt")
        self.before_put = before_put
        cycle = self.cycle()
        self.assertEqual(self.run_cycle(cycle)["frames_deferred"], 1)
        self.before_put = None
        self.other_writer()
        self.assertNotEqual(self.head(), admitted)
        return cycle, frame, admitted

    def ledger_files(self):
        return sorted(str(path) for name in self.LEDGER_ROOTS for path in Path(os.environ[name]).rglob("*"))

    def test_an_open_record_admits_no_other_frame_and_a_sender_cannot_name_one(self):
        cycle, crossing, admitted = self.deferred_crossing("probe-binding")
        identifier = kernel.admission_id(crossing)
        guesses = ({"admission_id": identifier},
                   {"admission_id": identifier, "admission_token": "0" * 64},
                   {})
        for index, extra in enumerate(guesses):
            packet_id = "probe-binding-forged-%d" % index
            forged = self.carried_frame(ADDRESS, diagnostic(packet_id), packet_id, source="ORGANIZATION_LEDGER_HEAD",
                                        head_receipt_sha=admitted, **extra)
            with self.subTest(extra=sorted(extra)):
                before = self.ledger_files()
                with self.assertRaises(kernel.SuppliedEpochRefused) as refused:
                    kernel.ingest_frame(self.copy, forged, mesh_root=self.mesh)
                self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
                # A sender-named admission is refused, never honoured; with none named, H0 is not current.
                self.assertIn("names an admission record" if extra else "not the current organization ledger head",
                              refused.exception.refusal["detail"])
                self.assertEqual(self.ledger_files(), before)
                self.assertFalse((self.copy / "resident-runtime/federation/admissions.d"
                                  / (kernel.admission_id(forged) + ".json")).exists())

    def test_an_open_record_admits_no_unrelated_writer(self):
        _, crossing, admitted = self.deferred_crossing("probe-binding-writer")
        identifier = kernel.admission_id(crossing)
        ledger = self.copy_ledger()
        before = self.ledger_files()
        for provenance in ({"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": admitted,
                            "admission_id": identifier},
                           {"source": "ORGANIZATION_LEDGER_HEAD", "head_receipt_sha": admitted,
                            "admission_id": identifier, "admission_token": "0" * 64}):
            for call in (
                    lambda: kernel.supplied_hb_reference(4096, retry_entrypoint="probe", provenance=provenance,
                                                         admission_root=self.copy),
                    lambda: ledger.append_repository("s9", "PROBE", kernel.sha({"p": 1}), kernel.sha({"p": 2}),
                                                     {}, "NONE", hb_epoch=4096, hb_provenance=provenance)):
                with self.subTest(fields=sorted(provenance)):
                    with self.assertRaises(ValueError) as refused:
                        call()
                    self.assertEqual(refused.exception.refusal["failure_code"], "CARRIED_PROVENANCE_UNVERIFIED")
        self.assertEqual(self.ledger_files(), before)

    def test_the_deferred_crossing_itself_still_completes_once_after_the_forgeries(self):
        cycle, crossing, admitted = self.deferred_crossing("probe-binding-own")
        forged = self.carried_frame(ADDRESS, diagnostic("probe-binding-own-forged"), "probe-binding-own-forged",
                                    source="ORGANIZATION_LEDGER_HEAD", head_receipt_sha=admitted,
                                    admission_id=kernel.admission_id(crossing))
        kernel.publish_frame(forged, root=self.mesh)
        record = self.run_cycle(cycle)
        self.assertEqual((record["frames_consumed"], record["frames_refused"]), (1, 1))
        repository, organization = self.crossing_receipts("probe-binding-own")
        self.assertEqual((len(repository), len(organization)), (1, 1))
        self.assertEqual(self.crossing_receipts("probe-binding-own-forged"), ([], []))



class ProcessBoundaryExitSplitTests(CopiedRepository):
    """PB-EXIT-SPLIT (lead 09:54Z, VALIDATOR V-P11): process_boundary exits 65 for the crossing's own
    fault (terminal six-field) and 75 for this organization's own write fault (non-terminal, nothing
    durable written). Its one caller, resident-runtime/run_once.py, keeps them apart: 65 is terminal,
    75 is non-terminal and the same run completes the crossing once. Frame ingest never calls
    process_boundary; its own split is kernel.ingest_or_quarantine (TotalGuardAndDispatchIoTests)."""

    def envelope(self):
        services = {row["boundary_role"]: row["service_id"] for row in REGISTRY["services"]}
        return {"schema_version": "stegverse.intr.org-boundary.v1", "packet_id": "probe-pb", "direction": "INGRESS",
                "origin": {"org": PEER, "service": "peer.boundary-diagnostic"},
                "destination": {"org": THIS, "service": services["BOUNDARY_LOCAL_DIAGNOSTIC"]},
                "carrier": {"kind": "HB_DERIVED", "reference": "HB-probe"}, "intr_profile": "stegverse.intr.org-boundary.v1",
                "transition": {"reference": "probe", "authority_effect": "NONE"}, "payload": {"probe": "ping"},
                "evidence": {"ingress_receipt": None, "dispatch_receipt": None, "consumption_receipt": None,
                             "egress_receipt": None, "reconstruction_reference": None}}

    def write(self, name, value):
        path = Path(self._work.name) / name
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def boundary(self, envelope, out):
        return subprocess.run(["python3", "org-boundary/runtime/process_boundary.py", "--envelope", str(envelope),
                               "--out", str(out)], cwd=self.copy, capture_output=True, text=True)

    def run_once(self, ingress, egress):
        return subprocess.run(["python3", "resident-runtime/run_once.py", "--ingress", str(ingress),
                               "--egress", str(egress)], cwd=self.copy, capture_output=True, text=True,
                              env={**os.environ, "PYTHONPATH": str(self.copy / "resident-runtime")})

    def six_field(self, run, code, terminal):
        self.assertNotIn("Traceback", run.stderr)
        record = json.loads(run.stdout.splitlines()[-1])
        self.assertEqual((record["disposition"], record["failure_code"], record["terminal"]),
                         ("FAIL_CLOSED", code, terminal))
        for field in ("failed_predicate", "detail", "required_evidence_or_repair", "retry_entrypoint",
                      "owning_existing_goal", "next_attempt"):
            self.assertTrue(record[field], field)
        return record

    def test_process_boundary_exits_65_for_a_bad_crossing_and_75_for_its_own_write_fault(self):
        out = Path(self._work.name) / "out" / "execution.json"
        for name, value in (("missing.json", None), ("not-json.json", "{not json"), ("list.json", "[1]"),
                            ("fields.json", {"packet_id": "x"}),
                            ("elsewhere.json", {**self.envelope(), "destination": {"org": PEER, "service": "x"}})):
            with self.subTest(input=name):
                path = Path(self._work.name) / name if value is None else self.write(name, value)
                run = self.boundary(path, out)
                self.assertEqual(run.returncode, 65, run.stderr)
                self.six_field(run, "PROCESS_BOUNDARY_INPUT_FAULT", True)
                self.assertFalse(out.exists())
        blocked = self.write("blocked", "a file where the --out directory must be")
        run = self.boundary(self.write("good.json", self.envelope()), blocked / "execution.json")
        self.assertEqual(run.returncode, 75, run.stderr)
        self.six_field(run, "PROCESS_BOUNDARY_WRITE_FAULT", False)
        run = self.boundary(self.write("good.json", self.envelope()), out)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(out.read_text())["consumed"])

    def stub_boundary(self, status, record):
        """Replace the copy's process_boundary with one that exits `status`, printing `record`."""
        path = self.copy / "org-boundary/runtime/process_boundary.py"
        original = path.read_text(encoding="utf-8")
        path.write_text("import json, sys\nprint(json.dumps(%r))\nsys.exit(%d)\n" % (record, status), encoding="utf-8")
        return lambda: path.write_text(original, encoding="utf-8")

    def test_run_once_keeps_75_non_terminal_and_65_terminal(self):
        ingress, egress = self.write("ingress.json", self.envelope()), Path(self._work.name) / "egress" / "egress.json"
        restore = self.stub_boundary(75, {"disposition": "FAIL_CLOSED", "failure_code": "PROCESS_BOUNDARY_WRITE_FAULT",
                                          "terminal": False, "failed_predicate": "P", "detail": "d",
                                          "required_evidence_or_repair": "r", "retry_entrypoint": "e",
                                          "owning_existing_goal": "g", "next_attempt": "n"})
        run = self.run_once(ingress, egress)
        restore()
        self.assertEqual(run.returncode, 75, run.stderr)
        self.six_field(run, "PROCESS_BOUNDARY_WRITE_FAULT", False)
        self.assertFalse(egress.exists())
        # The same run then completes the crossing, once.
        run = self.run_once(ingress, egress)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(egress.read_text())["payload"]["request_packet_id"], "probe-pb")
        egress.unlink()
        restore = self.stub_boundary(65, {"disposition": "FAIL_CLOSED", "failure_code": "PROCESS_BOUNDARY_INPUT_FAULT",
                                          "terminal": True, "failed_predicate": "P", "detail": "d",
                                          "required_evidence_or_repair": "r", "retry_entrypoint": "e",
                                          "owning_existing_goal": "g", "next_attempt": "n"})
        run = self.run_once(ingress, egress)
        restore()
        self.assertEqual(run.returncode, 65, run.stderr)
        self.six_field(run, "PROCESS_BOUNDARY_INPUT_FAULT", True)
        self.assertFalse(egress.exists())

    def test_run_once_own_faults_split_the_same_way(self):
        egress = Path(self._work.name) / "egress" / "egress.json"
        for name, value in (("missing.json", None), ("not-json.json", "{not json"),
                            ("wrong.json", {**self.envelope(), "direction": "EGRESS"})):
            with self.subTest(input=name):
                path = Path(self._work.name) / name if value is None else self.write(name, value)
                run = self.run_once(path, egress)
                self.assertEqual(run.returncode, 65, run.stderr)
                self.six_field(run, "RUN_ONCE_INPUT_FAULT", True)
        blocked = self.write("blocked-egress", "a file where the --egress directory must be")
        run = self.run_once(self.write("ingress.json", self.envelope()), blocked / "egress.json")
        self.assertEqual(run.returncode, 75, run.stderr)
        self.six_field(run, "RUN_ONCE_WRITE_FAULT", False)
        self.assertFalse(egress.exists())
