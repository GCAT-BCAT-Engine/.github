"""Companion committed-request binding receipts (lead rulings 20:08Z-20:14Z, VALIDATOR V-P11).

resident-runtime/intr_destination_ingress.py is the InTr lane's surface, kept
byte-identical to main, so its receipts do not carry the committed request
that triggered them. resident-runtime/committed_request_binding.py binds the
two with one stegverse.committed-request-binding-receipt/v1 per transition,
on its own committed-request-bindings/ chain in the same ledger root and ref.

The seven conditions are each asserted here:
  (1) the binding is in the same commit as the receipts it binds (git ref);
  (2) the bound receipts' sha256 and parent are checkable from the ref alone;
  (3) the bindings chain is hash-linked and append-only;
  (4) a replay mints no second binding; another digest is REPLAY_MISMATCH;
  (5) each binding carries the organization chain HEAD at append time;
  (6) it rides the same fast-forward push, and the fresh-fetch readback
      reports the bindings HEAD and stays ALLOW;
  (7) a missing or mismatched binding is FAIL_CLOSED BINDING_ABSENT.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
INTR = ROOT / "resident-runtime/intr_destination_ingress.py"
# INTR_PATH_FILE_BYTE_IDENTICAL_TO_MAIN_MODULO_GRADED_EXCEPTION_FIXES (lead 20:16Z, corrected 20:18Z):
# the InTr lane's intr_destination_ingress.py differs from main 620a5cc only by these graded
# exception fixes, held on this branch for Grok Lane B to port (org#207 6389029590).
INTR_MAIN_COMMIT = "620a5ccbfc26463afe829f64dc6cf76ce85477ac"
INTR_MAIN_SHA256 = "df72783f26f82ff9ec84f6b2d4c5a6111da24e9addbb1e19a00ea00661dade60"
INTR_EXCEPTION_COMMITS = ("3e09c4c", "442d542", "6f15f4d", "2c613bb", "2a18232", "a397e06", "1585bf2")
INTR_EXPECTED_SHA256 = "d8c23aa501cfcb0e028c4ef91832da5e267376a9aab16d2fe454635a82ffd6bc"
LEDGER_REF = "refs/stegverse/organization-ledger"
NAMESPACE = "repository-ledger/GCAT-BCAT-Engine/.github"
REQUEST = ".stegverse/intr-destination/self-closure-packet.json"
DIGEST = "sha256:" + "c" * 64
OTHER = "sha256:" + "d" * 64
SIX = ("failed_predicate", "required_evidence_or_repair", "retry_entrypoint", "owning_existing_goal", "next_attempt")


def _module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


binding = _module("committed_request_binding_under_test", "resident-runtime/committed_request_binding.py")
store_module = binding.S
REQUEST_ARG = REQUEST + "=" + DIGEST
REQUEST_RECORD = {"path": REQUEST, "sha256": DIGEST, "hb_epoch_source": "COMMITTED_REQUEST"}


class LedgerCase(unittest.TestCase):
    """Both ledger roots redirected; self_close is run through main's own CLI."""

    git = False

    def setUp(self):
        self._work = tempfile.TemporaryDirectory()
        self.addCleanup(self._work.cleanup)
        work = Path(self._work.name)
        if self.git:
            self.git_dir = work / "ledger.git"
            subprocess.run(["git", "init", "-q", "--bare", str(self.git_dir)], check=True)
            org = "git+" + str(self.git_dir) + "#" + LEDGER_REF
            repo = org + ":" + NAMESPACE
        else:
            org, repo = str(work / "org-ledger"), str(work / "repo-ledger")
        patcher = mock.patch.dict(os.environ, {"STEGVERSE_ORG_LEDGER_ROOT": org, "STEGVERSE_REPO_LEDGER_ROOT": repo})
        patcher.start()
        self.addCleanup(patcher.stop)

    def stores(self):
        return (store_module.open_store(store_module.parse_locator(os.environ["STEGVERSE_ORG_LEDGER_ROOT"])),
                store_module.open_store(store_module.parse_locator(os.environ["STEGVERSE_REPO_LEDGER_ROOT"])))

    def self_close(self, communication_id="probe-binding"):
        out = Path(self._work.name) / (communication_id + ".json")
        run = subprocess.run([sys.executable, str(INTR), "--self-close", "--communication-id", communication_id,
                              "--registry", str(ROOT / "org-boundary/registry/services.json"),
                              "--out", str(out), "--hb-epoch", "4096"],
                             env=dict(os.environ), capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return json.loads(out.read_text(encoding="utf-8")), out

    def bind_cli(self, result_path, request=REQUEST_ARG, *extra):
        return subprocess.run([sys.executable, str(ROOT / "resident-runtime/committed_request_binding.py"), "bind",
                               "--committed-request", request, "--ingress-result", str(result_path),
                               "--hb-epoch", "4096", *extra], env=dict(os.environ), capture_output=True, text=True)

    def bind(self, result, request=REQUEST_ARG, **extra):
        return binding.bind(request, repository_receipt_sha256=result["repository_receipt_sha256"],
                            organization_receipt_sha256=result["organization_receipt_sha256"], hb_epoch=4096, **extra)

    def assert_refused(self, raised, code):
        refusal = raised.exception.refusal
        self.assertEqual((refusal["disposition"], refusal["failure_code"], refusal["terminal"]),
                         ("FAIL_CLOSED", code, True))
        for field in SIX:
            self.assertTrue(refusal[field], field)
        self.assertIs(refusal["consequence_committed"], False)


class InTrSurfaceIsMainTests(unittest.TestCase):
    def test_the_intr_destination_ingress_is_main_plus_only_the_graded_exception_fixes(self):
        """Any other difference from main, a documentation edit included, fails here."""
        self.assertEqual(hashlib.sha256(INTR.read_bytes()).hexdigest(), INTR_EXPECTED_SHA256)
        self.assertEqual(INTR_EXCEPTION_COMMITS, ("3e09c4c", "442d542", "6f15f4d", "2c613bb", "2a18232",
                                                  "a397e06", "1585bf2"))
        self.assertNotIn("committed_request", INTR.read_text(encoding="utf-8"))


class PosixBindingTests(LedgerCase):
    def test_a_binding_matches_the_receipts_it_binds_byte_for_byte(self):
        """(2), (5): the bound receipts' digest and parent, and the organization HEAD."""
        result, _ = self.self_close()
        recorded = self.bind(result)
        org, repo = self.stores()
        self.assertEqual(recorded["schema"], "stegverse.committed-request-binding-receipt/v1")
        self.assertEqual((recorded["committed_request"], recorded["hb_epoch"], recorded["replayed"]),
                         (REQUEST_RECORD, 4096, False))
        for entry, store in zip(recorded["bound_receipts"], (repo, org)):
            receipt = store.get(store_module.receipt_key(entry["receipt_sha256"]))
            self.assertEqual(entry["receipt_sha256"], receipt["receipt_sha256"])
            self.assertEqual(entry["previous_receipt_sha256"], receipt["previous_receipt_sha256"])
            body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            self.assertEqual(binding.K.sha(body), entry["receipt_sha256"])
        self.assertEqual([entry["ledger"] for entry in recorded["bound_receipts"]], ["repository", "organization"])
        self.assertEqual(recorded["organization_head_receipt_sha256"], org.get("HEAD.json")["receipt_sha256"])
        self.assertEqual(recorded["organization_head_receipt_sha256"], result["organization_receipt_sha256"])
        # The InTr receipts are as main's operation writes them: no committed_request field.
        self.assertNotIn("committed_request", repo.get(store_module.receipt_key(result["repository_receipt_sha256"]))["evidence"])
        verified = binding.verify(expected=[(REQUEST_ARG, result["organization_receipt_sha256"])])
        self.assertEqual((verified["disposition"], verified["bindings_head_sha256"], verified["bindings_chain_length"]),
                         ("ALLOW", recorded["binding_sha256"], 1))

    def test_the_bindings_chain_is_hash_linked_and_append_only(self):
        """(3): each binding names the previous one; any edit breaks the chain."""
        first = self.bind(self.self_close("probe-binding-1")[0])
        second = self.bind(self.self_close("probe-binding-2")[0], REQUEST + "=" + OTHER)
        self.assertEqual((first["previous_binding_sha256"], second["previous_binding_sha256"]),
                         (None, first["binding_sha256"]))
        org, _ = self.stores()
        self.assertEqual([b["binding_sha256"] for b in binding.chain(org)],
                         [first["binding_sha256"], second["binding_sha256"]])
        path = Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / binding.binding_key(first["binding_sha256"])
        tampered = json.loads(path.read_text())
        tampered["hb_epoch"] = 4097
        path.write_text(json.dumps(tampered))
        with self.assertRaises(binding.BindingRefused) as raised:
            binding.verify()
        self.assert_refused(raised, "COMMITTED_REQUEST_BINDING_ABSENT")

    def test_a_replay_mints_no_second_binding_and_another_request_is_refused(self):
        """(4)."""
        result, _ = self.self_close()
        first = self.bind(result)
        replay = self.bind(self.self_close()[0])
        self.assertEqual((replay["replayed"], replay["binding_sha256"]), (True, first["binding_sha256"]))
        org, _ = self.stores()
        self.assertEqual(len(binding.chain(org)), 1)
        before = sorted(p.read_bytes() for p in Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]).rglob("*.json"))
        with self.assertRaises(binding.BindingRefused) as raised:
            self.bind(result, REQUEST + "=" + OTHER)
        self.assert_refused(raised, "COMMITTED_REQUEST_REPLAY_MISMATCH")
        after = sorted(p.read_bytes() for p in Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]).rglob("*.json"))
        self.assertEqual(after, before)

    def test_a_malformed_request_or_an_unreadable_receipt_writes_nothing(self):
        result, result_path = self.self_close()
        org_root = Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"])
        for request in ("no-digest", REQUEST + "=sha256:short", "=" + DIGEST, REQUEST + "=" + "c" * 71,
                        REQUEST + "=sha256:" + "C" * 64):
            with self.subTest(request=request):
                run = self.bind_cli(result_path, request)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertNotIn("Traceback", run.stderr)
                refusal = json.loads(run.stdout)
                self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("COMMITTED_REQUEST_INVALID", True))
                self.assertFalse((org_root / binding.CHAIN).exists())
        for field, value in (("repository_receipt_sha256", "sha256:" + "e" * 64),
                             ("organization_receipt_sha256", "sha256:" + "e" * 64),
                             ("organization_receipt_sha256", None)):
            with self.subTest(field=field, value=value):
                with self.assertRaises(binding.BindingRefused) as raised:
                    binding.bind(REQUEST_ARG, hb_epoch=4096, **{**{key: result[key] for key in (
                        "repository_receipt_sha256", "organization_receipt_sha256")}, field: value})
                self.assert_refused(raised, "BOUND_RECEIPT_UNREADABLE")
                self.assertFalse((org_root / binding.CHAIN).exists())

    def test_a_non_finite_epoch_or_value_is_refused(self):
        result, _ = self.self_close()
        for epoch in (float("nan"), float("inf"), "NaN", True):
            with self.subTest(epoch=epoch):
                with self.assertRaises(binding.BindingRefused):
                    binding.bind(REQUEST_ARG, repository_receipt_sha256=result["repository_receipt_sha256"],
                                 organization_receipt_sha256=result["organization_receipt_sha256"], hb_epoch=epoch)
        with self.assertRaises(ValueError):
            binding.K.canon({"x": float("nan")})
        with self.assertRaises(ValueError):
            store_module._document_bytes({"x": float("nan")})

    def test_a_missing_or_mismatched_binding_is_never_a_silent_allow(self):
        """(7)."""
        result, _ = self.self_close()
        with self.assertRaises(binding.BindingRefused) as raised:
            binding.verify(expected=[(REQUEST_ARG, result["organization_receipt_sha256"])])
        self.assert_refused(raised, "COMMITTED_REQUEST_BINDING_ABSENT")
        self.bind(result)
        with self.assertRaises(binding.BindingRefused) as raised:
            binding.verify(expected=[(REQUEST + "=" + OTHER, result["organization_receipt_sha256"])])
        self.assert_refused(raised, "COMMITTED_REQUEST_BINDING_ABSENT")
        # A bound receipt edited after the binding fails verification too.
        path = Path(os.environ["STEGVERSE_REPO_LEDGER_ROOT"]) / store_module.receipt_key(result["repository_receipt_sha256"])
        receipt = json.loads(path.read_text())
        receipt["evidence"]["communication_id"] = "tampered"
        path.write_text(json.dumps(receipt))
        with self.assertRaises(binding.BindingRefused) as raised:
            binding.verify()
        self.assert_refused(raised, "BOUND_RECEIPT_UNREADABLE")


class BindingFaultTests(LedgerCase):
    """Write faults are six-field and non-terminal, and the retry completes once; a torn read is six-field."""

    def test_a_write_fault_at_either_document_is_retried_to_exactly_one_binding(self):
        result, _ = self.self_close()
        real_put = store_module.PosixLedgerStore.put
        for failing in (binding.CHAIN + "receipts/", binding.BINDINGS_HEAD):
            with self.subTest(failing=failing):
                shutil.rmtree(Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / binding.CHAIN, ignore_errors=True)

                def put(store, key, value, failing=failing):
                    if key.startswith(failing):
                        raise OSError(28, "No space left on device")
                    return real_put(store, key, value)
                with mock.patch.object(store_module.PosixLedgerStore, "put", put):
                    with self.assertRaises(binding.BindingWriteFault) as raised:
                        self.bind(result)
                refusal = raised.exception.refusal
                self.assertEqual((refusal["failure_code"], refusal["terminal"], refusal["consequence_committed"]),
                                 ("COMMITTED_REQUEST_BINDING_WRITE_FAILED", False, "UNDETERMINED_RETRY_IS_IDEMPOTENT"))
                for field in SIX:
                    self.assertTrue(refusal[field], field)
                self.assertIs(raised.exception.writer_fault, True)
                retried = self.bind(result)
                self.assertIs(retried["replayed"], False)
                org, _ = self.stores()
                self.assertEqual([b["binding_sha256"] for b in binding.chain(org)], [retried["binding_sha256"]])
                self.assertEqual(len(list((Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / binding.CHAIN
                                           / "receipts").glob("*.json"))), 1)
                self.assertIs(self.bind(result)["replayed"], True)

    def test_a_torn_bindings_head_is_a_six_field_refusal_never_a_traceback(self):
        result, result_path = self.self_close()
        self.bind(result)
        head = Path(os.environ["STEGVERSE_ORG_LEDGER_ROOT"]) / binding.BINDINGS_HEAD
        head.write_text('{"binding_sha256": "sha256:', encoding="utf-8")
        for call in (lambda: binding.verify(), lambda: self.bind(result)):
            with self.assertRaises(binding.BindingRefused) as raised:
                call()
            self.assert_refused(raised, "COMMITTED_REQUEST_BINDING_ABSENT")
        run = self.bind_cli(result_path)
        self.assertEqual(run.returncode, 1)
        self.assertNotIn("Traceback", run.stderr)
        self.assertEqual(json.loads(run.stdout)["failure_code"], "COMMITTED_REQUEST_BINDING_ABSENT")


class ForgedCommittedRequestTests(LedgerCase):
    """Rows 5 and 7 (VALIDATOR V-P11 pre-read at 9cb1dfd): a committed request reaches the ledger only
    through the binding, never from caller evidence or from a receipt off the repository ledger."""

    FORGED = {"path": REQUEST, "sha256": OTHER, "hb_epoch_source": "COMMITTED_REQUEST"}

    def emit_cli(self, evidence):
        return subprocess.run([sys.executable, str(ROOT / ".stegverse/transition-ledger/emit.py"),
                               "--transition-id", "probe-forged", "--transition-class", "CLASS",
                               "--predecessor-state-sha256", "sha256:" + "a" * 64,
                               "--successor-state-sha256", "sha256:" + "b" * 64,
                               "--evidence-json", json.dumps(evidence), "--hb-epoch", "4096"],
                              env=dict(os.environ), capture_output=True, text=True)

    def aggregate_cli(self, receipt_path, boundary=None):
        return subprocess.run([sys.executable, str(ROOT / "resident-runtime/aggregate_repo_transition.py"),
                               "--repo-receipt", str(receipt_path), "--predecessor-org-state-sha256", "FROM_HEAD",
                               "--successor-org-state-sha256", "sha256:" + "f" * 64, "--hb-epoch", "4096",
                               "--boundary-evidence-json", json.dumps(boundary or {})],
                              env=dict(os.environ), capture_output=True, text=True)

    def ledger_files(self):
        return sorted((str(p), p.read_bytes()) for name in ("STEGVERSE_ORG_LEDGER_ROOT", "STEGVERSE_REPO_LEDGER_ROOT")
                      for p in Path(os.environ[name]).rglob("*") if p.is_file())

    def assert_refused_json(self, run, code):
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertNotIn("Traceback", run.stderr)
        refusal = json.loads(run.stdout.splitlines()[-1])
        self.assertEqual((refusal["disposition"], refusal["failure_code"], refusal["terminal"]),
                         ("FAIL_CLOSED", code, True))
        for field in SIX:
            self.assertTrue(refusal[field], field)

    def test_row_5_caller_evidence_cannot_carry_a_committed_request_at_any_depth(self):
        emit = _module("emit_forgery_probe", ".stegverse/transition-ledger/emit.py")
        aggregate = _module("aggregate_forgery_probe", "resident-runtime/aggregate_repo_transition.py")
        self.self_close()
        before = self.ledger_files()
        for evidence in ({"committed_request": self.FORGED}, {"a": {"b": [{"committed_request": self.FORGED}]}}):
            with self.subTest(evidence=evidence, writer="emit CLI"):
                self.assert_refused_json(self.emit_cli(evidence), "FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON")
            with self.subTest(evidence=evidence, writer="emit.append"):
                with self.assertRaises(binding.K.CallerEvidenceRefused.__mro__[1]) as raised:
                    emit.append("probe-forged", "CLASS", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                                evidence, "NONE", 4096)
                self.assertEqual(raised.exception.refusal["failure_code"], "FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON")
            source, = [p for p in Path(os.environ["STEGVERSE_REPO_LEDGER_ROOT"]).glob("receipts/*.json")]
            with self.subTest(evidence=evidence, writer="aggregate CLI"):
                self.assert_refused_json(self.aggregate_cli(source, evidence),
                                         "FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON")
            with self.subTest(evidence=evidence, writer="aggregate.append"):
                with self.assertRaises(ValueError) as raised:
                    aggregate.append(json.loads(source.read_text()), "REPO_STATE_PROPAGATION", "FROM_HEAD",
                                     "sha256:" + "f" * 64, evidence, "NONE", hb_epoch=4096)
                self.assertEqual(raised.exception.refusal["failure_code"], "FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON")
        self.assertEqual(self.ledger_files(), before)

    def test_row_7_a_source_receipt_off_the_repository_ledger_is_refused(self):
        result, _ = self.self_close()
        repo_root = Path(os.environ["STEGVERSE_REPO_LEDGER_ROOT"])
        on_ledger = json.loads((repo_root / store_module.receipt_key(result["repository_receipt_sha256"])).read_text())
        work = Path(self._work.name)

        def rehashed(receipt):
            body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            return {**body, "receipt_sha256": binding.K.sha(body)}
        forged_off_ledger = rehashed({**on_ledger, "transition_id": "probe-forged-off-ledger",
                                      "evidence": {**on_ledger["evidence"], "committed_request": self.FORGED}})
        tampered = rehashed({**on_ledger, "evidence": {**on_ledger["evidence"], "communication_id": "tampered"}})
        # OFF_LEDGER_SOURCE_RECEIPT_WITHOUT_BINDING_ACCEPTED: the ledger check is unconditional, so a
        # self-consistent receipt that names no committed request and was never appended is refused too.
        unbound_off_ledger = rehashed({**on_ledger, "transition_id": "probe-unbound-off-ledger"})
        self.assertIsNone(binding.K.committed_request_path(unbound_off_ledger))
        not_a_repository_receipt = {**unbound_off_ledger, "schema": "stegverse.canonical-state-transition-receipt/v1"}
        cases = {"a rehashed receipt never on the ledger, with a forged committed request": forged_off_ledger,
                 "a rehashed receipt never on the ledger, with no committed request": unbound_off_ledger,
                 "an on-ledger receipt tampered and rehashed": tampered,
                 "a receipt that is not a repository receipt": not_a_repository_receipt}
        before = self.ledger_files()
        for case, receipt in cases.items():
            with self.subTest(case=case):
                path = work / "forged.json"
                path.write_text(json.dumps(receipt))
                self.assert_refused_json(self.aggregate_cli(path), "SOURCE_RECEIPT_NOT_ON_LEDGER")
        self.assertEqual(self.ledger_files(), before)
        # The receipt exactly as the ledger holds it, reachable from its HEAD, is consumed.
        path = work / "on-ledger.json"
        path.write_text(json.dumps(on_ledger))
        consumed = self.aggregate_cli(path)
        self.assertEqual(consumed.returncode, 0, consumed.stdout + consumed.stderr)


class SourceLedgerTests(LedgerCase):
    """SOURCE_RECEIPT_NOT_ON_LEDGER in process (lead 20:45Z), and V-P11 rows 8 and 9 on a POSIX pair:
    the source ledger is this repository's own, bound to the organization ledger the append writes,
    and a corrupt ledger node is a six-field refusal, never a traceback."""

    aggregate_cli = ForgedCommittedRequestTests.aggregate_cli
    ledger_files = ForgedCommittedRequestTests.ledger_files
    assert_refused_json = ForgedCommittedRequestTests.assert_refused_json

    def setUp(self):
        super().setUp()
        self.aggregate = _module("aggregate_source_ledger_probe", "resident-runtime/aggregate_repo_transition.py")
        result, _ = self.self_close()
        self.repo_root = Path(os.environ["STEGVERSE_REPO_LEDGER_ROOT"])
        self.digest = result["repository_receipt_sha256"]
        self.on_ledger = json.loads((self.repo_root / store_module.receipt_key(self.digest)).read_text())
        self.work = Path(self._work.name)

    def in_process(self, receipt):
        return self.aggregate.append(receipt, "REPO_STATE_PROPAGATION", "FROM_HEAD", "sha256:" + "f" * 64,
                                     {}, "NONE", hb_epoch=4096)

    def cli(self, receipt):
        path = self.work / "source.json"
        path.write_text(json.dumps(receipt))
        return self.aggregate_cli(path)

    def stack(self, node):
        """Publish `node` (rehashed onto the current HEAD) as the repository ledger's new HEAD."""
        head = json.loads((self.repo_root / "HEAD.json").read_text())
        body = {**{key: value for key, value in node.items() if key != "receipt_sha256"},
                "previous_receipt_sha256": head["receipt_sha256"]}
        digest = binding.K.sha(body)
        (self.repo_root / store_module.receipt_key(digest)).write_text(json.dumps({**body, "receipt_sha256": digest}))
        (self.repo_root / "HEAD.json").write_text(json.dumps({**head, "receipt_sha256": digest}))
        return digest

    def test_an_in_process_append_refuses_an_off_ledger_source_and_takes_the_on_ledger_one(self):
        body = {key: value for key, value in self.on_ledger.items() if key != "receipt_sha256"}
        body["transition_id"] = "probe-in-process-off-ledger"
        off_ledger = {**body, "receipt_sha256": binding.K.sha(body)}
        before = self.ledger_files()
        with self.assertRaises(self.aggregate.SourceReceiptUnverified) as raised:
            self.in_process(off_ledger)
        self.assert_refused(raised, "SOURCE_RECEIPT_NOT_ON_LEDGER")
        self.assertEqual(self.ledger_files(), before)
        self.assertEqual(self.in_process(dict(self.on_ledger))["repo_receipt_sha256"], self.digest)

    def test_row_8_a_source_ledger_not_bound_to_the_organization_ledger_is_refused(self):
        organization = os.environ["STEGVERSE_ORG_LEDGER_ROOT"]
        attacker = self.work / "attacker-ledger"
        shutil.copytree(self.repo_root, attacker)
        (self.work / "link-to-org").symlink_to(organization)
        cases = {"the organization ledger root itself": organization,
                 "a root inside the organization ledger": str(Path(organization) / "receipts"),
                 "a symlink to the organization ledger root": str(self.work / "link-to-org"),
                 "a git ref beside a POSIX organization ledger": "git+" + str(self.work / "x.git") + "#" + LEDGER_REF}
        before = self.ledger_files()
        for case, root in cases.items():
            with self.subTest(case=case), mock.patch.dict(os.environ, {"STEGVERSE_REPO_LEDGER_ROOT": root}):
                self.assert_refused_json(self.cli(self.on_ledger), "CALLER_CHOSEN_SOURCE_LEDGER_REJECTED")
        self.assertEqual(self.ledger_files(), before)

    def test_row_8_a_ledger_holding_another_repositorys_receipts_is_refused(self):
        self.stack({**self.on_ledger, "repository": "GCAT-BCAT-Engine/another", "transition_id": "foreign"})
        before = self.ledger_files()
        self.assert_refused_json(self.cli(self.on_ledger), "SOURCE_LEDGER_NOT_THIS_REPOSITORY_LEDGER")
        self.assertEqual(self.ledger_files(), before)

    def test_row_9_a_corrupt_ledger_node_is_a_terminal_six_field_refusal_never_a_traceback(self):
        newer = self.stack({**self.on_ledger, "transition_id": "probe-newer"})
        node = self.repo_root / store_module.receipt_key(newer)
        intact = node.read_bytes()
        cases = {"a truncated receipt": intact[: len(intact) // 2], "garbage bytes": b"\xff\xfe garbage",
                 "a JSON list": b"[1, 2]", "a receipt that is not its address": json.dumps(
                     {**json.loads(intact), "transition_id": "edited"}).encode()}
        before = self.ledger_files()
        for case, data in cases.items():
            with self.subTest(case=case):
                node.write_bytes(data)
                self.assert_refused_json(self.cli(self.on_ledger), "SOURCE_LEDGER_CORRUPT")
                node.write_bytes(intact)
        for case, data in {"a truncated HEAD": b'{"receipt_sha256": "sha', "a HEAD that is a list": b"[]"}.items():
            head = self.repo_root / "HEAD.json"
            kept = head.read_bytes()
            with self.subTest(case=case):
                head.write_bytes(data)
                self.assert_refused_json(self.cli(self.on_ledger), "SOURCE_LEDGER_CORRUPT")
                head.write_bytes(kept)
        self.assertEqual(self.ledger_files(), before)

    def test_row_9_a_ledger_read_fault_is_non_terminal_and_the_retry_aggregates_once(self):
        store_type = type(self.aggregate.open_store(self.repo_root))
        real_get = store_type.get

        def get(store, key):
            if Path(store.root).resolve() == self.repo_root.resolve() and key.startswith("receipts/"):
                raise PermissionError("probe: repository ledger unreadable")
            return real_get(store, key)
        before = self.ledger_files()
        with mock.patch.object(store_type, "get", get), \
                self.assertRaises(self.aggregate.SourceLedgerReadFailed) as raised:
            self.in_process(dict(self.on_ledger))
        refusal = raised.exception.refusal
        self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("SOURCE_LEDGER_READ_FAILED", False))
        self.assertTrue(raised.exception.writer_fault)
        for field in SIX:
            self.assertTrue(refusal[field], field)
        self.assertEqual(self.ledger_files(), before)
        self.assertEqual(self.in_process(dict(self.on_ledger))["repo_receipt_sha256"], self.digest)


class GitSourceLedgerTests(LedgerCase):
    """V-P11 row 8 on a git ref: the source ledger is the declared namespace on the organization
    ledger's own ref and repository (by realpath); an attacker's git dir, another repository's
    namespace or a symlink to another git dir is SOURCE_LEDGER_NOT_THIS_REPOSITORY_LEDGER."""

    git = True
    aggregate_cli = ForgedCommittedRequestTests.aggregate_cli
    assert_refused_json = ForgedCommittedRequestTests.assert_refused_json

    def tip(self):
        return subprocess.run(["git", "--git-dir", str(self.git_dir), "rev-parse", LEDGER_REF],
                              capture_output=True, text=True).stdout.strip()

    def receipt(self, locator, digest):
        return store_module.open_store(store_module.parse_locator(locator)).get(store_module.receipt_key(digest))

    def test_row_8_an_attacker_ledger_another_namespace_or_a_symlink_is_refused(self):
        work = Path(self._work.name)
        attacker = work / "attacker.git"
        subprocess.run(["git", "init", "-q", "--bare", str(attacker)], check=True)
        attacker_repo = "git+" + str(attacker) + "#" + LEDGER_REF + ":" + NAMESPACE
        with mock.patch.dict(os.environ, {"STEGVERSE_ORG_LEDGER_ROOT": "git+" + str(attacker) + "#" + LEDGER_REF,
                                          "STEGVERSE_REPO_LEDGER_ROOT": attacker_repo}):
            minted, _ = self.self_close("probe-attacker")
        fabricated = self.receipt(attacker_repo, minted["repository_receipt_sha256"])
        genuine_result, _ = self.self_close()
        genuine = self.receipt(os.environ["STEGVERSE_REPO_LEDGER_ROOT"], genuine_result["repository_receipt_sha256"])
        (work / "link.git").symlink_to(attacker)
        (work / "real-link.git").symlink_to(self.git_dir)
        other_namespace = "git+" + str(self.git_dir) + "#" + LEDGER_REF + ":repository-ledger/GCAT-BCAT-Engine/another"
        cases = {"the attacker's ledger": (attacker_repo, fabricated),
                 "a symlink to the attacker's git dir": (
                     "git+" + str(work / "link.git") + "#" + LEDGER_REF + ":" + NAMESPACE, fabricated),
                 "another repository's namespace on the organization ref": (other_namespace, genuine),
                 "another ref": ("git+" + str(self.git_dir) + "#refs/stegverse/other:" + NAMESPACE, genuine),
                 "a filesystem root beside a git organization ledger": (str(work / "repo-ledger"), genuine)}
        tip = self.tip()
        for case, (locator, receipt) in cases.items():
            with self.subTest(case=case), mock.patch.dict(os.environ, {"STEGVERSE_REPO_LEDGER_ROOT": locator}):
                path = work / "source.json"
                path.write_text(json.dumps(receipt))
                self.assert_refused_json(self.aggregate_cli(path), "CALLER_CHOSEN_SOURCE_LEDGER_REJECTED")
                self.assertEqual(self.tip(), tip)
        # The emitter's store counts where it resolves to the designated ledger: a symlink to the
        # organization ledger's own git dir is the same repository by realpath.
        with mock.patch.dict(os.environ, {"STEGVERSE_REPO_LEDGER_ROOT":
                                          "git+" + str(work / "real-link.git") + "#" + LEDGER_REF + ":" + NAMESPACE}):
            path = work / "source.json"
            path.write_text(json.dumps(genuine))
            consumed = self.aggregate_cli(path)
        self.assertEqual(consumed.returncode, 0, consumed.stdout + consumed.stderr)

    def test_row_8_the_designated_ledger_is_derived_from_the_contract_not_the_caller(self):
        """Lead 20:57Z: with no STEGVERSE_REPO_LEDGER_ROOT at all, the designated ledger is still the
        one verified against; an attacker receipt is refused and the genuine one consumed."""
        genuine_result, _ = self.self_close()
        genuine = self.receipt(os.environ["STEGVERSE_REPO_LEDGER_ROOT"], genuine_result["repository_receipt_sha256"])
        body = {key: value for key, value in genuine.items() if key != "receipt_sha256"}
        body["transition_id"] = "probe-unbound"
        unbound = {**body, "receipt_sha256": binding.K.sha(body)}
        environment = {key: value for key, value in os.environ.items() if key != "STEGVERSE_REPO_LEDGER_ROOT"}
        work = Path(self._work.name)
        runs = {}
        for name, receipt in (("unbound", unbound), ("genuine", genuine)):
            path = work / (name + ".json")
            path.write_text(json.dumps(receipt))
            with mock.patch.dict(os.environ, environment, clear=True):
                runs[name] = self.aggregate_cli(path)
        self.assert_refused_json(runs["unbound"], "SOURCE_RECEIPT_NOT_ON_LEDGER")
        self.assertEqual(runs["genuine"].returncode, 0, runs["genuine"].stdout + runs["genuine"].stderr)


class TrackedLedgerRootTests(unittest.TestCase):
    """Lead 20:59Z repair (a), V-P11 row 8 on POSIX: a filesystem ledger root that holds git-tracked
    files of this checkout is LEDGER_ROOT_NOT_CONTRACT_DESIGNATED, six fields, nothing aggregated; an
    untracked runner-temporary or test root stays allowed."""

    def test_a_ledger_committed_in_the_checkout_is_refused_and_an_untracked_one_allowed(self):
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        checkout = work / "checkout"
        shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        git = ["git", "-C", str(checkout), "-c", "user.name=probe", "-c", "user.email=probe@invalid"]
        subprocess.run(git + ["init", "-q"], check=True)
        source_root, org_root = work / "minted-repo-ledger", work / "org-ledger"
        environment = {**os.environ, "STEGVERSE_REPO_LEDGER_ROOT": str(source_root),
                       "STEGVERSE_ORG_LEDGER_ROOT": str(org_root)}
        minted = subprocess.run([sys.executable, str(checkout / ".stegverse/transition-ledger/emit.py"),
                                 "--transition-id", "probe-tracked", "--transition-class", "CLASS",
                                 "--predecessor-state-sha256", "sha256:" + "a" * 64,
                                 "--successor-state-sha256", "sha256:" + "b" * 64, "--hb-epoch", "4096"],
                                env=environment, capture_output=True, text=True)
        self.assertEqual(minted.returncode, 0, minted.stdout + minted.stderr)
        receipt = json.loads(minted.stdout.splitlines()[-1])
        source = work / "source.json"
        source.write_text(json.dumps(receipt))
        shutil.copytree(source_root, checkout / "fake-ledger")
        shutil.copytree(source_root, checkout / "untracked-ledger")
        subprocess.run(git + ["add", "-A", "--", ".", ":!untracked-ledger"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "probe"], check=True)

        def aggregate(root):
            return subprocess.run([sys.executable, str(checkout / "resident-runtime/aggregate_repo_transition.py"),
                                   "--repo-receipt", str(source), "--predecessor-org-state-sha256", "GENESIS",
                                   "--successor-org-state-sha256", "sha256:" + "f" * 64, "--hb-epoch", "4096"],
                                  env={**environment, "STEGVERSE_REPO_LEDGER_ROOT": str(root)},
                                  capture_output=True, text=True)
        refused = aggregate(checkout / "fake-ledger")
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertNotIn("Traceback", refused.stderr)
        refusal = json.loads(refused.stdout.splitlines()[-1])
        self.assertEqual((refusal["failure_code"], refusal["terminal"]), ("LEDGER_ROOT_NOT_CONTRACT_DESIGNATED", True))
        for field in SIX:
            self.assertTrue(refusal[field], field)
        self.assertFalse(org_root.exists())
        allowed = aggregate(checkout / "untracked-ledger")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)


class TupleEvidenceTests(LedgerCase):
    """V-P11 @042a986 row 2: a committed_request key inside a tuple (json.dumps writes it as an array)
    or any mapping is refused in process like one inside a list; a self-referring value ends the walk."""

    def test_a_committed_request_in_a_tuple_is_refused_in_process(self):
        emit = _module("emit_tuple_probe", ".stegverse/transition-ledger/emit.py")
        aggregate = _module("aggregate_tuple_probe", "resident-runtime/aggregate_repo_transition.py")
        forged = {"path": REQUEST, "sha256": OTHER, "hb_epoch_source": "COMMITTED_REQUEST"}
        for evidence in ({"t": ({"committed_request": forged},)}, {"t": [(1, ({"committed_request": forged},))]}):
            with self.subTest(evidence=evidence, writer="emit.append"):
                with self.assertRaises(ValueError) as raised:
                    emit.append("probe-tuple", "CLASS", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                                evidence, "NONE", 4096)
                self.assertEqual(raised.exception.refusal["failure_code"], "FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON")
            with self.subTest(evidence=evidence, writer="aggregate.append"):
                with self.assertRaises(ValueError) as raised:
                    aggregate.append({}, "REPO_STATE_PROPAGATION", "FROM_HEAD", "sha256:" + "f" * 64,
                                     evidence, "NONE", hb_epoch=4096)
                self.assertEqual(raised.exception.refusal["failure_code"], "FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON")
        for name in ("STEGVERSE_ORG_LEDGER_ROOT", "STEGVERSE_REPO_LEDGER_ROOT"):
            self.assertFalse(Path(os.environ[name]).exists(), name)

    def test_a_self_referring_value_ends_the_walk(self):
        cyclic = {"a": []}
        cyclic["a"].append(cyclic)
        self.assertIsNone(binding.K.committed_request_path(cyclic))
        cyclic["a"].append({"committed_request": 1})
        self.assertEqual(binding.K.committed_request_path(cyclic), "$.a[1].committed_request")


class GitRefBindingTests(LedgerCase):
    git = True

    def git_out(self, git_dir, *args):
        return subprocess.run(["git", "--git-dir", str(git_dir), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def tip(self):
        completed = subprocess.run(["git", "--git-dir", str(self.git_dir), "rev-parse", "--verify", "--quiet", LEDGER_REF],
                                   capture_output=True, text=True)
        return completed.stdout.strip() or ""

    def readback(self, git_dir, result_path, request=REQUEST_ARG):
        return subprocess.run([sys.executable, str(ROOT / "resident-runtime/organization_ledger_readback.py"),
                               "--location", "git+" + str(git_dir) + "#" + LEDGER_REF,
                               "--ingress-result", str(result_path), "--repository-namespace", NAMESPACE,
                               "--committed-request", request], capture_output=True, text=True)

    def test_end_to_end_on_the_ledger_ref(self):
        """(1), (5), (6), (7) on a git ref, through the workflow's own commands."""
        self.assertEqual(self.tip(), "")
        first, first_path = self.self_close("probe-git-1")
        genesis = self.bind_cli(first_path, REQUEST_ARG, "--since-tip", "")
        self.assertEqual(genesis.returncode, 0, genesis.stdout + genesis.stderr)
        # On a ref that did not exist, the first transition and its binding are its one root commit.
        self.assertIs(json.loads(genesis.stdout)["same_commit_as_bound_receipts"], True)
        self.assertEqual(self.git_out(self.git_dir, "rev-list", "--count", LEDGER_REF), "1")
        since = self.tip()
        result, result_path = self.self_close("probe-git-2")
        run = self.bind_cli(result_path, REQUEST + "=" + OTHER, "--since-tip", since)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        recorded = json.loads(run.stdout)
        self.assertIs(recorded["same_commit_as_bound_receipts"], True)
        # (1) one commit on top of the previous tip holds both InTr receipts and the binding.
        self.assertEqual(self.git_out(self.git_dir, "rev-list", "--count", since + ".." + LEDGER_REF), "1")
        changed = set(self.git_out(self.git_dir, "diff", "--name-only", since, LEDGER_REF).splitlines())
        self.assertTrue({store_module.receipt_key(result["organization_receipt_sha256"]),
                         NAMESPACE + "/" + store_module.receipt_key(result["repository_receipt_sha256"]),
                         binding.binding_key(recorded["binding_sha256"]), binding.BINDINGS_HEAD} <= changed, changed)
        # (5) the binding names the organization HEAD it was appended at.
        head = json.loads(self.git_out(self.git_dir, "show", LEDGER_REF + ":HEAD.json"))
        self.assertEqual(recorded["organization_head_receipt_sha256"], head["receipt_sha256"])
        # (6) one fast-forward push, then a fresh fetch, read back ALLOW with the bindings HEAD.
        remote = Path(self._work.name) / "remote.git"
        fresh = Path(self._work.name) / "fresh.git"
        for path in (remote, fresh):
            subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True)
        subprocess.run(["git", "--git-dir", str(self.git_dir), "push", "-q", str(remote), LEDGER_REF + ":" + LEDGER_REF],
                       check=True)
        subprocess.run(["git", "--git-dir", str(fresh), "fetch", "-q", str(remote), "+" + LEDGER_REF + ":" + LEDGER_REF],
                       check=True)
        read = self.readback(fresh, result_path, REQUEST + "=" + OTHER)
        self.assertEqual(read.returncode, 0, read.stdout + read.stderr)
        report = json.loads(read.stdout)
        self.assertEqual(report["disposition"], "ALLOW")
        self.assertEqual(report["committed_request_binding"]["bindings_head_sha256"], recorded["binding_sha256"])
        self.assertEqual(report["committed_request_binding"]["bindings_chain_length"], 2)
        # (7) the wrong request, or a ref without the binding, is refused six-field.
        wrong = self.readback(fresh, result_path, REQUEST_ARG)
        self.assertEqual(wrong.returncode, 1)
        refusal = json.loads(wrong.stdout)
        self.assertEqual((refusal["disposition"], refusal["failure_code"]),
                         ("FAIL_CLOSED", "COMMITTED_REQUEST_BINDING_ABSENT"))
        for field in SIX:
            self.assertTrue(refusal[field], field)

    def test_a_torn_append_is_detected_from_the_ref(self):
        """A transition whose receipts landed without their binding reads back BINDING_ABSENT."""
        result, result_path = self.self_close("probe-git-torn")
        read = self.readback(self.git_dir, result_path)
        self.assertEqual(read.returncode, 1)
        self.assertEqual(json.loads(read.stdout)["failure_code"], "COMMITTED_REQUEST_BINDING_ABSENT")

    def test_a_replay_on_the_ref_writes_no_commit(self):
        """(4) on the ref: the ref does not move."""
        result, result_path = self.self_close("probe-git-replay")
        self.assertEqual(self.bind_cli(result_path).returncode, 0)
        before = self.tip()
        again = self.bind_cli(result_path)
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIs(json.loads(again.stdout)["replayed"], True)
        self.assertEqual(self.tip(), before)
        mismatch = self.bind_cli(result_path, REQUEST + "=" + OTHER)
        self.assertEqual(json.loads(mismatch.stdout)["failure_code"], "COMMITTED_REQUEST_REPLAY_MISMATCH")
        self.assertEqual(self.tip(), before)


if __name__ == "__main__":
    unittest.main()
