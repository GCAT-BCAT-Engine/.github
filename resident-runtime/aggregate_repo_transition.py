#!/usr/bin/env python3
"""Append organization receipts with serialized, durable HEAD publication.

The organization ledger is local sovereign state. This emitter records
organization-level transition evidence and does not perform InTr transport.
Authority and time are constraint variables. A disposition is transition
evidence only.

Admission follows the `consumes` list in the organization ledger contract,
not a single hard-coded schema. Every state transition occurring within the
organization emits an organization receipt, so a canonical state transition
manifested through Interlock/InTr is admitted on its own terms and bound by
its own canonical digest.

The exact source transition receipt is retained under `source-receipts/` in
the same store transaction as the organization receipt and HEAD, so the
organization ledger can replay a source transition without the ledger that
emitted it (contract: preserves_source_transition_receipt).

The predecessor organization state is an explicit sha256 digest, FROM_HEAD or
GENESIS. FROM_HEAD binds the current HEAD receipt digest and is resolved inside
each compare-and-swap attempt, so a contended append cannot bind a stale
predecessor. GENESIS opens an empty chain and is accepted only while HEAD is
absent; a chain is never opened by default.
"""
from contextlib import nullcontext
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ledger_store import GIT_SCHEME, HEAD_KEY, RECEIPT_PREFIX, SOURCE_PREFIX, LedgerWriteFailed, open_store, parse_locator, receipt_key, source_key  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
C = json.loads((ROOT / ".stegverse/transition-ledger/org-contract.json").read_text())

_spec = importlib.util.spec_from_file_location("kernel", ROOT / "org-kernel/kernel.py")
kernel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kernel)  # noqa: E402



SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")

FROM_HEAD = "FROM_HEAD"
GENESIS = "GENESIS"


class OrgLedgerAppendRefused(SystemExit):
    """A refused append, carrying its disposition and failed predicate.

    A SystemExit, so command-line use and existing callers behave as before,
    while a caller that records dispositions reads them from the exception.
    Nothing is written when this is raised.
    """

    retry_entrypoint = "resident-runtime/aggregate_repo_transition.py::append"

    def __init__(self, disposition, failed_predicate):
        super().__init__(failed_predicate)
        self.disposition = disposition
        self.failed_predicate = failed_predicate


# An append's epoch is supplied by its caller and checked by the kernel's
# shared rule (SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH), as in
# StegVerse-Labs/.github WU-B13a. An absent or invalid one is refused
# six-field FAIL_CLOSED before the store is opened, and no clock is read.
EPOCH_RETRY_ENTRYPOINT = "resident-runtime/aggregate_repo_transition.py::append (hb_epoch=, or --hb-epoch)"
OrgLedgerEpochRefused = kernel.SuppliedEpochRefused


def epoch_refusal(hb_epoch):
    """The six-field FAIL_CLOSED refusal of an append's epoch, or None."""
    return kernel.writer_epoch_refusal(hb_epoch, retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)


def require_supplied_epoch(hb_epoch, provenance=None):
    """The heartbeat reference of the supplied epoch, or OrgLedgerEpochRefused.

    A CARRIED `provenance` is verified against the current organization head
    and kept on the reference, or refused CARRIED_PROVENANCE_UNVERIFIED.
    """
    return kernel.supplied_hb_reference(hb_epoch, retry_entrypoint=EPOCH_RETRY_ENTRYPOINT,
                                        provenance=provenance)


# A repository receipt is admitted as a source only when its heartbeat
# reference is a supplied epoch. One recorded from a clock sample, or one that
# does not mark its provenance, is refused six-field before the store is
# opened: no organization receipt, no retained source copy, no HEAD change.
SOURCE_RECEIPT_IS_CLOCK_PROVENANCE = "SOURCE_RECEIPT_IS_CLOCK_PROVENANCE"
SOURCE_PROVENANCE_PREDICATE = "SOURCE_RECEIPT_REFERENCES_A_SUPPLIED_HB_EPOCH"
SOURCE_PROVENANCE_REPAIR = (
    "a WU-B13 migration transition that rebinds the legacy repo receipt under a supplied epoch "
    "with provenance CARRIED:LEGACY_CLOCK_RECEIPT + source sha; existing receipts are never mutated")


def source_provenance_refusal(receipt):
    """The six-field FAIL_CLOSED of a source repository receipt's provenance, or None."""
    reference = receipt.get("hb_reference")
    if isinstance(reference, dict) and (reference.get("derived_from_clock") is True
                                        or "sampled_unix_ns" in reference):
        failure = (SOURCE_RECEIPT_IS_CLOCK_PROVENANCE,
                   "the source repository receipt's heartbeat reference is a clock reading")
    elif not isinstance(reference, dict):
        failure = (kernel.HB_EPOCH_PROVENANCE_UNMARKED,
                   "the source repository receipt carries no heartbeat reference")
    else:
        failure = kernel.supplied_epoch_failure(reference.get("epoch"), reference)
    if failure is None:
        return None
    code, detail = failure
    return {"disposition": "FAIL_CLOSED", "failure_code": code,
            "failed_predicate": SOURCE_PROVENANCE_PREDICATE, "detail": detail,
            "required_evidence_or_repair": SOURCE_PROVENANCE_REPAIR,
            "retry_entrypoint": EPOCH_RETRY_ENTRYPOINT,
            "owning_existing_goal": kernel.HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt": "append the rebinding migration transition's receipt instead; nothing was written",
            "consequence_committed": False}


def require_state_digest(field, value):
    """A field named *_sha256 must carry one, or the chain records a claim it cannot check."""
    if not isinstance(value, str) or not SHA256_REF.match(value):
        raise SystemExit("ORG_LEDGER_" + field.upper() + "_NOT_A_SHA256_DIGEST")
    return value


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


class LedgerLocationRequired(ValueError):
    """No ledger root was supplied; nothing is appended and nothing is derived."""

    failed_predicate = "LEDGER_LOCATION_REQUIRED_FROM_MATERIALIZER"

    def __init__(self, variable):
        super().__init__("ledger_location_required_from_materializer: " + variable)
        self.variable = variable


# A ledger location is supplied by the materializer. The designated
# organization ref is named by the organization contract. Until a location is
# supplied, every append refuses with the six fields of a non-ALLOW.
LOCATION_FAILURE_CODE = "LEDGER_LOCATION_NOT_SUPPLIED"
LOCATION_OWNING_GOAL = "ORGANIZATION-ROLE-RUNTIME-REALITY-DEPLOYMENT-001"


def location_next_attempt(variable):
    return ("rerun once " + variable + " is supplied; nothing was appended, "
            "so retry the same receipt unchanged")


def location_refusal(exc):
    """The append attempt's own disposition when no ledger root was supplied."""
    return {
        "schema": "stegverse.organization-ledger-append-refusal/v1",
        "organization": C["organization"],
        "disposition": "FAIL_CLOSED",
        "failed_predicate": exc.failed_predicate,
        "failure_code": LOCATION_FAILURE_CODE,
        "required_evidence_or_repair": "supply the organization ledger root as " + exc.variable,
        "retry_entrypoint": "resident-runtime/aggregate_repo_transition.py::append",
        "owning_existing_goal": LOCATION_OWNING_GOAL,
        "next_attempt": location_next_attempt(exc.variable),
        "consequence_committed": False,
        "authority_effect": "NONE_REFUSAL_ONLY",
    }


def sha(value):
    return "sha256:" + hashlib.sha256(canon(value)).hexdigest()


def ledger_root():
    """The organization ledger root, as supplied to this execution.

    The ledger is the organization's runtime reality, so its location is
    supplied by whatever materialized this execution, exactly as the mesh is.
    It is never derived from the host: a home directory belongs to whichever
    machine happens to run this, and a chain written there is discarded with
    an ephemeral execution while appearing to have been appended. With no
    supplied root the append fails closed at this boundary.

    A supplied `git+<repository>#<ref>` names a git ref rather than a
    directory (see `ledger_store.parse_locator`). Which location is the
    organization's ledger is named by the organization contract, never here.
    """
    override = os.getenv("STEGVERSE_ORG_LEDGER_ROOT")
    if override:
        return parse_locator(override)
    raise LedgerLocationRequired("STEGVERSE_ORG_LEDGER_ROOT")


def load(path):
    return json.loads(Path(path).read_text())


def verify_required_evidence(receipt):
    """Require exact inline canonical evidence bytes for organization-local replay.

    Organization replay must terminate on this chain alone, so a canonical state
    transition carries its own evidence bytes rather than a reachability promise.
    """
    manifest = receipt.get("required_evidence_manifest")
    if not isinstance(manifest, list):
        raise SystemExit("canonical required evidence manifest missing")
    seen = set()
    for item in manifest:
        if not isinstance(item, dict):
            raise SystemExit("canonical evidence entry invalid")
        for key in ("evidence_id", "evidence_type", "origin_transition_id",
                    "encoding", "sha256", "content"):
            if key not in item:
                raise SystemExit("canonical evidence field missing: " + key)
        identity = item["evidence_id"]
        if not isinstance(identity, str) or not identity or identity in seen:
            raise SystemExit("canonical evidence identity invalid")
        seen.add(identity)
        if (not isinstance(item["evidence_type"], str) or not item["evidence_type"]
                or item["origin_transition_id"] != receipt.get("transition_id")):
            raise SystemExit("canonical evidence transition binding invalid")
        encoding = item["encoding"]
        content = item["content"]
        if encoding == "canonical-json":
            raw = canon(content)
        elif encoding == "utf-8" and isinstance(content, str):
            raw = content.encode("utf-8")
        elif encoding == "base64" and isinstance(content, str):
            try:
                raw = base64.b64decode(content.encode("ascii"), validate=True)
            except (ValueError, UnicodeError) as exc:
                raise SystemExit("canonical evidence base64 invalid") from exc
        else:
            raise SystemExit("canonical evidence encoding invalid")
        digest = item["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit("canonical required evidence digest mismatch")


COMMITTED_REQUEST_DIGEST_UNVERIFIED = "COMMITTED_REQUEST_DIGEST_UNVERIFIED"
SOURCE_RECEIPT_NOT_ON_LEDGER = "SOURCE_RECEIPT_NOT_ON_LEDGER"
SOURCE_LEDGER_NOT_THIS_REPOSITORY_LEDGER = "SOURCE_LEDGER_NOT_THIS_REPOSITORY_LEDGER"
CALLER_CHOSEN_SOURCE_LEDGER_REJECTED = "CALLER_CHOSEN_SOURCE_LEDGER_REJECTED"
LEDGER_ROOT_NOT_CONTRACT_DESIGNATED = "LEDGER_ROOT_NOT_CONTRACT_DESIGNATED"
SOURCE_LEDGER_CORRUPT = "SOURCE_LEDGER_CORRUPT"
SOURCE_LEDGER_READ_FAILED = "SOURCE_LEDGER_READ_FAILED"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SourceReceiptUnverified(ValueError):
    """A source receipt this run cannot verify against the repository ledger; six fields, terminal."""

    def __init__(self, detail, predicate, failure_code=SOURCE_RECEIPT_NOT_ON_LEDGER):
        super().__init__(detail)
        self.refusal = {
            "disposition": "FAIL_CLOSED", "failure_code": failure_code, "terminal": True,
            "failed_predicate": predicate, "detail": detail,
            "required_evidence_or_repair": ("supply a repository receipt exactly as this repository's own ledger "
                                            "holds it, reachable from its HEAD, carrying no committed request"),
            "retry_entrypoint": EPOCH_RETRY_ENTRYPOINT, "owning_existing_goal": kernel.HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt": "nothing was aggregated; supply the receipt the ledger holds", "consequence_committed": False}


class SourceLedgerReadFailed(OSError):
    """This boundary could not read the repository ledger; six fields, non-terminal: a writer
    fault (`writer_fault`), so a frame is deferred and the same run is retried."""

    writer_fault = True

    def __init__(self, detail):
        super().__init__(detail)
        self.refusal = {
            "disposition": "FAIL_CLOSED", "failure_code": SOURCE_LEDGER_READ_FAILED, "terminal": False,
            "failed_predicate": "THIS_BOUNDARY_READS_THE_REPOSITORY_LEDGER", "detail": detail,
            "required_evidence_or_repair": "the repository ledger is readable by this boundary",
            "retry_entrypoint": EPOCH_RETRY_ENTRYPOINT, "owning_existing_goal": kernel.HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt": "run the same command again; nothing was aggregated", "consequence_committed": False}


def _repository_contract():
    return json.loads((ROOT / ".stegverse/transition-ledger/contract.json").read_text())


def _real(path):
    return os.path.realpath(os.fspath(path))


def _holds_tracked_files(root):
    """True when `root` is, holds or contains part of this checkout's git-tracked tree.

    A root outside the checkout holds none of its files. One inside it is listed with
    `git ls-files`; a checkout that cannot be listed is taken to hold tracked files."""
    checkout, real = _real(ROOT), _real(root)
    if real != checkout and not real.startswith(checkout + os.sep) and not checkout.startswith(real + os.sep):
        return False
    scope = os.path.relpath(real, checkout) if real.startswith(checkout + os.sep) else "."
    try:
        listed = subprocess.run(["git", "-C", checkout, "ls-files", "-z", "--", scope],
                                capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return True
    return listed.returncode != 0 or bool(listed.stdout.strip(b"\0"))


def source_ledger(target):
    """This repository's designated ledger (contract.json repository_ledger_location), the only
    ledger a source receipt is verified against, bound to the organization ledger `target`.

    - git organization ledger: the designated ref and namespace in the organization ledger's
      own repository, by realpath. It is derived, not read from the caller: a
      STEGVERSE_REPO_LEDGER_ROOT (the emitter's store) counts only where it resolves to that
      same ledger, and any other value is CALLER_CHOSEN_SOURCE_LEDGER_REJECTED.
    - POSIX organization root (runner-temporary or test, never the published ref): the
      contract designates no POSIX location, so the emitter's POSIX root is used; it must not
      overlap the organization root (CALLER_CHOSEN_SOURCE_LEDGER_REJECTED), and neither root
      may hold git-tracked files of this checkout (LEDGER_ROOT_NOT_CONTRACT_DESIGNATED).
    No request field or argument names a source ledger. Six fields, nothing aggregated.
    """
    def refuse(code, detail):
        raise SourceReceiptUnverified(detail, "THE_SOURCE_LEDGER_IS_THIS_REPOSITORYS_DESIGNATED_LEDGER", code)
    declared = _repository_contract().get("repository_ledger_location") or {}
    supplied = os.environ.get("STEGVERSE_REPO_LEDGER_ROOT")
    try:
        location = parse_locator(supplied) if supplied else None
    except ValueError as exc:
        refuse(CALLER_CHOSEN_SOURCE_LEDGER_REJECTED, "STEGVERSE_REPO_LEDGER_ROOT names no ledger: " + str(exc)[:200])
    if getattr(target, "kind", None) == "GIT_REF":
        ref, namespace = declared.get("ref"), declared.get("namespace")
        if not ref or not namespace or target.ref != ref:
            refuse(LEDGER_ROOT_NOT_CONTRACT_DESIGNATED, "the organization ledger ref " + str(target.ref)
                   + " is not the ref contract.json designates for this repository's ledger, " + str(ref))
        if location is not None and (not hasattr(location, "ref") or _real(location.repository) != _real(target.repository)
                                     or location.ref != ref or location.namespace != namespace):
            refuse(CALLER_CHOSEN_SOURCE_LEDGER_REJECTED,
                   "STEGVERSE_REPO_LEDGER_ROOT " + str(supplied) + " is not this repository's designated ledger "
                   + ref + ":" + namespace + " in " + _real(target.repository))
        return open_store(parse_locator(GIT_SCHEME + _real(target.repository) + "#" + ref + ":" + namespace))
    root = getattr(target, "root", None)
    if location is None:
        refuse(LEDGER_ROOT_NOT_CONTRACT_DESIGNATED, "STEGVERSE_REPO_LEDGER_ROOT is not supplied and contract.json "
               "designates no filesystem ledger beside a filesystem organization root")
    if hasattr(location, "ref") or root is None:
        refuse(CALLER_CHOSEN_SOURCE_LEDGER_REJECTED, "a filesystem organization root takes a filesystem repository "
               "ledger, not " + str(supplied))
    source, organization = _real(location), _real(root)
    if source == organization or source.startswith(organization + os.sep) or organization.startswith(source + os.sep):
        refuse(CALLER_CHOSEN_SOURCE_LEDGER_REJECTED,
               "the repository ledger root " + source + " overlaps the organization ledger root " + organization)
    for name, path in (("repository", source), ("organization", organization)):
        if _holds_tracked_files(path):
            refuse(LEDGER_ROOT_NOT_CONTRACT_DESIGNATED, "the " + name + " ledger root " + path
                   + " holds git-tracked files of this checkout; a ledger is never a committed directory")
    return open_store(location)


def _walk_to(store, digest):
    """True when `digest` is reachable from HEAD. Every node walked must be a receipt of this
    repository that hashes to its own address; a corrupt node is SOURCE_LEDGER_CORRUPT."""
    repository = _repository_contract().get("repository")

    def corrupt(address, detail):
        raise SourceReceiptUnverified("the repository ledger node " + str(address) + " is " + detail,
                                      "THE_REPOSITORY_LEDGER_IS_READABLE_AS_RECEIPTS", SOURCE_LEDGER_CORRUPT)
    try:
        head = store.get(HEAD_KEY)
    except kernel.JSON_DOCUMENT_ERRORS as exc:
        corrupt("HEAD", "not a JSON document (" + type(exc).__name__ + ")")
    if head is None:
        return False
    if not isinstance(head, dict):
        corrupt("HEAD", "not an object")
    cursor, seen = head.get("receipt_sha256"), set()
    while cursor is not None:
        if not isinstance(cursor, str) or not _DIGEST.match(cursor) or cursor in seen:
            corrupt(cursor, "not a receipt address, or a cycle")
        seen.add(cursor)
        try:
            node = store.get(receipt_key(cursor))
        except kernel.JSON_DOCUMENT_ERRORS as exc:
            corrupt(cursor, "not a JSON document (" + type(exc).__name__ + ")")
        if node is None:
            corrupt(cursor, "missing")
        if not isinstance(node, dict) or node.get("receipt_sha256") != cursor \
                or sha({key: value for key, value in node.items() if key != "receipt_sha256"}) != cursor:
            corrupt(cursor, "not the receipt its address names")
        if node.get("repository") != repository:
            raise SourceReceiptUnverified("the repository ledger node " + cursor + " is a receipt of "
                                          + str(node.get("repository")) + ", not of " + str(repository),
                                          "THE_SOURCE_LEDGER_IS_THIS_REPOSITORYS_OWN_LEDGER",
                                          SOURCE_LEDGER_NOT_THIS_REPOSITORY_LEDGER)
        if cursor == digest:
            return True
        cursor = node.get("previous_receipt_sha256")
    return False


def verify_source_on_repository_ledger(receipt, target):
    """SOURCE_RECEIPT_NOT_ON_LEDGER unless `receipt` is on this repository's own ledger (see
    `source_ledger`): a repository receipt of this repository, stored at its address,
    byte-for-byte, and reachable from that ledger's HEAD. Checked for every source and every
    caller, CLI or in process, whether or not it carries a committed request.

    A receipt on the ledger that carries a committed request is refused too
    (COMMITTED_REQUEST_DIGEST_UNVERIFIED): no writer here records one on a receipt, and a
    committed request is bound only by the companion binding receipt.
    A corrupt ledger node is SOURCE_LEDGER_CORRUPT (terminal); a read fault is
    SOURCE_LEDGER_READ_FAILED (non-terminal). Run before any write; nothing is written.
    """
    def refuse(detail, predicate="THE_SOURCE_RECEIPT_IS_ON_THIS_REPOSITORY_LEDGER"):
        raise SourceReceiptUnverified(detail, predicate)
    if not isinstance(receipt, dict) or receipt.get("schema") != "stegverse.repo-transition-receipt/v1":
        refuse("schema " + str(receipt.get("schema") if isinstance(receipt, dict) else type(receipt).__name__)
               + " is not a repository receipt; it has no address on the repository ledger")
    repository = _repository_contract().get("repository")
    if receipt.get("repository") != repository:
        refuse("repository " + str(receipt.get("repository")) + " is not this ledger's " + str(repository))
    digest = receipt.get("receipt_sha256")
    if not isinstance(digest, str) or not _DIGEST.match(digest):
        refuse("receipt_sha256 " + str(digest) + " is not a receipt address")
    store = source_ledger(target)
    try:
        try:
            stored = store.get(receipt_key(digest))
        except kernel.JSON_DOCUMENT_ERRORS as exc:
            raise SourceReceiptUnverified("the repository ledger node " + digest + " is not a JSON document ("
                                          + type(exc).__name__ + ")", "THE_REPOSITORY_LEDGER_IS_READABLE_AS_RECEIPTS",
                                          SOURCE_LEDGER_CORRUPT) from None
        if stored != receipt:
            refuse("receipt " + digest + " is not stored at its address on the repository ledger")
        reachable = _walk_to(store, digest)
    except FileNotFoundError:
        refuse("the repository ledger does not exist, so receipt " + digest + " is not on it")
    except (OSError, LedgerWriteFailed) as exc:
        if isinstance(exc, SourceReceiptUnverified):
            raise
        raise SourceLedgerReadFailed("the repository ledger could not be read: " + type(exc).__name__ + ": "
                                     + str(exc)[:200]) from None
    if not reachable:
        refuse("receipt " + digest + " is not reachable from the repository ledger HEAD",
               "THE_SOURCE_RECEIPT_IS_REACHABLE_FROM_THE_REPOSITORY_HEAD")
    path = kernel.committed_request_path(receipt)
    if path is not None:
        raise SourceReceiptUnverified("the source receipt names " + path + "; this run reads no committed request",
                                      "A_SOURCE_RECEIPT_CARRIES_THE_RUNS_OWN_COMMITTED_REQUEST",
                                      COMMITTED_REQUEST_DIGEST_UNVERIFIED)


def verify_source(receipt):
    """Verify a source transition receipt this organization's contract consumes.

    The contract's `consumes` list is the admission gate. Every state transition
    occurring within the organization emits an organization receipt, so a
    canonical state transition is admitted on its own terms: it is bound by
    its own canonical digest and keeps its own schema and transition id, rather
    than being relabelled as a repository transition it is not.
    """
    schema = receipt.get("schema")
    allowed = C.get("consumes")
    if isinstance(allowed, str):
        allowed = [allowed]
    if schema not in (allowed or []):
        raise SystemExit("organization source receipt schema mismatch")
    transition_id = receipt.get("transition_id")
    if not isinstance(transition_id, str) or not transition_id:
        raise SystemExit("organization source transition id invalid")
    if schema == "stegverse.repo-transition-receipt/v1":
        repository = str(receipt.get("repository", ""))
        if not repository.startswith(C["organization"] + "/"):
            raise SystemExit("repo outside organization")
        claimed = receipt.get("receipt_sha256")
        body = dict(receipt)
        body.pop("receipt_sha256", None)
        if claimed != sha(body):
            raise SystemExit("repo receipt hash mismatch")
        refusal = source_provenance_refusal(receipt)
        if refusal is not None:
            raise OrgLedgerEpochRefused(refusal)
        return {
            "source_receipt_schema": schema,
            "source_transition_sha256": claimed,
            "source_transition_id": transition_id,
            "source_repository": repository,
            "repo_receipt_sha256": claimed,
            "repo_transition_id": transition_id,
            "canonical_state_transition_receipt_sha256": None,
            "subject_or_correlation_id": None,
        }
    verify_required_evidence(receipt)
    digest = sha(receipt)
    return {
        "source_receipt_schema": schema,
        "source_transition_sha256": digest,
        "source_transition_id": transition_id,
        "source_repository": None,
        "repo_receipt_sha256": None,
        "repo_transition_id": None,
        "canonical_state_transition_receipt_sha256": digest,
        "subject_or_correlation_id": receipt.get("subject_or_correlation_id"),
    }


def _validate_existing_head(store, pending=frozenset()):
    """Verify the chain the next append extends.

    `pending` names the content-addressed documents this append is about to
    write. A torn earlier attempt of the same append can leave exactly those
    documents written without the HEAD that publishes them. The rewrite is
    byte-identical, so they are tolerated and the append publishes HEAD. Any
    other unpublished document is this store's own torn state, not a defect of
    what is being appended. It is LedgerWriteFailed, a writer fault, so the
    caller can leave its input pending rather than refuse it.
    """
    head = store.get(HEAD_KEY)
    if head is None:
        # A missing HEAD with existing receipts requires explicit recovery;
        # never silently fork or reset the organization chain.
        if store.list_prefix(RECEIPT_PREFIX) - set(pending):
            raise LedgerWriteFailed("ORG_LEDGER_HEAD_MISSING_WITH_EXISTING_RECEIPTS")
        return None
    previous = head.get("receipt_sha256")
    if not isinstance(previous, str) or not previous.startswith("sha256:"):
        raise SystemExit("ORG_LEDGER_HEAD_INVALID")
    receipt = store.get(receipt_key(previous))
    if receipt is None:
        raise SystemExit("ORG_LEDGER_HEAD_RECEIPT_MISSING")
    body = dict(receipt)
    body.pop("receipt_sha256", None)
    if receipt.get("receipt_sha256") != previous or sha(body) != previous:
        raise SystemExit("ORG_LEDGER_HEAD_RECEIPT_HASH_MISMATCH")
    # A receipt written before a crash but not published as HEAD must not be
    # silently bypassed. Detect all unreachable receipts before appending.
    reachable = set()
    cursor = previous
    while cursor:
        if cursor in reachable:
            raise SystemExit("ORG_LEDGER_PREDECESSOR_CYCLE")
        reachable.add(cursor)
        record = store.get(receipt_key(cursor))
        if record is None:
            raise SystemExit("ORG_LEDGER_PREDECESSOR_MISSING")
        record_body = dict(record)
        record_body.pop("receipt_sha256", None)
        if record.get("receipt_sha256") != cursor or sha(record_body) != cursor:
            raise SystemExit("ORG_LEDGER_PREDECESSOR_HASH_MISMATCH")
        cursor = record.get("previous_receipt_sha256")
    if store.list_prefix(RECEIPT_PREFIX) - set(pending) != {receipt_key(digest) for digest in reachable}:
        raise LedgerWriteFailed("ORG_LEDGER_UNPUBLISHED_OR_ORPHAN_RECEIPTS_RECOVERY_REQUIRED")
    # A retained source copy is published only through the receipt that names
    # it. Ledgers written before retention existed simply have none.
    sources = {source_key(store.get(receipt_key(digest))["source_transition_sha256"])
               for digest in reachable
               if isinstance(store.get(receipt_key(digest)).get("source_transition_sha256"), str)}
    if not store.list_prefix(SOURCE_PREFIX) - set(pending) <= sources:
        raise LedgerWriteFailed("ORG_LEDGER_ORPHAN_SOURCE_RECEIPTS_RECOVERY_REQUIRED")
    return previous


def recorded(store, head, source_transition_sha256):
    """The organization receipt this chain already holds for a source receipt."""
    cursor = (head or {}).get("receipt_sha256")
    while cursor:
        receipt = store.get(receipt_key(cursor))
        if receipt is None:
            return None
        if receipt.get("source_transition_sha256") == source_transition_sha256:
            return receipt
        cursor = receipt.get("previous_receipt_sha256")
    return None


def append(source_receipt, org_transition_class, predecessor_state, successor_state,
           boundary_evidence, authority_effect, hb_epoch=None, store=None, idempotent=False,
           hb_provenance=None):
    # Ordering is a heartbeat count the caller supplies, never a clock reading.
    # It is checked first, so a refusal opens no store and writes nothing.
    heartbeat = require_supplied_epoch(hb_epoch, hb_provenance)
    # A committed request is never taken from caller evidence
    # (FORGED_COMMITTED_REQUEST_FROM_EVIDENCE_JSON); refused before any write.
    kernel.refuse_caller_committed_request(boundary_evidence, argument="boundary_evidence",
                                           retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)
    # Admission is decided before the append lock is taken; an inadmissible
    # source receipt never contends for the organization ledger. Every source, from
    # every caller, must be on this repository's own ledger, bound to the organization
    # ledger this append writes (SOURCE_RECEIPT_NOT_ON_LEDGER). Opening a store writes nothing.
    target = store or open_store(ledger_root())
    verify_source_on_repository_ledger(source_receipt, target)
    source = verify_source(source_receipt)
    if predecessor_state not in (FROM_HEAD, GENESIS):
        require_state_digest("predecessor_org_state_sha256", predecessor_state)
    require_state_digest("successor_org_state_sha256", successor_state)
    retained = {source_key(source["source_transition_sha256"]): source_receipt}
    target.initialize()
    # The storage substrate owns serialization. A lost comparison writes
    # nothing, so a retry cannot strand an orphan receipt.
    for _attempt in range(128):
        guard = target.exclusive() if hasattr(target, "exclusive") else nullcontext()
        with guard:
            expected_head = target.get(HEAD_KEY)
            previous = (expected_head or {}).get("receipt_sha256")
            # A source receipt is consumed once. With `idempotent` the chain is
            # read at the HEAD this attempt compares against, before the
            # predecessor is resolved: a receipt already consuming this exact
            # source is returned instead of a second one minted (a GENESIS rerun
            # whose append already committed included), and one consuming it
            # under another class is a collision.
            if idempotent:
                prior = recorded(target, expected_head, source["source_transition_sha256"])
                if prior is not None:
                    if prior.get("org_transition_class") != org_transition_class:
                        raise ValueError("ledger_receipt_collision")
                    return prior
            # Resolved against the HEAD this attempt will compare against, so a
            # retry after a lost comparison re-resolves rather than reusing it.
            if predecessor_state == FROM_HEAD:
                if expected_head is None:
                    raise OrgLedgerAppendRefused("FAIL_CLOSED", "ORG_LEDGER_GENESIS_NOT_DECLARED")
                predecessor = previous
            elif predecessor_state == GENESIS:
                if expected_head is not None:
                    raise OrgLedgerAppendRefused("DENY", "ORG_LEDGER_GENESIS_ON_NON_EMPTY_LEDGER")
                predecessor = None
            else:
                predecessor = predecessor_state
            body = {
                "schema": "stegverse.organization-transition-receipt/v1",
                "organization": C["organization"],
                **source,
                "org_transition_class": org_transition_class,
                "predecessor_org_state_sha256": predecessor,
                "successor_org_state_sha256": successor_state,
                "boundary_evidence": boundary_evidence,
                "authority_effect": authority_effect,
                "hb_reference": heartbeat,
                "previous_receipt_sha256": previous,
            }
            if predecessor_state == GENESIS:
                body["chain_genesis"] = True
            digest = sha(body)
            receipt = {**body, "receipt_sha256": digest}
            key = receipt_key(digest)
            # The documents this append writes may already exist, unpublished,
            # from a torn attempt of this same append; the rewrite is
            # byte-identical, so only they are tolerated.
            _validate_existing_head(target, pending=frozenset({key, *retained}))
        new_head = {
            "organization": C["organization"],
            "receipt_sha256": digest,
            "receipt_path": target.locator(key),
        }
        if target.append_transaction(key, receipt, expected_head, new_head, immutable=retained):
            return receipt
    raise LedgerWriteFailed("ORG_LEDGER_APPEND_CONTENTION_EXHAUSTED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-receipt")
    parser.add_argument("--transition-receipt")
    parser.add_argument("--org-transition-class", default=None)
    parser.add_argument("--predecessor-org-state-sha256", required=True,
                        help="sha256 digest, FROM_HEAD (bind the current HEAD), or GENESIS (open an empty chain)")
    parser.add_argument("--successor-org-state-sha256", required=True)
    parser.add_argument("--boundary-evidence-json", default="{}")
    parser.add_argument("--authority-effect", default="NONE")
    parser.add_argument("--hb-epoch", default=None,
                        help="heartbeat epoch, ASCII digits >= 32; the append refuses when absent or invalid")
    args = parser.parse_args()
    source_path = args.transition_receipt or args.repo_receipt
    if not source_path:
        raise SystemExit("transition receipt required")
    # Every input is read before any write; a bad one is the caller's terminal fault.
    try:
        receipt = kernel.read_json_input(
            source_path, argument="--transition-receipt" if args.transition_receipt else "--repo-receipt",
            retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)
        boundary_evidence = kernel.read_json_input(
            args.boundary_evidence_json, argument="--boundary-evidence-json", inline=True,
            retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)
    except kernel.InputRefused as exc:
        print(json.dumps(exc.refusal, sort_keys=True))
        raise SystemExit(1)
    default_class = ("REPO_STATE_PROPAGATION"
                     if receipt.get("schema") == "stegverse.repo-transition-receipt/v1"
                     else "ORGANIZATION_STATE_TRANSITION")
    try:
        result = append(receipt, args.org_transition_class or default_class,
                        args.predecessor_org_state_sha256, args.successor_org_state_sha256,
                        boundary_evidence, args.authority_effect,
                        hb_epoch=args.hb_epoch, idempotent=True)
    except LedgerLocationRequired as exc:
        print(json.dumps(location_refusal(exc), sort_keys=True))
        raise SystemExit(1)
    except (OrgLedgerEpochRefused, SourceReceiptUnverified, SourceLedgerReadFailed,
            kernel.CallerEvidenceRefused) as exc:
        print(json.dumps(exc.refusal, sort_keys=True))
        raise SystemExit(1)
    except ValueError as exc:
        if str(exc) != "ledger_receipt_collision":
            raise
        print(json.dumps(kernel.collision_refusal(source_path, retry_entrypoint=EPOCH_RETRY_ENTRYPOINT),
                         sort_keys=True))
        raise SystemExit(1)
    except (LedgerWriteFailed, OSError) as exc:
        # This boundary's own write fault: non-terminal six-field, never a traceback.
        print(json.dumps(kernel.writer_fault_refusal(exc, retry_entrypoint=EPOCH_RETRY_ENTRYPOINT), sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
