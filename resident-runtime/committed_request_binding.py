#!/usr/bin/env python3
"""Bind a committed request to the InTr receipts it triggered, with a companion receipt.

The InTr receiving operation (resident-runtime/intr_destination_ingress.py)
is another lane's surface and is kept byte-identical to main, so its receipts
do not carry the committed request that triggered them. This boundary binds
the two instead: for each transition, one
``stegverse.committed-request-binding-receipt/v1`` on its own chain,
``committed-request-bindings/`` with its own HEAD, inside the same
organization ledger root and ref. The organization receipt chain itself is
left as the readback and merge contracts expect it.

A binding records the committed request ``{path, sha256, hb_epoch_source}``,
each bound receipt's ``receipt_sha256`` and ``previous_receipt_sha256``, the
supplied ``hb_epoch``, the organization chain HEAD at append time, and the
previous binding's digest. It is content-addressed, so the chain is
hash-linked and append-only, and it is checkable from the ledger alone.

On a git ref, the binding lands in the same commit as the receipts it binds:
when the ref moved from ``since_tip`` by exactly the bound transition's own
commits, those commits and the binding are folded into one commit on
``since_tip``, published by compare-and-swap. A replay of the same
transition with the same request mints no second binding; with another
request it is COMMITTED_REQUEST_REPLAY_MISMATCH. A malformed request is
COMMITTED_REQUEST_INVALID and a bound receipt that cannot be read and
verified is BOUND_RECEIPT_UNREADABLE: six fields, terminal, nothing written.
``verify`` reads a ledger back and refuses a missing or mismatched binding as
COMMITTED_REQUEST_BINDING_ABSENT, never a silent ALLOW. No clock is read.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


K = _module("kernel_for_committed_request_binding", "org-kernel/kernel.py")
S = _module("ledger_store_for_committed_request_binding", "resident-runtime/ledger_store.py")

SCHEMA = "stegverse.committed-request-binding-receipt/v1"
CHAIN = "committed-request-bindings/"
BINDINGS_HEAD = CHAIN + "HEAD.json"
HB_EPOCH_SOURCE = "COMMITTED_REQUEST"
RETRY_ENTRYPOINT = "resident-runtime/committed_request_binding.py"
GOAL = "INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001"
# The bound transition's own commits on the ref: the repository half and the
# organization half (ledger_gitstore.MAX_COMMITS_PER_ATTEMPT).
MAX_FOLDED_COMMITS = 2

COMMITTED_REQUEST_INVALID = "COMMITTED_REQUEST_INVALID"
BOUND_RECEIPT_UNREADABLE = "BOUND_RECEIPT_UNREADABLE"
COMMITTED_REQUEST_REPLAY_MISMATCH = "COMMITTED_REQUEST_REPLAY_MISMATCH"
COMMITTED_REQUEST_BINDING_ABSENT = "COMMITTED_REQUEST_BINDING_ABSENT"
COMMITTED_REQUEST_BINDING_WRITE_FAILED = "COMMITTED_REQUEST_BINDING_WRITE_FAILED"
COMMITTED_REQUEST_BINDING_READ_FAILED = "COMMITTED_REQUEST_BINDING_READ_FAILED"


class BindingRefused(ValueError):
    """A six-field refusal; nothing was written."""

    def __init__(self, refusal: dict[str, Any]):
        super().__init__(refusal["failure_code"] + ": " + str(refusal["detail"]))
        self.refusal = refusal


class BindingWriteFault(RuntimeError):
    """This boundary's own ledger faulted while binding: six fields, not terminal.

    A write fault, or (`read=True`) a fault reading back this boundary's own
    ledger: an OSError, or, where the receipts were just written by this same
    transition (`own_writes`), a torn or unreadable bindings chain or receipt.
    `writer_fault` makes the kernel defer the frame rather than quarantine it,
    as for any ledger writer's own fault. The write is atomic and the binding
    content-addressed, so the same call run again completes it exactly once.
    """

    writer_fault = True

    def __init__(self, exc: BaseException, *, read: bool = False):
        code = COMMITTED_REQUEST_BINDING_READ_FAILED if read else COMMITTED_REQUEST_BINDING_WRITE_FAILED
        super().__init__(code + ": " + type(exc).__name__ + ": " + str(exc))
        self.refusal = {
            "disposition": "FAIL_CLOSED", "failure_code": code, "terminal": False,
            "failed_predicate": ("THIS_BOUNDARY_READS_ITS_OWN_LEDGER_BACK" if read
                                 else "THIS_BOUNDARY_RECORDS_ITS_OWN_BINDING"),
            "detail": type(exc).__name__ + ": " + str(exc)[:300],
            "required_evidence_or_repair": ("this boundary's own ledger reads back as written" if read
                                            else "this boundary's own ledger storage accepts the binding"),
            "retry_entrypoint": RETRY_ENTRYPOINT, "owning_existing_goal": GOAL,
            "next_attempt": ("run the same binding again: it is content-addressed, so the rerun returns the "
                             "recorded binding or writes it once, never a second"),
            "consequence_committed": "UNDETERMINED_RETRY_IS_IDEMPOTENT"}


def _get(store: Any, key: str, what: str) -> Any:
    """A document read back, or a six-field refusal for a torn or unreadable one; never a traceback."""
    try:
        return store.get(key)
    except OSError as exc:
        raise BindingWriteFault(exc, read=True) from None
    except K.JSON_DOCUMENT_ERRORS as exc:
        raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "EVERY_LEDGER_DOCUMENT_READS_BACK",
                      what + " " + key + " is torn or unreadable: " + type(exc).__name__,
                      "restore the document as written; a torn binding HEAD is never read as no binding") from None


def _refuse(code: str, predicate: str, detail: str, repair: str) -> BindingRefused:
    return BindingRefused({
        "disposition": "FAIL_CLOSED", "failure_code": code, "terminal": True,
        "failed_predicate": predicate, "detail": detail,
        "required_evidence_or_repair": repair, "retry_entrypoint": RETRY_ENTRYPOINT,
        "owning_existing_goal": GOAL,
        "next_attempt": "nothing was written; repair the input or the ledger and run again",
        "consequence_committed": False})


def binding_key(digest: str) -> str:
    return CHAIN + "receipts/" + digest.split(":", 1)[1] + ".json"


def committed_request(value: Any) -> dict[str, str]:
    """The committed request as recorded, or COMMITTED_REQUEST_INVALID."""
    if isinstance(value, str):
        path, _, digest = value.partition("=")
        value = {"path": path, "sha256": digest, "hb_epoch_source": HB_EPOCH_SOURCE}
    digest = value.get("sha256") if isinstance(value, Mapping) else None
    if (not isinstance(value, Mapping) or set(value) != {"path", "sha256", "hb_epoch_source"}
            or not isinstance(value["path"], str) or not value["path"]
            or not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71
            or any(c not in "0123456789abcdef" for c in digest[7:])
            or value["hb_epoch_source"] != HB_EPOCH_SOURCE):
        raise _refuse(COMMITTED_REQUEST_INVALID, "THE_COMMITTED_REQUEST_IS_A_PATH_AND_ITS_SHA256",
                      "not {path, sha256:<64 hex>, hb_epoch_source: COMMITTED_REQUEST}: " + repr(value)[:200],
                      "supply the committed request as PATH=sha256:<64 lowercase hex>")
    return {"path": value["path"], "sha256": digest, "hb_epoch_source": HB_EPOCH_SOURCE}


def _receipt(store: Any, digest: Any, ledger: str) -> dict[str, Any]:
    """A receipt read back by its address, verified against its own body, or BOUND_RECEIPT_UNREADABLE."""
    try:
        receipt = store.get(S.receipt_key(digest)) if isinstance(digest, str) and digest.startswith("sha256:") else None
    except OSError as exc:
        raise BindingWriteFault(exc, read=True) from None
    except K.JSON_DOCUMENT_ERRORS as exc:
        receipt, digest = None, str(digest) + " (" + type(exc).__name__ + ")"
    body = {key: value for key, value in (receipt or {}).items() if key != "receipt_sha256"}
    if not isinstance(receipt, dict) or receipt.get("receipt_sha256") != digest or K.sha(body) != digest:
        raise _refuse(BOUND_RECEIPT_UNREADABLE, "EVERY_BOUND_RECEIPT_READS_BACK_AND_VERIFIES",
                      ledger + " receipt " + str(digest) + " is absent, unreadable or does not hash to its address",
                      "bind only receipts the ledger holds, byte-for-byte as minted")
    return receipt


def _bound(store: Any, digest: Any, ledger: str) -> dict[str, Any]:
    receipt = _receipt(store, digest, ledger)
    return {"ledger": ledger, "receipt_sha256": digest,
            "previous_receipt_sha256": receipt.get("previous_receipt_sha256")}


def chain(org_store: Any) -> list[dict[str, Any]]:
    """The bindings, oldest first, each verified against its body and its predecessor."""
    head = _get(org_store, BINDINGS_HEAD, "the bindings HEAD")
    if head is not None and not isinstance(head, dict):
        raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "EVERY_LEDGER_DOCUMENT_READS_BACK",
                      "the bindings HEAD is not an object", "restore the bindings HEAD as written")
    found, cursor, seen = [], (head or {}).get("binding_sha256"), set()
    while cursor is not None:
        if cursor in seen:
            raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "THE_BINDINGS_CHAIN_IS_ACYCLIC", str(cursor),
                          "restore the bindings chain as appended")
        seen.add(cursor)
        binding = (_get(org_store, binding_key(cursor), "binding")
                   if isinstance(cursor, str) and cursor.startswith("sha256:") else None)
        body = {key: value for key, value in (binding or {}).items() if key != "binding_sha256"}
        if (not isinstance(binding, dict) or binding.get("schema") != SCHEMA
                or binding.get("binding_sha256") != cursor or K.sha(body) != cursor):
            raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "EVERY_BINDING_VERIFIES_AGAINST_ITS_BODY",
                          "binding " + str(cursor) + " is absent or does not hash to its address",
                          "restore the bindings chain as appended; a binding is never re-minted over a break")
        found.append(binding)
        cursor = binding.get("previous_binding_sha256")
    found.reverse()
    return found


def _organization_chain(org_store: Any) -> list[str]:
    head = _get(org_store, S.HEAD_KEY, "the organization HEAD")
    found, cursor = [], (head or {}).get("receipt_sha256")
    while cursor is not None and cursor not in found:
        found.append(cursor)
        cursor = _receipt(org_store, cursor, "organization").get("previous_receipt_sha256")
    return found


CALLER_CHOSEN_SOURCE_LEDGER_REJECTED = "CALLER_CHOSEN_SOURCE_LEDGER_REJECTED"
LEDGER_ROOT_NOT_CONTRACT_DESIGNATED = "LEDGER_ROOT_NOT_CONTRACT_DESIGNATED"
MIXED_LEDGER_KIND_PAIR = "MIXED_LEDGER_KIND_PAIR"


def designated_repository_store(org_store: Any, repo_store: Any = None) -> Any:
    """The repository ledger paired with `org_store` (lead 21:13Z, paired-override form).

    - Kinds first: a git ledger beside a filesystem one is MIXED_LEDGER_KIND_PAIR.
    - git: contract.json's designated ref and namespace in the organization ledger's own
      repository, by realpath. A caller-chosen repository store that is not that ledger is
      CALLER_CHOSEN_SOURCE_LEDGER_REJECTED, and an organization ref other than the designated
      one is LEDGER_ROOT_NOT_CONTRACT_DESIGNATED.
    - filesystem (runner-temporary or test): the repository root supplied beside the
      organization root, which must not overlap it (CALLER_CHOSEN_SOURCE_LEDGER_REJECTED); neither
      root may hold git-tracked files of this checkout (LEDGER_ROOT_NOT_CONTRACT_DESIGNATED).
    Six fields, terminal, nothing written."""
    org_kind = getattr(org_store, "kind", None)
    if repo_store is not None and getattr(repo_store, "kind", None) != org_kind:
        raise _refuse(MIXED_LEDGER_KIND_PAIR, "THE_LEDGER_PAIR_IS_ONE_KIND",
                      "a " + str(getattr(repo_store, "kind", None)) + " repository ledger beside a " + str(org_kind)
                      + " organization ledger", "supply both ledgers as git refs, or both as filesystem roots")
    if org_kind != "GIT_REF":
        roots = [("organization", os.path.realpath(org_store.root))]
        if repo_store is not None:
            source, organization = os.path.realpath(repo_store.root), roots[0][1]
            if source == organization or source.startswith(organization + os.sep) \
                    or organization.startswith(source + os.sep):
                raise _refuse(CALLER_CHOSEN_SOURCE_LEDGER_REJECTED, "THE_LEDGER_IS_THIS_REPOSITORYS_DESIGNATED_LEDGER",
                              "the repository ledger root " + source + " overlaps the organization ledger root "
                              + organization, "supply two separate ledger roots")
            roots.append(("repository", source))
        for name, path in roots:
            if K.holds_tracked_files(path, ROOT):
                raise _refuse(LEDGER_ROOT_NOT_CONTRACT_DESIGNATED, "THE_LEDGER_IS_THIS_REPOSITORYS_DESIGNATED_LEDGER",
                              "the " + name + " ledger root " + path + " holds git-tracked files of this checkout",
                              "a ledger is never a committed directory; use an untracked root")
        return repo_store
    declared = json.loads((ROOT / ".stegverse/transition-ledger/contract.json").read_text()).get(
        "repository_ledger_location") or {}
    ref, namespace = declared.get("ref"), declared.get("namespace")
    if not ref or not namespace or org_store.ref != ref:
        raise _refuse(LEDGER_ROOT_NOT_CONTRACT_DESIGNATED, "THE_LEDGER_IS_THIS_REPOSITORYS_DESIGNATED_LEDGER",
                      "the organization ledger ref " + str(org_store.ref) + " is not the designated " + str(ref),
                      "use the ledger ref contract.json designates")
    repository = os.path.realpath(org_store.repository)
    if repo_store is not None and (os.path.realpath(repo_store.repository) != repository
                                   or repo_store.ref != ref or repo_store.namespace != namespace):
        raise _refuse(CALLER_CHOSEN_SOURCE_LEDGER_REJECTED, "THE_LEDGER_IS_THIS_REPOSITORYS_DESIGNATED_LEDGER",
                      "the repository ledger supplied is not " + ref + ":" + namespace + " in " + repository,
                      "drop the override; the repository ledger is derived from the organization ledger")
    return S.GitLedgerStore(repository, ref, namespace)


def stores(org_store: Any = None, repo_store: Any = None) -> tuple[Any, Any]:
    def supplied(variable: str) -> Any:
        value = os.environ.get(variable)
        if not value:
            raise _refuse(BOUND_RECEIPT_UNREADABLE, "THE_LEDGER_LOCATIONS_ARE_SUPPLIED", variable + " is not set",
                          "supply " + variable + " as the materializer does")
        return S.open_store(S.parse_locator(value))
    org_store = org_store or supplied("STEGVERSE_ORG_LEDGER_ROOT")
    if repo_store is None and getattr(org_store, "kind", None) == "GIT_REF":
        value = os.environ.get("STEGVERSE_REPO_LEDGER_ROOT")
        repo_store = S.open_store(S.parse_locator(value)) if value else None
    else:
        repo_store = repo_store or supplied("STEGVERSE_REPO_LEDGER_ROOT")
    return org_store, designated_repository_store(org_store, repo_store)


def preflight(org_store: Any = None) -> None:
    """Before a transition writes the receipts it will bind: this boundary's own bindings chain
    and organization HEAD read back. A torn or unreadable one is a non-terminal
    COMMITTED_REQUEST_BINDING_READ_FAILED, so nothing is written that could not then be bound."""
    org_store = stores(org_store)[0]
    try:
        chain(org_store)
        _get(org_store, S.HEAD_KEY, "the organization HEAD")
    except BindingRefused as exc:
        raise BindingWriteFault(exc, read=True) from None


def tip(org_store: Any) -> str | None:
    """The commit the organization ledger ref names now (git), or None (POSIX, or never written)."""
    return org_store._tip() if isinstance(org_store, S.GitLedgerStore) else None


def _write(org_store: Any, documents: dict[str, Any], expected_head: Any, since_tip: str | None) -> bool:
    """Publish the binding and the bindings HEAD together; True when folded into the bound commit."""
    if not isinstance(org_store, S.GitLedgerStore):
        key = next(key for key in documents if key != BINDINGS_HEAD)
        org_store.put(key, documents[key])
        org_store.put(BINDINGS_HEAD, documents[BINDINGS_HEAD])  # HEAD last: an orphan is rewritten byte-identically
        return False
    for _attempt in range(org_store._ATTEMPTS):
        current = org_store._tip()
        if org_store._load(current, [BINDINGS_HEAD])[BINDINGS_HEAD] != expected_head:
            raise S.LedgerWriteFailed("COMMITTED_REQUEST_BINDINGS_HEAD_MOVED")
        written = {key: S._document_bytes(value) for key, value in documents.items()}
        committed = org_store._commit(current, written, "committed-request binding")
        folded = False
        if since_tip is not None and current is not None and current != since_tip:
            # since_tip "" is a ref that did not exist before the transition.
            if since_tip:
                span = org_store._git("rev-list", "--count", "--ancestry-path", since_tip + ".." + current,
                                      check=False)
                ancestor = org_store._git("merge-base", "--is-ancestor", since_tip, current, check=False).returncode == 0
            else:
                span = org_store._git("rev-list", "--count", current, check=False)
                ancestor = True
            if ancestor and span.returncode == 0 and int(span.stdout or 0) <= MAX_FOLDED_COMMITS:
                tree = org_store._git("rev-parse", committed + "^{tree}").stdout.decode().strip()
                parent = ["-p", since_tip] if since_tip else []
                committed = org_store._git("commit-tree", "--no-gpg-sign", tree, *parent, "-m",
                                           "ledger append and committed-request binding").stdout.decode().strip()
                folded = True
        if org_store._publish(committed, current):
            return folded
    raise S.LedgerWriteFailed("COMMITTED_REQUEST_BINDING_CONTENTION_EXHAUSTED")


def bind(request: Any, *, repository_receipt_sha256: str, organization_receipt_sha256: str, hb_epoch: Any,
         org_store: Any = None, repo_store: Any = None, since_tip: str | None = None,
         own_writes: bool = False) -> dict[str, Any]:
    """Append the binding for one transition, or return the recorded one; six-field refusals write nothing.

    `own_writes`: the receipts were just written by this same transition (the cycle path), so a
    bound receipt or bindings chain that does not read back is this boundary's own ledger fault,
    non-terminal COMMITTED_REQUEST_BINDING_READ_FAILED, and the retried transition binds once."""
    if own_writes:
        try:
            return bind(request, repository_receipt_sha256=repository_receipt_sha256,
                        organization_receipt_sha256=organization_receipt_sha256, hb_epoch=hb_epoch,
                        org_store=org_store, repo_store=repo_store, since_tip=since_tip)
        except BindingRefused as exc:
            if exc.refusal["failure_code"] in (BOUND_RECEIPT_UNREADABLE, COMMITTED_REQUEST_BINDING_ABSENT):
                raise BindingWriteFault(exc, read=True) from None
            raise
    request = committed_request(request)
    try:
        epoch = K.supplied_hb_reference(hb_epoch, retry_entrypoint=RETRY_ENTRYPOINT + "::bind (hb_epoch)")["epoch"]
    except K.SuppliedEpochRefused as exc:
        raise BindingRefused(exc.refusal) from None
    org_store, repo_store = stores(org_store, repo_store)
    with org_store.exclusive():
        bound = [_bound(repo_store, repository_receipt_sha256, "repository"),
                 _bound(org_store, organization_receipt_sha256, "organization")]
        recorded = chain(org_store)
        for binding in recorded:
            if any(entry["receipt_sha256"] == organization_receipt_sha256 for entry in binding["bound_receipts"]):
                if binding["committed_request"] == request and binding["bound_receipts"] == bound:
                    return {**binding, "replayed": True, "same_commit_as_bound_receipts": None}
                raise _refuse(COMMITTED_REQUEST_REPLAY_MISMATCH, "ONE_TRANSITION_BINDS_ONE_COMMITTED_REQUEST",
                              "organization receipt " + organization_receipt_sha256 + " is bound to "
                              + binding["committed_request"]["sha256"] + ", not " + request["sha256"],
                              "replay the transition with the committed request it was bound to")
        head = _get(org_store, S.HEAD_KEY, "the organization HEAD") or {}
        expected_head = _get(org_store, BINDINGS_HEAD, "the bindings HEAD")
        body = {"schema": SCHEMA, "committed_request": request, "bound_receipts": bound, "hb_epoch": epoch,
                "organization_head_receipt_sha256": head.get("receipt_sha256"),
                "previous_binding_sha256": (expected_head or {}).get("binding_sha256"),
                "authority_effect": "NONE_BINDING_ONLY"}
        digest = K.sha(body)
        binding = {**body, "binding_sha256": digest}
        try:
            folded = _write(org_store, {binding_key(digest): binding,
                                        BINDINGS_HEAD: {"binding_sha256": digest, "binding_key": binding_key(digest)}},
                            expected_head, since_tip)
        except (OSError, S.LedgerWriteFailed, ValueError) as exc:
            raise BindingWriteFault(exc) from exc
    return {**binding, "replayed": False, "same_commit_as_bound_receipts": folded}


def verify(*, org_store: Any = None, repo_store: Any = None,
           expected: list[tuple[Any, str]] = ()) -> dict[str, Any]:
    """Read the bindings back: every link, every bound receipt, and one binding per expected receipt."""
    org_store, repo_store = stores(org_store, repo_store)
    bindings = chain(org_store)
    organization = set(_organization_chain(org_store))
    for binding in bindings:
        for entry in binding["bound_receipts"]:
            store = repo_store if entry["ledger"] == "repository" else org_store
            receipt = _receipt(store, entry["receipt_sha256"], entry["ledger"])
            if receipt.get("previous_receipt_sha256") != entry["previous_receipt_sha256"] or (
                    entry["ledger"] == "organization" and entry["receipt_sha256"] not in organization):
                raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "EVERY_BINDING_MATCHES_THE_RECEIPT_IT_BINDS",
                              "binding " + binding["binding_sha256"] + " does not match receipt "
                              + entry["receipt_sha256"], "restore the ledger as appended")
        if binding["organization_head_receipt_sha256"] not in organization:
            raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "EVERY_BINDING_NAMES_AN_ORGANIZATION_CHAIN_HEAD",
                          "binding " + binding["binding_sha256"] + " names a head not on the organization chain",
                          "restore the ledger as appended")
    for request, digest in expected:
        request = committed_request(request)
        match = [binding for binding in bindings if any(entry["ledger"] == "organization"
                 and entry["receipt_sha256"] == digest for entry in binding["bound_receipts"])]
        if len(match) != 1 or match[0]["committed_request"] != request:
            raise _refuse(COMMITTED_REQUEST_BINDING_ABSENT, "EVERY_COMMITTED_REQUEST_RECEIPT_IS_BOUND",
                          "organization receipt " + str(digest) + " has " + str(len(match))
                          + " binding(s) for committed request " + request["sha256"],
                          "bind the transition to its committed request (committed_request_binding.bind)")
    head = _get(org_store, BINDINGS_HEAD, "the bindings HEAD")
    return {"disposition": "ALLOW", "bindings_head_sha256": (head or {}).get("binding_sha256"),
            "bindings_chain_length": len(bindings), "bound_organization_receipts": len(expected),
            "authority_effect": "NONE_READBACK_ONLY"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("bind", "verify"))
    parser.add_argument("--committed-request", required=True, help="PATH=sha256:<64 hex>")
    parser.add_argument("--ingress-result", required=True, type=Path,
                        help="the InTr result naming repository_receipt_sha256 and organization_receipt_sha256")
    parser.add_argument("--hb-epoch", default=None)
    parser.add_argument("--since-tip", default=None,
                        help="the organization ledger ref's commit before the transition (empty: the ref was absent)")
    args = parser.parse_args(argv)
    try:
        result = K.read_json_input(args.ingress_result, argument="--ingress-result",
                                   retry_entrypoint=RETRY_ENTRYPOINT)
        if args.command == "bind":
            out = bind(args.committed_request, repository_receipt_sha256=result.get("repository_receipt_sha256"),
                       organization_receipt_sha256=result.get("organization_receipt_sha256"),
                       hb_epoch=args.hb_epoch, since_tip=args.since_tip)
        else:
            out = verify(expected=[(args.committed_request, result.get("organization_receipt_sha256"))])
    except (K.InputRefused, BindingRefused, BindingWriteFault) as exc:
        print(json.dumps(exc.refusal, sort_keys=True))
        return 1
    except Exception as exc:
        refusal = K.cli_refusal(exc, retry_entrypoint=RETRY_ENTRYPOINT)
        if refusal is None:
            raise
        print(json.dumps(refusal, sort_keys=True))
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
