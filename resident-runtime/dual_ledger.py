#!/usr/bin/env python3
"""Append one transition at the repository level and the organization level.

Both levels go through the repository emitter and the organization aggregator.
``STEGVERSE_REPO_LEDGER_ROOT`` and ``STEGVERSE_ORG_LEDGER_ROOT`` select the
store. A plain path is a POSIX root. ``git+<repository>#<ref>`` is a git ref,
and ``git+<repository>#<ref>:<namespace>`` is a subtree of that ref. No host
path is filled in when a variable is unset.

A replay of the same transition id returns the recorded receipt. A different
body under that id is a collision.

These files are transition evidence for the packet that produced them. A
caller that redirects the roots is not writing the published organization
ledger ref.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]

REPO_SCHEMA = "stegverse.repo-transition-receipt/v1"
ORG_SCHEMA = "stegverse.organization-transition-receipt/v1"


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


emit = _load("repo_transition_emit", ".stegverse/transition-ledger/emit.py")
aggregate = _load("aggregate_repo_transition", "resident-runtime/aggregate_repo_transition.py")
ledger_store = _load("ledger_store_for_dual_ledger", "resident-runtime/ledger_store.py")


def find_repository(transition_id: str) -> dict[str, Any] | None:
    """The repository receipt already recorded for ``transition_id``, if any.

    The match is the transition id alone. The walk still verifies every node
    reachable from HEAD.
    """
    try:
        target = ledger_store.open_store(emit.lr())
        head = target.get(ledger_store.HEAD_KEY)
    except FileNotFoundError:
        return None
    if head is None:
        return None
    found = None
    for receipt in emit.chain(target, head):
        if found is None and receipt.get("transition_id") == transition_id:
            found = receipt
    return found


def append_repository(transition_id: str, transition_class: str, predecessor: str,
                      successor: str, evidence: Mapping[str, Any], authority_effect: str, *,
                      hb_epoch: int | None = None,
                      idempotent_on: tuple[str, ...] | None = None,
                      hb_provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Append one repository receipt, or return the recorded one on replay."""
    return emit.append(
        transition_id, transition_class, predecessor, successor, dict(evidence),
        authority_effect, hb_epoch=hb_epoch, idempotent_on=idempotent_on,
        hb_provenance=None if hb_provenance is None else dict(hb_provenance))


def append_organization(repository_receipt: Mapping[str, Any], transition_class: str,
                        predecessor: str, successor: str, evidence: Mapping[str, Any],
                        authority_effect: str, *, hb_epoch: int | None = None,
                        hb_provenance: Mapping[str, Any] | None = None,
                        idempotent: bool = True) -> dict[str, Any]:
    """Append the organization receipt that preserves the repository receipt."""
    return aggregate.append(
        dict(repository_receipt), transition_class, predecessor, successor,
        dict(evidence), authority_effect, hb_epoch=hb_epoch, idempotent=idempotent,
        hb_provenance=None if hb_provenance is None else dict(hb_provenance))
