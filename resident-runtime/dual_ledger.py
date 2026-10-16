#!/usr/bin/env python3
"""Append one transition at the repository level and the organization level.

This organization did not already have a ledger writer. Both levels are
redirectable through ``STEGVERSE_REPO_LEDGER_ROOT`` and
``STEGVERSE_ORG_LEDGER_ROOT``. A replay of the same transition id returns the
recorded receipt. A different body under that id is a collision.

These files are transition evidence for the packet that produced them. They
are not an authentic production receipt, and a caller that redirects the roots
is not writing this organization's durable ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

REPO_SCHEMA = "stegverse.repo-transition-receipt/v1"
ORG_SCHEMA = "stegverse.organization-transition-receipt/v1"
INDEX_SCHEMA = "stegverse.ledger-index/v1"
REPO_ENV = "STEGVERSE_REPO_LEDGER_ROOT"
ORG_ENV = "STEGVERSE_ORG_LEDGER_ROOT"


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canon(value)).hexdigest()


def repo_root() -> Path:
    value = os.environ.get(REPO_ENV)
    if not value:
        raise ValueError("ledger_location_required_from_materializer")
    return Path(value)


def org_root() -> Path:
    value = os.environ.get(ORG_ENV)
    if not value:
        raise ValueError("ledger_location_required_from_materializer")
    return Path(value)


def _index(root: Path) -> dict[str, Any]:
    path = root / "index.json"
    if not path.is_file():
        return {"schema": INDEX_SCHEMA, "transitions": {}}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("transitions"), dict):
        raise ValueError("ledger_index_unreadable")
    return value


def _write_index(root: Path, index: Mapping[str, Any]) -> None:
    path = root / "index.json"
    path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _receipt_path(root: Path, digest: str) -> Path:
    name = digest.split(":", 1)[-1] + ".json"
    return root / "receipts" / name


def _load_receipt(root: Path, digest: str) -> dict[str, Any] | None:
    path = _receipt_path(root, digest)
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else None


def _same(existing: Mapping[str, Any], evidence: Mapping[str, Any],
          idempotent_on: tuple[str, ...] | None) -> bool:
    recorded = existing.get("evidence")
    if not isinstance(recorded, Mapping):
        return False
    if not idempotent_on:
        return dict(recorded) == dict(evidence)
    return all(recorded.get(name) == evidence.get(name) for name in idempotent_on)


def _store(root: Path, transition_id: str, body: dict[str, Any]) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    digest = sha(body)
    stored = {**body, "receipt_sha256": digest}
    path = _receipt_path(root, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = json.loads(path.read_text(encoding="utf-8"))
        if current != stored:
            raise ValueError("ledger_receipt_collision")
    else:
        path.write_text(json.dumps(stored, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    index = _index(root)
    index["transitions"][transition_id] = digest
    _write_index(root, index)
    return stored


def find_repository(transition_id: str) -> dict[str, Any] | None:
    root = repo_root()
    if not root.exists():
        return None
    digest = _index(root)["transitions"].get(transition_id)
    if not isinstance(digest, str):
        return None
    return _load_receipt(root, digest)


def append_repository(transition_id: str, transition_class: str, predecessor: str,
                      successor: str, evidence: Mapping[str, Any], authority_effect: str, *,
                      hb_epoch: int | None = None,
                      idempotent_on: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Append one repository receipt, or return the recorded one on replay."""
    root = repo_root()
    prior = find_repository(transition_id) if root.exists() else None
    if prior is not None:
        if (prior.get("transition_class") == transition_class
                and _same(prior, evidence, idempotent_on)):
            return prior
        raise ValueError("ledger_receipt_collision")
    body = {
        "schema": REPO_SCHEMA,
        "transition_id": transition_id,
        "transition_class": transition_class,
        "predecessor": predecessor,
        "successor": successor,
        "evidence": dict(evidence),
        "authority_effect": authority_effect,
        "hb_reference": {"epoch": hb_epoch},
    }
    return _store(root, transition_id, body)


def append_organization(repository_receipt: Mapping[str, Any], transition_class: str,
                        predecessor: str, successor: str, evidence: Mapping[str, Any],
                        authority_effect: str, *, hb_epoch: int | None = None,
                        idempotent: bool = True) -> dict[str, Any]:
    """Append the organization receipt that preserves the repository receipt."""
    root = org_root()
    repo_sha = repository_receipt["receipt_sha256"]
    transition_id = "org:" + str(repo_sha)
    if root.exists() and idempotent:
        digest = _index(root)["transitions"].get(transition_id)
        if isinstance(digest, str):
            prior = _load_receipt(root, digest)
            if prior is not None and prior.get("repo_receipt_sha256") == repo_sha:
                return prior
            if prior is not None:
                raise ValueError("ledger_receipt_collision")
    body = {
        "schema": ORG_SCHEMA,
        "transition_id": transition_id,
        "transition_class": transition_class,
        "predecessor": predecessor,
        "successor": successor,
        "repo_receipt_sha256": repo_sha,
        "evidence": dict(evidence),
        "authority_effect": authority_effect,
        "hb_reference": {"epoch": hb_epoch},
    }
    return _store(root, transition_id, body)
