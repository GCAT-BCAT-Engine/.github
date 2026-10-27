#!/usr/bin/env python3
"""The committed state transition that triggers resident-federation-cycle.yml.

The resident cycle runs on push to main when this file changes, once per
committed request. It reads the cycle's inputs from the pushed commit's copy
of REQUEST_PATH instead of from dispatch inputs:

  {"schema": "stegverse.resident-federation-cycle-request/v1",
   "request_id": "<one visible token>",
   "hb_epoch": <non-negative integer>}

No clock is read. An absent, unreadable or malformed request is a six-field
FAIL_CLOSED and nothing runs. An absent hb_epoch is written as HB_EPOCH= and
refused by the kernel's shared rule at the workflow's gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "stegverse.resident-federation-cycle-request/v1"
REQUEST_PATH = ".stegverse/resident-federation/cycle-request.json"
ENTRYPOINT = ".github/workflows/resident-federation-cycle.yml (push to main touching " + REQUEST_PATH + ")"
GOAL = "INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001"
FIELDS = {"schema", "request_id", "hb_epoch"}


def refusal(code: str, predicate: str, repair: str) -> dict[str, Any]:
    return {"disposition": "FAIL_CLOSED", "failure_code": code, "failed_predicate": predicate,
            "required_evidence_or_repair": repair, "retry_entrypoint": ENTRYPOINT,
            "owning_existing_goal": GOAL,
            "next_attempt": "commit a corrected " + REQUEST_PATH + " to main; the cycle did not run",
            "consequence_committed": False, "authority_effect": "NONE_REFUSAL_ONLY"}


def _visible(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and all(33 <= ord(c) <= 126 for c in value)


def read_request(path: Path | str) -> dict[str, Any]:
    """{"disposition": "ALLOW", "request_id", "hb_epoch" (or None), "request_sha256"} or a refusal."""
    path = Path(path)
    if not path.is_file():
        return refusal("CYCLE_REQUEST_ABSENT", "PUSHED_COMMIT_CARRIES_THE_REQUEST",
                       REQUEST_PATH + " is absent at the pushed commit")
    try:
        raw = path.read_bytes()
        request = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError, MemoryError):
        return refusal("CYCLE_REQUEST_UNREADABLE", "REQUEST_IS_UTF8_JSON", REQUEST_PATH + " is not UTF-8 JSON")
    if not isinstance(request, dict) or request.get("schema") != SCHEMA or set(request) - FIELDS:
        return refusal("CYCLE_REQUEST_SCHEMA_MISMATCH", "REQUEST_MATCHES_" + SCHEMA,
                       "an object with schema " + SCHEMA + " and only the fields " + ", ".join(sorted(FIELDS)))
    if not _visible(request.get("request_id")):
        return refusal("CYCLE_REQUEST_INPUT_INVALID", "REQUEST_ID_IS_ONE_VISIBLE_TOKEN",
                       "request_id as one visible token")
    epoch = request.get("hb_epoch")
    if epoch is not None and (isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0):
        return refusal("CYCLE_REQUEST_HB_EPOCH_INVALID", "HB_EPOCH_IS_A_NON_NEGATIVE_INTEGER",
                       "hb_epoch as a non-negative integer")
    # The committed request's own digest, recorded in the cycle record.
    return {"disposition": "ALLOW", "request_id": request["request_id"], "hb_epoch": epoch,
            "request_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--request", default=REQUEST_PATH)
    parser.add_argument("--github-env", help="append HB_EPOCH / CYCLE_REQUEST_SHA256 here")
    args = parser.parse_args(argv)
    result = read_request(args.request)
    print(json.dumps(result, sort_keys=True))
    if result["disposition"] != "ALLOW":
        return 1
    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as env:
            env.write("HB_EPOCH=" + ("" if result["hb_epoch"] is None else str(result["hb_epoch"])) + "\n")
            env.write("CYCLE_REQUEST_SHA256=" + result["request_sha256"] + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
