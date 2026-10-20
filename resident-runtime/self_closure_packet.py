#!/usr/bin/env python3
"""The committed state transition that triggers organization-ledger-transition.yml.

The writer runs on push to main when this file changes. It reads the
diagnostic self-closure inputs from the pushed commit's copy of PACKET_PATH
instead of from dispatch inputs:

  {"schema": "stegverse.intr-destination-self-closure-packet/v1",
   "communication_id": "<one visible token>",
   "packet_id": "<one visible token>",      (optional)
   "hb_epoch": <non-negative integer>}        (required where --require-hb-epoch)

No clock is read. An absent, unreadable or malformed packet is a six-field
FAIL_CLOSED and nothing is appended. A packet already recorded under the same
communication_id replays through intr_destination_ingress, which returns the
recorded pair rather than minting another.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "stegverse.intr-destination-self-closure-packet/v1"
PACKET_PATH = ".stegverse/intr-destination/self-closure-packet.json"
ENTRYPOINT = ".github/workflows/organization-ledger-transition.yml (push to main touching " + PACKET_PATH + ")"
GOAL = "ORGANIZATION-ROLE-RUNTIME-REALITY-DEPLOYMENT-001"
FIELDS = {"schema", "communication_id", "packet_id", "hb_epoch"}


def refusal(code: str, predicate: str, repair: str) -> dict[str, Any]:
    return {"disposition": "FAIL_CLOSED", "failure_code": code, "failed_predicate": predicate,
            "required_evidence_or_repair": repair, "retry_entrypoint": ENTRYPOINT,
            "owning_existing_goal": GOAL,
            "next_attempt": "commit a corrected " + PACKET_PATH + " to main; nothing was appended",
            "consequence_committed": False, "authority_effect": "NONE_REFUSAL_ONLY"}


def _visible(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and all(33 <= ord(c) <= 126 for c in value)


def read_packet(path: Path | str, *, require_hb_epoch: bool) -> dict[str, Any]:
    """{"disposition": "ALLOW", "communication_id", "packet_id" (or None), "hb_epoch" (or None)} or a refusal."""
    path = Path(path)
    if not path.is_file():
        return refusal("SELF_CLOSURE_PACKET_ABSENT", "PUSHED_COMMIT_CARRIES_THE_PACKET",
                       PACKET_PATH + " is absent at the pushed commit")
    try:
        packet = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return refusal("SELF_CLOSURE_PACKET_UNREADABLE", "PACKET_IS_UTF8_JSON", PACKET_PATH + " is not UTF-8 JSON")
    if not isinstance(packet, dict) or packet.get("schema") != SCHEMA or set(packet) - FIELDS:
        return refusal("SELF_CLOSURE_PACKET_SCHEMA_MISMATCH", "PACKET_MATCHES_" + SCHEMA,
                       "an object with schema " + SCHEMA + " and only the fields " + ", ".join(sorted(FIELDS)))
    if not _visible(packet.get("communication_id")):
        return refusal("SELF_CLOSURE_INPUT_INVALID", "COMMUNICATION_ID_IS_ONE_VISIBLE_TOKEN",
                       "communication_id as one visible token")
    packet_id = packet.get("packet_id")
    if packet_id is not None and not _visible(packet_id):
        return refusal("SELF_CLOSURE_INPUT_INVALID", "PACKET_ID_IS_ONE_VISIBLE_TOKEN",
                       "packet_id omitted or one visible token")
    epoch = packet.get("hb_epoch")
    if epoch is None and require_hb_epoch:
        return refusal("SELF_CLOSURE_HB_EPOCH_UNSUPPLIED", "HB_EPOCH_IS_SUPPLIED_IN_THE_PACKET",
                       "hb_epoch as a non-negative integer; no clock is read for it")
    if epoch is not None and (isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0):
        return refusal("SELF_CLOSURE_HB_EPOCH_INVALID", "HB_EPOCH_IS_A_NON_NEGATIVE_INTEGER",
                       "hb_epoch as a non-negative integer")
    return {"disposition": "ALLOW", "communication_id": packet["communication_id"], "packet_id": packet_id,
            "hb_epoch": epoch}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--packet", default=PACKET_PATH)
    parser.add_argument("--require-hb-epoch", action="store_true")
    parser.add_argument("--github-env", help="append CLOSURE_COMMUNICATION_ID / CLOSURE_PACKET_ID / HB_EPOCH here")
    args = parser.parse_args(argv)
    result = read_packet(args.packet, require_hb_epoch=args.require_hb_epoch)
    print(json.dumps(result, sort_keys=True))
    if result["disposition"] != "ALLOW":
        return 1
    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as env:
            env.write("CLOSURE_COMMUNICATION_ID=" + result["communication_id"] + "\n")
            env.write("CLOSURE_PACKET_ID=" + (result["packet_id"] or "") + "\n")
            env.write("HB_EPOCH=" + ("" if result["hb_epoch"] is None else str(result["hb_epoch"])) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
