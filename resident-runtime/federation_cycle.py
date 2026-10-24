#!/usr/bin/env python3
from __future__ import annotations
import argparse, importlib.util, json, os
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("org_kernel",ROOT/"org-kernel"/"kernel.py")
K=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(K)
GWSPEC=importlib.util.spec_from_file_location("federation_gateway_transport",ROOT/"resident-runtime"/"federation_gateway_transport.py")
GW=importlib.util.module_from_spec(GWSPEC); GWSPEC.loader.exec_module(GW)

# A cycle's heartbeat epoch is supplied (--hb-epoch, or HB_EPOCH) and checked
# by the kernel's shared rule before any frame is consumed. It stamps the
# cycle record and every response frame; no clock is read in its place.
EPOCH_RETRY_ENTRYPOINT="resident-runtime/federation_cycle.py::main (--hb-epoch, or HB_EPOCH)"

def main(argv:list[str]|None=None)->int:
    ap=argparse.ArgumentParser()
    # HB_EPOCH unset is NOT_SUPPLIED; set, even to "", it is read by the rule.
    ap.add_argument("--hb-epoch",default=os.environ.get("HB_EPOCH"),
                    help="heartbeat epoch, ASCII digits >= 32; the cycle refuses when absent or invalid")
    ap.add_argument("--committed-request",default=None,
                    help="PATH=sha256:<hex>: the committed cycle request that triggered this run")
    args=ap.parse_args(argv)
    committed_request=None
    if args.committed_request is not None:
        path,_,digest=args.committed_request.partition("=")
        if (not path or not digest.startswith("sha256:") or len(digest)!=71
                or any(c not in "0123456789abcdef" for c in digest[7:])):
            print(json.dumps(K.input_refusal("--committed-request","not PATH=sha256:<64 hex>",
                                             retry_entrypoint=EPOCH_RETRY_ENTRYPOINT),sort_keys=True))
            return 1
        # The committed request's path and digest, recorded in the cycle record
        # (the COMMITTED_REQUEST rule, (b)).
        committed_request={"path":path,"sha256":digest,"hb_epoch_source":"COMMITTED_REQUEST"}
    try:
        heartbeat=K.supplied_hb_reference(args.hb_epoch,retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)
        if os.getenv("STEGVERSE_ORG_FEDERATION_GATEWAY_URL","").strip():
            receipt=GW.resident_gateway_cycle(ROOT,hb_epoch=heartbeat["epoch"])
            receipt["heartbeat_reference"]=heartbeat
            receipt["transport"]="SHARED_SERVICE_GATEWAY"
        else:
            results=K.consume_and_respond(ROOT,hb_epoch=heartbeat["epoch"])
            consumed=sum(1 for x in results if (x.get("result") or {}).get("status")=="CONSUMED")
            responses=sum(1 for x in results
                          if x.get("response_publication") and not x["response_publication"].get("reused"))
            refused=sum(1 for x in results if (x.get("result") or {}).get("status")=="REFUSED")
            deferred=sum(1 for x in results if (x.get("result") or {}).get("status")=="DEFERRED")
            receipt={
              "schema_version":"stegverse.org-federation-cycle.v1",
              "organization":K.load_registry(ROOT)["organization"],
              "heartbeat_reference":heartbeat,
              "frames_seen":len(results),
              "frames_consumed":consumed,
              "frames_refused":refused,
              "frames_deferred":deferred,
              "responses_emitted":responses,
              # Each frame this boundary's own write fault left pending, as its
              # non-terminal six-field record: the next run consumes it once.
              "deferrals":[x["result"]["refusal"] for x in results
                           if (x.get("result") or {}).get("status")=="DEFERRED"],
              "authority_effect":"NONE_CARRIER_ONLY",
              "transport":"LOCAL_SPOOL_FALLBACK"
            }
    except Exception as exc:
        # A six-field epoch refusal: the cycle's own, a frame's, or a receiving
        # operation's. It is raised by whichever kernel copy refused, so it is
        # read by its `refusal`, not its class. A write fault outside any one
        # frame is non-terminal six-field. No cycle record is written.
        refusal=K.cli_refusal(exc,retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)
        if refusal is None and isinstance(exc,GW.FederationGatewayTransportError):
            # The gateway did not answer with a usable document (unreachable,
            # not JSON, nested past the parser's depth): nothing was consumed or
            # acknowledged, so the next cycle fetches again.
            refusal={"disposition":"FAIL_CLOSED","failure_code":"GATEWAY_TRANSPORT_FAILED","terminal":False,
                     "failed_predicate":"THE_GATEWAY_ANSWERS_WITH_A_USABLE_DOCUMENT",
                     "detail":type(exc).__name__+": "+str(exc)[:200],
                     "required_evidence_or_repair":"the shared-service gateway answers with a JSON document",
                     "retry_entrypoint":EPOCH_RETRY_ENTRYPOINT,
                     "owning_existing_goal":K.HB_EPOCH_OWNING_EXISTING_GOAL,
                     "next_attempt":"run the cycle again; no frame was consumed or acknowledged",
                     "consequence_committed":False}
        if refusal is None:
            raise
        print(json.dumps(refusal,sort_keys=True))
        return 1
    if committed_request is not None:
        receipt["committed_request"]=committed_request
    out=ROOT/"resident-runtime"/"federation"/"latest-cycle.json"
    try:
        # Whole or not at all; every frame's own outcome is already durable on
        # its seen marker, so the next run completes without redoing any.
        K.write_json_atomic(out,receipt)
    except OSError as exc:
        print(json.dumps({"disposition":"FAIL_CLOSED","failure_code":"CYCLE_RECORD_WRITE_FAILED","terminal":False,
                          "failed_predicate":"THIS_BOUNDARY_RECORDS_ITS_OWN_STATE",
                          "detail":type(exc).__name__+": "+str(exc),
                          "required_evidence_or_repair":"this boundary's own storage accepts the cycle record",
                          "retry_entrypoint":EPOCH_RETRY_ENTRYPOINT,
                          "owning_existing_goal":K.HB_EPOCH_OWNING_EXISTING_GOAL,
                          "next_attempt":"run the cycle again; frames already marked are not redone",
                          "consequence_committed":False},sort_keys=True))
        return 1
    print(json.dumps(receipt,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
