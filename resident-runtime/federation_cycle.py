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
    args=ap.parse_args(argv)
    try:
        heartbeat=K.supplied_hb_reference(args.hb_epoch,retry_entrypoint=EPOCH_RETRY_ENTRYPOINT)
        if os.getenv("STEGVERSE_ORG_FEDERATION_GATEWAY_URL","").strip():
            receipt=GW.resident_gateway_cycle(ROOT,hb_epoch=heartbeat["epoch"])
            receipt["heartbeat_reference"]=heartbeat
            receipt["transport"]="SHARED_SERVICE_GATEWAY"
        else:
            results=K.consume_and_respond(ROOT,hb_epoch=heartbeat["epoch"])
            consumed=sum(1 for x in results if (x.get("result") or {}).get("status")=="CONSUMED")
            responses=sum(1 for x in results if x.get("response_publication"))
            refused=sum(1 for x in results if (x.get("result") or {}).get("status")=="REFUSED")
            receipt={
              "schema_version":"stegverse.org-federation-cycle.v1",
              "organization":K.load_registry(ROOT)["organization"],
              "heartbeat_reference":heartbeat,
              "frames_seen":len(results),
              "frames_consumed":consumed,
              "frames_refused":refused,
              "responses_emitted":responses,
              "authority_effect":"NONE_CARRIER_ONLY",
              "transport":"LOCAL_SPOOL_FALLBACK"
            }
    except ValueError as exc:
        # A six-field epoch refusal: the cycle's own, a frame's, or a receiving
        # operation's. It is raised by whichever kernel copy refused, so it is
        # read by its `refusal`, not its class. No cycle record is written.
        if not isinstance(getattr(exc,"refusal",None),dict):
            raise
        print(json.dumps(exc.refusal,sort_keys=True))
        return 1
    out=ROOT/"resident-runtime"/"federation"/"latest-cycle.json"
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
