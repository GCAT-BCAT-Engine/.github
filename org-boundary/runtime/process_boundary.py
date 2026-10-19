#!/usr/bin/env python3
import argparse, hashlib, json, importlib.util, os, sys, tempfile
from pathlib import Path
# The exit-status split this boundary shares with its callers (Data-Continuation#10):
# 65 is the frame's own fault, terminal; 75 is this boundary's own write fault, nothing
# durable was written and the same run completes it. Each prints its six-field record.
EXIT_INPUT_FAULT=65
EXIT_WRITE_FAULT=75
RETRY_ENTRYPOINT="org-boundary/runtime/process_boundary.py"
class BoundaryFault(Exception):
 def __init__(self,record,status): super().__init__(record["detail"]); self.record=record; self.status=status
def fault(code,terminal,predicate,detail,repair,next_attempt,status):
 return BoundaryFault({"disposition":"FAIL_CLOSED","failure_code":code,"terminal":terminal,"failed_predicate":predicate,"detail":detail,"required_evidence_or_repair":repair,"retry_entrypoint":RETRY_ENTRYPOINT,"owning_existing_goal":"INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001","next_attempt":next_attempt,"consequence_committed":False},status)
def input_fault(detail):
 return fault("PROCESS_BOUNDARY_INPUT_FAULT",True,"THE_ENVELOPE_AND_REGISTRY_ARE_A_PROCESSABLE_CROSSING",detail,"a readable JSON envelope addressed to an installed boundary service of this organization","this frame is terminal; nothing was written",EXIT_INPUT_FAULT)
KINDS=["INGRESS_ACCEPTED","DISPATCHED","CONSUMED","RESULT_BOUND","EGRESS_EMITTED"]
def canon(v): return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def hid(prefix,v): return prefix+"-"+hashlib.sha256(canon(v)).hexdigest()[:24]
def load(path,argument):
 try: value=json.loads(Path(path).read_bytes().decode("utf-8"))
 except (OSError,UnicodeError,ValueError) as exc: raise input_fault(argument+": "+type(exc).__name__+": "+str(exc)) from None
 if not isinstance(value,dict): raise input_fault(argument+": the document is a "+type(value).__name__+", not a JSON object")
 return value
def write_out(path,text):
 """Whole or not at all: a temp file, fsynced, then os.replace."""
 try:
  path.parent.mkdir(parents=True,exist_ok=True); fd,temp=tempfile.mkstemp(prefix=".boundary-",suffix=".tmp",dir=str(path.parent))
  try:
   with os.fdopen(fd,"wb") as stream: stream.write(text.encode("utf-8")); stream.flush(); os.fsync(stream.fileno())
   os.replace(temp,path)
  finally:
   if os.path.exists(temp): os.unlink(temp)
 except OSError as exc:
  raise fault("PROCESS_BOUNDARY_WRITE_FAULT",False,"THIS_BOUNDARY_RECORDS_ITS_OWN_STATE","--out: "+type(exc).__name__+": "+str(exc),"this boundary's own storage accepts the execution record","nothing durable was written; run the same crossing again",EXIT_WRITE_FAULT) from None
def main():
 try: return process()
 except BoundaryFault as exc:
  print(json.dumps(exc.record,sort_keys=True)); return exc.status
def process():
 ap=argparse.ArgumentParser(); ap.add_argument("--envelope",required=True); ap.add_argument("--registry",default="org-boundary/registry/services.json"); ap.add_argument("--out",required=True); a=ap.parse_args()
 env=load(a.envelope,"--envelope"); reg=load(a.registry,"--registry")
 req=["schema_version","packet_id","direction","origin","destination","carrier","intr_profile","transition","payload","evidence"]; miss=[k for k in req if k not in env]
 if miss: raise input_fault("missing:"+",".join(miss))
 try:
  if env["destination"]["org"]!=reg["organization"]: raise input_fault("wrong-destination-org")
  svc=next((s for s in reg["services"] if s["service_id"]==env["destination"]["service"]),None)
 except (KeyError,TypeError) as exc: raise input_fault("malformed: "+type(exc).__name__+": "+str(exc)) from None
 if not svc: raise input_fault("unknown-service")
 if svc.get("boundary_role") not in {"BOUNDARY_LOCAL_DIAGNOSTIC","BOUNDARY_LOCAL_CONFORMANCE"}: raise input_fault("endpoint-adapter-not-installed")
 base={"packet_id":env["packet_id"],"service_id":svc["service_id"],"payload_hash":hashlib.sha256(canon(env["payload"])).hexdigest()}
 receipts=[]; prev=None
 for kind in KINDS:
  subject={**base,"kind":kind,"previous_receipt_id":prev}; rid=hid(kind.lower(),subject); receipts.append({"kind":kind,"receipt_id":rid,"subject":svc["service_id"],"evidence_hash":hashlib.sha256(canon(subject)).hexdigest(),"previous_receipt_id":prev}); prev=rid
 app={"echo":env["payload"]}
 if svc.get("boundary_role")=="BOUNDARY_LOCAL_CONFORMANCE":
  hp=Path(svc["handler"]); spec=importlib.util.spec_from_file_location("organization_role_conformance",hp); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); app=mod.evaluate(env["payload"])
 result={"schema_version":reg["organization"].lower().replace(" ","-")+".boundary-execution.v1","packet_id":env["packet_id"],"organization":reg["organization"],"service_id":svc["service_id"],"consumed":True,"application_result":app,"authority_effect":env["transition"]["authority_effect"],"receipts":receipts,"reconstruction":{"same_execution_required":True,"status":"RECONSTRUCTED","terminal_receipt_id":prev}}
 write_out(Path(a.out),json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps({"status":"PASS","terminal_receipt_id":prev})); return 0
if __name__=="__main__": sys.exit(main())
