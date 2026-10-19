#!/usr/bin/env python3
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path
from org_boundary_runtime import build_egress, validate_org_crossing
# process_boundary's exit split (Data-Continuation#10), kept apart here: 65 is the
# crossing's own fault and terminal; 75 is this organization's own write fault,
# non-terminal, nothing durable was written and the same run completes it.
EXIT_INPUT_FAULT=65
EXIT_WRITE_FAULT=75
RETRY_ENTRYPOINT="resident-runtime/run_once.py"
def record(code,terminal,predicate,detail,repair,next_attempt):
 return {"disposition":"FAIL_CLOSED","failure_code":code,"terminal":terminal,"failed_predicate":predicate,"detail":detail,"required_evidence_or_repair":repair,"retry_entrypoint":RETRY_ENTRYPOINT,"owning_existing_goal":"INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001","next_attempt":next_attempt,"consequence_committed":False}
def input_fault(detail):
 print(json.dumps(record("RUN_ONCE_INPUT_FAULT",True,"THE_INGRESS_IS_A_PROCESSABLE_CROSSING",detail,"a readable JSON ingress envelope that validates as an organization crossing","this crossing is terminal; nothing was written"),sort_keys=True)); return EXIT_INPUT_FAULT
def write_fault(detail):
 print(json.dumps(record("RUN_ONCE_WRITE_FAULT",False,"THIS_BOUNDARY_RECORDS_ITS_OWN_STATE",detail,"this organization's own storage accepts the write","nothing durable was written; run the same crossing again"),sort_keys=True)); return EXIT_WRITE_FAULT
def child_record(run):
 for line in reversed(run.stdout.splitlines()):
  try: value=json.loads(line)
  except ValueError: continue
  if isinstance(value,dict) and value.get("disposition")=="FAIL_CLOSED": return value
 return None
def write_egress(path,egress):
 path.parent.mkdir(parents=True,exist_ok=True); fd,temp=tempfile.mkstemp(prefix=".egress-",suffix=".tmp",dir=str(path.parent))
 try:
  with os.fdopen(fd,"wb") as stream: stream.write((json.dumps(egress,indent=2,sort_keys=True)+"\n").encode("utf-8")); stream.flush(); os.fsync(stream.fileno())
  os.replace(temp,path)
 finally:
  if os.path.exists(temp): os.unlink(temp)
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--ingress",required=True); ap.add_argument("--egress",required=True); a=ap.parse_args()
 try:
  ingress=json.loads(Path(a.ingress).read_bytes().decode("utf-8")); validate_org_crossing(ingress,"INGRESS")
 except (OSError,UnicodeError,ValueError,KeyError,TypeError,AttributeError) as exc:
  return input_fault("--ingress: "+type(exc).__name__+": "+str(exc))
 try:
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/"execution.json"; run=subprocess.run(["python3","org-boundary/runtime/process_boundary.py","--envelope",a.ingress,"--out",str(p)],capture_output=True,text=True)
   if run.returncode==EXIT_INPUT_FAULT:
    # The crossing's own fault: terminal, relayed as the boundary recorded it.
    print(json.dumps(child_record(run) or record("PROCESS_BOUNDARY_INPUT_FAULT",True,"THE_ENVELOPE_AND_REGISTRY_ARE_A_PROCESSABLE_CROSSING",run.stderr[-500:],"a processable crossing","this crossing is terminal"),sort_keys=True)); return EXIT_INPUT_FAULT
   if run.returncode!=0:
    # 75, or any other non-zero status: never treated as the crossing's fault.
    child=child_record(run)
    if run.returncode==EXIT_WRITE_FAULT and child is not None:
     print(json.dumps(child,sort_keys=True)); return EXIT_WRITE_FAULT
    return write_fault("process_boundary exited "+str(run.returncode)+": "+(run.stdout+run.stderr)[-500:])
   result=json.loads(p.read_text())
  egress=build_egress(ingress,result); validate_org_crossing(egress,"EGRESS"); write_egress(Path(a.egress),egress)
 except OSError as exc:
  return write_fault(type(exc).__name__+": "+str(exc))
 print(json.dumps({"status":"PASS","packet_id":ingress["packet_id"],"egress_packet_id":egress["packet_id"],"consumed":result["consumed"],"reconstruction":result["reconstruction"]["status"]}))
 return 0
if __name__=="__main__": sys.exit(main())
