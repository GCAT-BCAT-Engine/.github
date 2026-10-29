#!/usr/bin/env python3
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path
from org_boundary_runtime import build_egress, validate_org_crossing
# process_boundary's exit split (Data-Continuation#10), kept apart here: 65 is the
# crossing's own fault and terminal; 75 is this organization's own write fault,
# non-terminal, nothing durable was written and the same run completes it.
EXIT_INPUT_FAULT=65
EXIT_WRITE_FAULT=75
# Everything parsing a JSON document can raise for its content, nesting past the
# parser's depth included.
JSON_DOCUMENT_ERRORS=(ValueError,UnicodeError,RecursionError,MemoryError)
RETRY_ENTRYPOINT="resident-runtime/run_once.py"
def record(code,terminal,predicate,detail,repair,next_attempt):
 return {"disposition":"FAIL_CLOSED","failure_code":code,"terminal":terminal,"failed_predicate":predicate,"detail":detail,"required_evidence_or_repair":repair,"retry_entrypoint":RETRY_ENTRYPOINT,"owning_existing_goal":"INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001","next_attempt":next_attempt,"consequence_committed":False}
def input_fault(detail):
 print(json.dumps(record("RUN_ONCE_INPUT_FAULT",True,"THE_INGRESS_IS_A_PROCESSABLE_CROSSING",detail,"a readable JSON ingress envelope that validates as an organization crossing","this crossing is terminal; nothing was written"),sort_keys=True)); return EXIT_INPUT_FAULT
def write_fault(detail):
 print(json.dumps(record("RUN_ONCE_WRITE_FAULT",False,"THIS_BOUNDARY_RECORDS_ITS_OWN_STATE",detail,"this organization's own storage accepts the write","nothing durable was written; run the same crossing again"),sort_keys=True)); return EXIT_WRITE_FAULT
def result_invalid(detail):
 print(json.dumps(record("PROCESS_BOUNDARY_RESULT_INVALID",True,"AN_EXIT_0_RESULT_IS_AN_EGRESSABLE_EXECUTION_RECORD",detail,"a process_boundary whose exit-0 result is a JSON execution record this crossing can egress","this crossing is terminal; nothing was written"),sort_keys=True)); return EXIT_INPUT_FAULT
def child_record(run):
 for line in reversed(run.stdout.splitlines()):
  try: value=json.loads(line)
  except JSON_DOCUMENT_ERRORS: continue
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
 except (OSError,*JSON_DOCUMENT_ERRORS,KeyError,TypeError,AttributeError) as exc:
  return input_fault("--ingress: "+type(exc).__name__+": "+str(exc)[:200])
 try:
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/"execution.json"; run=subprocess.run(["python3","org-boundary/runtime/process_boundary.py","--envelope",a.ingress,"--out",str(p)],capture_output=True,text=True)
   if run.returncode==EXIT_INPUT_FAULT:
    # The crossing's own fault: terminal, relayed as the boundary recorded it.
    print(json.dumps(child_record(run) or record("PROCESS_BOUNDARY_INPUT_FAULT",True,"THE_ENVELOPE_AND_REGISTRY_ARE_A_PROCESSABLE_CROSSING",run.stderr[-500:],"a processable crossing","this crossing is terminal"),sort_keys=True)); return EXIT_INPUT_FAULT
   if run.returncode==EXIT_WRITE_FAULT:
    # The boundary's own write fault: non-terminal, nothing durable was written.
    child=child_record(run)
    if child is not None:
     print(json.dumps(child,sort_keys=True)); return EXIT_WRITE_FAULT
    return write_fault("process_boundary exited 75: "+(run.stdout+run.stderr)[-500:])
   if run.returncode!=0:
    # Exit 1, an unknown code or a crash: a terminal refusal, so an unclassified
    # failure never stays pending forever.
    print(json.dumps(record("PROCESS_BOUNDARY_REFUSED_EXIT_"+str(run.returncode),True,"PROCESS_BOUNDARY_EXITS_0_65_OR_75","process_boundary exited "+str(run.returncode)+": "+(run.stdout+run.stderr)[-500:],"a process_boundary that classifies its fault as 65 (input) or 75 (own write)","this crossing is terminal; nothing was written"),sort_keys=True)); return EXIT_INPUT_FAULT
   raw=p.read_bytes()
  # The boundary exited 0, so its result must be an execution record this crossing
  # can egress; one that is not is terminal, and nothing is written.
  try:
   result=json.loads(raw.decode("utf-8"))
   if not isinstance(result,dict): raise TypeError("the result is a "+type(result).__name__+", not a JSON object")
   egress=build_egress(ingress,result); validate_org_crossing(egress,"EGRESS")
   summary={"status":"PASS","packet_id":ingress["packet_id"],"egress_packet_id":egress["packet_id"],"consumed":result["consumed"],"reconstruction":result["reconstruction"]["status"]}
  except (*JSON_DOCUMENT_ERRORS,KeyError,TypeError,IndexError,AttributeError) as exc:
   return result_invalid(type(exc).__name__+": "+str(exc)[:200])
  write_egress(Path(a.egress),egress)
 except OSError as exc:
  return write_fault(type(exc).__name__+": "+str(exc))
 print(json.dumps(summary))
 return 0
if __name__=="__main__": sys.exit(main())
