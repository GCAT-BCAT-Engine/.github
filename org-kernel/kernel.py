#!/usr/bin/env python3
"""Universal StegVerse organization resident kernel.

Organization-neutral runtime behavior extracted from StegVerse-Labs/.github.
No GitHub, hosted scheduler, provider, or carrier sets authority. Authority and time are constraint variables; a disposition is transition evidence only.
"""
from __future__ import annotations
import base64, hashlib, hmac, importlib.util, json, math, os, secrets, tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HB_ANCHOR_EPOCH=32
HB_ANCHOR_UNIX_NS=1_787_511_600_000_000_000
HB_PERIOD_NS=10_000_000
HB_HZ=100
CHANNEL_COUNT=16
SCHEMA="stegverse.org-resident-kernel/v1"
CARRIER_SCHEMA="stegverse.org-resident-kernel.carrier/v1"
PACKET_SCHEMA="stegverse.intr.org-boundary.v1"

def canon(v:Any)->bytes:
    return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()

def sha(v:Any)->str:
    raw=v if isinstance(v,(bytes,bytearray)) else canon(v)
    return "sha256:"+hashlib.sha256(bytes(raw)).hexdigest()

def hb_reference(now_ns:int|None=None, *, epoch:int|None=None,
                 provenance:dict[str,Any]|None=None)->dict[str,Any]:
    """Heartbeat reference. Time is a constraint variable.

    A supplied epoch is a count of heartbeat periods from the HB32 anchor, and
    the reference then omits the clock sample. A clock sample keeps the fields
    this kernel already returned for a carrier frame. `provenance`, a verified
    CARRIED claim's `source` and `head_receipt_sha`, is kept on the reference so
    it reads as CARRIED rather than SUPPLIED.
    """
    if epoch is not None:
        if now_ns is not None:
            raise ValueError("supply_epoch_or_sample_not_both")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < HB_ANCHOR_EPOCH:
            raise ValueError("epoch_precedes_hb32_anchor")
        reference = {"epoch": epoch, "generation": epoch, "heartbeat_id": f"HB:{epoch}",
                     "phase_offset_ns": 0, "frequency_hz": HB_HZ,
                     "progression_dependency": "OSCILLATOR_ONLY",
                     "derived_from_clock": False, "authority_effect": "NONE"}
        if provenance:
            reference.update({key: provenance[key] for key in ("source", "head_receipt_sha")})
        return reference
    if now_ns is None:
        now_ns=int(datetime.now(timezone.utc).timestamp()*1_000_000_000)
    if now_ns<HB_ANCHOR_UNIX_NS:
        raise ValueError("sample_precedes_hb32_anchor")
    q,phase=divmod(now_ns-HB_ANCHOR_UNIX_NS,HB_PERIOD_NS)
    epoch=HB_ANCHOR_EPOCH+q
    return {"epoch":epoch,"generation":epoch,"heartbeat_id":f"HB:{epoch}","sampled_unix_ns":now_ns,
            "phase_offset_ns":phase,"frequency_hz":HB_HZ,"progression_dependency":"OSCILLATOR_ONLY",
            "authority_effect":"NONE"}

# A receipt writer's heartbeat epoch is supplied by its caller and checked by
# the shared rule below, ported from StegVerse-Labs/.github WU-B13a; an
# absent or invalid one is refused six-field FAIL_CLOSED before anything is
# written, and no clock is read in its place.
HB_EPOCH_NOT_SUPPLIED="HB_EPOCH_NOT_SUPPLIED"
HB_EPOCH_INVALID="HB_EPOCH_INVALID"
HB_EPOCH_PROVENANCE_UNMARKED="HB_EPOCH_PROVENANCE_UNMARKED"
HB_EPOCH_PREDICATE="SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH"
HB_EPOCH_OWNING_EXISTING_GOAL="INTERLOCK-INTR-RUNTIME-INDEPENDENT-PROTOCOL-001"

def supplied_epoch_failure(hb_epoch: Any, reference: Any = None) -> tuple[str, str] | None:
    """The shared supplied-epoch rule (SUBMISSION_CARRIES_THE_SUPPLIED_HB_EPOCH).

    Byte-identical in StegVerse-org/.github#185 and StegVerse-Labs/.github#3212
    and #3213. `hb_epoch` absent (None) is HB_EPOCH_NOT_SUPPLIED. Otherwise it
    must be ASCII [0-9]+ only -- an int is read as its decimal text; a bool, a
    float or anything coerced ('+33', ' 33', '3_3', '33.0') is refused -- with
    integer value >= 32 (the HB32 anchor). `reference`, the carrier frame's
    heartbeat reference when there is one, must be an object, and a
    `derived_from_clock` it carries must be exactly false. Any failure is
    HB_EPOCH_INVALID. Returns (failure_code, detail), or None when the epoch is
    supplied. No clock is read.
    """
    if reference is not None and not isinstance(reference, dict):
        return "HB_EPOCH_INVALID", "the carrier's heartbeat reference is not an object"
    if hb_epoch is None:
        return "HB_EPOCH_NOT_SUPPLIED", "no hb_epoch was supplied and no clock is read"
    if isinstance(hb_epoch, bool):
        text = None
    elif isinstance(hb_epoch, int):
        text = str(hb_epoch)
    elif isinstance(hb_epoch, str):
        text = hb_epoch
    else:
        text = None
    if text is None or not text.isascii() or not text.isdigit():
        return "HB_EPOCH_INVALID", "hb_epoch " + repr(hb_epoch) + " is not ASCII [0-9]+"
    if int(text) < 32:
        return "HB_EPOCH_INVALID", "hb_epoch " + text + " is below the HB32 anchor (32)"
    if reference is not None and "derived_from_clock" in reference \
            and reference["derived_from_clock"] is not False:
        return "HB_EPOCH_INVALID", ("the carrier's derived_from_clock is not exactly false; "
                                    "a clock-derived epoch is not a supplied one")
    if reference is not None and "sampled_unix_ns" in reference: return "HB_EPOCH_INVALID", "the carrier's heartbeat reference carries sampled_unix_ns; a sampled clock value is CLOCK, never a supplied epoch"
    if reference is not None and "derived_from_clock" not in reference: return "HB_EPOCH_PROVENANCE_UNMARKED", "the carrier's heartbeat reference carries no derived_from_clock; an unmarked clock value is laundering, and a carrier cannot self-assert CARRIED provenance"
    return None

# sha256 of inspect.getsource(supplied_epoch_failure), the #3282 FINAL text
# (StegVerse-Labs/.github#3282 @e1b3ac8). Every copy of the rule pins it.
SHARED_VALIDATOR_SHA256="ad8ff52936d5bcd9a2ad6caceb2d9a637a099518989b34bbb3370301c7a4cce2"

class SuppliedEpochRefused(ValueError):
    """A receipt writer's refusal of an absent or invalid supplied epoch.

    `refusal` is the six-field FAIL_CLOSED from `writer_epoch_refusal`. Raised
    before anything is written; no clock is read to stand in for the epoch.
    """
    def __init__(self, refusal:dict[str,Any])->None:
        super().__init__(refusal["failure_code"]+": "+refusal["detail"])
        self.disposition=refusal["disposition"]
        self.failed_predicate=refusal["failed_predicate"]
        self.refusal=dict(refusal)

def writer_epoch_refusal(hb_epoch:Any, *, retry_entrypoint:str, reference:Any=None)->dict[str,Any]|None:
    """The six-field FAIL_CLOSED of a receipt writer's epoch, or None when it is supplied.

    The shape StegVerse-org/.github#189 gave the organization ledger
    (`epoch_refusal`): a receipt references the heartbeat epoch its caller
    supplies, checked by `supplied_epoch_failure`; an absent one is
    HB_EPOCH_NOT_SUPPLIED and is never derived from a clock. `reference` is
    the carrier frame's heartbeat reference, when the epoch is carried by one.
    """
    failure=supplied_epoch_failure(hb_epoch,reference)
    if failure is None:
        return None
    code,detail=failure
    return {"disposition":"FAIL_CLOSED","failure_code":code,"failed_predicate":HB_EPOCH_PREDICATE,
            "detail":detail,
            "required_evidence_or_repair":("the caller supplies hb_epoch= (or --hb-epoch): ASCII digits with "
                                           "value >= "+str(HB_ANCHOR_EPOCH)+"; it is never derived from a clock"),
            "retry_entrypoint":retry_entrypoint,
            "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":"call again with the supplied epoch; nothing was written",
            "derived_from_clock":False,"consequence_committed":False}

def supplied_hb_reference(hb_epoch:Any, *, retry_entrypoint:str, provenance:dict[str,Any]|None=None,
                          admission_root:Path|None=None)->dict[str,Any]:
    """The heartbeat reference of a supplied epoch, or SuppliedEpochRefused. No clock is read.

    With `provenance` (a CARRIED claim's `source` and `head_receipt_sha`), the
    writer verifies the claim itself against the current organization ledger
    head, exactly as ingest does. It is kept on the reference, and one that
    does not verify is CARRIED_PROVENANCE_UNVERIFIED.
    """
    refusal=writer_epoch_refusal(hb_epoch,retry_entrypoint=retry_entrypoint)
    if refusal is not None:
        raise SuppliedEpochRefused(refusal)
    epoch=int(str(hb_epoch))
    if provenance is not None:
        claim={"epoch":epoch,"derived_from_clock":False,
               **{key:provenance.get(key) for key in CARRIED_PROVENANCE_FIELDS}}
        for key in ADMISSION_FIELDS:
            if key in provenance:
                claim[key]=provenance[key]
        unverified=carried_provenance_failure(claim,admission_root=admission_root)
        if unverified is not None:
            raise SuppliedEpochRefused(carried_provenance_refusal(unverified,retry_entrypoint))
    return hb_reference(epoch=epoch,provenance=provenance)

def derive_channel(payload_hash:str)->dict[str,Any]:
    if not isinstance(payload_hash,str) or not payload_hash.startswith("sha256:") or len(payload_hash)!=71:
        raise ValueError("payload_hash_invalid")
    slot=int(payload_hash[7:23],16)%CHANNEL_COUNT
    return {"channel_id":f"HB:H1:P{slot}","phase_slot":slot,"phase_slot_count":CHANNEL_COUNT,
            "derivation":"PAYLOAD_SHA256_FIRST64_MOD_16","authority_effect":"NONE_CARRIER_ONLY"}

def carrier_frame(packet:dict[str,Any], *, now_ns:int|None=None, epoch:int|None=None)->dict[str,Any]:
    """A carrier frame. A supplied `epoch` is the frame's heartbeat reference and no clock is read."""
    raw=canon(packet); payload_hash=sha(packet.get("payload",{})); ref=hb_reference(now_ns,epoch=epoch); channel=derive_channel(payload_hash)
    body={"schema":CARRIER_SCHEMA,"packet_id":packet["packet_id"],"packet_sha256":sha(raw),
          "packet_base64":base64.b64encode(raw).decode("ascii"),"heartbeat_reference":ref,
          "channel":channel,"origin_org":packet["origin"]["org"],"destination_org":packet["destination"]["org"],
          "intr_profile":packet["intr_profile"],"authority_effect":"NONE_CARRIER_ONLY"}
    return {**body,"frame_sha256":sha(body)}

def recover_packet(frame:dict[str,Any])->dict[str,Any]:
    body=dict(frame); claimed=body.pop("frame_sha256",None)
    if claimed!=sha(body): raise ValueError("carrier_frame_hash_mismatch")
    raw=base64.b64decode(frame["packet_base64"].encode("ascii"),validate=True)
    if sha(raw)!=frame["packet_sha256"]: raise ValueError("packet_hash_mismatch")
    packet=json.loads(raw)
    if packet["packet_id"]!=frame["packet_id"]: raise ValueError("packet_id_mismatch")
    if packet["destination"]["org"]!=frame["destination_org"]: raise ValueError("destination_org_mismatch")
    return packet

def receipt(kind:str, packet_id:str, subject:str, previous:str|None, detail:dict[str,Any])->dict[str,Any]:
    body={"kind":kind,"packet_id":packet_id,"subject":subject,"previous_receipt_id":previous,"detail":detail}
    rid=kind.lower()+"-"+hashlib.sha256(canon(body)).hexdigest()[:24]
    return {**body,"receipt_id":rid,"evidence_hash":sha(body)}

def load_registry(root:Path)->dict[str,Any]:
    return json.loads((root/"org-boundary/registry/services.json").read_text())

#: The boundary role whose dispatch resolves a bound capability's address.
#:
#: The role vocabulary is this kernel's, as `BOUNDARY_LOCAL_DIAGNOSTIC` and
#: `BOUNDARY_LOCAL_CONTROL` already are. `capability_ingress.ROLE` is that
#: module's assertion of which role it serves. A resolver serving a role the
#: kernel never dispatches would be unreachable.
CAPABILITY_INGRESS_ROLE="BOUNDARY_LOCAL_CAPABILITY_INGRESS"
NO_PROCESSOR_SELECTED="BOUNDARY_LOCAL_NO_PROCESSOR_SELECTED"

def capability_ingress(root:Path):
    """Load the organization's capability-ingress module from its boundary runtime.

    A registered capability is bound to a receiving operation in the
    organization's own overlay. This resolves the address to that operation.
    Loaded only when a capability address is dispatched: a root that never
    serves one is not defective for having no resolver until it is addressed.
    """
    path=root/"org-boundary/runtime/capability_ingress.py"
    if not path.is_file(): raise ValueError("org_boundary_capability_ingress_missing")
    spec=importlib.util.spec_from_file_location("capability_ingress",path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def dispatch(root:Path, packet:dict[str,Any], *, mesh_root:Path|None=None, hb_epoch:Any=None,
             hb_provenance:dict[str,Any]|None=None,
             committed_request:dict[str,Any]|None=None)->dict[str,Any]:
    registry=load_registry(root)
    if packet["destination"]["org"]!=registry["organization"]: raise ValueError("wrong_destination_org")
    service=next((s for s in registry["services"] if s["service_id"]==packet["destination"]["service"]),None)
    if service is None: raise ValueError("unknown_service")
    role=service.get("boundary_role")
    if role not in {"BOUNDARY_LOCAL_DIAGNOSTIC","BOUNDARY_LOCAL_CONTROL",CAPABILITY_INGRESS_ROLE}:
        raise ValueError("endpoint_adapter_not_installed")
    # A capability address resolves before any receipt is minted. Its refusal
    # is this boundary's refusal. The receiving operation records both ledger
    # levels itself, so this kernel does not write a second pair for the frame.
    extra={}
    if role==CAPABILITY_INGRESS_ROLE:
        try:
            # The committed request that triggered this cycle, when there is
            # one, is recorded in every receipt the operation writes (the
            # COMMITTED_REQUEST rule, (b)).
            application_result=capability_ingress(root).receive(
                root,service,packet,registry=registry,mesh_root=mesh_root,hb_epoch=hb_epoch,
                hb_provenance=hb_provenance,
                **({} if committed_request is None else {"committed_request":committed_request}))
        except SystemExit as refused:
            raise ValueError("capability_ingress_refused:"+str(refused)) from None
        extra["processing_selection"]=NO_PROCESSOR_SELECTED
    prev=None; receipts=[]
    for kind in ("INGRESS_ACCEPTED","DISPATCHED","CONSUMED","RESULT_BOUND","EGRESS_EMITTED"):
        r=receipt(kind,packet["packet_id"],service["service_id"],prev,{"payload_hash":sha(packet["payload"])})
        receipts.append(r); prev=r["receipt_id"]
    if role=="BOUNDARY_LOCAL_CONTROL":
        application_result=handle_control_message(root,packet,registry,hb_epoch=hb_epoch,
                                                  hb_provenance=hb_provenance)
    elif role!=CAPABILITY_INGRESS_ROLE:
        application_result={"echo":packet["payload"]}
    return {"schema_version":SCHEMA,"organization":registry["organization"],"packet_id":packet["packet_id"],
            "service_id":service["service_id"],"consumed":True,"application_result":application_result,
            **extra,
            "authority_effect":packet["transition"]["authority_effect"],"receipts":receipts,
            "reconstruction":{"same_execution_required":True,"status":"RECONSTRUCTED","terminal_receipt_id":prev}}

def write_json_atomic(path:Path, value:Any)->Path:
    """Write a JSON document whole or not at all: a temp file in the same
    directory, fsynced, then os.replace. A fault part-way leaves the previous
    document (or none), never a torn one."""
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix=".atomic-",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write((json.dumps(value,indent=2,sort_keys=True)+"\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return path

def write_once_json(path:Path, value:Any, *, collision:str)->Path:
    """Write a write-once JSON document, idempotently resumable.

    The same document already there is success. A different one is the
    `collision`. One that does not parse is a torn earlier write of this
    boundary's own, written before writes were atomic, and is replaced rather
    than refusing itself forever.
    """
    if path.exists():
        try:
            existing=json.loads(path.read_bytes().decode("utf-8"))
        except JSON_DOCUMENT_ERRORS:
            existing=_TORN
        if existing is not _TORN:
            if existing!=value:
                raise ValueError(collision)
            return path
    return write_json_atomic(path,value)

_TORN=object()

#: Everything parsing one JSON document can raise for its content: not UTF-8,
#: not JSON, or nested past the parser's depth (RecursionError) or memory. A
#: peer- or caller-supplied document raising one is that document's fault.
JSON_DOCUMENT_ERRORS=(ValueError,UnicodeError,RecursionError,MemoryError)

def persist_outbox(root:Path, frame:dict[str,Any])->Path:
    out=root/"resident-runtime/federation/outbox"
    path=out/(hashlib.sha256(frame["packet_id"].encode()).hexdigest()+".json")
    return write_once_json(path,frame,collision="write_once_collision")

INGEST_EPOCH_RETRY_ENTRYPOINT="org-kernel/kernel.py::ingest_frame (the carrier frame's heartbeat_reference)"
CARRIED_PROVENANCE_UNVERIFIED="CARRIED_PROVENANCE_UNVERIFIED"
CARRIED_PROVENANCE_PREDICATE="CARRIED_PROVENANCE_IS_THE_CURRENT_VERIFIED_ORGANIZATION_HEAD"
CARRIED_PROVENANCE_SOURCE="ORGANIZATION_LEDGER_HEAD"
CARRIED_PROVENANCE_FIELDS=("source","head_receipt_sha")

def _ledger_store():
    path=Path(__file__).resolve().parents[1]/"resident-runtime/ledger_store.py"
    spec=importlib.util.spec_from_file_location("ledger_store_for_kernel",path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def carried_provenance_refusal(detail:str, retry_entrypoint:str)->dict[str,Any]:
    """The six-field FAIL_CLOSED of a CARRIED claim that does not verify."""
    return {"disposition":"FAIL_CLOSED","failure_code":CARRIED_PROVENANCE_UNVERIFIED,
            "failed_predicate":CARRIED_PROVENANCE_PREDICATE,"detail":detail,
            "required_evidence_or_repair":("a carried epoch names source "+CARRIED_PROVENANCE_SOURCE
                                           +" and head_receipt_sha of the current verified organization "
                                           "ledger head; it is never stripped and accepted as supplied"),
            "retry_entrypoint":retry_entrypoint,
            "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":"re-emit with a verifiable claim or a supplied epoch; nothing was written",
            "derived_from_clock":False,"consequence_committed":False}

ADMISSION_SCHEMA="stegverse.carried-crossing-admission.v1"
#: What ingest threads to a crossing's writers, in process only. The id names
#: the record; the token, drawn at random each time ingest opens the record, is
#: what proves the writer is inside that crossing. Neither is read from a frame,
#: and the record keeps only the token's digest, never the token.
ADMISSION_FIELDS=("admission_id","admission_token")

def admission_directory(root:Path|None=None)->Path:
    """This boundary's own durable admission records."""
    return (root or Path(__file__).resolve().parents[1])/"resident-runtime/federation/admissions.d"

def admission_id(frame:dict[str,Any])->str:
    """A crossing's admission id: the frame's packet id and frame digest, never a caller's choice."""
    return sha(str(frame.get("packet_id"))+"|"+str(frame.get("frame_sha256")))[7:]

def admission_record(identifier:Any, *, root:Path|None=None, include_closed:bool=False)->dict[str,Any]|None:
    """The open admission record ingest wrote for a crossing, or None.

    Only ingest writes one, after verifying the crossing's claim against the
    then-current organization head; it is closed when the crossing's dispatch
    ends, so a closed or absent record admits nothing.
    """
    if not isinstance(identifier,str) or len(identifier)!=64 or any(c not in "0123456789abcdef" for c in identifier):
        return None
    path=admission_directory(root)/(identifier+".json")
    try:
        record=json.loads(path.read_bytes().decode("utf-8"))
    except (OSError,*JSON_DOCUMENT_ERRORS):
        return None
    if not isinstance(record,dict) or record.get("schema")!=ADMISSION_SCHEMA or record.get("admission_id")!=identifier:
        return None
    if record.get("closed") is not False and not include_closed:
        return None
    return record

def organization_chain_member(store_module:Any, store:Any, head:Any, digest:str)->bool:
    """Whether `digest` is on the organization chain the live HEAD reaches."""
    cursor=head.get("receipt_sha256") if isinstance(head,dict) else None
    visited=set()
    while isinstance(cursor,str) and cursor not in visited:
        if cursor==digest:
            return True
        visited.add(cursor)
        node=store.get(store_module.receipt_key(cursor))
        cursor=node.get("previous_receipt_sha256") if isinstance(node,dict) else None
    return False

def carried_provenance_failure(reference:dict[str,Any], *, admission_root:Path|None=None)->str|None:
    """Why a carrier's CARRIED claim does not verify, or None when it makes none or verifies.

    A reference naming `source` or `head_receipt_sha` claims its epoch was read
    from the organization ledger head. It is verified against that head, read
    without writing: the source is ORGANIZATION_LEDGER_HEAD, the sha is the
    current HEAD, the head receipt is bound by its digest, its own reference
    passes the shared rule, and the epochs agree. A claim is never stripped
    and the frame accepted as supplied.

    Inside an admitted crossing (`admission_id`), another writer may move the
    live head between the crossing's repository and organization writes. Its
    writers then verify against the crossing's durable admission record,
    written by ingest alone: the claim is the admitted head and epoch, that
    head is on the chain the live head reaches, and the digest and the shared
    rule hold as before. The id names a record, never a head, and the record
    admits only its own crossing: the writer must also hold the record's
    random token, which ingest threads in process to that crossing's
    dispatch alone, never read from a frame. A closed or absent record, or a
    missing or wrong token, admits nothing.
    """
    if not any(field in reference for field in CARRIED_PROVENANCE_FIELDS):
        return None
    if reference.get("source")!=CARRIED_PROVENANCE_SOURCE:
        return "the carried source "+repr(reference.get("source"))+" is not "+CARRIED_PROVENANCE_SOURCE
    claimed=reference.get("head_receipt_sha")
    if not isinstance(claimed,str) or not claimed.startswith("sha256:") or len(claimed)!=71:
        return "the carried head_receipt_sha is not a sha256 digest"
    location=os.environ.get("STEGVERSE_ORG_LEDGER_ROOT")
    if not location:
        return "no organization ledger root is supplied to verify the carried head against"
    store_module=_ledger_store()
    store=store_module.open_store(store_module.parse_locator(location))
    head=store.get(store_module.HEAD_KEY)
    if "admission_id" in reference:
        # A writer inside an admitted crossing: the head it verifies against is
        # the one ingest admitted and recorded durably, not the live head, which
        # another writer may have moved since. That head must still be on the
        # organization chain the live head reaches.
        admitted=admission_record(reference["admission_id"],root=admission_root)
        if admitted is None:
            return "no open admission record "+repr(reference["admission_id"])+" was written by ingest"
        token=reference.get("admission_token")
        if (not isinstance(token,str) or not isinstance(admitted.get("admission_token_sha256"),str)
                or not hmac.compare_digest(sha(token),admitted["admission_token_sha256"])):
            return ("the admission token is not the one ingest threaded to this crossing; an admission "
                    "record admits only the crossing it was written for")
        if admitted.get("head_receipt_sha")!=claimed or admitted.get("epoch")!=reference.get("epoch"):
            return "the carried claim is not the head and epoch its crossing's admission record admitted"
        if not organization_chain_member(store_module,store,head,claimed):
            return "the admitted head is not on the organization ledger chain"
    elif not isinstance(head,dict) or head.get("receipt_sha256")!=claimed:
        return "the carried head_receipt_sha is not the current organization ledger head"
    receipt=store.get(store_module.receipt_key(claimed))
    body=dict(receipt or {}); body.pop("receipt_sha256",None)
    if not isinstance(receipt,dict) or receipt.get("receipt_sha256")!=claimed or sha(body)!=claimed:
        return "the organization ledger head receipt does not verify against its digest"
    head_reference=receipt.get("hb_reference")
    failure=supplied_epoch_failure(head_reference.get("epoch") if isinstance(head_reference,dict) else None,
                                   head_reference if head_reference is not None else {})
    if failure is not None:
        return "the organization ledger head's own reference fails the shared rule: "+failure[0]
    if head_reference.get("epoch")!=reference.get("epoch"):
        return "the carried epoch is not the organization ledger head's epoch"
    return None

HB_EPOCH_CONFLICT="HB_EPOCH_CONFLICT"

def carried_frame_epoch(frame:dict[str,Any], *, admission:dict[str,Any]|None=None,
                        admission_root:Path|None=None)->int|None:
    """The epoch a carrier frame lends, checked by the shared rule, or SuppliedEpochRefused.

    The reference is bound to the frame by its digest. A CLOCK one -- flagged
    (`derived_from_clock` exactly true), or the legacy bare sample (no flag,
    `sampled_unix_ns` present) -- lends no epoch and returns None: the frame is
    consumed, and a route that needs an epoch refuses NOT_SUPPLIED (NARROW S1,
    pending WU-B13). Its epoch field must still be well formed: a missing one is
    NOT_SUPPLIED and a malformed one INVALID, six-field, and a cycle
    quarantines the frame. Otherwise the shared rule decides: an unmarked reference
    (no flag, no sample) is refused six-field, as is one that claims SUPPLIED
    while carrying a sample, and a CARRIED claim that does not verify against
    the organization ledger head. No clock is read.
    """
    reference=frame.get("heartbeat_reference")
    clock=isinstance(reference,dict) and (reference.get("derived_from_clock") is True
                                          or ("derived_from_clock" not in reference
                                              and "sampled_unix_ns" in reference))
    # A CARRIED claim is checked before the CLOCK path, whatever the clock
    # marker: a CLOCK reference cannot carry one, so asserting it is refused,
    # never silently dropped.
    # The receiver derives a crossing's admission itself; a sender never names
    # one. A frame carrying an admission field is refused, never honoured.
    if isinstance(reference,dict) and any(field in reference for field in ADMISSION_FIELDS):
        raise SuppliedEpochRefused(carried_provenance_refusal(
            "the frame's heartbeat reference names an admission record ("
            +", ".join(sorted(field for field in ADMISSION_FIELDS if field in reference))
            +"); only the receiving boundary derives a crossing's admission",INGEST_EPOCH_RETRY_ENTRYPOINT))
    if clock and any(field in reference for field in CARRIED_PROVENANCE_FIELDS):
        raise SuppliedEpochRefused(carried_provenance_refusal(
            "a CLOCK heartbeat reference asserts CARRIED provenance; only a supplied (derived_from_clock false) "
            "reference may carry a claim",INGEST_EPOCH_RETRY_ENTRYPOINT))
    if clock:
        malformed=writer_epoch_refusal(reference.get("epoch"),retry_entrypoint=INGEST_EPOCH_RETRY_ENTRYPOINT)
        if malformed is not None:
            raise SuppliedEpochRefused(malformed)
        reference_consistency(reference)
        return None
    epoch=reference.get("epoch") if isinstance(reference,dict) else None
    refusal=writer_epoch_refusal(epoch,retry_entrypoint=INGEST_EPOCH_RETRY_ENTRYPOINT,
                                 reference=reference if reference is not None else {})
    if refusal is not None:
        raise SuppliedEpochRefused(refusal)
    reference_consistency(reference)
    claim=reference if admission is None else {**reference,**{key:admission[key] for key in ADMISSION_FIELDS}}
    unverified=carried_provenance_failure(claim,admission_root=admission_root)
    if unverified is not None:
        raise SuppliedEpochRefused(carried_provenance_refusal(unverified,INGEST_EPOCH_RETRY_ENTRYPOINT))
    return int(str(epoch))

HB_REFERENCE_INVALID="HB_REFERENCE_INVALID"
HB_REFERENCE_PREDICATE="HEARTBEAT_REFERENCE_NAMES_ONE_EPOCH"

def reference_consistency(reference:dict[str,Any])->None:
    """Refuse a reference whose generation or heartbeat_id names another epoch than its own."""
    epoch=int(str(reference["epoch"]))
    for field,expected in (("generation",epoch),("heartbeat_id","HB:"+str(epoch))):
        if field in reference and reference[field]!=expected:
            raise SuppliedEpochRefused({
                "disposition":"FAIL_CLOSED","failure_code":HB_REFERENCE_INVALID,
                "failed_predicate":HB_REFERENCE_PREDICATE,
                "detail":"the reference's "+field+" "+repr(reference[field])+" is not epoch "+str(epoch)+"'s",
                "required_evidence_or_repair":"a heartbeat reference whose generation and heartbeat_id name its epoch",
                "retry_entrypoint":INGEST_EPOCH_RETRY_ENTRYPOINT,
                "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
                "next_attempt":"re-emit the frame with a consistent reference; nothing was written",
                "derived_from_clock":False,"consequence_committed":False})

def frame_provenance(frame:dict[str,Any])->dict[str,Any]|None:
    """The CARRIED claim a frame makes (`source`, `head_receipt_sha`), or None.

    Read only after `carried_frame_epoch` has verified it; it is handed on to
    every writer so a receipt made in response reads as CARRIED, never stripped
    to SUPPLIED.
    """
    reference=frame.get("heartbeat_reference")
    if not isinstance(reference,dict) or not any(field in reference for field in CARRIED_PROVENANCE_FIELDS):
        return None
    return {field:reference.get(field) for field in CARRIED_PROVENANCE_FIELDS}

def close_admission(root:Path, identifier:str)->None:
    """Close a crossing's admission record: it admits nothing after its dispatch ends."""
    record=admission_record(identifier,root=root)
    if record is not None:
        write_json_atomic(admission_directory(root)/(identifier+".json"),{**record,"closed":True})

def ingest_frame(root:Path, frame:dict[str,Any], *, mesh_root:Path|None=None,
                 hb_epoch:Any=None, committed_request:dict[str,Any]|None=None)->dict[str,Any]:
    """Consume one addressed frame at the epoch it is supplied, or refuse six-field.

    An explicit `hb_epoch` (the cycle's) is checked by the shared rule first;
    an invalid one is HB_EPOCH_INVALID whatever the frame carries. The frame's
    epoch is checked before dispatch. When both are present and differ the
    frame is HB_EPOCH_CONFLICT and nothing is written; when only one is present
    it is the supplied epoch for everything done in response to the frame: the
    receiving operation's receipts, the control status and the response frame.
    """
    packet=recover_packet(frame)
    registry=load_registry(root)
    if frame["destination_org"]!=registry["organization"]:
        return {"status":"IGNORED_NOT_ADDRESSED","packet_id":frame["packet_id"]}
    explicit=None
    if hb_epoch is not None:
        explicit=supplied_hb_reference(hb_epoch,retry_entrypoint=INGEST_EPOCH_RETRY_ENTRYPOINT)["epoch"]
    # This frame's own admission record, if ingest already wrote one: the id is
    # derived from the frame, so a re-offered frame (a deferred retry, or a
    # gateway frame whose ack was lost) verifies against the head it was
    # admitted at, reopening its record for the replay.
    record=(admission_record(admission_id(frame),root=root,include_closed=True)
            if frame_provenance(frame) is not None else None)
    admitted=None
    if record is not None:
        # Reopened for this ingest with a fresh token; only its digest is
        # durable, so no reader of the record can hold a usable token.
        admitted={"admission_id":record["admission_id"],"admission_token":secrets.token_hex(32)}
        reopened={key:value for key,value in record.items() if key!="admission_token"}
        write_json_atomic(admission_directory(root)/(record["admission_id"]+".json"),
                          {**reopened,"admission_token_sha256":sha(admitted["admission_token"]),"closed":False})
    try:
        carried=carried_frame_epoch(frame,admission=admitted,admission_root=root)
    except SuppliedEpochRefused:
        if admitted is not None:
            close_admission(root,admitted["admission_id"])
        raise
    if explicit is not None and carried is not None and explicit!=carried:
        raise SuppliedEpochRefused({
            "disposition":"FAIL_CLOSED","failure_code":HB_EPOCH_CONFLICT,
            "failed_predicate":HB_EPOCH_PREDICATE,
            "detail":"the supplied epoch "+str(explicit)+" is not the frame's epoch "+str(carried),
            "required_evidence_or_repair":"supply the frame's own epoch, or none so the frame's epoch is used",
            "retry_entrypoint":INGEST_EPOCH_RETRY_ENTRYPOINT,
            "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":"nothing was written; retry with one epoch",
            "derived_from_clock":False,"consequence_committed":False})
    epoch=explicit if explicit is not None else carried
    provenance=frame_provenance(frame) if carried is not None else None
    if provenance is not None:
        # The crossing's durable admission record, before any write: the head
        # its claim verified against. A retry of a deferred crossing reads the
        # same record, so a head another writer moved meanwhile refuses nothing.
        if admitted is None:
            admitted={"admission_id":admission_id(frame),"admission_token":secrets.token_hex(32)}
            write_json_atomic(admission_directory(root)/(admitted["admission_id"]+".json"),{
                "schema":ADMISSION_SCHEMA,"admission_id":admitted["admission_id"],
                "admission_token_sha256":sha(admitted["admission_token"]),"packet_id":frame["packet_id"],
                "frame_sha256":frame["frame_sha256"],"head_receipt_sha":provenance["head_receipt_sha"],
                "epoch":carried,"closed":False})
        provenance={**provenance,**admitted}
    try:
        result=dispatch(root,packet,mesh_root=mesh_root,hb_epoch=epoch,hb_provenance=provenance,
                        committed_request=committed_request)
    except Exception as exc:
        # A writer fault leaves the crossing pending, its record open for the
        # retry; any other end closes it.
        if provenance is not None and not is_writer_fault(exc):
            close_admission(root,provenance["admission_id"])
        raise
    if provenance is not None:
        close_admission(root,provenance["admission_id"])
        provenance={key:provenance[key] for key in CARRIED_PROVENANCE_FIELDS}
    return {"status":"CONSUMED","packet":packet,"execution_result":result,
            "carried_hb_epoch":carried,"hb_epoch":epoch,"carried_provenance":provenance}

__all__=["hb_reference","derive_channel","carrier_frame","recover_packet","dispatch","persist_outbox","ingest_frame",
         "capability_ingress","CAPABILITY_INGRESS_ROLE","HB_EPOCH_NOT_SUPPLIED","HB_EPOCH_INVALID",
         "HB_EPOCH_PROVENANCE_UNMARKED","HB_EPOCH_CONFLICT","carried_frame_epoch","carried_provenance_failure",
         "carried_provenance_refusal","frame_provenance","admission_id","admission_record","close_admission",
         "ADMISSION_SCHEMA","ADMISSION_FIELDS","ingest_or_quarantine","frame_failure_refusal",
         "recorded_response","response_collision_refusal","writer_fault_refusal","cli_refusal",
         "WRITER_IO_FAILED","WRITER_WRITE_FAILED","CLI_INPUT_INVALID","InputRefused","input_refusal",
         "read_json_input","strict_json_loads","JSON_DOCUMENT_ERRORS","collision_refusal","LEDGER_RECEIPT_COLLISION","control_response_packet_id","request_binding",
         "RESPONSE_ID_COLLISION","ResponseIdCollision","RESPONDING_MESSAGE_CLASSES","write_json_atomic","write_once_json",
         "HB_REFERENCE_INVALID","FRAME_INTEGRITY_INVALID","FRAME_INGEST_FAILED","FRAME_DISPATCH_IO_FAILED",
         "CARRIED_PROVENANCE_UNVERIFIED",
         "supplied_epoch_failure","SHARED_VALIDATOR_SHA256","SuppliedEpochRefused","writer_epoch_refusal","supplied_hb_reference"]


# --- Federation mesh v1.1 additions ---
FEDERATION_ROOT_ENV="STEGVERSE_ORG_FEDERATION_ROOT"

def federation_root(env:dict[str,str]|None=None)->Path:
    values=os.environ if env is None else env
    override=values.get(FEDERATION_ROOT_ENV)
    if override:
        return Path(override).expanduser().resolve()
    base=Path(values.get("XDG_STATE_HOME",str(Path.home()/".local"/"state")))
    return (base/"stegverse"/"org-federation").resolve()

def publish_frame(frame:dict[str,Any], *, root:Path|None=None)->Path:
    mesh=(root or federation_root()).resolve()
    frames=mesh/"frames.d"
    frame_id=hashlib.sha256((frame["packet_id"]+"|"+frame["frame_sha256"]).encode()).hexdigest()
    return write_once_json(frames/(frame_id+".json"),frame,collision="federation_frame_write_once_collision")

#: The declared size cap of one carrier frame file. A larger file is not read.
MAX_CARRIER_FRAME_BYTES=1_048_576

def scan_addressed_frames(organization:str, *, root:Path|None=None, seen:set[str]|None=None,
                          include_unreadable:bool=False)->list[dict[str,Any]]:
    mesh=(root or federation_root()).resolve()
    frames=mesh/"frames.d"
    if not frames.exists():
        return []
    consumed=seen or set()
    out=[]
    for path in sorted(frames.glob("*.json")):
        if path.name in consumed:
            continue
        try:
            if path.stat().st_size>MAX_CARRIER_FRAME_BYTES:
                raise ValueError("carrier_frame_exceeds_size_cap_"+str(MAX_CARRIER_FRAME_BYTES))
            frame=json.loads(path.read_bytes().decode("utf-8"))
            if not isinstance(frame,dict):
                raise ValueError("carrier_frame_not_an_object")
        except (*JSON_DOCUMENT_ERRORS,OSError) as exc:
            # Unreadable, oversized, not UTF-8, not JSON, nested past the
            # parser's depth, or not an object: each
            # file is guarded on its own and offered to a consuming cycle, which
            # quarantines it by name; it blocks no cycle.
            if include_unreadable:
                out.append({"path":str(path),"frame":None,"load_error":exc})
            continue
        if frame.get("destination_org")==organization:
            out.append({"path":str(path),"frame":frame})
    return out

def build_packet(*, origin_org:str, origin_service:str, destination_org:str, destination_service:str,
                 payload:dict[str,Any], transition_reference:str="federation.v1",
                 authority_effect:str="NONE", packet_id:str|None=None)->dict[str,Any]:
    pid=packet_id or "pkt-"+hashlib.sha256(canon({
        "origin_org":origin_org,"origin_service":origin_service,"destination_org":destination_org,
        "destination_service":destination_service,"payload":payload,"transition_reference":transition_reference
    })).hexdigest()[:24]
    return {
      "schema_version":PACKET_SCHEMA,
      "packet_id":pid,
      "direction":"INGRESS",
      "origin":{"org":origin_org,"service":origin_service},
      "destination":{"org":destination_org,"service":destination_service},
      "carrier":{"kind":"HB_DERIVED","reference":"org-federation"},
      "intr_profile":"stegverse.intr.org-boundary.v1",
      "transition":{"reference":transition_reference,"authority_effect":authority_effect,"conditions":[]},
      "payload":payload,
      "evidence":{"ingress_receipt":None,"dispatch_receipt":None,"consumption_receipt":None,"egress_receipt":None,"reconstruction_reference":None}
    }

def publish_packet(packet:dict[str,Any], *, root:Path|None=None, now_ns:int|None=None,
                   epoch:Any=None)->dict[str,Any]:
    """Publish a packet's carrier frame.

    A supplied `epoch` is checked by `supplied_epoch_failure` before anything is
    published: ASCII digits (an int as its decimal text) with value >= 32, else
    SuppliedEpochRefused carrying the six-field FAIL_CLOSED. `epoch=None` keeps
    the clock-sampled reference; no epoch-taking receipt writer reaches it.
    """
    if epoch is not None:
        epoch=supplied_hb_reference(epoch,retry_entrypoint="org-kernel/kernel.py::publish_packet")["epoch"]
    frame=carrier_frame(packet,now_ns=now_ns,epoch=epoch)
    path=publish_frame(frame,root=root)
    return {"packet":packet,"frame":frame,"path":str(path)}

def consume_addressed_frames(repo_root:Path, *, mesh_root:Path|None=None, seen:set[str]|None=None)->list[dict[str,Any]]:
    registry=load_registry(repo_root)
    organization=registry["organization"]
    results=[]
    for item in scan_addressed_frames(organization,root=mesh_root,seen=seen):
        result=ingest_frame(repo_root,item["frame"],mesh_root=mesh_root)
        results.append({"path":item["path"],"result":result})
    return results


# --- Ecosystem-wide communication v1.2 additions ---
def organization_slug(organization:str)->str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in organization).strip("-")

def build_ecosystem_packets(*, origin_org:str, origin_service:str, organizations:list[str],
                            message_class:str, subject:str, body:dict[str,Any],
                            requested_action:str|None=None, transition_reference:str="ecosystem.communication.v1",
                            authority_effect:str="NONE", communication_id:str|None=None)->dict[str,Any]:
    ordered=sorted(dict.fromkeys(organizations))
    if not ordered:
        raise ValueError("organizations_required")
    comm_id=communication_id or "ecosystem-"+hashlib.sha256(canon({
        "origin_org":origin_org,"origin_service":origin_service,"organizations":ordered,
        "message_class":message_class,"subject":subject,"body":body,
        "requested_action":requested_action,"transition_reference":transition_reference
    })).hexdigest()[:24]
    packets=[]
    for org in ordered:
        service=organization_slug(org)+".org-control"
        payload={
          "communication_id":comm_id,
          "message_class":message_class,
          "subject":subject,
          "body":body,
          "requested_action":requested_action,
          "audience":"ECOSYSTEM",
          "target_organization":org,
          "target_count":len(ordered)
        }
        packet=build_packet(
          origin_org=origin_org,
          origin_service=origin_service,
          destination_org=org,
          destination_service=service,
          payload=payload,
          transition_reference=transition_reference,
          authority_effect=authority_effect,
          packet_id=comm_id+":"+organization_slug(org)
        )
        packets.append(packet)
    return {"communication_id":comm_id,"organization_count":len(ordered),"packets":packets}

def publish_ecosystem_message(*, origin_org:str, origin_service:str, organizations:list[str],
                              message_class:str, subject:str, body:dict[str,Any],
                              requested_action:str|None=None, transition_reference:str="ecosystem.communication.v1",
                              authority_effect:str="NONE", communication_id:str|None=None,
                              root:Path|None=None, now_ns:int|None=None, epoch:Any=None)->dict[str,Any]:
    built=build_ecosystem_packets(
      origin_org=origin_org,origin_service=origin_service,organizations=organizations,
      message_class=message_class,subject=subject,body=body,requested_action=requested_action,
      transition_reference=transition_reference,authority_effect=authority_effect,
      communication_id=communication_id
    )
    publications=[publish_packet(packet,root=root,now_ns=now_ns,epoch=epoch) for packet in built["packets"]]
    return {"communication_id":built["communication_id"],"organization_count":built["organization_count"],
            "published_count":len(publications),"publications":publications}

def aggregate_ecosystem_results(communication_id:str, results_by_org:dict[str,list[dict[str,Any]]])->dict[str,Any]:
    rows=[]
    for org,items in sorted(results_by_org.items()):
        matched=[]
        for item in items:
            result=item.get("result") or {}
            packet=result.get("packet") or {}
            payload=packet.get("payload") or {}
            if payload.get("communication_id")==communication_id:
                matched.append(item)
        status="CONSUMED" if any((x.get("result") or {}).get("status")=="CONSUMED" for x in matched) else "NOT_OBSERVED"
        terminal=None
        for x in matched:
            er=(x.get("result") or {}).get("execution_result") or {}
            terminal=(er.get("reconstruction") or {}).get("terminal_receipt_id") or terminal
        rows.append({"organization":org,"status":status,"terminal_receipt_id":terminal})
    consumed=sum(1 for row in rows if row["status"]=="CONSUMED")
    return {"communication_id":communication_id,"organization_count":len(rows),
            "consumed_count":consumed,"pending_count":len(rows)-consumed,
            "complete":consumed==len(rows) and len(rows)>0,"organizations":rows}


# --- Ecosystem control/response v1.3 additions ---
def load_federation_directory(root:Path)->dict[str,Any]:
    path=root/"org-boundary/registry/federation.json"
    value=json.loads(path.read_text())
    if value.get("denominator")!=len(value.get("organizations") or []):
        raise ValueError("federation_directory_denominator_mismatch")
    return value

RESIDENT_STATUS_EPOCH_RETRY_ENTRYPOINT="org-kernel/kernel.py::resident_status (hb_epoch=, carried by the request frame or supplied)"

def resident_status(root:Path, registry:dict[str,Any]|None=None, *, hb_epoch:Any=None,
                    hb_provenance:dict[str,Any]|None=None)->dict[str,Any]:
    heartbeat=supplied_hb_reference(hb_epoch,retry_entrypoint=RESIDENT_STATUS_EPOCH_RETRY_ENTRYPOINT,
                                    provenance=hb_provenance,admission_root=root)
    reg=registry or load_registry(root)
    activation_path=root/"resident-runtime/activation-manifest.json"
    activation=json.loads(activation_path.read_text()) if activation_path.exists() else {}
    kernel=(activation.get("kernel") or {})
    return {
      "organization":reg["organization"],
      "kernel_version":kernel.get("version"),
      "activation_state":activation.get("state"),
      "registered_service_count":len(reg.get("services") or []),
      "registered_services":[s.get("service_id") for s in reg.get("services") or []],
      "org_control_service":organization_slug(reg["organization"])+".org-control",
      "heartbeat_reference":heartbeat,
      "runtime_observation_claimed":False
    }

def persist_work_request(root:Path, packet:dict[str,Any])->dict[str,Any]:
    payload=packet.get("payload") or {}
    communication_id=payload.get("communication_id")
    inbox=root/"resident-runtime/control/inbox"
    inbox.mkdir(parents=True,exist_ok=True)
    name=hashlib.sha256((packet["packet_id"]+"|"+str(communication_id)).encode()).hexdigest()+".json"
    path=inbox/name
    record={
      "schema_version":"stegverse.ecosystem-work-intake.v1",
      "communication_id":communication_id,
      "packet_id":packet["packet_id"],
      "origin":packet["origin"],
      "destination":packet["destination"],
      "requested_action":payload.get("requested_action"),
      "body":payload.get("body"),
      "transition":packet["transition"],
      "state":"QUEUED_FOR_LOCAL_ADMISSION_EVALUATION",
      "execution_authority_inferred":False,
      "execution_authority_constraint":"CONSTRAINT_VARIABLE",
      "time_constraint":"CONSTRAINT_VARIABLE"
    }
    write_once_json(path,record,collision="work_intake_write_once_collision")
    return {"state":record["state"],"intake_ref":str(path),"execution_authority_inferred":False}

def handle_control_message(root:Path, packet:dict[str,Any], registry:dict[str,Any], *,
                           hb_epoch:Any=None, hb_provenance:dict[str,Any]|None=None)->dict[str,Any]:
    payload=packet.get("payload") or {}
    message_class=payload.get("message_class")
    result={
      "message_received":True,
      "message_class":message_class,
      "communication_id":payload.get("communication_id"),
      "requested_action":payload.get("requested_action"),
      "execution_authority_inferred":False,
      "execution_authority_effect":packet["transition"]["authority_effect"]
    }
    if message_class=="ecosystem.monitor.request":
        result["monitor_status"]=resident_status(root,registry,hb_epoch=hb_epoch,hb_provenance=hb_provenance)
    elif message_class=="ecosystem.work.request":
        result["work_intake"]=persist_work_request(root,packet)
    elif message_class=="ecosystem.communication":
        result["communication_acknowledged"]=True
    elif message_class in {"ecosystem.monitor.response","ecosystem.work.ack","ecosystem.communication.ack"}:
        result["response_acknowledged"]=True
    return result

def response_message_class(request_class:str|None)->str:
    return {
      "ecosystem.monitor.request":"ecosystem.monitor.response",
      "ecosystem.work.request":"ecosystem.work.ack",
      "ecosystem.communication":"ecosystem.communication.ack"
    }.get(request_class or "","ecosystem.communication.ack")

def build_control_response(request_packet:dict[str,Any], execution_result:dict[str,Any])->dict[str,Any]:
    req_payload=request_packet.get("payload") or {}
    origin_org=request_packet["origin"]["org"]
    local_org=request_packet["destination"]["org"]
    cls=response_message_class(req_payload.get("message_class"))
    payload={
      "communication_id":req_payload.get("communication_id"),
      "message_class":cls,
      "subject":"response:"+str(req_payload.get("subject") or ""),
      "body":{
        "request_packet_id":request_packet["packet_id"],
        "request_packet_sha256":sha(request_packet),
        "responding_organization":local_org,
        "application_result":execution_result.get("application_result"),
        "receipt_terminal":(execution_result.get("reconstruction") or {}).get("terminal_receipt_id")
      },
      "requested_action":None,
      "audience":"ORIGIN",
      "target_organization":origin_org,
      "target_count":1
    }
    return build_packet(
      origin_org=local_org,
      origin_service=organization_slug(local_org)+".org-control",
      destination_org=origin_org,
      destination_service=organization_slug(origin_org)+".org-control",
      payload=payload,
      transition_reference=str((request_packet.get("transition") or {}).get("reference") or "ecosystem.communication.v1")+".response",
      authority_effect="NONE",
      packet_id=control_response_packet_id(request_packet)
    )

#: Request classes this boundary answers with one control response each.
RESPONDING_MESSAGE_CLASSES=frozenset({"ecosystem.monitor.request","ecosystem.work.request","ecosystem.communication"})
RESPONSE_ID_COLLISION="RESPONSE_ID_COLLISION"

class ResponseIdCollision(ValueError):
    """A response id already answers a different request; carries the six-field refusal."""
    def __init__(self, refusal:dict[str,Any]):
        super().__init__(refusal["detail"]); self.refusal=refusal

def control_response_packet_id(request_packet:dict[str,Any])->str:
    """The id of the one response to a request: its communication id and this organization."""
    return (str((request_packet.get("payload") or {}).get("communication_id"))+":response:"
            +organization_slug(request_packet["destination"]["org"]))

def request_binding(request_packet:dict[str,Any])->dict[str,str]:
    """What makes a request the same request: its packet id and its packet digest."""
    return {"request_packet_id":request_packet["packet_id"],"request_packet_sha256":sha(request_packet)}

def response_id_collision(response_packet_id:str, recorded:dict[str,Any], binding:dict[str,str])->ResponseIdCollision:
    """The six-field refusal of a request whose response id already answers another request."""
    return ResponseIdCollision({
        "disposition":"FAIL_CLOSED","failure_code":RESPONSE_ID_COLLISION,"terminal":True,
        "failed_predicate":"A_RESPONSE_ID_ANSWERS_EXACTLY_ONE_REQUEST",
        "detail":("response "+response_packet_id+" already answers request "
                  +str(recorded.get("request_packet_id"))+" ("+str(recorded.get("request_packet_sha256"))
                  +"); this request is "+binding["request_packet_id"]+" ("+binding["request_packet_sha256"]+")"),
        "required_evidence_or_repair":"the sender sends a different request under a new communication id",
        "retry_entrypoint":CONSUME_EPOCH_RETRY_ENTRYPOINT,
        "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
        "next_attempt":"this frame is quarantined and never handed the earlier response",
        "consequence_committed":False})

CONSUME_EPOCH_RETRY_ENTRYPOINT="org-kernel/kernel.py::consume_and_respond (hb_epoch=)"
FRAME_REFUSED_QUARANTINED="FRAME_REFUSED_QUARANTINED"

def quarantine_result(frame:dict[str,Any], refusal:dict[str,Any])->dict[str,Any]:
    """A frame refused six-field at ingest, made terminal.

    Its seen marker records this refusal, so it is never re-processed and does
    not hold back the frames behind it. No clock is read and none is written.
    """
    return {"status":"REFUSED","packet_id":frame.get("packet_id"),
            "refusal":{"disposition":"FAIL_CLOSED","failure_code":FRAME_REFUSED_QUARANTINED,"terminal":True,
                       "failed_predicate":refusal.get("failed_predicate"),
                       "detail":"frame refused at ingest: "+str(refusal.get("failure_code"))+": "+str(refusal.get("detail")),
                       "refused_failure_code":refusal.get("failure_code"),
                       "required_evidence_or_repair":("the sender re-emits the packet in a new frame that "
                                                      "carries a supplied epoch; this frame is terminal"),
                       "retry_entrypoint":refusal.get("retry_entrypoint"),
                       "owning_existing_goal":refusal.get("owning_existing_goal") or HB_EPOCH_OWNING_EXISTING_GOAL,
                       "next_attempt":"this frame is never re-processed; the next frame and the next cycle proceed",
                       "consequence_committed":False}}

FRAME_INTEGRITY_INVALID="FRAME_INTEGRITY_INVALID"
FRAME_INGEST_FAILED="FRAME_INGEST_FAILED"
FRAME_INTEGRITY_ERRORS={"carrier_frame_hash_mismatch","packet_hash_mismatch","packet_id_mismatch",
                        "destination_org_mismatch"}

def frame_failure_refusal(exc:BaseException)->dict[str,Any]:
    """The six-field refusal of one frame's ingest failure, whatever raised it."""
    refusal=getattr(exc,"refusal",None)
    if isinstance(refusal,dict):
        return refusal
    if isinstance(exc,ValueError) and str(exc) in FRAME_INTEGRITY_ERRORS:
        code,predicate=FRAME_INTEGRITY_INVALID,"CARRIER_FRAME_BINDS_ITS_PACKET"
    else:
        code,predicate=FRAME_INGEST_FAILED,type(exc).__name__
    return {"disposition":"FAIL_CLOSED","failure_code":code,"failed_predicate":predicate,
            "detail":str(exc),"required_evidence_or_repair":"the sender re-emits the packet in a well-formed frame",
            "retry_entrypoint":INGEST_EPOCH_RETRY_ENTRYPOINT,"owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":"this frame is terminal; the next frame and the next cycle proceed",
            "consequence_committed":False}

FRAME_DISPATCH_IO_FAILED="FRAME_DISPATCH_IO_FAILED"
FRAME_DISPATCH_WRITE_FAILED="FRAME_DISPATCH_WRITE_FAILED"

def is_writer_fault(exc:BaseException)->bool:
    """This boundary failing to record its own state, not a defect of the frame.

    An OSError, or a ledger store's LedgerWriteFailed (a lost comparison it
    could not retry past, a failed substrate command), from whichever loaded
    copy of the store raised it.
    """
    return isinstance(exc,OSError) or getattr(exc,"writer_fault",False) is True

WRITER_IO_FAILED="WRITER_IO_FAILED"
WRITER_WRITE_FAILED="WRITER_WRITE_FAILED"

def writer_fault_refusal(exc:BaseException, *, retry_entrypoint:str)->dict[str,Any]:
    """The six-field record a writer CLI prints when its own write faults.

    Not terminal: every ledger and spool write is atomic, and a rerun of the
    same command is idempotent, so it completes the write once. The fault may
    have come after a write was already published (for example the directory
    sync after HEAD's replace), so the record does not claim nothing was
    written: the rerun returns what is already recorded.
    """
    return {"disposition":"FAIL_CLOSED",
            "failure_code":WRITER_IO_FAILED if isinstance(exc,OSError) else WRITER_WRITE_FAILED,
            "terminal":False,
            "failed_predicate":"THIS_BOUNDARY_RECORDS_ITS_OWN_STATE",
            "detail":type(exc).__name__+": "+str(exc),
            "required_evidence_or_repair":"this boundary's own storage accepts the write",
            "retry_entrypoint":retry_entrypoint,
            "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":("the write may already be committed; run the same command again: the rerun is "
                            "idempotent and returns what is recorded, never a second receipt"),
            "consequence_committed":"UNKNOWN_RETRY_IS_IDEMPOTENT"}

LEDGER_RECEIPT_COLLISION="LEDGER_RECEIPT_COLLISION"

def collision_refusal(identity:str, *, retry_entrypoint:str)->dict[str,Any]:
    """The terminal six-field record of a rerun that names a recorded transition with other content."""
    return {"disposition":"FAIL_CLOSED","failure_code":LEDGER_RECEIPT_COLLISION,"terminal":True,
            "failed_predicate":"ONE_TRANSITION_IDENTITY_BINDS_ONE_RECEIPT",
            "detail":identity+" is already recorded with other content",
            "required_evidence_or_repair":"rerun the recorded transition unchanged, or use a new identity",
            "retry_entrypoint":retry_entrypoint,
            "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":"nothing was written; the recorded receipt stands",
            "consequence_committed":False}

CLI_INPUT_INVALID="CLI_INPUT_INVALID"

class InputRefused(ValueError):
    """A CLI input that cannot be read as the JSON document it must be; carries the six-field refusal."""
    def __init__(self, refusal:dict[str,Any]):
        super().__init__(refusal["detail"]); self.refusal=refusal

def input_refusal(argument:str, detail:str, *, retry_entrypoint:str)->dict[str,Any]:
    """The terminal six-field record of a bad CLI input: the caller's fault, and nothing was written."""
    return {"disposition":"FAIL_CLOSED","failure_code":CLI_INPUT_INVALID,"terminal":True,
            "failed_predicate":"EVERY_CLI_INPUT_IS_A_READABLE_JSON_DOCUMENT_OF_ITS_TYPE",
            "detail":argument+": "+detail,
            "required_evidence_or_repair":"supply "+argument+" as readable UTF-8 JSON of the expected type",
            "retry_entrypoint":retry_entrypoint,
            "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
            "next_attempt":"nothing was read past the input and nothing was written; fix the input and run again",
            "consequence_committed":False}

def _refuse_non_finite_constant(name:str)->Any:
    raise ValueError("non-finite number "+name+" is not JSON")

def _finite_float(text:str)->float:
    value=float(text)
    if not math.isfinite(value):
        raise ValueError("number "+text[:40]+" overflows to a non-finite float")
    return value

def strict_json_loads(text:str)->Any:
    """json.loads that refuses NaN, Infinity, -Infinity and a float that overflows (1e999), so a
    non-finite number never reaches a receipt; each is a ValueError, a JSON_DOCUMENT_ERRORS."""
    return json.loads(text,parse_constant=_refuse_non_finite_constant,parse_float=_finite_float)

def read_json_input(source:Any, *, argument:str, retry_entrypoint:str, inline:bool=False,
                    expect:type|None=dict)->Any:
    """Read one CLI input -- a file path, or `inline` JSON text -- before any write, or InputRefused.

    A missing or unreadable file, bytes that are not UTF-8, text that is not
    JSON, a non-finite number, and a document of the wrong top-level type are each the terminal
    CLI_INPUT_INVALID, never an OSError for the own-state fault classifier.
    """
    try:
        raw=source.encode("utf-8") if inline else Path(source).read_bytes()
        value=strict_json_loads(raw.decode("utf-8"))
    except (OSError,*JSON_DOCUMENT_ERRORS) as exc:
        raise InputRefused(input_refusal(argument,type(exc).__name__+": "+str(exc),
                                         retry_entrypoint=retry_entrypoint)) from None
    if expect is not None and not isinstance(value,expect):
        raise InputRefused(input_refusal(argument,"the document is a "+type(value).__name__+", not a JSON "
                                         +("object" if expect is dict else expect.__name__),
                                         retry_entrypoint=retry_entrypoint))
    return value

def cli_refusal(exc:BaseException, *, retry_entrypoint:str)->dict[str,Any]|None:
    """What a writer CLI prints for an exception, or None to re-raise it.

    This boundary's own write fault is its non-terminal writer_fault_refusal;
    a six-field refusal raised by any loaded copy is printed as it is. A raw
    OSError or traceback never reaches the caller for either.
    """
    if is_writer_fault(exc):
        return writer_fault_refusal(exc,retry_entrypoint=retry_entrypoint)
    refusal=getattr(exc,"refusal",None)
    return refusal if isinstance(refusal,dict) else None

def dispatch_io_deferral(frame:dict[str,Any], exc:BaseException)->dict[str,Any]:
    """A frame left pending because this boundary could not record its own state.

    The frame is not at fault, so it gets no seen marker: the next cycle offers
    it again, and the ledgers' idempotent replay consumes it exactly once.
    """
    code=FRAME_DISPATCH_IO_FAILED if isinstance(exc,OSError) else FRAME_DISPATCH_WRITE_FAILED
    return {"status":"DEFERRED","packet_id":frame.get("packet_id"),
            "refusal":{"disposition":"FAIL_CLOSED","failure_code":code,"terminal":False,
                       "failed_predicate":"THIS_BOUNDARY_RECORDS_ITS_OWN_STATE",
                       "detail":type(exc).__name__+": "+str(exc),
                       "required_evidence_or_repair":"this boundary's own storage accepts the write",
                       "retry_entrypoint":INGEST_EPOCH_RETRY_ENTRYPOINT,
                       "owning_existing_goal":HB_EPOCH_OWNING_EXISTING_GOAL,
                       "next_attempt":"the frame stays pending; the next cycle consumes it exactly once",
                       "consequence_committed":False}}

def ingest_or_quarantine(root:Path, frame:Any, *, mesh_root:Path|None=None,
                         hb_epoch:Any=None,
                         committed_request:dict[str,Any]|None=None)->tuple[dict[str,Any]|None,dict[str,Any]]:
    """Ingest one frame of a cycle, or make it terminal: (packet or None, result).

    The guard is total. Any error that is the frame's own -- a six-field
    refusal, a broken digest, a wrong-typed field, a malformed frame, an
    adapter error -- is a six-field refusal and a REFUSED result. A writer
    fault (an OSError, or a ledger store's LedgerWriteFailed such as a lost
    comparison) is this boundary's own storage failing, not the frame: it is a
    DEFERRED result, six-field FRAME_DISPATCH_IO_FAILED or
    FRAME_DISPATCH_WRITE_FAILED with terminal false, and no marker, so the frame
    stays pending. Either way the cycle continues with the next frame.
    No clock is read.
    """
    try:
        if not isinstance(frame,dict):
            raise ValueError("carrier_frame_not_an_object")
        packet=recover_packet(frame)
        return packet,ingest_frame(root,frame,mesh_root=mesh_root,hb_epoch=hb_epoch,
                                   committed_request=committed_request)
    except Exception as exc:
        # The writer's own fault is checked before the content guard.
        if is_writer_fault(exc):
            return None,dispatch_io_deferral(frame if isinstance(frame,dict) else {},exc)
        return None,quarantine_result(frame if isinstance(frame,dict) else {},frame_failure_refusal(exc))

def consume_and_respond(repo_root:Path, *, mesh_root:Path|None=None, seen:set[str]|None=None,
                        hb_epoch:Any=None, committed_request:dict[str,Any]|None=None)->list[dict[str,Any]]:
    """Consume addressed frames and publish each response.

    A response frame references the epoch its request was consumed at: the
    supplied `hb_epoch`, or the epoch the request frame carried (the two must
    agree). A clock-flagged request with no supplied epoch lends none, so its
    response is refused NOT_SUPPLIED and recorded on its seen marker; never a
    clock reading.
    """
    if hb_epoch is not None:
        hb_epoch=supplied_hb_reference(hb_epoch,retry_entrypoint=CONSUME_EPOCH_RETRY_ENTRYPOINT)["epoch"]
    registry=load_registry(repo_root)
    organization=registry["organization"]
    durable_seen=federation_seen_frame_names(repo_root)
    effective_seen=set(seen or set())|durable_seen
    out=[]
    for item in scan_addressed_frames(organization,root=mesh_root,seen=effective_seen,include_unreadable=True):
        # One frame's failure, of any kind, is that frame's terminal refusal.
        if item.get("load_error") is not None:
            packet,result=None,quarantine_result({},frame_failure_refusal(item["load_error"]))
        else:
            collision=response_collision_refusal(item["frame"],mesh_root=mesh_root)
            if collision is not None:
                packet,result=None,quarantine_result(item["frame"],collision)
            else:
                packet,result=ingest_or_quarantine(repo_root,item["frame"],mesh_root=mesh_root,hb_epoch=hb_epoch,
                                                   committed_request=committed_request)
        message_class=((packet or {}).get("payload") or {}).get("message_class")
        if result.get("status")=="DEFERRED":
            # Not the frame's fault: no marker, so it stays pending.
            out.append({"path":item["path"],"result":result,"response_publication":None,"seen_marker":None})
            continue
        response_publication=None
        if result.get("status")=="CONSUMED" and message_class in RESPONDING_MESSAGE_CLASSES:
            response=build_control_response(packet,result["execution_result"])
            if result["hb_epoch"] is None:
                result["response_refusal"]=writer_epoch_refusal(None,retry_entrypoint=CONSUME_EPOCH_RETRY_ENTRYPOINT)
            else:
                try:
                    response_publication=(recorded_response(response["packet_id"],packet,mesh_root=mesh_root)
                                          or publish_packet(response,root=mesh_root,epoch=result["hb_epoch"]))
                except ResponseIdCollision as exc:
                    # Raced in after the check before ingest: still never the earlier response.
                    result=quarantine_result(item["frame"],exc.refusal)
                except OSError as exc:
                    # Publishing is this boundary's own write: no marker, so the
                    # next cycle publishes the response once.
                    out.append({"path":item["path"],"result":dispatch_io_deferral(item["frame"],exc),
                                "response_publication":None,"seen_marker":None})
                    continue
        try:
            marker=mark_federation_frame_seen(repo_root,item["path"],
                                              item["frame"] if isinstance(item["frame"],dict) else {},result)
        except OSError as exc:
            # The marker is this boundary's own state: the frame stays pending,
            # and the next cycle reuses the response already published.
            out.append({"path":item["path"],"result":dispatch_io_deferral(item["frame"],exc),
                        "response_publication":response_publication,"seen_marker":None})
            continue
        out.append({"path":item["path"],"result":result,"response_publication":response_publication,"seen_marker":str(marker)})
    return out

def recorded_response(response_packet_id:str, request_packet:dict[str,Any], *,
                      mesh_root:Path|None=None)->dict[str,Any]|None:
    """The response this boundary already published for this request, or None.

    Publication is idempotent per request: the same packet id and the same
    packet digest. A cycle that published a response and then failed before
    its seen marker was durable offers the request again, and reuses that
    response rather than publishing a second one. A response under this id
    that answers any other request -- another packet id, or the same id with
    other content, or no recorded digest -- is ResponseIdCollision: the
    request is never handed the earlier response.
    """
    frames=(mesh_root or federation_root()).resolve()/"frames.d"
    if not frames.is_dir():
        return None
    binding=request_binding(request_packet)
    reuse=None
    for path in sorted(frames.glob("*.json")):
        try:
            frame=json.loads(path.read_bytes().decode("utf-8"))
            if not isinstance(frame,dict) or frame.get("packet_id")!=response_packet_id:
                continue
            packet=recover_packet(frame)
        except (*JSON_DOCUMENT_ERRORS,KeyError,TypeError,AttributeError,OSError):
            continue
        body=(packet.get("payload") or {}).get("body") or {}
        recorded={key:body.get(key) for key in binding}
        if recorded!=binding:
            raise response_id_collision(response_packet_id,recorded,binding)
        reuse=reuse or {"packet":packet,"frame":frame,"path":str(path),"reused":True}
    return reuse

def response_collision_refusal(frame:Any, *, mesh_root:Path|None=None)->dict[str,Any]|None:
    """The RESPONSE_ID_COLLISION of a request frame, checked before it is ingested, or None.

    A frame that cannot be recovered, or that is not a request this boundary
    answers, is left to ingest. No ledger is written for a colliding request.
    """
    try:
        packet=recover_packet(frame)
        if ((packet.get("payload") or {}).get("message_class")) not in RESPONDING_MESSAGE_CLASSES:
            return None
        recorded_response(control_response_packet_id(packet),packet,mesh_root=mesh_root)
    except ResponseIdCollision as exc:
        return exc.refusal
    except (*JSON_DOCUMENT_ERRORS,KeyError,TypeError,AttributeError):
        return None
    return None

def collect_ecosystem_responses(origin_org:str, communication_id:str, *, mesh_root:Path|None=None)->dict[str,Any]:
    responses=[]
    for item in scan_addressed_frames(origin_org,root=mesh_root):
        try:
            packet=recover_packet(item["frame"])
        except (ValueError,KeyError,TypeError):
            # A frame whose digests do not bind its packet is not a response.
            continue
        payload=packet.get("payload") or {}
        if payload.get("communication_id")!=communication_id:
            continue
        if payload.get("message_class") not in {
            "ecosystem.monitor.response","ecosystem.work.ack","ecosystem.communication.ack"}:
            continue
        body=payload.get("body") or {}
        responses.append({
          "organization":body.get("responding_organization") or packet["origin"]["org"],
          "message_class":payload.get("message_class"),
          "request_packet_id":body.get("request_packet_id"),
          "application_result":body.get("application_result"),
          "receipt_terminal":body.get("receipt_terminal"),
          "response_packet_id":packet["packet_id"],
          "frame_sha256":item["frame"].get("frame_sha256")
        })
    dedup={}
    for row in responses:
        dedup[row["organization"]]=row
    rows=[dedup[k] for k in sorted(dedup)]
    return {
      "communication_id":communication_id,
      "response_count":len(rows),
      "organizations":rows
    }

def publish_ecosystem_from_directory(repo_root:Path, *, message_class:str, subject:str, body:dict[str,Any],
                                     requested_action:str|None=None, authority_effect:str="NONE",
                                     communication_id:str|None=None, mesh_root:Path|None=None,
                                     now_ns:int|None=None, epoch:Any=None)->dict[str,Any]:
    registry=load_registry(repo_root)
    directory=load_federation_directory(repo_root)
    organizations=[row["organization"] for row in directory["organizations"]]
    origin=registry["organization"]
    return publish_ecosystem_message(
      origin_org=origin,
      origin_service=organization_slug(origin)+".org-control",
      organizations=organizations,
      message_class=message_class,
      subject=subject,
      body=body,
      requested_action=requested_action,
      authority_effect=authority_effect,
      communication_id=communication_id,
      root=mesh_root,
      now_ns=now_ns,
      epoch=epoch
    )


# --- Federation replay/dedup v1.3.1 additions ---
def federation_seen_frame_names(repo_root:Path)->set[str]:
    seen_dir=repo_root/"resident-runtime/federation/seen.d"
    if not seen_dir.exists():
        return set()
    names=set()
    for path in seen_dir.glob("*.json"):
        try:
            value=json.loads(path.read_text())
            if isinstance(value.get("frame_name"),str):
                names.add(value["frame_name"])
        except Exception:
            continue
    return names

def mark_federation_frame_seen(repo_root:Path, frame_path:str, frame:dict[str,Any], result:dict[str,Any])->Path:
    seen_dir=repo_root/"resident-runtime/federation/seen.d"
    seen_dir.mkdir(parents=True,exist_ok=True)
    frame_name=Path(frame_path).name
    marker={
      "schema_version":"stegverse.federation-frame-consumption.v1",
      "frame_name":frame_name,
      "frame_sha256":frame.get("frame_sha256"),
      "packet_id":frame.get("packet_id"),
      "destination_org":frame.get("destination_org"),
      "status":result.get("status"),
      "authority_effect":"NONE_CARRIER_ONLY"
    }
    if isinstance(result.get("refusal"),dict):
        marker["refusal"]=dict(result["refusal"])
    if isinstance(result.get("response_refusal"),dict):
        marker["response_refusal"]=dict(result["response_refusal"])
    marker_path=seen_dir/(hashlib.sha256(frame_name.encode()).hexdigest()+".json")
    return write_once_json(marker_path,marker,collision="federation_seen_marker_collision")
