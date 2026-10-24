#!/usr/bin/env python3
"""Outbound-only Service Gateway transport for organization federation."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("org_kernel", ROOT / "org-kernel" / "kernel.py")
K = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(K)

GATEWAY_ENV = "STEGVERSE_ORG_FEDERATION_GATEWAY_URL"
TIMEOUT_ENV = "STEGVERSE_ORG_FEDERATION_GATEWAY_TIMEOUT_SECONDS"


class FederationGatewayTransportError(RuntimeError):
    pass


def gateway_base_url() -> str:
    raw = os.getenv(GATEWAY_ENV, "").strip().rstrip("/")
    if not raw:
        raise FederationGatewayTransportError("organization federation gateway URL not configured")
    if not raw.startswith("https://"):
        raise FederationGatewayTransportError("organization federation gateway must use HTTPS")
    return raw


def timeout_seconds() -> float:
    raw = os.getenv(TIMEOUT_ENV, "10").strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise FederationGatewayTransportError("invalid federation gateway timeout") from exc
    if value <= 0 or value > 60:
        raise FederationGatewayTransportError("federation gateway timeout outside bounds")
    return value


def _raw_request(method: str, path: str, *, body: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None) -> bytes:
    url = gateway_base_url() + path
    raw = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    hdrs = {"Accept": "application/json", **(headers or {})}
    if raw is not None:
        hdrs["Content-Type"] = "application/json"
    req = Request(url, data=raw, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=timeout_seconds()) as resp:
            payload = resp.read()
    except (HTTPError, URLError, TimeoutError) as exc:
        raise FederationGatewayTransportError(f"gateway request failed: {exc}") from exc
    return payload


def _json_request(method: str, path: str, *, body: dict[str, Any] | None = None,
                  headers: dict[str, str] | None = None) -> dict[str, Any]:
    payload = _raw_request(method, path, body=body, headers=headers)
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise FederationGatewayTransportError("gateway response is not JSON") from exc


_WHITESPACE = " \t\n\r"


def _skip_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index] in _WHITESPACE:
        index += 1
    return index


def _value_end(text: str, index: int) -> int:
    """The end of the JSON value starting at `index`, found without recursion.

    Brackets are counted iteratively and strings skipped whole, so a value
    nested past the parser's depth still has a known span.
    """
    if index >= len(text):
        raise ValueError("value expected")
    if text[index] == '"':
        return json.decoder.scanstring(text, index + 1)[1]
    if text[index] in "[{":
        depth = 0
        while index < len(text):
            char = text[index]
            if char == '"':
                index = json.decoder.scanstring(text, index + 1)[1]
                continue
            if char in "[{":
                depth += 1
            elif char in "]}":
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        raise ValueError("unterminated value")
    end = index
    while end < len(text) and text[end] not in ",}]" + _WHITESPACE:
        end += 1
    if end == index:
        raise ValueError("value expected")
    return end


def _object_members(text: str) -> dict[str, str]:
    """The raw text of each top-level member of a JSON object, without parsing the values."""
    index = _skip_whitespace(text, 0)
    if index >= len(text) or text[index] != "{":
        raise ValueError("object expected")
    members: dict[str, str] = {}
    index = _skip_whitespace(text, index + 1)
    if index < len(text) and text[index] == "}":
        return members
    while True:
        if index >= len(text) or text[index] != '"':
            raise ValueError("member name expected")
        name, index = json.decoder.scanstring(text, index + 1)
        index = _skip_whitespace(text, index)
        if index >= len(text) or text[index] != ":":
            raise ValueError("':' expected")
        start = _skip_whitespace(text, index + 1)
        end = _value_end(text, start)
        members[name] = text[start:end]
        index = _skip_whitespace(text, end)
        if index < len(text) and text[index] == ",":
            index = _skip_whitespace(text, index + 1)
            continue
        if index < len(text) and text[index] == "}":
            if _skip_whitespace(text, index + 1) != len(text):
                raise ValueError("trailing content after the object")
            return members
        raise ValueError("',' or '}' expected")


def read_fetch_reply(payload: bytes) -> dict[str, Any]:
    """A gateway fetch reply, with the envelope read apart from the frame it carries.

    A frame that cannot be parsed (nested past the parser's depth, or not a
    document this boundary can use) inside a readable envelope is returned
    as `unusable_frame`: its `packet_id` and `frame_sha256`, read from the
    frame's own top-level members, so the frame can be acknowledged BLOCKED
    and the gateway moves on to the next one. Only an envelope that cannot
    be read is a FederationGatewayTransportError.
    """
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise FederationGatewayTransportError("gateway response is not UTF-8") from exc
    try:
        return json.loads(text)
    except K.JSON_DOCUMENT_ERRORS as whole:
        try:
            envelope = _object_members(text)
            reply = {name: json.loads(raw) for name, raw in envelope.items() if name != "frame"}
            frame_members = _object_members(envelope["frame"])
            handle = {name: json.loads(frame_members[name]) for name in ("packet_id", "frame_sha256")}
        except (*K.JSON_DOCUMENT_ERRORS, KeyError) as exc:
            raise FederationGatewayTransportError("gateway response is not a readable document") from exc
        if not all(isinstance(value, str) and value for value in handle.values()):
            raise FederationGatewayTransportError("gateway frame names no acknowledgeable packet")
        reply["unusable_frame"] = {**handle, "error": whole}
        return reply


def submit_frame(frame: dict[str, Any]) -> dict[str, Any]:
    validated = K.recover_packet(frame)
    origin_org = validated["origin"]["org"]
    return _json_request(
        "POST",
        "/api/org-federation/v1/frames",
        body=frame,
        headers={"X-StegVerse-Origin-Organization": origin_org},
    )


def fetch_frame(organization: str) -> dict[str, Any]:
    query = urlencode({"organization": organization})
    return read_fetch_reply(_raw_request(
        "GET",
        "/api/org-federation/v1/frames?" + query,
        headers={"X-StegVerse-Organization": organization},
    ))


#: A gateway cycle's epoch is supplied by the federation cycle and stamps the
#: acknowledgement; no clock is read for it.
GATEWAY_EPOCH_RETRY_ENTRYPOINT = "resident-runtime/federation_gateway_transport.py::resident_gateway_cycle (hb_epoch=)"


def acknowledge_frame(organization: str, frame: dict[str, Any], state: str, *,
                      hb_epoch: Any = None, refusal: dict[str, Any] | None = None) -> dict[str, Any]:
    heartbeat = K.supplied_hb_reference(hb_epoch, retry_entrypoint=GATEWAY_EPOCH_RETRY_ENTRYPOINT)
    ack = {
        "schema": "stegverse.org-federation-rendezvous.ack/v1",
        "organization": organization,
        "packet_id": frame["packet_id"],
        "frame_sha256": frame["frame_sha256"],
        "state": state,
        "hb_reference": heartbeat,
        "gateway_execution_authority": "NONE",
        "authority_effect": "NONE_OBSERVATION_ONLY",
    }
    if refusal is not None:
        ack["refusal"] = dict(refusal)
    return _json_request(
        "POST",
        "/api/org-federation/v1/acknowledgements",
        body=ack,
        headers={"X-StegVerse-Organization": organization},
    )


def publish_ecosystem_via_gateway(
    *,
    repo_root: Path,
    message_class: str,
    subject: str,
    body: dict[str, Any],
    requested_action: str | None = None,
    communication_id: str | None = None,
    epoch: int | None = None,
) -> dict[str, Any]:
    registry = K.load_registry(repo_root)
    directory = K.load_federation_directory(repo_root)
    orgs = [row["organization"] for row in directory["organizations"]]
    built = K.build_ecosystem_packets(
        origin_org=registry["organization"],
        origin_service=K.organization_slug(registry["organization"]) + ".org-control",
        organizations=orgs,
        message_class=message_class,
        subject=subject,
        body=body,
        requested_action=requested_action,
        communication_id=communication_id,
    )
    results = []
    for packet in built["packets"]:
        frame = K.carrier_frame(packet, epoch=epoch)
        stored = submit_frame(frame)
        results.append({
            "organization": packet["destination"]["org"],
            "packet_id": packet["packet_id"],
            "frame_sha256": frame["frame_sha256"],
            "gateway_state": stored.get("state"),
        })
    return {
        "communication_id": built["communication_id"],
        "organization_count": len(results),
        "published_count": sum(1 for row in results if row["gateway_state"] == "PENDING"),
        "gateway_execution_authority": "NONE",
        "organizations": results,
    }


def _persist_response(repo_root: Path, packet: dict[str, Any], execution_result: dict[str, Any]) -> Path:
    payload = packet.get("payload") or {}
    communication_id = str(payload.get("communication_id") or "unknown")
    out = repo_root / "resident-runtime" / "control" / "responses.d"
    out.mkdir(parents=True, exist_ok=True)
    name = K.sha({
        "communication_id": communication_id,
        "packet_id": packet["packet_id"],
        "origin_org": packet["origin"]["org"],
    }).split(":", 1)[1] + ".json"
    record = {
        "schema_version": "stegverse.ecosystem-response-observation.v1",
        "communication_id": communication_id,
        "packet_id": packet["packet_id"],
        "origin_org": packet["origin"]["org"],
        "message_class": payload.get("message_class"),
        "application_result": execution_result.get("application_result"),
        "reconstruction": execution_result.get("reconstruction"),
        "authority_effect": execution_result.get("authority_effect"),
    }
    try:
        return K.write_once_json(out / name, record, collision="response observation write-once collision")
    except ValueError as exc:
        raise FederationGatewayTransportError(str(exc)) from None


def _submitted_response_path(repo_root: Path, response_packet_id: str) -> Path:
    name = K.sha(response_packet_id)[7:] + ".json"
    return repo_root / "resident-runtime" / "federation" / "gateway-responses.d" / name


def _submitted_response_record(repo_root: Path, request_packet: dict[str, Any]) -> dict[str, Any] | None:
    """The gateway response already recorded for this request, or None.

    The record is keyed by the response id. One that answers any other request
    -- another packet id, or the same id with other content -- is
    K.ResponseIdCollision: this request is never handed that response.
    """
    response_id = K.control_response_packet_id(request_packet)
    path = _submitted_response_path(repo_root, response_id)
    record = None
    if path.is_file():
        try:
            record = json.loads(path.read_bytes().decode("utf-8"))
        except K.JSON_DOCUMENT_ERRORS:
            record = None
    if not isinstance(record, dict) or not isinstance(record.get("frame"), dict):
        return None
    binding = K.request_binding(request_packet)
    recorded = {key: record.get(key) for key in binding}
    if recorded != binding:
        raise K.response_id_collision(response_id, recorded, binding)
    return record


def _gateway_response_collision(repo_root: Path, frame: Any) -> dict[str, Any] | None:
    """The RESPONSE_ID_COLLISION of a gateway request frame, checked before ingest, or None."""
    try:
        packet = K.recover_packet(frame)
        if (packet.get("payload") or {}).get("message_class") not in K.RESPONDING_MESSAGE_CLASSES:
            return None
        _submitted_response_record(repo_root, packet)
    except K.ResponseIdCollision as exc:
        return exc.refusal
    except (*K.JSON_DOCUMENT_ERRORS, KeyError, TypeError, AttributeError):
        pass
    return None


def _submit_response_once(repo_root: Path, request_packet: dict[str, Any], response_frame: dict[str, Any]) -> dict[str, Any]:
    """Submit one response per request, resumable at every step.

    1. The response frame is recorded, atomically and marked unsubmitted,
       under its response id and with the request's packet id and digest,
       before it is submitted.
    2. It is submitted.
    3. The record is marked submitted.

    A fault at any step leaves the request pending. The retry of the same
    request reuses the recorded frame: it resubmits the same bytes if step 3
    had not happened, and submits nothing if it had. A different request under
    the same response id is K.ResponseIdCollision, never the recorded frame.
    """
    path = _submitted_response_path(repo_root, response_frame["packet_id"])
    binding = K.request_binding(request_packet)
    record = _submitted_response_record(repo_root, request_packet)
    if record is not None:
        frame = record["frame"]
        if record.get("submitted") is not True:
            submit_frame(frame)
            K.write_json_atomic(path, {**binding, "frame": frame, "submitted": True})
        return {"frame": frame, "reused": True}
    K.write_json_atomic(path, {**binding, "frame": response_frame, "submitted": False})
    submit_frame(response_frame)
    K.write_json_atomic(path, {**binding, "frame": response_frame, "submitted": True})
    return {"frame": response_frame, "reused": False}


def _deferred_cycle(organization: str, frame: dict[str, Any], exc: BaseException,
                    responses_emitted: int = 0, response_ref: str | None = None) -> dict[str, Any]:
    """A gateway cycle left pending because this boundary's own write or the gateway failed."""
    return {
        "schema_version": "stegverse.org-federation-gateway-cycle.v1",
        "organization": organization,
        "state": "DEFERRED",
        "refusal": K.dispatch_io_deferral(frame, exc if isinstance(exc, OSError) else OSError(str(exc)))["refusal"],
        "packet_id": frame.get("packet_id") if isinstance(frame, dict) else None,
        "frames_consumed": 0,
        "responses_emitted": responses_emitted,
        "response_frame_sha256": response_ref,
        "gateway_execution_authority": "NONE",
    }


def resident_gateway_cycle(repo_root: Path, *, hb_epoch: int | None = None) -> dict[str, Any]:
    """Consume one gateway frame, submit its response, and acknowledge it.

    The cycle's `hb_epoch` is checked first and stamps the response frame and
    the acknowledgement; never a clock reading. A frame refused six-field at
    ingest is acknowledged BLOCKED with its quarantine refusal, so this
    boundary does not consume it again.
    """
    ack_epoch = K.supplied_hb_reference(hb_epoch, retry_entrypoint=GATEWAY_EPOCH_RETRY_ENTRYPOINT)["epoch"]
    registry = K.load_registry(repo_root)
    organization = registry["organization"]
    fetched = fetch_frame(organization)
    if fetched.get("state") == "NO_FRAME":
        return {
            "schema_version": "stegverse.org-federation-gateway-cycle.v1",
            "organization": organization,
            "state": "NO_FRAME",
            "frames_consumed": 0,
            "responses_emitted": 0,
            "gateway_execution_authority": "NONE",
        }
    if fetched.get("state") != "FRAME_AVAILABLE":
        raise FederationGatewayTransportError("unexpected gateway fetch state")
    unusable = fetched.get("unusable_frame")
    if unusable is not None:
        # The frame's own fault, read apart from a readable envelope: it is
        # terminal and acknowledged BLOCKED, so the gateway drops it and the
        # next frame is offered. It is never ingested.
        frame = {"packet_id": unusable["packet_id"], "frame_sha256": unusable["frame_sha256"]}
        result = K.quarantine_result(frame, K.frame_failure_refusal(unusable["error"]))
        try:
            ack = acknowledge_frame(organization, frame, "BLOCKED", hb_epoch=ack_epoch, refusal=result["refusal"])
        except (OSError, FederationGatewayTransportError) as exc:
            return _deferred_cycle(organization, frame, exc)
        return {
            "schema_version": "stegverse.org-federation-gateway-cycle.v1",
            "organization": organization,
            "state": "REFUSED",
            "refusal": result["refusal"],
            "packet_id": frame["packet_id"],
            "frame_sha256": frame["frame_sha256"],
            "frames_consumed": 0,
            "responses_emitted": 0,
            "response_frame_sha256": None,
            "ack_state": ack.get("state"),
            "gateway_execution_authority": "NONE",
        }
    frame = fetched["frame"]
    collision = _gateway_response_collision(repo_root, frame)
    if collision is not None:
        # Refused before ingest: acknowledged BLOCKED, never the earlier response.
        packet, result = None, K.quarantine_result(frame if isinstance(frame, dict) else {}, collision)
    else:
        packet, result = K.ingest_or_quarantine(repo_root, frame, hb_epoch=ack_epoch)
    if result.get("status") == "DEFERRED":
        # This boundary's own storage failed: the frame is not acknowledged,
        # so the gateway offers it again and the next cycle consumes it once.
        return {
            "schema_version": "stegverse.org-federation-gateway-cycle.v1",
            "organization": organization,
            "state": "DEFERRED",
            "refusal": result["refusal"],
            "packet_id": frame.get("packet_id") if isinstance(frame, dict) else None,
            "frames_consumed": 0,
            "responses_emitted": 0,
            "gateway_execution_authority": "NONE",
        }
    response_emitted = 0
    response_ref = None
    if result.get("status") == "CONSUMED":
        execution = result["execution_result"]
        message_class = (packet.get("payload") or {}).get("message_class")
        try:
            if message_class in K.RESPONDING_MESSAGE_CLASSES:
                response = K.build_control_response(packet, execution)
                submitted = _submit_response_once(
                    repo_root, packet, K.carrier_frame(response, epoch=result["hb_epoch"]))
                response_emitted = 0 if submitted["reused"] else 1
                response_ref = submitted["frame"]["frame_sha256"]
            elif message_class in {"ecosystem.monitor.response", "ecosystem.work.ack", "ecosystem.communication.ack"}:
                _persist_response(repo_root, packet, execution)
        except K.ResponseIdCollision as exc:
            # Raced in after the check before ingest: still never the earlier response.
            result = K.quarantine_result(frame, exc.refusal)
        except (OSError, FederationGatewayTransportError) as exc:
            return _deferred_cycle(organization, frame, exc)
    ack_state = "CONSUMED" if result.get("status") == "CONSUMED" else "BLOCKED"
    try:
        ack = acknowledge_frame(organization, frame, ack_state, hb_epoch=ack_epoch,
                                refusal=result.get("refusal"))
    except (OSError, FederationGatewayTransportError) as exc:
        # The ack is this boundary's own write: the frame stays pending, and the
        # retried request reuses the response it already submitted.
        return _deferred_cycle(organization, frame, exc, response_emitted, response_ref)
    return {
        "schema_version": "stegverse.org-federation-gateway-cycle.v1",
        "organization": organization,
        "state": "REFUSED" if result.get("status") == "REFUSED" else ack_state,
        "refusal": result.get("refusal"),
        "packet_id": frame["packet_id"],
        "frame_sha256": frame["frame_sha256"],
        "frames_consumed": 1 if ack_state == "CONSUMED" else 0,
        "responses_emitted": response_emitted,
        "response_frame_sha256": response_ref,
        "ack_state": ack.get("state"),
        "gateway_execution_authority": "NONE",
    }


def collect_local_responses(repo_root: Path, communication_id: str) -> dict[str, Any]:
    directory = repo_root / "resident-runtime" / "control" / "responses.d"
    rows = []
    if directory.exists():
        for path in sorted(directory.glob("*.json")):
            try:
                value = json.loads(path.read_text())
            except Exception:
                continue
            if value.get("communication_id") == communication_id:
                rows.append(value)
    orgs = sorted({row.get("origin_org") for row in rows if row.get("origin_org")})
    return {
        "communication_id": communication_id,
        "response_count": len(orgs),
        "organizations": orgs,
        "complete": len(orgs) == 14,
    }
