import json
import time
from typing import Any


PROTOCOL_VERSION = 1
MAX_DATAGRAM_BYTES = 1300


def build_packet(packet_type: str, **fields: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "type": packet_type,
        "ts": int(time.time() * 1000),
    }
    payload.update(fields)
    return payload


def encode_packet(payload: dict[str, Any]) -> bytes:
    raw = dict(payload)
    raw.setdefault("v", PROTOCOL_VERSION)
    return json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_packet(data: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "PACKET_NOT_UTF8"

    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError:
        return None, "PACKET_NOT_JSON"

    if not isinstance(payload, dict):
        return None, "PACKET_NOT_OBJECT"

    if payload.get("v") != PROTOCOL_VERSION:
        return None, "PACKET_VERSION_UNSUPPORTED"

    packet_type = payload.get("type")
    if not isinstance(packet_type, str) or not packet_type.strip():
        return None, "PACKET_TYPE_MISSING"

    return payload, None


def sanitize_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    compact = " ".join(value.strip().split())
    return compact[:limit]
