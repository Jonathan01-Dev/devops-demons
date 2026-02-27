from __future__ import annotations

import json
import struct

MAGIC = b"ARCP"

TYPE_HELLO = 0x01
TYPE_PEER_LIST = 0x02


def build_packet(pkt_type: int, node_id_hex: str, payload: dict) -> bytes:
    node_id = bytes.fromhex(node_id_hex)
    if len(node_id) != 32:
        raise ValueError("node_id must be 32 bytes (64 hex chars)")
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = b"".join([MAGIC, struct.pack("!B", pkt_type), node_id, struct.pack("!I", len(payload_raw))])
    return header + payload_raw


def parse_packet(data: bytes) -> dict:
    if len(data) < 41:
        raise ValueError("packet too short")
    if data[0:4] != MAGIC:
        raise ValueError("bad magic")
    pkt_type = data[4]
    node_id_hex = data[5:37].hex()
    payload_len = struct.unpack("!I", data[37:41])[0]
    payload_end = 41 + payload_len
    if payload_end > len(data):
        raise ValueError("invalid payload length")
    payload = json.loads(data[41:payload_end].decode("utf-8")) if payload_len else {}
    return {"type": pkt_type, "node_id": node_id_hex, "payload": payload}
