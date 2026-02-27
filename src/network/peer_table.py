from __future__ import annotations

import json
import time
from pathlib import Path


class PeerTable:
    def __init__(self, timeout_ms: int, storage_path: Path) -> None:
        self.timeout_ms = timeout_ms
        self.storage_path = storage_path
        self.peers: dict[str, dict] = {}
        self._load()

    def upsert(self, node_id: str, ip: str, tcp_port: int) -> None:
        now_ms = int(time.time() * 1000)
        prev = self.peers.get(node_id, {})
        self.peers[node_id] = {
            "node_id": node_id,
            "ip": ip,
            "tcp_port": tcp_port,
            "last_seen": now_ms,
            "shared_files": prev.get("shared_files", []),
            "reputation": prev.get("reputation", 1.0),
        }
        self._save()

    def sweep(self) -> int:
        now_ms = int(time.time() * 1000)
        stale = [k for k, p in self.peers.items() if now_ms - int(p["last_seen"]) > self.timeout_ms]
        for k in stale:
            self.peers.pop(k, None)
        if stale:
            self._save()
        return len(stale)

    def list(self) -> list[dict]:
        return sorted(self.peers.values(), key=lambda x: x["node_id"])

    def serialize_for_wire(self) -> list[dict]:
        out = []
        for p in self.list():
            out.append(
                {
                    "node_id": p["node_id"],
                    "ip": p["ip"],
                    "tcp_port": p["tcp_port"],
                    "last_seen": p["last_seen"],
                }
            )
        return out

    def _load(self) -> None:
        try:
            raw = self.storage_path.read_text(encoding="utf-8")
            items = json.loads(raw)
            if isinstance(items, list):
                for p in items:
                    self.peers[p["node_id"]] = p
        except Exception:
            return

    def _save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(json.dumps(self.list(), indent=2), encoding="utf-8")
