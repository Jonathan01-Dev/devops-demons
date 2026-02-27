from __future__ import annotations

import os
from pathlib import Path


def _parse_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def load_config() -> dict[str, object]:
    cwd = Path.cwd()
    env_file = _parse_dotenv(cwd / ".env")

    def get(name: str, default: str) -> str:
        return os.getenv(name) or env_file.get(name) or default

    tcp_port = int(get("TCP_PORT", "7777"))
    return {
        "node_id": get("NODE_ID", ""),
        "tcp_port": tcp_port,
        "udp_port": int(get("UDP_PORT", "6000")),
        "multicast_addr": get("MULTICAST_ADDR", "239.255.42.99"),
        "hello_interval_ms": int(get("HELLO_INTERVAL_MS", "30000")),
        "peer_timeout_ms": int(get("PEER_TIMEOUT_MS", "90000")),
        "peer_store_path": cwd / ".archipel" / f"peers-{tcp_port}.json",
    }
