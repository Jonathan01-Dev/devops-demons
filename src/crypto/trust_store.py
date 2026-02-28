from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path


class TrustStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = self._load()

    def verify_or_trust(self, node_id_hex: str, public_raw: bytes) -> tuple[bool, str]:
        pub_b64 = base64.b64encode(public_raw).decode("ascii")
        fp = hashlib.sha256(public_raw).hexdigest()
        existing = self.data.get(node_id_hex)
        if existing is None:
            self.data[node_id_hex] = {"public_key_b64": pub_b64, "fingerprint_sha256": fp, "trust": "tofu"}
            self._save()
            return True, f"TOFU accepted {node_id_hex[:10]}.."
        if existing.get("public_key_b64") != pub_b64:
            return False, f"Trust mismatch for {node_id_hex[:10]}.. (possible MITM)"
        return True, f"Trust verified {node_id_hex[:10]}.."

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
