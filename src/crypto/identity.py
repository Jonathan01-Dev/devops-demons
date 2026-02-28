from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class NodeIdentity:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey, public_key: ed25519.Ed25519PublicKey) -> None:
        self.private_key = private_key
        self.public_key = public_key

    @property
    def public_raw(self) -> bytes:
        return self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    @property
    def node_id_hex(self) -> str:
        return self.public_raw.hex()

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def load_identity(keys_dir: Path) -> NodeIdentity:
    private_path = keys_dir / "node_private.key"
    public_path = keys_dir / "node_public.key"
    if not private_path.exists() or not public_path.exists():
        raise FileNotFoundError(f"Missing key files in {keys_dir}. Run: python main.py keygen --out-dir {keys_dir}")

    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(private_key, ed25519.Ed25519PrivateKey) or not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise TypeError("Loaded keys are not Ed25519 keys")
    return NodeIdentity(private_key, public_key)


def verify_signature(public_raw: bytes, signature: bytes, data: bytes) -> bool:
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_raw)
        key.verify(signature, data)
        return True
    except Exception:
        return False
