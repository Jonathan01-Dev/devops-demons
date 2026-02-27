from __future__ import annotations

import os
import subprocess
from pathlib import Path


def generate_node_identity(out_dir: Path, force: bool = False) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / "node_private.key"
    public_path = out_dir / "node_public.key"

    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError(
            "Key file already exists. Use --force to overwrite, or remove existing files first."
        )

    if _generate_with_cryptography(private_path, public_path):
        pass
    elif _generate_with_openssl(private_path, public_path):
        pass
    else:
        raise RuntimeError(
            "Unable to generate Ed25519 keys. Install Python package 'cryptography' or OpenSSL."
        )

    try:
        os.chmod(private_path, 0o600)
    except Exception:
        # Windows may ignore POSIX permissions; keep best effort.
        pass

    node_id_hex = _extract_public_key_hex(public_path)
    return {
        "private_key_path": str(private_path),
        "public_key_path": str(public_path),
        "node_id_hex": node_id_hex,
    }


def _generate_with_cryptography(private_path: Path, public_path: Path) -> bool:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:
        return False

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return True


def _generate_with_openssl(private_path: Path, public_path: Path) -> bool:
    try:
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except Exception:
        return False


def _extract_public_key_hex(public_path: Path) -> str:
    data = public_path.read_bytes()
    try:
        from cryptography.hazmat.primitives import serialization

        pub = serialization.load_pem_public_key(data)
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()
    except Exception:
        # Fallback when 'cryptography' is unavailable: expose PEM bytes hash-like marker.
        # Sprint 0 only needs persisted identity files; raw key hex is preferred.
        return data.hex()[:64]
