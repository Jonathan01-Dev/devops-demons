from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.crypto.identity import NodeIdentity, load_identity, verify_signature
from src.crypto.session import decrypt_message, derive_session_key, encrypt_message
from src.crypto.trust_store import TrustStore


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


async def _read_json_line(reader: asyncio.StreamReader) -> dict[str, Any]:
    line = await reader.readline()
    if not line:
        raise ConnectionError("Connection closed")
    return json.loads(line.decode("utf-8"))


async def _write_json_line(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()


@dataclass
class HandshakeResult:
    session_key: bytes
    transcript_hash: bytes
    peer_node_id: str


def _transcript_hash(client_eph_pub: bytes, server_eph_pub: bytes, client_node_id: str, server_node_id: str) -> bytes:
    h = hashlib.sha256()
    h.update(client_eph_pub)
    h.update(server_eph_pub)
    h.update(bytes.fromhex(client_node_id))
    h.update(bytes.fromhex(server_node_id))
    return h.digest()


async def _server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: NodeIdentity,
    trust: TrustStore,
) -> HandshakeResult:
    hello = await _read_json_line(reader)
    if hello.get("type") != "HELLO":
        raise ValueError("Expected HELLO")

    client_node_id = hello["node_id"]
    client_pub_raw = _unb64(hello["ed25519_pub"])
    client_eph_pub = _unb64(hello["e_pub"])

    ok, msg = trust.verify_or_trust(client_node_id, client_pub_raw)
    print(f"[trust] {msg}")
    if not ok:
        raise ValueError("Peer trust verification failed")

    server_eph = x25519.X25519PrivateKey.generate()
    server_eph_pub = server_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    transcript = _transcript_hash(client_eph_pub, server_eph_pub, client_node_id, identity.node_id_hex)
    sig_b = identity.sign(transcript)

    await _write_json_line(
        writer,
        {
            "type": "HELLO_REPLY",
            "node_id": identity.node_id_hex,
            "ed25519_pub": _b64(identity.public_raw),
            "e_pub": _b64(server_eph_pub),
            "sig_b": _b64(sig_b),
        },
    )

    auth = await _read_json_line(reader)
    if auth.get("type") != "AUTH":
        raise ValueError("Expected AUTH")
    sig_a = _unb64(auth["sig_a"])
    if not verify_signature(client_pub_raw, sig_a, transcript):
        raise ValueError("Bad AUTH signature")

    await _write_json_line(writer, {"type": "AUTH_OK"})
    shared = server_eph.exchange(x25519.X25519PublicKey.from_public_bytes(client_eph_pub))
    key = derive_session_key(shared, transcript)
    return HandshakeResult(key, transcript, client_node_id)


async def _client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: NodeIdentity,
    trust: TrustStore,
) -> HandshakeResult:
    client_eph = x25519.X25519PrivateKey.generate()
    client_eph_pub = client_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    await _write_json_line(
        writer,
        {
            "type": "HELLO",
            "node_id": identity.node_id_hex,
            "ed25519_pub": _b64(identity.public_raw),
            "e_pub": _b64(client_eph_pub),
        },
    )

    reply = await _read_json_line(reader)
    if reply.get("type") != "HELLO_REPLY":
        raise ValueError("Expected HELLO_REPLY")

    server_node_id = reply["node_id"]
    server_pub_raw = _unb64(reply["ed25519_pub"])
    server_eph_pub = _unb64(reply["e_pub"])
    sig_b = _unb64(reply["sig_b"])

    ok, msg = trust.verify_or_trust(server_node_id, server_pub_raw)
    print(f"[trust] {msg}")
    if not ok:
        raise ValueError("Peer trust verification failed")

    transcript = _transcript_hash(client_eph_pub, server_eph_pub, identity.node_id_hex, server_node_id)
    if not verify_signature(server_pub_raw, sig_b, transcript):
        raise ValueError("Bad HELLO_REPLY signature")

    await _write_json_line(writer, {"type": "AUTH", "sig_a": _b64(identity.sign(transcript))})
    auth_ok = await _read_json_line(reader)
    if auth_ok.get("type") != "AUTH_OK":
        raise ValueError("Expected AUTH_OK")

    shared = client_eph.exchange(x25519.X25519PublicKey.from_public_bytes(server_eph_pub))
    key = derive_session_key(shared, transcript)
    return HandshakeResult(key, transcript, server_node_id)


class Sprint2SecureServer:
    def __init__(self, host: str, port: int, keys_dir: Path, trust_db: Path) -> None:
        self.host = host
        self.port = port
        self.identity = load_identity(keys_dir)
        self.trust = TrustStore(trust_db)

    async def run(self) -> None:
        server = await asyncio.start_server(self._on_client, self.host, self.port)
        print(f"[s2-server] listening on {self.host}:{self.port} node_id={self.identity.node_id_hex}")
        async with server:
            await server.serve_forever()

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            hs = await _server_handshake(reader, writer, self.identity, self.trust)
            msg = await _read_json_line(reader)
            if msg.get("type") != "MSG":
                raise ValueError("Expected MSG")
            plaintext = decrypt_message(
                hs.session_key,
                _unb64(msg["nonce"]),
                _unb64(msg["ciphertext"]),
                aad=hs.transcript_hash,
            )
            decoded = plaintext.decode("utf-8", errors="replace")
            print(f"[s2-server] msg from {hs.peer_node_id[:10]}..: {decoded}")
            await _write_json_line(writer, {"type": "ACK", "status": "OK"})
        except Exception as exc:
            await _write_json_line(writer, {"type": "ERROR", "error": str(exc)})
        finally:
            writer.close()
            await writer.wait_closed()


class Sprint2SecureClient:
    def __init__(self, host: str, port: int, keys_dir: Path, trust_db: Path) -> None:
        self.host = host
        self.port = port
        self.identity = load_identity(keys_dir)
        self.trust = TrustStore(trust_db)

    async def send(self, message: str) -> None:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            hs = await _client_handshake(reader, writer, self.identity, self.trust)
            nonce, ciphertext = encrypt_message(hs.session_key, message.encode("utf-8"), aad=hs.transcript_hash)
            await _write_json_line(writer, {"type": "MSG", "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)})
            print(f"[s2-client] server reply: {await _read_json_line(reader)}")
        finally:
            writer.close()
            await writer.wait_closed()
