from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from src.crypto.identity import load_identity, verify_signature
from src.crypto.session import decrypt_message, encrypt_message
from src.crypto.trust_store import TrustStore
from src.messaging.sprint2_secure_channel import (
    _client_handshake,
    _server_handshake,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _manifest_payload_no_sig(path: Path, sender_id: str, chunk_size: int) -> dict[str, Any]:
    file_size = path.stat().st_size
    chunks: list[dict[str, Any]] = []
    file_hash = hashlib.sha256()
    with path.open("rb") as f:
        index = 0
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            file_hash.update(data)
            chunks.append({"index": index, "hash": _sha256_hex(data), "size": len(data)})
            index += 1

    return {
        "file_id": file_hash.hexdigest(),
        "filename": path.name,
        "size": file_size,
        "chunk_size": chunk_size,
        "nb_chunks": len(chunks),
        "chunks": chunks,
        "sender_id": sender_id,
    }


def _sign_manifest(identity, manifest_no_sig: dict[str, Any]) -> str:
    sig = identity.sign(_canonical_json_bytes(manifest_no_sig))
    return _b64(sig)


def _verify_manifest_signature(manifest: dict[str, Any]) -> bool:
    signature = manifest.get("signature")
    sender_id = manifest.get("sender_id")
    if not isinstance(signature, str) or not isinstance(sender_id, str):
        return False
    material = dict(manifest)
    material.pop("signature", None)
    return verify_signature(bytes.fromhex(sender_id), _unb64(signature), _canonical_json_bytes(material))


def _chunk_signature_input(file_id: str, chunk_idx: int, chunk_hash: str) -> bytes:
    return f"{file_id}:{chunk_idx}:{chunk_hash}".encode("utf-8")


def _load_index(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"files": {}}


def _save_index(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


async def _write_framed_json(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
    raw = _canonical_json_bytes(payload)
    writer.write(len(raw).to_bytes(4, byteorder="big") + raw)
    await writer.drain()


async def _read_framed_json(reader: asyncio.StreamReader, max_len: int = 20 * 1024 * 1024) -> dict[str, Any]:
    header = await reader.readexactly(4)
    size = int.from_bytes(header, byteorder="big")
    if size < 0 or size > max_len:
        raise ValueError(f"Invalid framed message size: {size}")
    raw = await reader.readexactly(size)
    return json.loads(raw.decode("utf-8"))


async def _send_secure(writer: asyncio.StreamWriter, session_key: bytes, aad: bytes, payload: dict[str, Any]) -> None:
    nonce, ciphertext = encrypt_message(session_key, _canonical_json_bytes(payload), aad=aad)
    await _write_framed_json(writer, {"type": "SECURE", "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)})


async def _recv_secure(reader: asyncio.StreamReader, session_key: bytes, aad: bytes) -> dict[str, Any]:
    msg = await _read_framed_json(reader)
    if msg.get("type") != "SECURE":
        raise ValueError("Expected SECURE message")
    plaintext = decrypt_message(session_key, _unb64(msg["nonce"]), _unb64(msg["ciphertext"]), aad=aad)
    return json.loads(plaintext.decode("utf-8"))


class Sprint3FileServer:
    def __init__(self, host: str, port: int, keys_dir: Path, trust_db: Path, file_path: Path, chunk_size: int = 524288) -> None:
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"Missing shared file: {file_path}")
        self.host = host
        self.port = port
        self.identity = load_identity(keys_dir)
        self.trust = TrustStore(trust_db)
        self.file_path = file_path
        self.chunk_size = chunk_size
        self.manifest_no_sig = _manifest_payload_no_sig(self.file_path, self.identity.node_id_hex, self.chunk_size)
        self.manifest = dict(self.manifest_no_sig)
        self.manifest["signature"] = _sign_manifest(self.identity, self.manifest_no_sig)

    async def run(self) -> None:
        server = await asyncio.start_server(self._on_client, self.host, self.port)
        print(
            f"[s3-server] listening on {self.host}:{self.port} "
            f"file={self.file_path.name} file_id={self.manifest['file_id']} chunks={self.manifest['nb_chunks']}"
        )
        async with server:
            await server.serve_forever()

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            hs = await _server_handshake(reader, writer, self.identity, self.trust)
            while True:
                req = await _recv_secure(reader, hs.session_key, hs.transcript_hash)
                req_type = req.get("type")
                if req_type == "MANIFEST_REQ":
                    await _send_secure(writer, hs.session_key, hs.transcript_hash, {"type": "MANIFEST", "manifest": self.manifest})
                    continue
                if req_type == "CHUNK_REQ":
                    await self._handle_chunk_req(writer, hs.session_key, hs.transcript_hash, req)
                    continue
                if req_type == "CLOSE":
                    break
                await _send_secure(writer, hs.session_key, hs.transcript_hash, {"type": "ERROR", "error": "Unknown request type"})
        except Exception as exc:
            try:
                await _write_framed_json(writer, {"type": "ERROR", "error": str(exc)})
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_chunk_req(self, writer: asyncio.StreamWriter, session_key: bytes, aad: bytes, req: dict[str, Any]) -> None:
        file_id = req.get("file_id")
        chunk_idx = int(req.get("chunk_idx", -1))
        if file_id != self.manifest["file_id"]:
            await _send_secure(writer, session_key, aad, {"type": "ACK", "chunk_idx": chunk_idx, "status": "NOT_FOUND"})
            return
        if chunk_idx < 0 or chunk_idx >= self.manifest["nb_chunks"]:
            await _send_secure(writer, session_key, aad, {"type": "ACK", "chunk_idx": chunk_idx, "status": "NOT_FOUND"})
            return

        with self.file_path.open("rb") as f:
            f.seek(chunk_idx * self.chunk_size)
            chunk = f.read(self.chunk_size)

        chunk_hash = _sha256_hex(chunk)
        signature = self.identity.sign(_chunk_signature_input(file_id, chunk_idx, chunk_hash))
        await _send_secure(
            writer,
            session_key,
            aad,
            {
                "type": "CHUNK_DATA",
                "file_id": file_id,
                "chunk_idx": chunk_idx,
                "chunk_hash": chunk_hash,
                "data": _b64(chunk),
                "signature": _b64(signature),
            },
        )


class Sprint3FileDownloader:
    class _PeerSession:
        def __init__(
            self,
            host: str,
            port: int,
            peer_node_id: str,
            session_key: bytes,
            transcript_hash: bytes,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            self.host = host
            self.port = port
            self.peer_node_id = peer_node_id
            self.session_key = session_key
            self.transcript_hash = transcript_hash
            self.reader = reader
            self.writer = writer
            self.lock = asyncio.Lock()

        async def request(self, payload: dict[str, Any]) -> dict[str, Any]:
            async with self.lock:
                await _send_secure(self.writer, self.session_key, self.transcript_hash, payload)
                return await _recv_secure(self.reader, self.session_key, self.transcript_hash)

        async def close(self) -> None:
            try:
                await self.request({"type": "CLOSE"})
            except Exception:
                pass
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    def __init__(
        self,
        host: str | None,
        port: int | None,
        peers: list[tuple[str, int]],
        keys_dir: Path,
        trust_db: Path,
        out_dir: Path,
        index_db: Path,
        parallelism: int = 3,
    ) -> None:
        self.host = host
        self.port = port
        self.peers = list(peers)
        if not self.peers and self.host and self.port:
            self.peers = [(self.host, self.port)]
        if not self.peers:
            raise ValueError("At least one peer is required")
        self.parallelism = max(1, parallelism)
        self.identity = load_identity(keys_dir)
        self.trust = TrustStore(trust_db)
        self.out_dir = out_dir
        self.index_db = index_db

    async def _connect_peer(self, host: str, port: int) -> tuple[dict[str, Any], Sprint3FileDownloader._PeerSession]:
        reader, writer = await asyncio.open_connection(host, port)
        hs = await _client_handshake(reader, writer, self.identity, self.trust)
        peer = Sprint3FileDownloader._PeerSession(
            host=host,
            port=port,
            peer_node_id=hs.peer_node_id,
            session_key=hs.session_key,
            transcript_hash=hs.transcript_hash,
            reader=reader,
            writer=writer,
        )
        reply = await peer.request({"type": "MANIFEST_REQ"})
        if reply.get("type") != "MANIFEST":
            raise ValueError(f"Expected MANIFEST from {host}:{port}")
        manifest = reply["manifest"]
        if manifest.get("sender_id") != hs.peer_node_id:
            raise ValueError(f"Manifest sender_id mismatch from {host}:{port}")
        if not _verify_manifest_signature(manifest):
            raise ValueError(f"Invalid manifest signature from {host}:{port}")
        return manifest, peer

    async def download(self) -> None:
        sessions: list[Sprint3FileDownloader._PeerSession] = []
        try:
            base_manifest: dict[str, Any] | None = None
            for host, port in self.peers:
                try:
                    manifest, session = await self._connect_peer(host, port)
                    if base_manifest is None:
                        base_manifest = manifest
                    if manifest.get("file_id") != base_manifest.get("file_id"):
                        await session.close()
                        print(f"[s3-download] skip {host}:{port} (different file_id)")
                        continue
                    sessions.append(session)
                    print(f"[s3-download] source online {host}:{port}")
                except Exception as exc:
                    print(f"[s3-download] source offline {host}:{port} ({exc})")

            if not sessions or base_manifest is None:
                raise ValueError("No valid source peer available")

            manifest = base_manifest
            file_id = manifest["file_id"]
            filename = manifest["filename"]
            chunk_count = int(manifest["nb_chunks"])
            print(f"[s3-download] file={filename} file_id={file_id} chunks={chunk_count} sources={len(sessions)}")

            chunks_dir = Path(".archipel") / "chunks" / file_id
            chunks_dir.mkdir(parents=True, exist_ok=True)

            chunk_hashes: dict[int, str] = {}
            for chunk_meta in manifest["chunks"]:
                idx = int(chunk_meta["index"])
                chunk_hashes[idx] = chunk_meta["hash"]
                chunk_path = chunks_dir / f"{idx:08d}.chunk"
                if chunk_path.exists():
                    existing = chunk_path.read_bytes()
                    if _sha256_hex(existing) == chunk_hashes[idx]:
                        chunk_hashes.pop(idx, None)

            remaining = sorted(chunk_hashes.keys())
            if remaining:
                sem = asyncio.Semaphore(min(self.parallelism, len(sessions)))
                completed = chunk_count - len(remaining)

                async def fetch_chunk(idx: int) -> None:
                    nonlocal completed
                    expected_hash = chunk_hashes[idx]
                    last_err: Exception | None = None
                    start = idx % len(sessions)
                    ordered = sessions[start:] + sessions[:start]
                    for session in ordered:
                        try:
                            async with sem:
                                data = await session.request({"type": "CHUNK_REQ", "file_id": file_id, "chunk_idx": idx})
                            if data.get("type") != "CHUNK_DATA":
                                raise ValueError(f"Expected CHUNK_DATA for idx={idx}")
                            if data.get("file_id") != file_id or int(data.get("chunk_idx", -1)) != idx:
                                raise ValueError(f"Bad chunk metadata for idx={idx}")

                            raw = _unb64(data["data"])
                            got_hash = _sha256_hex(raw)
                            if got_hash != expected_hash or got_hash != data.get("chunk_hash"):
                                raise ValueError(f"Chunk hash mismatch idx={idx}")
                            sig_ok = verify_signature(
                                bytes.fromhex(session.peer_node_id),
                                _unb64(data["signature"]),
                                _chunk_signature_input(file_id, idx, got_hash),
                            )
                            if not sig_ok:
                                raise ValueError(f"Invalid chunk signature idx={idx}")
                            (chunks_dir / f"{idx:08d}.chunk").write_bytes(raw)
                            completed += 1
                            print(f"[s3-download] chunk {completed}/{chunk_count} ok via {session.host}:{session.port}")
                            return
                        except Exception as exc:
                            last_err = exc
                            continue
                    raise ValueError(f"Failed chunk idx={idx}: {last_err}")

                await asyncio.gather(*(fetch_chunk(i) for i in remaining))

            self.out_dir.mkdir(parents=True, exist_ok=True)
            out_file = self.out_dir / filename
            with out_file.open("wb") as out:
                for i in range(chunk_count):
                    out.write((chunks_dir / f"{i:08d}.chunk").read_bytes())

            final_hash = _sha256_hex(out_file.read_bytes())
            if final_hash != file_id:
                raise ValueError("Final file hash mismatch")
            print(f"[s3-download] completed {out_file} sha256={final_hash}")

            index = _load_index(self.index_db)
            index.setdefault("files", {})
            index["files"][file_id] = {
                "filename": filename,
                "path": str(out_file),
                "size": int(manifest["size"]),
                "nb_chunks": chunk_count,
                "sender_id": manifest["sender_id"],
            }
            _save_index(self.index_db, index)
        finally:
            await asyncio.gather(*(s.close() for s in sessions), return_exceptions=True)
