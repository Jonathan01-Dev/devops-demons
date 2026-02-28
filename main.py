import argparse
import asyncio
import json
from pathlib import Path

from src.config import load_config
from src.crypto.keygen import generate_node_identity
from src.cli.web_demo import run_web_demo
from src.messaging.gemini_assistant import GeminiAssistant
from src.messaging.sprint2_secure_channel import Sprint2SecureClient, Sprint2SecureServer
from src.network.node import Sprint1Node
from src.network.peer_table import PeerTable
from src.transfer.sprint3_file_transfer import Sprint3FileDownloader, Sprint3FileServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Archipel CLI - Sprint 0 to Sprint 4")
    sub = parser.add_subparsers(dest="command")

    keygen_parser = sub.add_parser("keygen", help="Generate Ed25519 node identity")
    keygen_parser.add_argument("--out-dir", default=".keys", help="Directory where keys are stored")
    keygen_parser.add_argument("--force", action="store_true", help="Overwrite existing key files")
    sub.add_parser("start", help="Start Sprint 1 P2P node")
    sub.add_parser("peers", help="Show persisted peer table")
    s2_server = sub.add_parser("s2-server", help="Start Sprint 2 secure server")
    s2_server.add_argument("--host", default="0.0.0.0")
    s2_server.add_argument("--port", type=int, default=9001)
    s2_server.add_argument("--keys-dir", default=".keys")
    s2_server.add_argument("--trust-db", default=".archipel/trust.json")
    s2_send = sub.add_parser("s2-send", help="Sprint 2 secure send")
    s2_send.add_argument("--host", required=True)
    s2_send.add_argument("--port", type=int, default=9001)
    s2_send.add_argument("--msg", required=True)
    s2_send.add_argument("--keys-dir", default=".keys")
    s2_send.add_argument("--trust-db", default=".archipel/trust.json")
    s3_server = sub.add_parser("s3-server", help="Sprint 3 chunk file server")
    s3_server.add_argument("--host", default="0.0.0.0")
    s3_server.add_argument("--port", type=int, default=9101)
    s3_server.add_argument("--file", required=True)
    s3_server.add_argument("--chunk-size", type=int, default=524288)
    s3_server.add_argument("--keys-dir", default=".keys")
    s3_server.add_argument("--trust-db", default=".archipel/trust.json")
    s3_download = sub.add_parser("s3-download", help="Sprint 3 file download from peer")
    s3_download.add_argument("--host")
    s3_download.add_argument("--port", type=int, default=9101)
    s3_download.add_argument(
        "--peer",
        action="append",
        default=[],
        help="Additional source peer in host:port format. Can be repeated.",
    )
    s3_download.add_argument("--parallel", type=int, default=3, help="Max parallel chunk downloads")
    s3_download.add_argument("--out-dir", default="downloads")
    s3_download.add_argument("--index-db", default=".archipel/index.json")
    s3_download.add_argument("--keys-dir", default=".keys")
    s3_download.add_argument("--trust-db", default=".archipel/trust.json")
    # Sprint 4 unified aliases
    msg = sub.add_parser("msg", help="Send encrypted message to peer endpoint")
    msg.add_argument("endpoint", help="Peer endpoint in host:port format")
    msg.add_argument("message", help="Message plaintext")
    msg.add_argument("--no-ai", action="store_true", help="Disable Gemini assistant integration")
    msg.add_argument("--keys-dir", default=".keys")
    msg.add_argument("--trust-db", default=".archipel/trust.json")
    ask = sub.add_parser("ask", help="Query Archipel AI assistant without sending a peer message")
    ask.add_argument("query")
    ask.add_argument("--no-ai", action="store_true")
    send = sub.add_parser("send", help="Share a file (starts Sprint 3 file server)")
    send.add_argument("filepath")
    send.add_argument("--host", default="0.0.0.0")
    send.add_argument("--port", type=int, default=9101)
    send.add_argument("--chunk-size", type=int, default=524288)
    send.add_argument("--keys-dir", default=".keys")
    send.add_argument("--trust-db", default=".archipel/trust.json")
    download = sub.add_parser("download", help="Download file from one or many peers")
    download.add_argument("--peer", action="append", default=[], help="Source peer host:port (repeatable)")
    download.add_argument("--host", help="Single source host (legacy style)")
    download.add_argument("--port", type=int, default=9101, help="Single source port")
    download.add_argument("--parallel", type=int, default=3)
    download.add_argument("--out-dir", default="downloads")
    download.add_argument("--index-db", default=".archipel/index.json")
    download.add_argument("--keys-dir", default=".keys")
    download.add_argument("--trust-db", default=".archipel/trust.json")
    receive = sub.add_parser("receive", help="List locally downloaded/shared files from index")
    receive.add_argument("--index-db", default=".archipel/index.json")
    status = sub.add_parser("status", help="Show node status summary")
    status.add_argument("--keys-dir", default=".keys")
    status.add_argument("--trust-db", default=".archipel/trust.json")
    status.add_argument("--index-db", default=".archipel/index.json")
    trust = sub.add_parser("trust", help="Approve a known peer in trust store")
    trust.add_argument("node_id", help="Peer node_id (64 hex)")
    trust.add_argument("--trust-db", default=".archipel/trust.json")
    web = sub.add_parser("web", help="Start local web interface for demo")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    if args.command == "keygen":
        identity = generate_node_identity(Path(args.out_dir), force=args.force)
        print("Node identity generated successfully.")
        print(f"Public key file : {identity['public_key_path']}")
        print(f"Private key file: {identity['private_key_path']}")
        print(f"Node ID (hex)   : {identity['node_id_hex']}")
        return 0
    if args.command == "start":
        return asyncio.run(run_start())
    if args.command == "peers":
        return run_peers()
    if args.command == "s2-server":
        return asyncio.run(run_s2_server(args.host, args.port, Path(args.keys_dir), Path(args.trust_db)))
    if args.command == "s2-send":
        return asyncio.run(run_s2_send(args.host, args.port, args.msg, Path(args.keys_dir), Path(args.trust_db)))
    if args.command == "s3-server":
        return asyncio.run(
            run_s3_server(
                args.host,
                args.port,
                Path(args.keys_dir),
                Path(args.trust_db),
                Path(args.file),
                int(args.chunk_size),
            )
        )
    if args.command == "s3-download":
        peers = _parse_peers(args.peer)
        return asyncio.run(
            run_s3_download(
                args.host,
                args.port,
                peers,
                Path(args.keys_dir),
                Path(args.trust_db),
                Path(args.out_dir),
                Path(args.index_db),
                int(args.parallel),
            )
        )
    if args.command == "msg":
        host, port = _parse_endpoint(args.endpoint)
        return asyncio.run(run_msg(host, port, args.message, Path(args.keys_dir), Path(args.trust_db), args.no_ai))
    if args.command == "ask":
        return run_ask(args.query, args.no_ai)
    if args.command == "send":
        return asyncio.run(
            run_s3_server(
                args.host,
                args.port,
                Path(args.keys_dir),
                Path(args.trust_db),
                Path(args.filepath),
                int(args.chunk_size),
            )
        )
    if args.command == "download":
        peers = _parse_peers(args.peer)
        return asyncio.run(
            run_s3_download(
                args.host,
                args.port,
                peers,
                Path(args.keys_dir),
                Path(args.trust_db),
                Path(args.out_dir),
                Path(args.index_db),
                int(args.parallel),
            )
        )
    if args.command == "receive":
        return run_receive(Path(args.index_db))
    if args.command == "status":
        return run_status(Path(args.keys_dir), Path(args.trust_db), Path(args.index_db))
    if args.command == "trust":
        return run_trust_approve(args.node_id, Path(args.trust_db))
    if args.command == "web":
        run_web_demo(args.host, args.port)
        return 0

    parser.print_help()
    return 1


async def run_start() -> int:
    cfg = load_config()
    node = Sprint1Node(
        node_id=str(cfg["node_id"]),
        tcp_port=int(cfg["tcp_port"]),
        udp_port=int(cfg["udp_port"]),
        multicast_addr=str(cfg["multicast_addr"]),
        hello_interval_ms=int(cfg["hello_interval_ms"]),
        peer_timeout_ms=int(cfg["peer_timeout_ms"]),
        storage_path=cfg["peer_store_path"],
    )
    await node.start()
    print("[archipel] sprint-1 node started")
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        await node.stop()
    return 0


def run_peers() -> int:
    cfg = load_config()
    table = PeerTable(timeout_ms=int(cfg["peer_timeout_ms"]), storage_path=cfg["peer_store_path"])
    peers = table.list()
    if not peers:
        print("No peers found in local persisted table.")
        return 0
    for p in peers:
        print(f"{p['node_id']}  {p['ip']}:{p['tcp_port']}  last_seen={p['last_seen']}")
    return 0


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    raw = endpoint.strip()
    if not raw:
        raise SystemExit("Invalid endpoint: empty value (expected host:port)")
    if "://" in raw:
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        if not parsed.hostname or not parsed.port:
            raise SystemExit(f"Invalid endpoint '{endpoint}' (expected host:port or http://host:port)")
        return parsed.hostname.strip(), int(parsed.port)
    if ":" not in raw:
        raise SystemExit(f"Invalid endpoint '{endpoint}' (expected host:port)")
    host, port_raw = raw.rsplit(":", 1)
    return host.strip(), int(port_raw.strip())


def _parse_peers(peer_args: list[str]) -> list[tuple[str, int]]:
    peers: list[tuple[str, int]] = []
    for p in peer_args:
        peers.append(_parse_endpoint(p))
    return peers


def _load_json_file(path: Path, default: dict) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def run_receive(index_db: Path) -> int:
    index = _load_json_file(index_db, {"files": {}})
    files = index.get("files", {})
    if not files:
        print("No local files found in index.")
        return 0
    for file_id, meta in files.items():
        print(f"{file_id}  {meta.get('filename')}  size={meta.get('size')}  chunks={meta.get('nb_chunks')}")
    return 0


def run_status(keys_dir: Path, trust_db: Path, index_db: Path) -> int:
    cfg = load_config()
    node_id = cfg["node_id"]
    if not node_id:
        try:
            from src.crypto.identity import load_identity

            node_id = load_identity(keys_dir).node_id_hex
        except Exception:
            node_id = "unknown"
    table = PeerTable(timeout_ms=int(cfg["peer_timeout_ms"]), storage_path=cfg["peer_store_path"])
    trust = _load_json_file(trust_db, {})
    index = _load_json_file(index_db, {"files": {}})
    print(f"node_id={node_id}")
    print(f"peers_known={len(table.list())}")
    print(f"trusted_peers={len(trust)}")
    print(f"local_files={len(index.get('files', {}))}")
    print(f"tcp_port={cfg['tcp_port']} udp_port={cfg['udp_port']}")
    return 0


def run_trust_approve(node_id: str, trust_db: Path) -> int:
    if len(node_id) != 64:
        raise SystemExit("node_id must be 64 hex chars")
    trust = _load_json_file(trust_db, {})
    entry = trust.get(node_id)
    if entry is None:
        print("Peer not found in trust store. Connect once first (TOFU), then approve.")
        return 1
    entry["trust"] = "approved"
    trust[node_id] = entry
    trust_db.parent.mkdir(parents=True, exist_ok=True)
    trust_db.write_text(json.dumps(trust, indent=2), encoding="utf-8")
    print(f"Peer approved: {node_id}")
    return 0


async def run_s2_server(host: str, port: int, keys_dir: Path, trust_db: Path) -> int:
    server = Sprint2SecureServer(host=host, port=port, keys_dir=keys_dir, trust_db=trust_db)
    await server.run()
    return 0


async def run_s2_send(host: str, port: int, msg: str, keys_dir: Path, trust_db: Path) -> int:
    client = Sprint2SecureClient(host=host, port=port, keys_dir=keys_dir, trust_db=trust_db)
    await client.send(msg)
    return 0


async def run_msg(host: str, port: int, message: str, keys_dir: Path, trust_db: Path, no_ai: bool) -> int:
    client = Sprint2SecureClient(host=host, port=port, keys_dir=keys_dir, trust_db=trust_db)
    await client.send(message)
    assistant = GeminiAssistant()
    assistant.append_history("user", message)
    if assistant.is_triggered(message):
        query = assistant.extract_query(message)
        if not query:
            print("[archipel-ai] Question vide après trigger (/ask ou @archipel-ai).")
            return 0
        ok, ai_text = assistant.query(query, no_ai=no_ai)
        if ok:
            assistant.append_history("assistant", ai_text)
            print(f"[archipel-ai] {ai_text}")
        else:
            print(f"[archipel-ai] {ai_text}")
    return 0


def run_ask(query: str, no_ai: bool) -> int:
    assistant = GeminiAssistant()
    assistant.append_history("user", query)
    ok, ai_text = assistant.query(query, no_ai=no_ai)
    if ok:
        assistant.append_history("assistant", ai_text)
        print(f"[archipel-ai] {ai_text}")
        return 0
    print(f"[archipel-ai] {ai_text}")
    return 0


async def run_s3_server(host: str, port: int, keys_dir: Path, trust_db: Path, file_path: Path, chunk_size: int) -> int:
    server = Sprint3FileServer(
        host=host,
        port=port,
        keys_dir=keys_dir,
        trust_db=trust_db,
        file_path=file_path,
        chunk_size=chunk_size,
    )
    await server.run()
    return 0


async def run_s3_download(
    host: str | None,
    port: int | None,
    peers: list[tuple[str, int]],
    keys_dir: Path,
    trust_db: Path,
    out_dir: Path,
    index_db: Path,
    parallel: int,
) -> int:
    downloader = Sprint3FileDownloader(
        host=host,
        port=port,
        peers=peers,
        keys_dir=keys_dir,
        trust_db=trust_db,
        out_dir=out_dir,
        index_db=index_db,
        parallelism=parallel,
    )
    await downloader.download()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
