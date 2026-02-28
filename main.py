import argparse
import asyncio
from pathlib import Path

from src.config import load_config
from src.crypto.keygen import generate_node_identity
from src.messaging.sprint2_secure_channel import Sprint2SecureClient, Sprint2SecureServer
from src.network.node import Sprint1Node
from src.network.peer_table import PeerTable
from src.transfer.sprint3_file_transfer import Sprint3FileDownloader, Sprint3FileServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Archipel Hackathon - Sprint 0 / Sprint 1")
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
        peers: list[tuple[str, int]] = []
        for p in args.peer:
            if ":" not in p:
                raise SystemExit(f"Invalid --peer value '{p}' (expected host:port)")
            host, port_raw = p.rsplit(":", 1)
            peers.append((host, int(port_raw)))
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


async def run_s2_server(host: str, port: int, keys_dir: Path, trust_db: Path) -> int:
    server = Sprint2SecureServer(host=host, port=port, keys_dir=keys_dir, trust_db=trust_db)
    await server.run()
    return 0


async def run_s2_send(host: str, port: int, msg: str, keys_dir: Path, trust_db: Path) -> int:
    client = Sprint2SecureClient(host=host, port=port, keys_dir=keys_dir, trust_db=trust_db)
    await client.send(msg)
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
