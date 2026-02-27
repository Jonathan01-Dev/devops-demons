import argparse
import asyncio
from pathlib import Path

from src.config import load_config
from src.crypto.keygen import generate_node_identity
from src.network.node import Sprint1Node
from src.network.peer_table import PeerTable


def main() -> int:
    parser = argparse.ArgumentParser(description="Archipel Hackathon - Sprint 0 / Sprint 1")
    sub = parser.add_subparsers(dest="command")

    keygen_parser = sub.add_parser("keygen", help="Generate Ed25519 node identity")
    keygen_parser.add_argument("--out-dir", default=".keys", help="Directory where keys are stored")
    keygen_parser.add_argument("--force", action="store_true", help="Overwrite existing key files")
    sub.add_parser("start", help="Start Sprint 1 P2P node")
    sub.add_parser("peers", help="Show persisted peer table")

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


if __name__ == "__main__":
    raise SystemExit(main())
