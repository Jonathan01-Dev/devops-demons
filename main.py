import argparse
from pathlib import Path

from src.crypto.keygen import generate_node_identity


def main() -> int:
    parser = argparse.ArgumentParser(description="Archipel Hackathon - Sprint 0")
    sub = parser.add_subparsers(dest="command")

    keygen_parser = sub.add_parser("keygen", help="Generate Ed25519 node identity")
    keygen_parser.add_argument("--out-dir", default=".keys", help="Directory where keys are stored")
    keygen_parser.add_argument("--force", action="store_true", help="Overwrite existing key files")

    args = parser.parse_args()

    if args.command == "keygen":
        identity = generate_node_identity(Path(args.out_dir), force=args.force)
        print("Node identity generated successfully.")
        print(f"Public key file : {identity['public_key_path']}")
        print(f"Private key file: {identity['private_key_path']}")
        print(f"Node ID (hex)   : {identity['node_id_hex']}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
