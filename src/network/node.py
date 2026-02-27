from __future__ import annotations

import asyncio
import json
import secrets
import socket
import time

from .packet import TYPE_HELLO, build_packet, parse_packet
from .peer_table import PeerTable


def _short(node_id: str) -> str:
    return f"{node_id[:8]}..{node_id[-6:]}"


class Sprint1Node:
    def __init__(
        self,
        node_id: str,
        tcp_port: int,
        udp_port: int,
        multicast_addr: str,
        hello_interval_ms: int,
        peer_timeout_ms: int,
        storage_path,
    ) -> None:
        self.node_id = node_id or secrets.token_hex(32)
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.multicast_addr = multicast_addr
        self.hello_interval_ms = hello_interval_ms
        self.peer_table = PeerTable(timeout_ms=peer_timeout_ms, storage_path=storage_path)
        self.udp_sock: socket.socket | None = None
        self.tcp_server: asyncio.AbstractServer | None = None
        self.tasks: list[asyncio.Task] = []
        self.stopped = asyncio.Event()

    async def start(self) -> None:
        await self._start_tcp_server()
        await self._start_udp_socket()
        self.tasks.append(asyncio.create_task(self._udp_recv_loop()))
        self.tasks.append(asyncio.create_task(self._hello_loop()))
        self.tasks.append(asyncio.create_task(self._sweep_loop()))
        self._log_boot()

    async def stop(self) -> None:
        self.stopped.set()
        for t in self.tasks:
            t.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
        if self.udp_sock:
            self.udp_sock.close()

    async def _start_tcp_server(self) -> None:
        self.tcp_server = await asyncio.start_server(self._on_tcp_client, host="0.0.0.0", port=self.tcp_port)

    async def _on_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=2)
            if line.strip() == b"GET_PEERS":
                payload = {"peers": self.peer_table.serialize_for_wire()}
                writer.write((json.dumps(payload) + "\n").encode("utf-8"))
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _start_udp_socket(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", self.udp_port))
        mreq = socket.inet_aton(self.multicast_addr) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setblocking(False)
        self.udp_sock = sock

    async def _udp_recv_loop(self) -> None:
        assert self.udp_sock is not None
        loop = asyncio.get_running_loop()
        while not self.stopped.is_set():
            try:
                data, (ip, _port) = await loop.sock_recvfrom(self.udp_sock, 65535)
                pkt = parse_packet(data)
                if pkt["node_id"] == self.node_id:
                    continue
                if pkt["type"] == TYPE_HELLO:
                    tcp_port = int(pkt["payload"]["tcp_port"])
                    self.peer_table.upsert(pkt["node_id"], ip=ip, tcp_port=tcp_port)
                    print(f"[hello] peer={_short(pkt['node_id'])} ip={ip} tcp={tcp_port} peers={len(self.peer_table.list())}")
                    await self._request_peer_list(ip, tcp_port)
            except asyncio.CancelledError:
                break
            except Exception:
                continue

    async def _request_peer_list(self, host: str, port: int) -> None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
            writer.write(b"GET_PEERS\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=1.5)
            parsed = json.loads(line.decode("utf-8"))
            n = len(parsed.get("peers", []))
            print(f"[peer-list] exchanged with {host}:{port} known={n}")
            writer.close()
            await writer.wait_closed()
        except Exception:
            return

    async def _hello_loop(self) -> None:
        while not self.stopped.is_set():
            await self._send_hello()
            await asyncio.sleep(self.hello_interval_ms / 1000.0)

    async def _send_hello(self) -> None:
        assert self.udp_sock is not None
        pkt = build_packet(
            TYPE_HELLO,
            self.node_id,
            {"node_id": self.node_id, "tcp_port": self.tcp_port, "timestamp": int(time.time() * 1000)},
        )
        self.udp_sock.sendto(pkt, (self.multicast_addr, self.udp_port))
        # Fallback useful on Windows local tests if multicast is filtered.
        self.udp_sock.sendto(pkt, ("255.255.255.255", self.udp_port))
        self.udp_sock.sendto(pkt, ("127.0.0.1", self.udp_port))

    async def _sweep_loop(self) -> None:
        while not self.stopped.is_set():
            removed = self.peer_table.sweep()
            if removed:
                print(f"[peer-table] removed {removed} stale peer(s)")
            await asyncio.sleep(5)

    def _log_boot(self) -> None:
        print(f"[boot] node={self.node_id}")
        print(f"[boot] tcp={self.tcp_port} udp={self.udp_port} multicast={self.multicast_addr}")
        print(f"[boot] hello_interval={self.hello_interval_ms}ms timeout={self.peer_table.timeout_ms}ms")

