from __future__ import annotations

import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.config import load_config
from src.crypto.identity import load_identity
from src.messaging.gemini_assistant import GeminiAssistant
from src.messaging.sprint2_secure_channel import Sprint2SecureClient
from src.network.peer_table import PeerTable


def _load_json_file(path: Path, default: dict) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _status(keys_dir: Path, trust_db: Path, index_db: Path) -> dict[str, Any]:
    cfg = load_config()
    node_id = cfg["node_id"]
    if not node_id:
        try:
            node_id = load_identity(keys_dir).node_id_hex
        except Exception:
            node_id = "unknown"
    table = PeerTable(timeout_ms=int(cfg["peer_timeout_ms"]), storage_path=cfg["peer_store_path"])
    trust = _load_json_file(trust_db, {})
    index = _load_json_file(index_db, {"files": {}})
    return {
        "node_id": node_id,
        "peers_known": len(table.list()),
        "trusted_peers": len(trust),
        "local_files": len(index.get("files", {})),
        "tcp_port": cfg["tcp_port"],
        "udp_port": cfg["udp_port"],
    }


def _peers() -> list[dict[str, Any]]:
    cfg = load_config()
    table = PeerTable(timeout_ms=int(cfg["peer_timeout_ms"]), storage_path=cfg["peer_store_path"])
    return table.list()


def _receive(index_db: Path) -> list[dict[str, Any]]:
    index = _load_json_file(index_db, {"files": {}})
    out: list[dict[str, Any]] = []
    for file_id, meta in index.get("files", {}).items():
        out.append(
            {
                "file_id": file_id,
                "filename": meta.get("filename"),
                "size": meta.get("size"),
                "chunks": meta.get("nb_chunks"),
            }
        )
    return out


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    raw = endpoint.strip()
    if not raw:
        raise ValueError("Endpoint vide (attendu host:port)")
    if "://" in raw:
        parsed = urlparse(raw)
        if not parsed.hostname or not parsed.port:
            raise ValueError("Endpoint invalide (attendu host:port ou http://host:port)")
        return parsed.hostname.strip(), int(parsed.port)
    if ":" not in raw:
        raise ValueError("Endpoint must be host:port")
    host, port_raw = raw.rsplit(":", 1)
    return host.strip(), int(port_raw.strip())


async def _send_msg(endpoint: str, message: str, keys_dir: Path, trust_db: Path, no_ai: bool) -> dict[str, Any]:
    host, port = _parse_endpoint(endpoint)
    client = Sprint2SecureClient(host=host, port=port, keys_dir=keys_dir, trust_db=trust_db)
    await client.send(message)
    result = {"sent": True}
    assistant = GeminiAssistant()
    assistant.append_history("user", message)
    if assistant.is_triggered(message):
        q = assistant.extract_query(message)
        ok, text = assistant.query(q, no_ai=no_ai)
        result["ai_ok"] = ok
        result["ai"] = text
        if ok:
            assistant.append_history("assistant", text)
    return result


def _ask(query: str, no_ai: bool) -> dict[str, Any]:
    assistant = GeminiAssistant()
    assistant.append_history("user", query)
    ok, text = assistant.query(query, no_ai=no_ai)
    if ok:
        assistant.append_history("assistant", text)
    return {"ok": ok, "answer": text}


def run_web_demo(host: str = "127.0.0.1", port: int = 8080) -> None:
    keys_dir = Path(".keys")
    trust_db = Path(".archipel/trust.json")
    index_db = Path(".archipel/index.json")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, html: str) -> None:
            raw = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> dict[str, Any]:
            size = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(size) if size > 0 else b"{}"
            return json.loads(raw.decode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/":
                self._send_html(_HTML)
                return
            if path == "/api/status":
                self._send(200, {"ok": True, "data": _status(keys_dir, trust_db, index_db)})
                return
            if path == "/api/peers":
                self._send(200, {"ok": True, "data": _peers()})
                return
            if path == "/api/receive":
                self._send(200, {"ok": True, "data": _receive(index_db)})
                return
            self._send(404, {"ok": False, "error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                body = self._read_json()
                if path == "/api/msg":
                    data = asyncio.run(
                        _send_msg(
                            endpoint=str(body.get("endpoint", "")),
                            message=str(body.get("message", "")),
                            keys_dir=keys_dir,
                            trust_db=trust_db,
                            no_ai=bool(body.get("no_ai", False)),
                        )
                    )
                    self._send(200, {"ok": True, "data": data})
                    return
                if path == "/api/ask":
                    data = _ask(str(body.get("query", "")), bool(body.get("no_ai", False)))
                    self._send(200, {"ok": True, "data": data})
                    return
                self._send(404, {"ok": False, "error": "Not found"})
            except Exception as exc:
                self._send(400, {"ok": False, "error": str(exc)})

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[web-demo] http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


_HTML = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Archipel Demo UI - devops-demons</title>
  <style>
    :root {
      --bg1: #f8f7f6;
      --bg2: #f2efed;
      --card: #ffffff;
      --ink: #23161a;
      --muted: #6b4b52;
      --brand: #7b1e3a;
      --brand-2: #a1294c;
      --stroke: #e4d8dc;
      --terminal: #2a1119;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "Trebuchet MS", "Gill Sans", sans-serif;
      background:
        radial-gradient(1100px 500px at 15% -10%, rgba(123,30,58,0.16), transparent 60%),
        radial-gradient(1000px 500px at 90% 0%, rgba(161,41,76,0.12), transparent 58%),
        linear-gradient(165deg, var(--bg1), var(--bg2));
      padding: 24px;
    }
    .shell {
      max-width: 1200px;
      margin: 0 auto;
      animation: reveal 340ms ease-out;
    }
    .hero {
      background: linear-gradient(120deg, rgba(255,255,255,0.98), rgba(251,247,248,0.98));
      border: 1px solid var(--stroke);
      border-radius: 16px;
      padding: 18px 20px;
      margin-bottom: 16px;
      box-shadow: 0 18px 40px rgba(2,6,23,0.45);
    }
    .title {
      margin: 0;
      font-family: "Impact", "Franklin Gothic Heavy", sans-serif;
      letter-spacing: 0.8px;
      font-size: 34px;
      line-height: 1;
    }
    .meta {
      margin-top: 8px;
      color: #7d5c63;
      font-size: 14px;
    }
    .badge {
      display: inline-block;
      border: 1px solid #cfb4bc;
      color: #fff7fa;
      background: #7b1e3a;
      border-radius: 999px;
      padding: 4px 10px;
      font-weight: 700;
      margin-left: 8px;
      font-size: 12px;
      vertical-align: middle;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--stroke);
      border-radius: 14px;
      padding: 14px;
      box-shadow: 0 6px 18px rgba(2,6,23,0.35);
    }
    .card h3 {
      margin: 0 0 8px;
      font-size: 18px;
    }
    .hint {
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 13px;
    }
    input, textarea, button {
      width: 100%;
      margin-top: 8px;
      padding: 10px 11px;
      border-radius: 10px;
      border: 1px solid #cfb4bc;
      font-size: 14px;
      font-family: "Trebuchet MS", "Gill Sans", sans-serif;
      background: #fffafa;
      color: #23161a;
    }
    textarea { resize: vertical; min-height: 84px; }
    button {
      border: 0;
      background: linear-gradient(120deg, var(--brand), var(--brand-2));
      color: #f8fbff;
      font-weight: 800;
      cursor: pointer;
      transition: transform .08s ease, filter .2s ease;
    }
    button:hover { filter: brightness(1.08); }
    button:active { transform: translateY(1px) scale(.995); }
    label {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      font-size: 13px;
      color: #6b4b52;
    }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      background: var(--terminal);
      color: #ffeef3;
      border: 1px solid #4f1627;
      padding: 10px;
      border-radius: 10px;
      min-height: 106px;
      margin-bottom: 0;
      font-family: "Consolas", "Lucida Console", monospace;
      font-size: 12px;
    }
    @media (max-width: 900px) {
      body { padding: 14px; }
      .grid { grid-template-columns: 1fr; }
      .title { font-size: 28px; }
    }
    @keyframes reveal {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <h1 class="title">ARCHIPEL CONTROL PANEL <span class="badge">devops-demons</span></h1>
      <p class="meta">Prototype P2P chiffré local • Sprint 1/2/3/4 • Interface web de démo</p>
    </section>

    <div class="grid">
      <section class="card">
        <h3>Status</h3>
        <p class="hint">État global du nœud actif.</p>
        <button onclick="apiGet('/api/status','out_status')">Refresh status</button>
        <pre id="out_status"></pre>
      </section>
      <section class="card">
        <h3>Peers</h3>
        <p class="hint">Pairs détectés par la couche Sprint 1.</p>
        <button onclick="apiGet('/api/peers','out_peers')">Refresh peers</button>
        <pre id="out_peers"></pre>
      </section>
      <section class="card">
        <h3>Secure Msg</h3>
        <p class="hint">Message Sprint 2 (E2E). Endpoint attendu: host:port.</p>
        <input id="msg_endpoint" placeholder="127.0.0.1:9001" />
        <textarea id="msg_text" rows="3" placeholder="Message, /ask ..., ou @archipel-ai ..."></textarea>
        <label><input id="msg_no_ai" type="checkbox" style="width:auto" /> no-ai</label>
        <button onclick="sendMsg()">Send secure message</button>
        <pre id="out_msg"></pre>
      </section>
      <section class="card">
        <h3>Ask AI</h3>
        <p class="hint">Question directe à l’assistant contextuel Gemini.</p>
        <textarea id="ask_text" rows="3" placeholder="Pose une question"></textarea>
        <label><input id="ask_no_ai" type="checkbox" style="width:auto" /> no-ai</label>
        <button onclick="askAi()">Ask assistant</button>
        <pre id="out_ask"></pre>
      </section>
      <section class="card">
        <h3>Receive</h3>
        <p class="hint">Fichiers locaux indexés (Sprint 3).</p>
        <button onclick="apiGet('/api/receive','out_recv')">List local files</button>
        <pre id="out_recv"></pre>
      </section>
    </div>
  </div>
  <script>
    async function apiGet(url, out) {
      const r = await fetch(url);
      const j = await r.json();
      document.getElementById(out).textContent = JSON.stringify(j, null, 2);
    }
    async function sendMsg() {
      const body = {
        endpoint: document.getElementById('msg_endpoint').value,
        message: document.getElementById('msg_text').value,
        no_ai: document.getElementById('msg_no_ai').checked
      };
      const r = await fetch('/api/msg', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      const j = await r.json();
      document.getElementById('out_msg').textContent = JSON.stringify(j, null, 2);
    }
    async function askAi() {
      const body = {
        query: document.getElementById('ask_text').value,
        no_ai: document.getElementById('ask_no_ai').checked
      };
      const r = await fetch('/api/ask', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      const j = await r.json();
      document.getElementById('out_ask').textContent = JSON.stringify(j, null, 2);
    }
  </script>
</body>
</html>
"""
