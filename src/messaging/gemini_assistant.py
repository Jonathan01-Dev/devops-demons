from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class GeminiAssistant:
    def __init__(
        self,
        api_key: str | None = None,
        history_path: Path = Path(".archipel/chat_history.jsonl"),
        model: str | None = None,
        max_context_messages: int = 8,
    ) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "") or self._read_key_from_env_file()
        self.history_path = history_path
        self.model = model or os.getenv("GEMINI_MODEL", "").strip() or "gemini-2.5-flash"
        self.max_context_messages = max_context_messages

    def _read_key_from_env_file(self) -> str:
        env_path = Path(".env")
        if not env_path.exists():
            return ""
        for line in env_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            if k.strip() == "GEMINI_API_KEY":
                return v.strip()
        return ""

    def append_history(self, role: str, text: str) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"role": role, "text": text}, ensure_ascii=False) + "\n")

    def load_recent_context(self) -> list[dict[str, str]]:
        if not self.history_path.exists():
            return []
        lines = self.history_path.read_text(encoding="utf-8").splitlines()
        out: list[dict[str, str]] = []
        for line in lines[-self.max_context_messages :]:
            try:
                parsed = json.loads(line)
                role = str(parsed.get("role", "user"))
                text = str(parsed.get("text", ""))
                if text:
                    out.append({"role": role, "text": text})
            except Exception:
                continue
        return out

    def is_triggered(self, message: str) -> bool:
        lowered = message.strip().lower()
        return lowered.startswith("/ask ") or "@archipel-ai" in lowered

    def extract_query(self, message: str) -> str:
        text = message.strip()
        if text.lower().startswith("/ask "):
            return text[5:].strip()
        return text.replace("@archipel-ai", "").replace("@ARCHIPEL-AI", "").strip()

    def query(self, user_query: str, no_ai: bool = False) -> tuple[bool, str]:
        if no_ai:
            return True, self._local_response(user_query, reason="Mode local (--no-ai)")
        if not self.api_key:
            return True, self._local_response(user_query, reason="Clé Gemini absente")

        context = self.load_recent_context()
        prompt = self._build_prompt(context, user_query)
        payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
        fallback_models = [self.model, "gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]
        tried: list[str] = []
        body: dict[str, Any] | None = None
        last_http_error: str | None = None
        for model_name in dict.fromkeys(fallback_models):
            tried.append(model_name)
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
                f"?key={self.api_key}"
            )
            req = urllib.request.Request(
                url=url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    break
            except urllib.error.HTTPError as exc:
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = ""
                last_http_error = f"HTTP {exc.code} ({err_body[:140]})"
                if exc.code == 404:
                    continue
                return True, self._local_response(user_query, reason=f"Gemini indisponible: {last_http_error}")
            except Exception as exc:
                return True, self._local_response(user_query, reason=f"Réseau/API indisponible: {exc}")

        if body is None:
            return True, self._local_response(
                user_query,
                reason=f"Aucun modèle Gemini valide ({', '.join(tried)})",
            )

        text = self._extract_text(body)
        if not text:
            return True, self._local_response(user_query, reason="Réponse Gemini vide")
        return True, text

    def _local_response(self, user_query: str, reason: str = "") -> str:
        q = user_query.strip()
        ql = q.lower()

        if "demo" in ql or "jury" in ql:
            body = (
                "Plan démo rapide:\n"
                "1) Sprint 1: lancer 2 noeuds et montrer `peers`.\n"
                "2) Sprint 2: envoyer un message chiffré et montrer ACK.\n"
                "3) Sprint 3: transférer un fichier et comparer SHA-256.\n"
                "4) Sprint 4: montrer l'UI web + ask IA."
            )
        elif "wireshark" in ql or "chiffr" in ql:
            body = (
                "Pour prouver le chiffrement:\n"
                "1) Filtre `tcp.port == 9001 || tcp.port == 9101`.\n"
                "2) Vérifier que le plaintext n'apparaît pas.\n"
                "3) Montrer nonce/ciphertext et ACK applicatif."
            )
        elif "test" in ql:
            body = (
                "Checklist test:\n"
                "1) Discovery: 2 noeuds visibles.\n"
                "2) Message E2E: ACK OK.\n"
                "3) Fichier: hash source == hash destination.\n"
                "4) Offline IA: `--no-ai` sans crash."
            )
        else:
            body = (
                "Réponse locale:\n"
                f"- Question reçue: {q or '(vide)'}\n"
                "- Recommandation: donne le contexte (sprint, machine, commande, erreur) "
                "pour une réponse plus précise."
            )

        if reason:
            return f"[Mode IA local] {reason}\n\n{body}"
        return body

    def _build_prompt(self, context: list[dict[str, str]], user_query: str) -> str:
        lines: list[str] = [
            "Tu es Archipel-AI, assistant technique pour un protocole P2P chiffré local.",
            "Réponds de manière concise et actionnable.",
            "",
            "Contexte récent:",
        ]
        for item in context:
            lines.append(f"- {item['role']}: {item['text']}")
        lines.append("")
        lines.append(f"Question utilisateur: {user_query}")
        return "\n".join(lines)

    def _extract_text(self, body: dict[str, Any]) -> str:
        try:
            return (
                body.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
                .strip()
            )
        except Exception:
            return ""
