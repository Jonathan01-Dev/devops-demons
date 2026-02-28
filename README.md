# Archipel Hackathon - Sprint 0 + Sprint 1 + Sprint 2 + Sprint 3 + Sprint 4

## Sprint 0
- Structure de projet initiale
- Configuration `.env.example`
- Generateur de cles Ed25519 (`python main.py keygen`)

## Sprint 1 (objectif atteint dans ce repo)
Couche reseau P2P minimale:
- decouverte de pairs via UDP multicast `239.255.42.99:6000`
- emission `HELLO` periodique
- table de pairs persistante (`.archipel/peers-<port>.json`)
- serveur TCP local pour echange `PEER_LIST` (`GET_PEERS`)
- timeout des pairs inactifs

## Sprint 2 (MVP dans ce repo)
- handshake authentifie sans CA: `HELLO -> HELLO_REPLY(sig_B) -> AUTH(sig_A) -> AUTH_OK`
- identite noeud: Ed25519 (cles permanentes)
- echange de secret: X25519 (cles ephemeres par connexion)
- derivation de cle: HKDF-SHA256
- chiffrement message: AES-256-GCM
- trust model: TOFU (premier contact memorise, mismatch detecte)

## Sprint 3 (MVP dans ce repo)
- serveur de partage de fichier en chunks
- manifest signe (hash fichier + hash de chaque chunk)
- requete/reponse `CHUNK_REQ` / `CHUNK_DATA`
- verification SHA-256 de chaque chunk + verification signature fournisseur
- reassemblage du fichier et verification hash final
- index local des fichiers completes: `.archipel/index.json`

## Sprint 4 (CLI unifiee)
- commandes unifiees: `start`, `peers`, `msg`, `send`, `download`, `receive`, `status`, `trust`
- compatibilite maintenue avec commandes detaillees `s2-*` et `s3-*`
- assistant Gemini contextuel: trigger par `/ask` ou `@archipel-ai`
- mode offline strict: desactivation IA via `--no-ai`

## Commandes
Generer les cles (Sprint 0):
```bash
python main.py keygen --out-dir .keys
```

Demarrer un noeud Sprint 1:
```bash
python main.py start
```

Afficher la peer table locale:
```bash
python main.py peers
```

Serveur securise Sprint 2:
```bash
python main.py s2-server --host 0.0.0.0 --port 9001 --keys-dir .keys --trust-db .archipel/trust.json
```

Client securise Sprint 2:
```bash
python main.py s2-send --host <IP_SERVEUR> --port 9001 --msg "Hello chiffre" --keys-dir .keys --trust-db .archipel/trust.json
```

Serveur fichier Sprint 3:
```bash
python main.py s3-server --host 0.0.0.0 --port 9101 --file demo/sample.bin --keys-dir .keys-a --trust-db .archipel/trust-a.json
```

Telechargement fichier Sprint 3:
```bash
python main.py s3-download --host <IP_SERVEUR> --port 9101 --out-dir downloads --keys-dir .keys-b --trust-db .archipel/trust-b.json
```

Telechargement multi-sources Sprint 3:
```bash
python main.py s3-download --peer 192.168.1.10:9101 --peer 192.168.1.11:9101 --parallel 4 --out-dir downloads --keys-dir .keys-b --trust-db .archipel/trust-b.json
```

Message chiffre (CLI Sprint 4):
```bash
python main.py msg 192.168.1.10:9001 "Hello!"
```

Message + trigger IA (CLI Sprint 4):
```bash
python main.py msg 192.168.1.10:9001 "/ask comment optimiser le chunking?"
python main.py msg 192.168.1.10:9001 "@archipel-ai propose un plan de debug reseau"
```

Question IA locale (sans envoi pair):
```bash
python main.py ask "Comment tester la resilience en LAN?"
python main.py ask "Comment tester la resilience en LAN?" --no-ai
```

Partager un fichier (CLI Sprint 4):
```bash
python main.py send demo/sample.bin --host 0.0.0.0 --port 9101
```

Telecharger (CLI Sprint 4):
```bash
python main.py download --peer 192.168.1.10:9101 --peer 192.168.1.11:9101 --parallel 4
```

Lister les fichiers locaux (CLI Sprint 4):
```bash
python main.py receive
```

Etat du noeud (CLI Sprint 4):
```bash
python main.py status
```

Approuver un pair deja connu (CLI Sprint 4):
```bash
python main.py trust <node_id>
```

Interface Web de demo (Sprint 4):
```bash
python main.py web --host 127.0.0.1 --port 8080
```
Puis ouvrir `http://127.0.0.1:8080`.

Variable IA:
- `GEMINI_API_KEY` pour activer l'assistant.

## Variables `.env`
- `NODE_ID` (optionnel, 64 hex chars)
- `TCP_PORT` (defaut `7777`)
- `UDP_PORT` (defaut `6000`)
- `MULTICAST_ADDR` (defaut `239.255.42.99`)
- `HELLO_INTERVAL_MS` (defaut `30000`)
- `PEER_TIMEOUT_MS` (defaut `90000`)

## Test Sprint 1 (3 noeuds, meme machine)
Ouvrir 3 terminaux:

Terminal 1:
```powershell
$env:TCP_PORT='7777'; $env:HELLO_INTERVAL_MS='3000'; python main.py start
```

Terminal 2:
```powershell
$env:TCP_PORT='7778'; $env:HELLO_INTERVAL_MS='3000'; python main.py start
```

Terminal 3:
```powershell
$env:TCP_PORT='7779'; $env:HELLO_INTERVAL_MS='3000'; python main.py start
```

Attendu:
- chaque noeud voit les autres via logs `[hello]`
- `python main.py peers` montre des pairs persistes

## Structure
```text
devops-demons/
  README.md
  .env.example
  .gitignore
  main.py
  src/
    crypto/
    network/
    transfer/
    messaging/
    cli/
  tests/
  docs/
  demo/
```
