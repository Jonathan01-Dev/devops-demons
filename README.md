# Archipel Hackathon - Sprint 0 + Sprint 1

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
