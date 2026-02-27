# Archipel Hackathon - Sprint 0

## 1. Description du projet
Archipel est un protocole P2P chiffré et décentralisé qui doit fonctionner en réseau local sans serveur central.
Ce dépôt couvre le Sprint 0 : cadrage technique, structure du projet, configuration, et génération d'identité cryptographique des nœuds.

## 2. Membres de l'équipe
- A compléter
- A completer
- A completer

## 3. Architecture cible (vue Sprint 0)
```text
+-------------------+          +-------------------+          +-------------------+
| Node A            | <------> | Node B            | <------> | Node C            |
| client + serveur  |          | client + serveur  |          | client + serveur  |
| Ed25519 identity  |          | Ed25519 identity  |          | Ed25519 identity  |
+-------------------+          +-------------------+          +-------------------+
        ^                                 ^                               ^
        |                                 |                               |
        +-------- UDP multicast (HELLO/discovery) +-----------------------+
                          TCP (data/messages/chunks)
```

## 4. Choix techniques
- Langage: Python 3
  - Rapide pour prototypage hackathon
  - Bonne lisibilité pour équipe multi-niveaux
  - Ecosystème crypto/réseau mature
- Structure modulaire:
  - `src/crypto` pour identités, signatures, chiffrement
  - `src/network` pour découverte/routage
  - `src/transfer` pour chunking/transfert de fichiers
  - `src/messaging` pour messages chiffrés
  - `src/cli` pour interface terminal

## 5. Livrables Sprint 0
- Structure de dépôt créée
- Fichier `.env.example` créé
- Fichier `.gitignore` créé
- Générateur de clés Ed25519 implémenté

## 6. Génération d'identité du nœud
Commande:
```bash
python main.py keygen --out-dir .keys
```

Fichiers produits:
- `.keys/node_private.key` (secret, jamais versionné)
- `.keys/node_public.key` (partageable)

Affichage terminal:
- Chemin des fichiers
- Node ID (hex)

## 7. Lancement du projet
1. Copier `.env.example` vers `.env`
2. Adapter les ports/adresses selon la machine
3. Générer les clés:
```bash
python main.py keygen --out-dir .keys
```

## 8. Structure du dépôt
```text
archipel-hackathon/
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

## 9. Sécurité minimale Sprint 0
- Ne jamais commiter `.env` et les clés privées
- Régénérer les clés si compromission
- Utiliser des variables d'environnement pour la configuration sensible
