# FCK MULTI TOOL v1.3.0

**66 modules** · nouvelle catégorie Pentest & Offensive · animation d'ouverture refaite · 100 % gratuit · tout en français.

## Nouveautés

### 7 nouveaux modules (59 → 66)
- **Réseau (13) — Stress-Test** : test de charge multi-vecteurs (UDP-Flood, HTTP-GET, HTTP-POST, Slowloris, TCP-Connect, mixte), pool de threads adaptatif, stats en direct, confirmation d'autorisation obligatoire, vecteurs directs uniquement.
- **Crypto (54–55)** : Hash-Identifier (60+ signatures : bcrypt, argon2, scrypt, JWT, MD5, SHA…), Wordlist-Factory (mutations leet, casse, années/suffixes, combinatorio — export jusqu'à 500 000 lignes).
- **Pentest & Offensive (56–58) — nouvelle catégorie** : Shell-Generator (reverse/bind bash, Python, PowerShell, PHP, Ruby, Perl, nc/ncat/socat + listeners + msfvenom), Packet-Sniffer (scapy ou socket brut, filtres host/port, lecture seule), Code-Obfuscator (minify, chaînes base64, wrappers zlib/hex).
- **Système (66) — MAC-Changer** : lecture, vérification, MAC aléatoire, changement (Windows / Linux).

### Interface
- **Animation d'ouverture refaite** : boot coloré (lignes RGB, barre, hexadécimaux) puis bannière ASCII géante sur mesure en 4 frames de glitch, effet de frappe et barre de chargement.
- **Menu 10 pages** (66 modules), arbre `├─ [NN]`, transition glitch, prompt `camzzz@fckmt ~ [menu-N]$`.
- Titres de modules toujours rendus (repli automatique sur titre long).

## Installation

```bash
git clone https://github.com/cameleonnbss/Fck-Multi-Tool.git
cd Fck-Multi-Tool
python main.py            # Windows : double-cliquer sur start.bat
python main.py --selftest # 56 vérifications
```

Prérequis : Python 3.8+. Aucune dépendance obligatoire.

## Vérifié

- Selftest : 56/56 ✓
- Stress-Test validé en local (826 requêtes/s sur serveur de test, 0 erreur) ✓
- Sniffer : dégradation propre sans droits administrateur ✓
- Obfuscation : 4 modes produisent du code exécutable ✓

**Usage responsable** : audit uniquement sur des systèmes où vous êtes autorisé à intervenir — le Stress-Test exige une confirmation d'autorisation.

MIT — https://github.com/cameleonnbss/Fck-Multi-Tool
