# Changelog

Toutes les notable changes à FCK MULTI TOOL sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/).

## [1.3.0] — 2026-09-29

### Ajouté

- **7 nouveaux modules** (59 → 66) :
  - Réseau (13) : Stress-Test — test de charge multi-vecteurs (UDP-Flood, HTTP-GET, HTTP-POST, Slowloris, TCP-Connect, mixte), pool de threads adaptatif (`AdaptiveScaler`), stats en direct, confirmation d'autorisation obligatoire, vecteurs directs uniquement.
  - Crypto (54–55) : Hash-Identifier (60+ signatures : bcrypt, argon2, scrypt, phpass, md5crypt/sha256crypt/sha512crypt, JWT, MD5, SHA…), Wordlist-Factory (mutations leet par produit cartésien, casse, années/suffixes, combinatorio, plafond 500 000 lignes).
  - **Nouvelle catégorie « PENTEST & OFFENSIVE » (56–58)** : Shell-Generator (reverse/bind bash, Python, PowerShell, PHP, Ruby, Perl, nc/ncat/socat + listeners + références msfvenom), Packet-Sniffer (scapy si présent, sinon socket brut avec `select`, filtres host/port, capture locale en lecture seule), Code-Obfuscator (minification par `tokenize`, chaînes en base64, wrappers zlib/hex — sortie vérifiée par `compile` avant écriture).
  - Système (66) : MAC-Changer (validation, MAC aléatoire, changement `netsh` / `ip link` / `ipconfig`).
- **Animation d'ouverture refaite** (`banner.py`) : phase de boot colorée (lignes système en RGB, barre de progression, semis hexadécimaux), puis bannière héro (`assets/banner_big.txt`, art sur mesure du dépôt) en 4 frames de glitch → net, effet de frappe sur la ligne d'auteur, barre de chargement des modules, surlignage glitch final.
- **Menu en arbre** : lignes `├─ [NN]`, transition glitch entre les pages, prompt `camzzz@fckmt ~ [menu-N]$`.
- **Repli `pack_title`** (`fonts.py`) : coupure dure par paquets de 14 caractères — un titre de module trop long est toujours rendu en art ASCII (plus jamais de titre vide).
- **Selftest étendu** : 56 vérifications, dont scaler adaptatif, payloads reverse shell, parseur IPv4, identification de hash, mutations leet, combinatorio, 4 modes d'obfuscation, normalisation MAC.

### Changé

- Renumbering complet en 1..66 par catégorie : Réseau/Web/OSINT/Crypto inchangés en tête, nouveau module 13 (Stress-Test), web/websec/webadv/osint/intel/osadv/crypto/pwtools/cryptox +1, system/sysaudit/sysadv +6.
- 6 catégories, 10 pages de menu (contre 8 en 1.2.0).
- README, badges, menu et `USER_AGENT` à jour pour 66 modules — version 1.3.0.

## [1.2.0] — 2026-09-28

### Ajouté

- **12 nouveaux modules** (47 → 59) :
  - Réseau (12) : Trace-HTTP — serveur de traçage local (journal JSONL, dashboard, ip-api, tunnel cloudflared indicatif), métadonnées visiteurs uniquement, aucune page de collecte de clés.
  - Web (23–25) : Cert-Transparency (crt.sh avec 3 tentatives + résolution DNS + CNAME suspendus / takeover), Injection-Fuzzer (SQLi/XSS/traversal sur cible autorisée, abort sur 429), URLScan-Search (scans publics urlscan.io).
  - OSINT (38–42) : Email-Accounts-Checker (heuristique pages de reset, 16 plateformes), Email-Breach-Check (XposedOrNot sans clé), Instagram-OSINT (profil public sans clé API), Dork-Builder (dorks d'identité auto-générés), Roblox-ID-Info (fiche asset / place).
  - Crypto (51–52) : Stegano-PNG (masquage/extraction LSB, décodeur PNG pur Python filtres 0–4), BIP39-Generator (12/24 mots, checksum, seed hex — vecteurs officiels BIP39 et TREZOR).
  - Système (59) : WiFi-Profils (`netsh`/`nmcli` — profils enregistrés avec clés + réseaux visibles).
- **Bannière géante ANSI Shadow** : `assets/banner_big.txt` (13 × 65) affichée en 4 frames (glitch 55 % → 30 % → 14 % → net), garde terminal ≥ 66×24, repli sur la fonte bloc.
- **Wordlist BIP39 embarquée** : `fckmt/data/bip39_english.txt` (2048 mots, source officielle).
- **Nouveaux fichiers modules** : `tracenet.py`, `webadv.py`, `osadv.py`, `cryptox.py`, `sysadv.py`.
- **`start.bat` / `start.sh`** : ouvrent aussi le profil GitHub de l'auteur, en plus du repo.
- **Selftest étendu** : 44 vérifications, dont roundtrip stégano, seed BIP39 zéro + vecteur TREZOR, payloads de fuzzing, services de takeover, sites de reset email.

### Changé

- Renumbering des modules : anciens 12–21 → 13–22, 22–33 → 26–37, 34–41 → 43–50, 42–47 → 53–58.
- README, badges, menu (8 pages) et `USER_AGENT` à jour pour 59 modules — version 1.2.0.

## [1.1.0] — 2026-09-28

### Ajouté

- **17 nouveaux modules** (30 → 47) :
  - Réseau (10–11) : CIDR calculator, MAC vendor lookup (base OUI locale + table ARP).
  - Web (17–21) : directory brute avec baseline soft-404, CORS scanner (ACAO/ACAC), fingerprint CDN/WAF/CMS, historique Wayback (API CDX), analyseur JWT (claims, alg none, test de secrets courants).
  - OSINT (30–33) : Shodan InternetDB (sans clé), vérification de fuite HIBP en k-anonymat, analyseur d'en-tête email (Received, SPF/DKIM/DMARC), recherche CVE (NVD/NIST).
  - Crypto (39–41) : générateur de passphrase, analyse de robustesse de mot de passe (entropie corrigée, motifs, temps de craquage), TOTP RFC 6238 (générer/utiliser/vérifier).
  - Système (45–47) : extracteur de strings (ASCII/UTF-16), parser d'en-têtes PE (sections, entropie, imports, ASLR/DEP), audit de sécurité local en lecture seule (Defender, pare-feu, UAC, RDP, SMBv1).
- **Exécution en fenêtre dédiée** : chaque module choisi dans le menu s'ouvre dans sa propre console Windows (`start` + `--module N`), avec bascule `f` fenêtre/console unique.
- **CLI `--module N`** : lancer un module seul par numéro ou par nom (`--module JWT-Analyzer`).
- **Thème rouge** complet : bannière, boîtes, spinners, barres de progression, prompt.
- **Fonte bloc embarquée** (`fckmt/fonts.py`) : bannière FCK MULTI TOOL et grands titres ASCII de chaque module générés et alignés automatiquement.
- **Icônes du repo** : `assets/icon.png` (256px) + `assets/icon.ico` (16/32/48/256), générés par `tools/gen_icon.py` en pur Python.
- **Menu paginé par tranches de 10** modules, 7 pages au total.
- **Selftest étendu** : 37 vérifications, dont vecteur TOTP RFC 6238, décodage JWT, calcul CIDR, parse PE de `python.exe`.

### Changé

- Renumbering des modules : les anciens 10–30 sont décalés (10→12 … 30→44).
- README, badges et menu à jour pour 47 modules.

## [1.0.0] — 2026-09-28

### Ajouté

- **Animation d'ouverture** : bannière ASCII affichée ligne par ligne, cycle de couleurs, glitch et barre de chargement.
- **Menu paginé « push »** : 5 pages par catégorie, navigation `n`/`p`, contact `c`, infos `i`, sortie `q`.
- **30 modules** répartis en 5 catégories :
  - Réseau (01–09) : scan de ports avec bannière, ping sweep, pinger, IP lookup, whois, DNS recon + brute-force, traceroute, proxy scraper, réseau local.
  - Web (10–14) : info scanner avec score de sécurité, vuln scanner (fichiers sensibles, XSS reflet, SQLi par erreur), URL scanner, SSL cert checker, Google dorking.
  - OSINT (15–22) : username tracker, email lookup, EXIF/GPS, phone lookup, Roblox, Discord (invite, webhook, bot ID).
  - Crypto (23–27) : hash generator, hash cracker, zip cracker, encodeur/décodeur, password generator.
  - Système (28–30) : system info, file analyzer (magic/hashs/entropie), local ports.
- **Lanceurs** : `setup.bat`, `start.bat`, `setup.sh`, `start.sh`, `setup.py` — `start` ouvre la page GitHub puis lance le tool.
- **Sauvegarde automatique** dans `output/` pour chaque module produisant un résultat.
- **Selftest** : `python main.py --selftest` — 20 vérifications fonctionnelles (registre, parseurs, scan local, hashs, réseau).
- **CI GitHub Actions** : selftest sur Windows et Ubuntu à chaque push.
- **README FR** complet, licence MIT, `.gitignore`.
