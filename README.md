# 🐯 FCK MULTI TOOL

<img src="assets/icon.png" width="120" alt="FCK MULTI TOOL">

**Suite multi-outils terminal — réseau, web, OSINT, crypto, pentest, système — 66 modules, un menu, zéro dépendance obligatoire.**

[![Release](https://img.shields.io/github/v/release/cameleonnbss/Fck-Multi-Tool?style=flat-square&color=ff3d57)](https://github.com/cameleonnbss/Fck-Multi-Tool/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Linux-0d1117?style=flat-square)](https://github.com/cameleonnbss/Fck-Multi-Tool)
[![Language](https://img.shields.io/badge/language-Python%203.8%2B-3572A5?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-3dd68c?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-66-ff3d57?style=flat-square)](#-les-66-modules)

**Menu paginé rouge** · **animation d'ouverture (boot coloré + bannière ASCII géante animée)** · **chaque module dans sa propre fenêtre** · **scanners réseau** · **audit de sécurité web** · **OSINT multi-plateformes** · **craquage de hash** · **pentest : shells, sniffer, obfuscation** · **100 % gratuit**

`Python 3.8+` · `Windows / Linux / macOS` · `aucune config requise` · `résultats sauvegardés dans output/`

[⬇️ **Télécharger v1.3.0**](https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.3.0) · [Démarrage rapide](#-démarrage-rapide) · [Les modules](#-les-66-modules) · [CLI](#-cli) · **Français**

---

## 🆕 Nouveautés en 1.3.0

- **7 nouveaux modules** (59 → 66) :
  - **Stress-Test (13)** : test de charge multi-vecteurs (UDP-Flood, HTTP-GET, HTTP-POST, Slowloris, TCP-Connect, mixte) avec pool de threads adaptatif, stats en direct et confirmation d'autorisation obligatoire.
  - **Hash-Identifier (54)** : type d'un hash par longueur, format et regex — 60+ signatures (bcrypt, argon2, scrypt, phpass, md5crypt, JWT, MD5, SHA…).
  - **Wordlist-Factory (55)** : mutations leet, casse, années/suffixes, combinatorio — jusqu'à 500 000 lignes exportées.
  - **Shell-Generator (56)** : commandes reverse/bind shell multi-plateformes (bash, Python, PowerShell, PHP, Ruby, Perl, nc/ncat/socat) + listeners + références msfvenom.
  - **Packet-Sniffer (57)** : capture locale (scapy si présent, sinon socket brut), filtres host/port — lecture seule, dégradation propre sans droits admin.
  - **Code-Obfuscator (58)** : minification, encodage base64 des chaînes, wrappers zlib/hex — source vérifiée (`compile`) avant écriture.
  - **MAC-Changer (66)** : lecture, vérification, MAC aléatoire, changement (Windows / Linux).
- **Nouvelle catégorie « PENTEST & OFFENSIVE »** (modules 56 → 58) — 6 catégories, 10 pages.
- **Animation d'ouverture refaite** : séquence de boot colorée (lignes système RGB, barre de progression, semis hexadécimaux), puis la bannière ASCII géante sur mesure (`assets/banner_big.txt`) en 4 frames de glitch, effet de frappe et barre de chargement des modules.
- **Menu en arbre** : ligne `├─ [NN]` par module, transition glitch entre les pages, prompt `camzzz@fckmt ~ [menu-N]$`.
- **Titres ASCII de modules** : repli automatique par coupure dure — un titre long est toujours rendu.
- **Selftest étendu** : 56 vérifications dont scaler adaptatif, payloads reverse shell, parseur IPv4, hashid, mutations leet, combinatorio, 4 modes d'obfuscation, validation MAC.

---

## 📦 Téléchargement

| Release | Lien |
|---------|------|
| **v1.3.0 (actuelle)** | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.3.0 |
| v1.2.0 | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.2.0 |
| v1.1.0 | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.1.0 |
| v1.0.0 | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.0.0 |
| Toutes les releases | https://github.com/cameleonnbss/Fck-Multi-Tool/releases |

---

## ⚡ Démarrage rapide

| Tu veux | Fais ceci |
|---------|-----------|
| **Tout installer** (Windows) | Double-clique sur `setup.bat` |
| **Lancer le tool** (Windows) | Double-clique sur `start.bat` (ouvre aussi GitHub) |
| **Installer** (Linux / macOS) | `./setup.sh` ou `python setup.py` |
| **Lancer** (Linux / macOS) | `./start.sh` |
| **Lancer à la main** | `python main.py` |
| **Lancer un module seul** | `python main.py --module 54` |
| **Vérifier que tout marche** | `python main.py --selftest` |

Prérequis : [Python 3.8+](https://www.python.org/downloads/) (avec `python` dans le PATH).
Les dépendances (`requests`, `colorama`) sont installées par le setup — le tool démarre aussi sans elles (repli automatique sur la bibliothèque standard).

---

## 🧰 Les 66 modules

### 🌐 Réseau & infra

| # | Module | Description |
|---|--------|-------------|
| 01 | Scanner-de-Ports | Scan TCP multi-threads, plages, récupération de bannière |
| 02 | Ping-Sweep | Hôtes actifs sur un sous-réseau (CIDR, 64 threads) |
| 03 | IP-Pinger | 4 paquets, latence min/avg/max, perte |
| 04 | IP-Lookup | Géolocalisation, FAI, ASN (ip-api) |
| 05 | Whois-Lookup | Registrar, dates, netrange avec suivi de referral |
| 06 | DNS-Recon | A/AAAA/MX/NS/TXT/CNAME/SOA + brute-force de sous-domaines |
| 07 | Traceroute | Chemin des paquets (tracert / traceroute / tracepath) |
| 08 | Proxy-Scraper | Collecte de 3 listes publiques + test de vivacité |
| 09 | Reseau-Local | Interfaces, IP locales, table ARP |
| 10 | CIDR-Calculator | Réseau, masque, wildcard, broadcast, plage d'hôtes |
| 11 | MAC-Vendor-Lookup | Fabricant (OUI) + table ARP du local |
| 12 | Trace-HTTP | Serveur de traçage local : journalise les métadonnées de vos propres liens (IP, navigateur, langue, referer) + dashboard. Aucune page de collecte de clés |
| 13 | Stress-Test | **NEW** Test de charge multi-vecteurs (UDP, HTTP GET/POST, Slowloris, TCP, mixte), threads adaptatifs, stats en direct — confirmation d'autorisation obligatoire |

### 🛡️ Web & sécurité web

| # | Module | Description |
|---|--------|-------------|
| 14 | Website-Info-Scanner | En-têtes de sécurité (score /7), technologies, robots.txt, sitemap |
| 15 | Website-Vuln-Scanner | Fichiers sensibles (.git, .env, dumps SQL…), directory listing, XSS reflet, SQLi par erreur |
| 16 | Website-Url-Scanner | Crawl des liens internes/externes, formulaires, e-mails de la page |
| 17 | SSL-Cert-Checker | Certificat, émetteur, SAN, jours restants, TLS, chiffrement |
| 18 | Google-Dorking | 18 dorks générés (filetype, inurl, intitle…) + ouverture navigateur |
| 19 | Directory-Brute | Découverte de chemins, baseline soft-404, wordlist intégrée ou fichier |
| 20 | CORS-Scanner | Test ACAO/ACAC avec origines malveillantes, verdict critique/alerte |
| 21 | Tech-Fingerprint | Détection CDN/WAF (Cloudflare, Akamai, Sucuri, Imperva, F5…), CMS, frameworks |
| 22 | Wayback-URL-History | URLs archivées via l'API CDX, extension breakdown, chemins sensibles |
| 23 | JWT-Analyzer | Header, claims, exp/iat, alg none, kid suspect, test de secrets courants |
| 24 | Cert-Transparency | Sous-domaines certifiés (crt.sh, 3 tentatives) + résolution DNS + CNAME suspendus (takeover) |
| 25 | Injection-Fuzzer | Fuzzing SQLi / XSS / traversal sur cible autorisée, signatures de preuves, abort sur 429 |
| 26 | URLScan-Search | Scans publics urlscan.io d'un domaine (titres, IPs, tags) |

### 🔍 OSINT & investigation

| # | Module | Description |
|---|--------|-------------|
| 27 | Username-Tracker | Pseudo vérifié sur 20+ plateformes (EXISTE / LIBRE / PROBABLE) |
| 28 | Email-Lookup | Syntaxe, MX, provider, jetable, empreinte Gravatar |
| 29 | Image-EXIF-Reader | Make/Model/date/GPS → lien Google Maps (parsé en pur Python) |
| 30 | Phone-Lookup | Indicatif pays (80+ pays), formats E.164 / national |
| 31 | Roblox-User-Info | Profil public, amis, avatar (API officielle) |
| 32 | Discord-Invite-Info | Serveur, membres en ligne, boosts (API publique) |
| 33 | Discord-Webhook-Info | Métadonnées d'un webhook — lecture seule, aucun envoi |
| 34 | Discord-Bot-Invite-To-Id | ID du bot et du serveur depuis une invitation |
| 35 | Shodan-InternetDB | Ports ouverts, hôtes, CVE d'une IP (gratuit, sans clé API) |
| 36 | Password-Breach-Check | k-anonymat HIBP — seul le préfixe SHA-1 part, jamais le mot de passe |
| 37 | Email-Header-Analyzer | Chaîne Received, IP d'origine, SPF/DKIM/DMARC |
| 38 | CVE-Lookup | Recherche NVD officielle NIST (ID CVE ou mot-clé), CVSS |
| 39 | Email-Accounts-Checker | Comptes potentiellement liés à un email (heuristique de pages de reset, 16 plateformes) |
| 40 | Email-Breach-Check | Fuites et pastes (XposedOrNot, sans clé API) |
| 41 | Instagram-OSINT | Profil public Instagram (nom, bio, abonnés, vérifié, privé) sans clé API |
| 42 | Dork-Builder | Dorks d'identité auto-générés (pseudo, email, nom) + liens Google/Bing/DuckDuckGo |
| 43 | Roblox-ID-Info | Fiche publique d'un asset ou d'une place Roblox (jeu, visites, créateur) |

### 🔐 Crypto & mots de passe

| # | Module | Description |
|---|--------|-------------|
| 44 | Hash-Generator | MD5, SHA1/224/256/384/512, BLAKE2, SHA3 — texte ou fichier |
| 45 | Hash-Cracker | Identification automatique + wordlist ou brute-force PIN |
| 46 | Zip-Cracker | Archive ZIP chiffrée ouverte par wordlist |
| 47 | Encodeur-Decodeur | Base64, Base32, Hex, URL, ROT13, binaire, inverse, Caesar |
| 48 | Password-Generator | `secrets` + entropie mesurée en bits |
| 49 | Passphrase-Generator | Phrases mémorisables (dictionnaire embarqué) + entropie |
| 50 | Password-Strength | Entropie corrigée, motifs faibles, temps de craquage estimé |
| 51 | TOTP-2FA-Generator | Codes RFC 6238, secret Base32, URI d'ajout, vérification |
| 52 | Stegano-PNG | Message caché dans un PNG (LSB, encode + decode, décodeur PNG pur Python avec tous les filtres) |
| 53 | BIP39-Generator | Seed phrase 12/24 mots, checksum, entropie, seed hex (vecteurs officiels BIP39/TREZOR en selftest) |
| 54 | Hash-Identifier | **NEW** Type d'un hash : longueur, format, regex — 60+ signatures (bcrypt, argon2, scrypt, phpass, JWT, MD5, SHA…) |
| 55 | Wordlist-Factory | **NEW** Mutations leet, casse, années/suffixes, combinatorio — export jusqu'à 500 000 lignes |

### ⚔️ Pentest & offensive

| # | Module | Description |
|---|--------|-------------|
| 56 | Shell-Generator | **NEW** Commandes reverse/bind shell (bash, Python, PowerShell, PHP, Ruby, Perl, nc/ncat/socat) + listeners + références msfvenom |
| 57 | Packet-Sniffer | **NEW** Capture de paquets locale (scapy ou socket brut), filtres host/port — lecture seule |
| 58 | Code-Obfuscator | **NEW** Minification, chaînes en base64, wrappers zlib/hex — `compile` vérifié avant écriture |

### 💻 Système & fichiers

| # | Module | Description |
|---|--------|-------------|
| 59 | System-Info | CPU, RAM, disques, uptime, IP publique |
| 60 | File-Analyzer | Type réel (magic bytes), MD5/SHA, entropie, hexdump |
| 61 | Local-Ports | Ports en écoute + processus et PID (netstat/tasklist) |
| 62 | Strings-Extractor | Chaînes ASCII/UTF-16, URLs, chemins, e-mails, IP |
| 63 | PE-Header-Parser | Machine, sections + entropie, imports, drapeaux ASLR/DEP |
| 64 | Local-Security-Audit | Defender, pare-feu, UAC, RDP, SMBv1, autoruns (lecture seule) |
| 65 | WiFi-Profils | Profils Wi-Fi enregistrés (clés comprises, `netsh`/`nmcli`) + réseaux visibles |
| 66 | MAC-Changer | **NEW** Adresse MAC de la machine : lecture, vérification, MAC aléatoire, changement (Windows / Linux) |

---

## 🎮 Menu

```
  ╔════════════════════════════════════════════════════════════════╗
  ║                         FCK MULTI TOOL                         ║
  ║     v1.3.0 · par camzzz (cameleonnbss) · 66 modules · MIT      ║
  ╚════════════════════════════════════════════════════════════════╝

  ┌────────────────────────────────────────────────────────────────┐
  │  RESEAU & INFRA  —  page 1/10                                  │
  ├────────────────────────────────────────────────────────────────┤
  │  ├─ [01] Scanner-de-Ports        Scan TCP multi-threads + banni│
  │  ├─ [02] Ping-Sweep              Hotes actifs sur un sous-resea│
  │  ├─ [03] IP-Pinger               Latence moyenne sur 4 paquets │
  │  ...                                                            │
  │  └─ [10] CIDR-Calculator         Sous-reseau, masque, broadcast│
  └────────────────────────────────────────────────────────────────┘

  [n] Page suivante   [p] Page precedente   [f] Execution : fenetre
  [c] Contact   [i] Infos   [q] Quitter

  camzzz@fckmt ~ [menu-1]$
```

- **un numéro** → ouvre le module (nouvelle fenêtre console sur Windows, `f` pour basculer en console unique)
- **n / p** → page suivante / précédente (10 modules max par page, transition glitch)
- **f** → mode d'exécution : `fenetre` / `local`
- **c** → ouvre la page GitHub (contact)
- **i** → boîte d'informations (avec grand titre ASCII)
- **q** → quitter

---

## 💻 CLI

```
python main.py                lancer avec animation
python main.py --no-anim      démarrage instantané
python main.py --module 54    lancer un module seul (numéro)
python main.py --module JWT-Analyzer    … ou par nom de module
python main.py --selftest     vérifier les modules puis quitter
python main.py --list         lister les 66 modules
python main.py --version      afficher la version
```

---

## 🏗️ Architecture

```
fck-multi-tool/
├── main.py                 # entrée : animation, menu, fenêtres, dispatch, selftest
├── setup.bat / setup.sh    # installation (pip + selftest)
├── start.bat / start.sh    # ouvre GitHub puis lance le tool
├── setup.py                # installeur cross-platform
├── fckmt/
│   ├── config.py           # nom, version, liens
│   ├── fonts.py            # fonte bloc 5 lignes → bannière + titres ASCII (avec repli)
│   ├── ui.py               # thème rouge, boîtes, spinners, tables, sauvegarde
│   ├── banner.py           # animation d'ouverture : boot RGB + bannière héro glitch
│   ├── net.py              # HTTP, DNS UDP brut, whois, TLS, IP locale
│   ├── registry.py         # catalogue des 66 modules, pagination
│   ├── data/
│   │   └── bip39_english.txt  # wordlist BIP39 officielle (2048 mots)
│   └── modules/
│       ├── network.py      # modules 01 → 09
│       ├── nettools.py     # modules 10 → 11
│       ├── tracenet.py     # module 12 (serveur de trace local)
│       ├── stress.py       # module 13 (test de charge)
│       ├── web.py          # modules 14 → 18
│       ├── websec.py       # modules 19 → 23
│       ├── webadv.py       # modules 24 → 26 (CT, fuzz, urlscan)
│       ├── osint.py        # modules 27 → 34
│       ├── intel.py        # modules 35 → 38
│       ├── osadv.py        # modules 39 → 43 (email, Instagram, dorks, Roblox)
│       ├── crypto.py       # modules 44 → 48
│       ├── pwtools.py      # modules 49 → 51
│       ├── cryptox.py      # modules 52 → 53 (stégano, BIP39)
│       ├── hashid.py       # module 54 (identification de hash)
│       ├── wordlist.py     # module 55 (génération de wordlists)
│       ├── shells.py       # module 56 (payloads reverse/bind)
│       ├── sniff.py        # module 57 (capture de paquets)
│       ├── obfusc.py       # module 58 (obfuscation Python)
│       ├── system.py       # modules 59 → 61
│       ├── sysaudit.py     # modules 62 → 64
│       └── sysadv.py       # modules 65 → 66 (WiFi, MAC)
├── tools/gen_icon.py       # régénère assets/icon.png + icon.ico
├── assets/banner.txt       # bannière de repli (fonte bloc)
├── assets/banner_big.txt   # bannière héro sur mesure (art ASCII du dépôt)
├── assets/icon.png/.ico    # icône du repo
├── output/                 # résultats sauvegardés (gitignoré)
└── .github/workflows/ci.yml  # selftest à chaque push
```

- **DNS en pur Python** : requêtes UDP directes (A, MX, NS, TXT…), aucun `dnspython`.
- **EXIF en pur Python** : parseur JPEG/TIFF/GPS complet, aucune dépendance.
- **PE en pur Python** : DOS/COFF/optional header, sections, table d'imports.
- **TOTP en pur Python** : HMAC-SHA1/256/512, testé contre le vecteur RFC 6238.
- **Obfuscation en pur Python** : `tokenize` + `zlib`, sortie vérifiée par `compile` avant écriture.
- **Zéro dépendance obligatoire** : `requests` et `colorama` sont repliés sur `urllib` / ANSI natif s'ils manquent.

---

## 🛡️ Usage responsable

Ces outils sont conçus pour l'**audit de sécurité que vous êtes autorisé à mener** : vos propres machines, vos serveurs, vos applications, vos cibles de bug bounty avec accord écrit. Scanner un système tiers sans autorisation est illégal dans la plupart des juridictions. Le **Stress-Test exige une confirmation écrite d'autorisation** avant de démarrer, et n'utilise que des vecteurs directs (pas d'amplification, pas de spoofing). Chaque module reste sous votre contrôle — aucun envoi automatique, aucun effet de bord caché, les résultats sont locaux dans `output/`.

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE).

**Si FCK MULTI TOOL vous est utile, une ⭐ sur le repo aide énormément.**

---

## 👤 Auteur

**camzzz** (alias **cameleonnbss**) — https://github.com/cameleonnbss

Issues et suggestions : https://github.com/cameleonnbss/Fck-Multi-Tool/issues
