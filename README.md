# 🐯 FCK MULTI TOOL

<img src="assets/icon.png" width="120" alt="FCK MULTI TOOL">

**Suite multi-outils terminal — réseau, web, OSINT, crypto, système — 59 modules, un menu, zéro dépendance obligatoire.**

[![Release](https://img.shields.io/github/v/release/cameleonnbss/Fck-Multi-Tool?style=flat-square&color=ff3d57)](https://github.com/cameleonnbss/Fck-Multi-Tool/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Linux-0d1117?style=flat-square)](https://github.com/cameleonnbss/Fck-Multi-Tool)
[![Language](https://img.shields.io/badge/language-Python%203.8%2B-3572A5?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-3dd68c?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-59-ff3d57?style=flat-square)](#-les-59-modules)

**Menu paginé rouge** · **bannière géante ANSI Shadow animée (4 frames de glitch)** · **chaque module dans sa propre fenêtre** · **scanners réseau** · **audit de sécurité web** · **OSINT multi-plateformes** · **craquage de hash** · **encodeurs** · **analyse de fichiers** · **100 % gratuit**

`Python 3.8+` · `Windows / Linux / macOS` · `aucune config requise` · `résultats sauvegardés dans output/`

[⬇️ **Télécharger v1.2.0**](https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.2.0) · [Démarrage rapide](#-démarrage-rapide) · [Les modules](#-les-59-modules) · [CLI](#-cli) · **Français**

---

## 🆕 Nouveautés en 1.2.0

- **12 nouveaux modules** (47 → 59) : Trace-HTTP (serveur de traçage local, métadonnées uniquement), Cert-Transparency (sous-domaines crt.sh + détection de CNAME suspendus), Injection-Fuzzer (SQLi/XSS/traversal sur cible autorisée), URLScan-Search (scans publics urlscan.io), Email-Accounts-Checker, Email-Breach-Check (XposedOrNot), Instagram-OSINT (profil public sans clé API), Dork-Builder (dorks d'identité auto-générés), Roblox-ID-Info (fiche asset/place), Stegano-PNG (masquage/extraction LSB), BIP39-Generator (seed 12/24 mots + seed hex, vecteurs officiels), WiFi-Profils (profils Wi-Fi de la machine + clés, netsh/nmcli).
- **Bannière géante ANSI Shadow** : `assets/banner_big.txt` (13 lignes × 65 colonnes) s'affiche en 4 frames de glitch rouge → blanc → rouge → net, avec garde de taille de terminal et repli sur la fonte bloc.
- **Wordlist BIP39 embarquée** : `fckmt/data/bip39_english.txt` (2048 mots) — checksum + test vecteur TREZOR vérifiés en selftest.
- **Nouvelles sources OSINT** : `fckmt/modules/tracenet.py`, `webadv.py`, `osadv.py`, `cryptox.py`, `sysadv.py`.
- **Selftest étendu** : 44 vérifications dont roundtrip stégano, seed BIP39, payloads de fuzzing, services de takeover et sites de reset email.

---

## 📦 Téléchargement

| Release | Lien |
|---------|------|
| **v1.2.0 (actuelle)** | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.2.0 |
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
| **Lancer un module seul** | `python main.py --module 13` |
| **Vérifier que tout marche** | `python main.py --selftest` |

Prérequis : [Python 3.8+](https://www.python.org/downloads/) (avec `python` dans le PATH).
Les dépendances (`requests`, `colorama`) sont installées par le setup — le tool démarre aussi sans elles (repli automatique sur la bibliothèque standard).

---

## 🧰 Les 59 modules

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
| 12 | Trace-HTTP | **NEW** Serveur de traçage local : journalise les métadonnées de vos propres liens (IP, navigateur, langue, referer) + dashboard. Aucune page de collecte de clés |

### 🛡️ Web & sécurité web

| # | Module | Description |
|---|--------|-------------|
| 13 | Website-Info-Scanner | En-têtes de sécurité (score /7), technologies, robots.txt, sitemap |
| 14 | Website-Vuln-Scanner | Fichiers sensibles (.git, .env, dumps SQL…), directory listing, XSS reflet, SQLi par erreur |
| 15 | Website-Url-Scanner | Crawl des liens internes/externes, formulaires, e-mails de la page |
| 16 | SSL-Cert-Checker | Certificat, émetteur, SAN, jours restants, TLS, chiffrement |
| 17 | Google-Dorking | 18 dorks générés (filetype, inurl, intitle…) + ouverture navigateur |
| 18 | Directory-Brute | Découverte de chemins, baseline soft-404, wordlist intégrée ou fichier |
| 19 | CORS-Scanner | Test ACAO/ACAC avec origines malveillantes, verdict critique/alerte |
| 20 | Tech-Fingerprint | Détection CDN/WAF (Cloudflare, Akamai, Sucuri, Imperva, F5…), CMS, frameworks |
| 21 | Wayback-URL-History | URLs archivées via l'API CDX, extension breakdown, chemins sensibles |
| 22 | JWT-Analyzer | Header, claims, exp/iat, alg none, kid suspect, test de secrets courants |
| 23 | Cert-Transparency | **NEW** Sous-domaines certifiés (crt.sh, 3 tentatives) + résolution DNS + CNAME suspendus (takeover) |
| 24 | Injection-Fuzzer | **NEW** Fuzzing SQLi / XSS / traversal sur cible autorisée, signatures de preuves, abort sur 429 |
| 25 | URLScan-Search | **NEW** Scans publics urlscan.io d'un domaine (titres, IPs, tags) |

### 🔍 OSINT & investigation

| # | Module | Description |
|---|--------|-------------|
| 26 | Username-Tracker | Pseudo vérifié sur 20+ plateformes (EXISTE / LIBRE / PROBABLE) |
| 27 | Email-Lookup | Syntaxe, MX, provider, jetable, empreinte Gravatar |
| 28 | Image-EXIF-Reader | Make/Model/date/GPS → lien Google Maps (parsé en pur Python) |
| 29 | Phone-Lookup | Indicatif pays (80+ pays), formats E.164 / national |
| 30 | Roblox-User-Info | Profil public, amis, avatar (API officielle) |
| 31 | Discord-Invite-Info | Serveur, membres en ligne, boosts (API publique) |
| 32 | Discord-Webhook-Info | Métadonnées d'un webhook — lecture seule, aucun envoi |
| 33 | Discord-Bot-Invite-To-Id | ID du bot et du serveur depuis une invitation |
| 34 | Shodan-InternetDB | Ports ouverts, hôtes, CVE d'une IP (gratuit, sans clé API) |
| 35 | Password-Breach-Check | k-anonymat HIBP — seul le préfixe SHA-1 part, jamais le mot de passe |
| 36 | Email-Header-Analyzer | Chaîne Received, IP d'origine, SPF/DKIM/DMARC |
| 37 | CVE-Lookup | Recherche NVD officielle NIST (ID CVE ou mot-clé), CVSS |
| 38 | Email-Accounts-Checker | **NEW** Comptes potentiellement liés à un email (heuristique de pages de reset, 16 plateformes) |
| 39 | Email-Breach-Check | **NEW** Fuites et pastes (XposedOrNot, sans clé API) |
| 40 | Instagram-OSINT | **NEW** Profil public Instagram (nom, bio, abonnés, vérifié, privé) sans clé API |
| 41 | Dork-Builder | **NEW** Dorks d'identité auto-générés (pseudo, email, nom) + liens Google/Bing/DuckDuckGo |
| 42 | Roblox-ID-Info | **NEW** Fiche publique d'un asset ou d'une place Roblox (jeu, visites, créateur) |

### 🔐 Crypto & mots de passe

| # | Module | Description |
|---|--------|-------------|
| 43 | Hash-Generator | MD5, SHA1/224/256/384/512, BLAKE2, SHA3 — texte ou fichier |
| 44 | Hash-Cracker | Identification automatique + wordlist ou brute-force PIN |
| 45 | Zip-Cracker | Archive ZIP chiffrée ouverte par wordlist |
| 46 | Encodeur-Decodeur | Base64, Base32, Hex, URL, ROT13, binaire, inverse, Caesar |
| 47 | Password-Generator | `secrets` + entropie mesurée en bits |
| 48 | Passphrase-Generator | Phrases mémorisables (dictionnaire embarqué) + entropie |
| 49 | Password-Strength | Entropie corrigée, motifs faibles, temps de craquage estimé |
| 50 | TOTP-2FA-Generator | Codes RFC 6238, secret Base32, URI d'ajout, vérification |
| 51 | Stegano-PNG | **NEW** Message caché dans un PNG (LSB, encode + decode, décodeur PNG pur Python avec tous les filtres) |
| 52 | BIP39-Generator | **NEW** Seed phrase 12/24 mots, checksum, entropie, seed hex (vecteurs officiels BIP39/TREZOR en selftest) |

### 💻 Système & fichiers

| # | Module | Description |
|---|--------|-------------|
| 53 | System-Info | CPU, RAM, disques, uptime, IP publique |
| 54 | File-Analyzer | Type réel (magic bytes), MD5/SHA, entropie, hexdump |
| 55 | Local-Ports | Ports en écoute + processus et PID (netstat/tasklist) |
| 56 | Strings-Extractor | Chaînes ASCII/UTF-16, URLs, chemins, e-mails, IP |
| 57 | PE-Header-Parser | Machine, sections + entropie, imports, drapeaux ASLR/DEP |
| 58 | Local-Security-Audit | Defender, pare-feu, UAC, RDP, SMBv1, autoruns (lecture seule) |
| 59 | WiFi-Profils | **NEW** Profils Wi-Fi enregistrés (clés comprises, `netsh`/`nmcli`) + réseaux visibles |

---

## 🎮 Menu

```
  ╔══════════════════════════════════════════════════════════╗
  ║                     FCK MULTI TOOL                       ║
  ║    v1.2.0 · par camzzz (cameleonnbss) · 59 modules · MIT  ║
  ╚══════════════════════════════════════════════════════════╝

  ┌────────────────────────────────────────────────────────────┐
  │  WEB & SECURITE WEB  —  page 3/8                           │
  ├────────────────────────────────────────────────────────────┤
  │  [13] Website-Info-Scanner    En-tetes, tech, robots       │
  │  [14] Website-Vuln-Scanner    Fichiers sensibles, SQLi     │
  │  ...                                                       │
  └────────────────────────────────────────────────────────────┘

  [n] Page suivante   [p] Page precedente   [f] Execution : fenetre
  [c] Contact   [i] Infos   [q] Quitter
```

- **un numéro** → ouvre le module (nouvelle fenêtre console sur Windows, `f` pour basculer en console unique)
- **n / p** → page suivante / précédente (10 modules max par page)
- **f** → mode d'exécution : `fenetre` / `local`
- **c** → ouvre la page GitHub (contact)
- **i** → boîte d'informations (avec grand titre ASCII)
- **q** → quitter

---

## 💻 CLI

```
python main.py                lancer avec animation
python main.py --no-anim      démarrage instantané
python main.py --module 13    lancer un module seul (numéro)
python main.py --module JWT-Analyzer    … ou par nom de module
python main.py --selftest     vérifier les modules puis quitter
python main.py --list         lister les 59 modules
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
│   ├── fonts.py            # fonte bloc 5 lignes → bannière + titres ASCII
│   ├── ui.py               # thème rouge, boîtes, spinners, tables, sauvegarde
│   ├── banner.py           # bannière géante ANSI Shadow + animation glitch 4 frames
│   ├── net.py              # HTTP, DNS UDP brut, whois, TLS, IP locale
│   ├── registry.py         # catalogue des 59 modules, pagination
│   ├── data/
│   │   └── bip39_english.txt  # wordlist BIP39 officielle (2048 mots)
│   └── modules/
│       ├── network.py      # modules 01 → 09
│       ├── nettools.py     # modules 10 → 11
│       ├── tracenet.py     # module 12 (serveur de trace local)
│       ├── web.py          # modules 13 → 17
│       ├── websec.py       # modules 18 → 22
│       ├── webadv.py       # modules 23 → 25 (CT, fuzz, urlscan)
│       ├── osint.py        # modules 26 → 33
│       ├── intel.py        # modules 34 → 37
│       ├── osadv.py        # modules 38 → 42 (email, Instagram, dorks, Roblox)
│       ├── crypto.py       # modules 43 → 47
│       ├── pwtools.py      # modules 48 → 50
│       ├── cryptox.py      # modules 51 → 52 (stégano, BIP39)
│       ├── system.py       # modules 53 → 55
│       ├── sysaudit.py     # modules 56 → 58
│       └── sysadv.py       # module 59 (profils WiFi)
├── tools/gen_icon.py       # régénère assets/icon.png + icon.ico
├── assets/banner.txt       # bannière de repli (fonte bloc)
├── assets/banner_big.txt   # bannière géante ANSI Shadow (13 × 65)
├── assets/icon.png/.ico    # icône du repo
├── output/                 # résultats sauvegardés (gitignoré)
└── .github/workflows/ci.yml  # selftest à chaque push
```

- **DNS en pur Python** : requêtes UDP directes (A, MX, NS, TXT…), aucun `dnspython`.
- **EXIF en pur Python** : parseur JPEG/TIFF/GPS complet, aucune dépendance.
- **PE en pur Python** : DOS/COFF/optional header, sections, table d'imports.
- **TOTP en pur Python** : HMAC-SHA1/256/512, testé contre le vecteur RFC 6238.
- **Zéro dépendance obligatoire** : `requests` et `colorama` sont repliés sur `urllib` / ANSI natif s'ils manquent.

---

## 🛡️ Usage responsable

Ces outils sont conçus pour l'**audit de sécurité que vous êtes autorisé à mener** : vos propres machines, vos serveurs, vos applications, vos cibles de bug bounty avec accord écrit. Scanner un système tiers sans autorisation est illégal dans la plupart des juridictions. Chaque module reste sous votre contrôle — aucun envoi automatique, aucun effet de bord caché, les résultats sont locaux dans `output/`.

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE).

**Si FCK MULTI TOOL vous est utile, une ⭐ sur le repo aide énormément.**

---

## 👤 Auteur

**camzzz** (alias **cameleonnbss**) — https://github.com/cameleonnbss

Issues et suggestions : https://github.com/cameleonnbss/Fck-Multi-Tool/issues
