# 🐯 FCK MULTI TOOL

<img src="assets/icon.png" width="120" alt="FCK MULTI TOOL">

**Suite multi-outils terminal — réseau, web, OSINT, crypto, système — 47 modules, un menu, zéro dépendance obligatoire.**

[![Release](https://img.shields.io/github/v/release/cameleonnbss/Fck-Multi-Tool?style=flat-square&color=ff3d57)](https://github.com/cameleonnbss/Fck-Multi-Tool/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Linux-0d1117?style=flat-square)](https://github.com/cameleonnbss/Fck-Multi-Tool)
[![Language](https://img.shields.io/badge/language-Python%203.8%2B-3572A5?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-3dd68c?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-47-ff3d57?style=flat-square)](#-les-47-modules)

**Menu paginé rouge** · **bannière ASCII à fonte bloc** · **chaque module dans sa propre fenêtre** · **scanners réseau** · **audit de sécurité web** · **OSINT multi-plateformes** · **craquage de hash** · **encodeurs** · **analyse de fichiers** · **100 % gratuit**

`Python 3.8+` · `Windows / Linux / macOS` · `aucune config requise` · `résultats sauvegardés dans output/`

[⬇️ **Télécharger v1.1.0**](https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.1.0) · [Démarrage rapide](#-démarrage-rapide) · [Les modules](#-les-47-modules) · [CLI](#-cli) · **Français**

---

## 🆕 Nouveautés en 1.1.0

- **17 nouveaux modules** (30 → 47) : CIDR calculator, MAC vendor + ARP, directory brute avec détection soft-404, CORS scanner, fingerprint CDN/WAF/CMS, historique Wayback, analyseur JWT, Shodan InternetDB, vérification de fuite HIBP, analyseur d'en-tête email, recherche CVE (NVD), générateur de passphrase, analyse de robustesse de mot de passe, TOTP/RFC 6238, extracteur de strings, parser d'en-têtes PE, audit de sécurité local.
- **Chaque module dans sa propre fenêtre** : sur Windows, un numéro du menu ouvre une console dédiée (`--module N` en CLI). Touche `f` pour basculer fenêtre / console unique.
- **Thème rouge** : bannière, boîtes, spinners, barres de progression — tout est en rouge.
- **Bannière à fonte bloc** : `fckmt/fonts.py` génère la bannière FCK MULTI TOOL et les grands titres ASCII de chaque module — alignement parfait, aucun art collé-collé.
- **Icône du repo** : `assets/icon.png` + `assets/icon.ico` générés par `tools/gen_icon.py` (pur Python).
- **Selftest étendu** : 37 vérifications dont vecteurs RFC 6238, decode JWT, parse PE, calcul CIDR.

---

## 📦 Téléchargement

| Release | Lien |
|---------|------|
| **v1.1.0 (actuelle)** | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.1.0 |
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

## 🧰 Les 47 modules

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
| 10 | CIDR-Calculator | **NEW** Réseau, masque, wildcard, broadcast, plage d'hôtes |
| 11 | MAC-Vendor-Lookup | **NEW** Fabricant (OUI) + table ARP du local |

### 🛡️ Web & sécurité web

| # | Module | Description |
|---|--------|-------------|
| 12 | Website-Info-Scanner | En-têtes de sécurité (score /7), technologies, robots.txt, sitemap |
| 13 | Website-Vuln-Scanner | Fichiers sensibles (.git, .env, dumps SQL…), directory listing, XSS reflet, SQLi par erreur |
| 14 | Website-Url-Scanner | Crawl des liens internes/externes, formulaires, e-mails de la page |
| 15 | SSL-Cert-Checker | Certificat, émetteur, SAN, jours restants, TLS, chiffrement |
| 16 | Google-Dorking | 18 dorks générés (filetype, inurl, intitle…) + ouverture navigateur |
| 17 | Directory-Brute | **NEW** Découverte de chemins, baseline soft-404, wordlist intégrée ou fichier |
| 18 | CORS-Scanner | **NEW** Test ACAO/ACAC avec origines malveillantes, verdict critique/alerte |
| 19 | Tech-Fingerprint | **NEW** Détection CDN/WAF (Cloudflare, Akamai, Sucuri, Imperva, F5…), CMS, frameworks |
| 20 | Wayback-URL-History | **NEW** URLs archivées via l'API CDX, extension breakdown, chemins sensibles |
| 21 | JWT-Analyzer | **NEW** Header, claims, exp/iat, alg none, kid suspect, test de secrets courants |

### 🔍 OSINT & investigation

| # | Module | Description |
|---|--------|-------------|
| 22 | Username-Tracker | Pseudo vérifié sur 20+ plateformes (EXISTE / LIBRE / PROBABLE) |
| 23 | Email-Lookup | Syntaxe, MX, provider, jetable, empreinte Gravatar |
| 24 | Image-EXIF-Reader | Make/Model/date/GPS → lien Google Maps (parsé en pur Python) |
| 25 | Phone-Lookup | Indicatif pays (80+ pays), formats E.164 / national |
| 26 | Roblox-User-Info | Profil public, amis, avatar (API officielle) |
| 27 | Discord-Invite-Info | Serveur, membres en ligne, boosts (API publique) |
| 28 | Discord-Webhook-Info | Métadonnées d'un webhook — lecture seule, aucun envoi |
| 29 | Discord-Bot-Invite-To-Id | ID du bot et du serveur depuis une invitation |
| 30 | Shodan-InternetDB | **NEW** Ports ouverts, hôtes, CVE d'une IP (gratuit, sans clé API) |
| 31 | Password-Breach-Check | **NEW** k-anonymat HIBP — seul le préfixe SHA-1 part, jamais le mot de passe |
| 32 | Email-Header-Analyzer | **NEW** Chaîne Received, IP d'origine, SPF/DKIM/DMARC |
| 33 | CVE-Lookup | **NEW** Recherche NVD officielle NIST (ID CVE ou mot-clé), CVSS |

### 🔐 Crypto & mots de passe

| # | Module | Description |
|---|--------|-------------|
| 34 | Hash-Generator | MD5, SHA1/224/256/384/512, BLAKE2, SHA3 — texte ou fichier |
| 35 | Hash-Cracker | Identification automatique + wordlist ou brute-force PIN |
| 36 | Zip-Cracker | Archive ZIP chiffrée ouverte par wordlist |
| 37 | Encodeur-Decodeur | Base64, Base32, Hex, URL, ROT13, binaire, inverse, Caesar |
| 38 | Password-Generator | `secrets` + entropie mesurée en bits |
| 39 | Passphrase-Generator | **NEW** Phrases mémorisables (dictionnaire embarqué) + entropie |
| 40 | Password-Strength | **NEW** Entropie corrigée, motifs faibles, temps de craquage estimé |
| 41 | TOTP-2FA-Generator | **NEW** Codes RFC 6238, secret Base32, URI d'ajout, vérification |

### 💻 Système & fichiers

| # | Module | Description |
|---|--------|-------------|
| 42 | System-Info | CPU, RAM, disques, uptime, IP publique |
| 43 | File-Analyzer | Type réel (magic bytes), MD5/SHA, entropie, hexdump |
| 44 | Local-Ports | Ports en écoute + processus et PID (netstat/tasklist) |
| 45 | Strings-Extractor | **NEW** Chaînes ASCII/UTF-16, URLs, chemins, e-mails, IP |
| 46 | PE-Header-Parser | **NEW** Machine, sections + entropie, imports, drapeaux ASLR/DEP |
| 47 | Local-Security-Audit | **NEW** Defender, pare-feu, UAC, RDP, SMBv1, autoruns (lecture seule) |

---

## 🎮 Menu

```
  ╔══════════════════════════════════════════════════════════╗
  ║                     FCK MULTI TOOL                       ║
  ║    v1.1.0 · par camzzz (cameleonnbss) · 47 modules · MIT  ║
  ╚══════════════════════════════════════════════════════════╝

  ┌────────────────────────────────────────────────────────────┐
  │  WEB & SECURITE WEB  —  page 3/7                           │
  ├────────────────────────────────────────────────────────────┤
  │  [12] Website-Info-Scanner    En-tetes, tech, robots       │
  │  [13] Website-Vuln-Scanner    Fichiers sensibles, SQLi     │
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
python main.py --list         lister les 47 modules
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
│   ├── banner.py           # bannière ASCII + animation d'ouverture
│   ├── net.py              # HTTP, DNS UDP brut, whois, TLS, IP locale
│   ├── registry.py         # catalogue des 47 modules, pagination
│   └── modules/
│       ├── network.py      # modules 01 → 09
│       ├── nettools.py     # modules 10 → 11
│       ├── web.py          # modules 12 → 16
│       ├── websec.py       # modules 17 → 21
│       ├── osint.py        # modules 22 → 29
│       ├── intel.py        # modules 30 → 33
│       ├── crypto.py       # modules 34 → 38
│       ├── pwtools.py      # modules 39 → 41
│       ├── system.py       # modules 42 → 44
│       └── sysaudit.py     # modules 45 → 47
├── tools/gen_icon.py       # régénère assets/icon.png + icon.ico
├── assets/banner.txt       # ta bannière (modifie-la librement)
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
