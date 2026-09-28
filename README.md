# 🐯 FCK MULTI TOOL

**Suite multi-outils terminal — réseau, web, OSINT, crypto, système — 30 modules, un menu, zéro dépendance obligatoire.**

[![Release](https://img.shields.io/github/v/release/cameleonnbss/Fck-Multi-Tool?style=flat-square&color=ff3d57)](https://github.com/cameleonnbss/Fck-Multi-Tool/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Linux-0d1117?style=flat-square)](https://github.com/cameleonnbss/Fck-Multi-Tool)
[![Language](https://img.shields.io/badge/language-Python%203.8%2B-3572A5?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-3dd68c?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-30-ff3d57?style=flat-square)](#-les-30-modules)

**Menu paginé en couleur** · **animation d'ouverture glitch** · **scanners réseau** · **audit de sécurité web** · **OSINT multi-plateformes** · **craquage de hash** · **encodeurs** · **analyse de fichiers** · **100 % gratuit** · **FR / EN**

`Python 3.8+` · `Windows / Linux / macOS` · `aucune config requise` · `résultats sauvegardés dans output/`

[⬇️ **Télécharger v1.0.0**](https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.0.0) · [Démarrage rapide](#-démarrage-rapide) · [Les modules](#-les-30-modules) · [CLI](#-cli) · **Français**

---

## 🆕 Nouveautés en 1.0.0

**Première release publique — tout est inclus, tout est gratuit.**

- **Animation d'ouverture** : ta bannière ASCII FCK MULTI TOOL affichée ligne par ligne avec cycle de couleurs, effet glitch et barre de chargement.
- **Menu « push » paginé** : 5 pages par catégorie, numéros `[01]` → `[30]`, navigation `n` / `p`, contact `c`, infos `i`.
- **30 modules fonctionnels** : chaque module tourne pour de vrai (scan TCP avec bannière, DNS brute-force, tests d'injection, craquage de hash, EXIF/GPS…), avec spinners et barres de progression.
- **Lanceurs** : `start.bat` ouvre ta page GitHub puis lance le tool, `setup.bat` installe tout et lance le selftest.
- **Sauvegarde automatique** : chaque résultat est écrit dans `output/<module>_<horodatage>.txt`.
- **Selftest intégré** : `python main.py --selftest` vérifie les 20 points fonctionnels en quelques secondes.

---

## 📦 Téléchargement

| Release | Lien |
|---------|------|
| **v1.0.0 (actuelle)** | https://github.com/cameleonnbss/Fck-Multi-Tool/releases/tag/v1.0.0 |
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
| **Vérifier que tout marche** | `python main.py --selftest` |

Prérequis : [Python 3.8+](https://www.python.org/downloads/) (avec `python` dans le PATH).
Les dépendances (`requests`, `colorama`) sont installées par le setup — le tool démarre aussi sans elles (repli automatique sur la bibliothèque standard).

---

## 🧰 Les 30 modules

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

### 🛡️ Web & sécurité web

| # | Module | Description |
|---|--------|-------------|
| 10 | Website-Info-Scanner | En-têtes de sécurité (score /7), technologies, robots.txt, sitemap |
| 11 | Website-Vuln-Scanner | Fichiers sensibles (.git, .env, dumps SQL…), directory listing, XSS reflet, SQLi par erreur |
| 12 | Website-Url-Scanner | Crawl des liens internes/externes, formulaires, e-mails de la page |
| 13 | SSL-Cert-Checker | Certificat, émetteur, SAN, jours restants, TLS, chiffrement |
| 14 | Google-Dorking | 18 dorks générés (filetype, inurl, intitle…) + ouverture navigateur |

### 🔍 OSINT & investigation

| # | Module | Description |
|---|--------|-------------|
| 15 | Username-Tracker | Pseudo vérifié sur 20+ plateformes (EXISTE / LIBRE / PROBABLE) |
| 16 | Email-Lookup | Syntaxe, MX, provider, jetable, empreinte Gravatar |
| 17 | Image-EXIF-Reader | Make/Model/date/GPS → lien Google Maps (parsé en pur Python) |
| 18 | Phone-Lookup | Indicatif pays (80+ pays), formats E.164 / national |
| 19 | Roblox-User-Info | Profil public, amis, avatar (API officielle) |
| 20 | Discord-Invite-Info | Serveur, membres en ligne, boosts (API publique) |
| 21 | Discord-Webhook-Info | Métadonnées d'un webhook — lecture seule, aucun envoi |
| 22 | Discord-Bot-Invite-To-Id | ID du bot et du serveur depuis une invitation |

### 🔐 Crypto & mots de passe

| # | Module | Description |
|---|--------|-------------|
| 23 | Hash-Generator | MD5, SHA1/224/256/384/512, BLAKE2, SHA3 — texte ou fichier |
| 24 | Hash-Cracker | Identification automatique + wordlist ou brute-force PIN |
| 25 | Zip-Cracker | Archive ZIP chiffrée ouverte par wordlist |
| 26 | Encodeur-Decodeur | Base64, Base32, Hex, URL, ROT13, binaire, inverse, Caesar |
| 27 | Password-Generator | `secrets` + entropie mesurée en bits |

### 💻 Système & fichiers

| # | Module | Description |
|---|--------|-------------|
| 28 | System-Info | CPU, RAM, disques, uptime, IP publique |
| 29 | File-Analyzer | Type réel (magic bytes), MD5/SHA, entropie, hexdump |
| 30 | Local-Ports | Ports en écoute + processus et PID (netstat/tasklist) |

---

## 🎮 Menu

```
  ╔══════════════════════════════════════════════════════════╗
  ║                     FCK MULTI TOOL                       ║
  ║    v1.0.0 · par camzzz (cameleonnbss) · 30 modules · MIT  ║
  ╚══════════════════════════════════════════════════════════╝

  ┌────────────────────────────────────────────────────────────┐
  │  RESEAU & INFRA  —  page 1/5                               │
  ├────────────────────────────────────────────────────────────┤
  │  [01] Scanner-de-Ports          Scan TCP multi-threads     │
  │  [02] Ping-Sweep                Hotes actifs sous-reseau   │
  │  ...                                                       │
  └────────────────────────────────────────────────────────────┘

  [n] Page suivante   [p] Page precedente   [c] Contact   [q] Quitter
```

- **un numéro** → lancement du module
- **n / p** → page suivante / précédente
- **c** → ouvre la page GitHub (contact)
- **i** → boîte d'informations
- **q** → quitter

---

## 💻 CLI

```
python main.py                lancer avec animation
python main.py --no-anim      démarrage instantané
python main.py --selftest     vérifier les modules puis quitter
python main.py --list         lister les 30 modules
python main.py --version      afficher la version
```

---

## 🏗️ Architecture

```
fck-multi-tool/
├── main.py                 # point d'entrée : animation, menu, dispatch, selftest
├── setup.bat / setup.sh    # installation (pip + selftest)
├── start.bat / start.sh    # ouvre GitHub puis lance le tool
├── setup.py                # installeur cross-platform
├── fckmt/
│   ├── config.py           # nom, version, liens
│   ├── ui.py               # couleurs, boîtes, spinners, tables, sauvegarde
│   ├── banner.py           # bannière ASCII + animation d'ouverture
│   ├── net.py              # HTTP, DNS UDP brut, whois, TLS, IP locale
│   ├── registry.py         # catalogue des 30 modules
│   └── modules/
│       ├── network.py      # modules 01 → 09
│       ├── web.py          # modules 10 → 14
│       ├── osint.py        # modules 15 → 22
│       ├── crypto.py       # modules 23 → 27
│       └── system.py       # modules 28 → 30
├── assets/banner.txt       # ta bannière (modifie-la librement)
├── output/                 # résultats sauvegardés (gitignoré)
└── .github/workflows/ci.yml  # selftest à chaque push
```

- **DNS en pur Python** : requêtes UDP directes (A, MX, NS, TXT…), aucun `dnspython`.
- **EXIF en pur Python** : parseur JPEG/TIFF/GPS complet, aucune dépendance.
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
