# FCK MULTI TOOL v1.2.0

**59 modules** · bannière géante ANSI Shadow animée · 100 % gratuit · tout en français.

## Nouveautés

### 12 nouveaux modules (47 → 59)
- **Réseau (12) — Trace-HTTP** : serveur de traçage local (journal JSONL + dashboard), métadonnées visiteurs uniquement.
- **Web (23–25)** : Cert-Transparency (crt.sh + détection de CNAME suspendus), Injection-Fuzzer (SQLi/XSS/traversal sur cible autorisée), URLScan-Search (scans publics urlscan.io).
- **OSINT (38–42)** : Email-Accounts-Checker, Email-Breach-Check (XposedOrNot), Instagram-OSINT (sans clé API), Dork-Builder, Roblox-ID-Info (asset / place).
- **Crypto (51–52)** : Stegano-PNG (masquage/extraction LSB), BIP39-Generator (seed 12/24 mots + seed hex, vecteurs officiels vérifiés).
- **Système (59)** : WiFi-Profils (profils Wi-Fi de la machine + réseaux visibles).

### Interface
- **Bannière géante ANSI Shadow** (13 × 65) affichée en 4 frames de glitch → net, avec repli automatique sur petits terminaux.
- **Menu 8 pages** (59 modules), touche `f` fenêtre/console inchangée.
- `start.bat` / `start.sh` ouvrent aussi le profil GitHub.

## Installation

```bash
git clone https://github.com/cameleonnbss/Fck-Multi-Tool.git
cd Fck-Multi-Tool
python main.py            # Windows : double-cliquer sur start.bat
python main.py --selftest # 44 vérifications
```

Prérequis : Python 3.8+. Aucune dépendance obligatoire.

## Vérifié

- Selftest : 44/44 ✓
- Modules testés en conditions réelles (Instagram, Roblox, crt.sh, urlscan, BIP39, stégano, WiFi, traçage local) ✓

**Usage responsable** : audit uniquement sur des systèmes où vous êtes autorisé à intervenir.

MIT — https://github.com/cameleonnbss/Fck-Multi-Tool
