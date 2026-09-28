# Changelog

Toutes les notable changes à FCK MULTI TOOL sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/).

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
