from .modules import network, web, osint, crypto, system

CATEGORIES = [
    ("RESEAU & INFRA", [
        (1, "Scanner-de-Ports", "Scan TCP multi-threads + bannieres", network.scan_ports),
        (2, "Ping-Sweep", "Hotes actifs sur un sous-reseau", network.ping_sweep),
        (3, "IP-Pinger", "Latence moyenne sur 4 paquets", network.ip_pinger),
        (4, "IP-Lookup", "Geolocalisation et FAI", network.ip_lookup),
        (5, "Whois-Lookup", "Registrar, dates, reseaux", network.whois_module),
        (6, "DNS-Recon", "Enregistrements + brute-force sous-domaines", network.dns_recon),
        (7, "Traceroute", "Chemin des paquets vers la cible", network.traceroute),
        (8, "Proxy-Scraper", "Collecte et test de proxys publics", network.proxy_scraper),
        (9, "Reseau-Local", "Interfaces, ARP, passerelle", network.reseau_local),
    ]),
    ("WEB & SECURITE WEB", [
        (10, "Website-Info-Scanner", "En-tetes, tech, robots, score", web.site_info),
        (11, "Website-Vuln-Scanner", "Fichiers sensibles, SQLi/XSS", web.vuln_scan),
        (12, "Website-Url-Scanner", "Liens, formulaires, mails", web.url_scan),
        (13, "SSL-Cert-Checker", "Certificat, chaine, expiration", web.ssl_check),
        (14, "Google-Dorking", "Requetes de recherche avancee", web.google_dorking),
    ]),
    ("OSINT & INVESTIGATION", [
        (15, "Username-Tracker", "Pseudo sur 20+ plateformes", osint.username_tracker),
        (16, "Email-Lookup", "Syntaxe, MX, jetable, Gravatar", osint.email_lookup),
        (17, "Image-EXIF-Reader", "Metadonnees et GPS", osint.exif_reader),
        (18, "Phone-Lookup", "Indicatif pays et formatage", osint.phone_lookup),
        (19, "Roblox-User-Info", "Profil public API Roblox", osint.roblox_user),
        (20, "Discord-Invite-Info", "Infos publiques d'une invitation", osint.discord_invite),
        (21, "Discord-Webhook-Info", "Metadonnees webhook (lecture)", osint.discord_webhook),
        (22, "Discord-Bot-Invite-To-Id", "ID bot depuis une invitation", osint.discord_bot_id),
    ]),
    ("CRYPTO & MOTS DE PASSE", [
        (23, "Hash-Generator", "MD5 / SHA / BLAKE2", crypto.hash_generator),
        (24, "Hash-Cracker", "Wordlist ou force brute PIN", crypto.hash_cracker),
        (25, "Zip-Cracker", "Archive ZIP chiffree par wordlist", crypto.zip_cracker),
        (26, "Encodeur-Decodeur", "Base64, Hex, URL, ROT13, Caesar", crypto.encoders),
        (27, "Password-Generator", "Aleatoire + entropie", crypto.password_generator),
    ]),
    ("SYSTEME & FICHIERS", [
        (28, "System-Info", "Materiel, RAM, disques, IP publique", system.system_info),
        (29, "File-Analyzer", "Type reel, hashs, entropie", system.file_analyzer),
        (30, "Local-Ports", "Ports en ecoute + processus", system.local_ports),
    ]),
]


def entries():
    result = []
    for category, items in CATEGORIES:
        for num, key, desc, func in items:
            result.append({"num": num, "key": key, "desc": desc, "func": func, "category": category})
    return result


def by_number(number):
    for item in entries():
        if item["num"] == number:
            return item
    return None


MODULE_COUNT = sum(len(items) for _, items in CATEGORIES)
