from .modules import network, web, osint, crypto, system
from .modules import nettools, websec, intel, pwtools, sysaudit

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
        (10, "CIDR-Calculator", "Sous-reseau, masque, broadcast, hotes", nettools.cidr_calculator),
        (11, "MAC-Vendor-Lookup", "Fabricant d'une carte reseau + ARP", nettools.mac_vendor),
    ]),
    ("WEB & SECURITE WEB", [
        (12, "Website-Info-Scanner", "En-tetes, tech, robots, score", web.site_info),
        (13, "Website-Vuln-Scanner", "Fichiers sensibles, SQLi/XSS", web.vuln_scan),
        (14, "Website-Url-Scanner", "Liens, formulaires, mails", web.url_scan),
        (15, "SSL-Cert-Checker", "Certificat, chaine, expiration", web.ssl_check),
        (16, "Google-Dorking", "Requetes de recherche avancee", web.google_dorking),
        (17, "Directory-Brute", "Decouverte de chemins publics", websec.dir_brute),
        (18, "CORS-Scanner", "Verification Cross-Origin (ACAO)", websec.cors_scan),
        (19, "Tech-Fingerprint", "Detection CDN/WAF, CMS, frameworks", websec.tech_fingerprint),
        (20, "Wayback-URL-History", "URLs archivees par le Wayback CDX", websec.wayback_history),
        (21, "JWT-Analyzer", "Entete, claims et signature d'un JWT", websec.jwt_analyzer),
    ]),
    ("OSINT & INVESTIGATION", [
        (22, "Username-Tracker", "Pseudo sur 20+ plateformes", osint.username_tracker),
        (23, "Email-Lookup", "Syntaxe, MX, jetable, Gravatar", osint.email_lookup),
        (24, "Image-EXIF-Reader", "Metadonnees et GPS", osint.exif_reader),
        (25, "Phone-Lookup", "Indicatif pays et formatage", osint.phone_lookup),
        (26, "Roblox-User-Info", "Profil public API Roblox", osint.roblox_user),
        (27, "Discord-Invite-Info", "Infos publiques d'une invitation", osint.discord_invite),
        (28, "Discord-Webhook-Info", "Metadonnees webhook (lecture)", osint.discord_webhook),
        (29, "Discord-Bot-Invite-To-Id", "ID bot depuis une invitation", osint.discord_bot_id),
        (30, "Shodan-InternetDB", "Ports, services et CVE d'une IP", intel.shodan_internetdb),
        (31, "Password-Breach-Check", "Verification fuites (HIBP, k-anonymat)", intel.password_breach_check),
        (32, "Email-Header-Analyzer", "Trace Received, SPF/DKIM/DMARC", intel.email_header_analysis),
        (33, "CVE-Lookup", "Recherche NVD (base NIST)", intel.cve_lookup),
    ]),
    ("CRYPTO & MOTS DE PASSE", [
        (34, "Hash-Generator", "MD5 / SHA / BLAKE2", crypto.hash_generator),
        (35, "Hash-Cracker", "Wordlist ou force brute PIN", crypto.hash_cracker),
        (36, "Zip-Cracker", "Archive ZIP chiffree par wordlist", crypto.zip_cracker),
        (37, "Encodeur-Decodeur", "Base64, Hex, URL, ROT13, Caesar", crypto.encoders),
        (38, "Password-Generator", "Aleatoire + entropie", crypto.password_generator),
        (39, "Passphrase-Generator", "Phrase de passe memorisable", pwtools.passphrase_generator),
        (40, "Password-Strength", "Entropie, motifs faibles, temps de craquage", pwtools.password_strength),
        (41, "TOTP-2FA-Generator", "Code temporel RFC 6238", pwtools.totp_generator),
    ]),
    ("SYSTEME & FICHIERS", [
        (42, "System-Info", "Materiel, RAM, disques, IP publique", system.system_info),
        (43, "File-Analyzer", "Type reel, hashs, entropie", system.file_analyzer),
        (44, "Local-Ports", "Ports en ecoute + processus", system.local_ports),
        (45, "Strings-Extractor", "Chaines ASCII/UTF-16 et URLs cachees", sysaudit.strings_extractor),
        (46, "PE-Header-Parser", "En-tetes d'un executable Windows", sysaudit.pe_parser),
        (47, "Local-Security-Audit", "Etat de securite de la machine", sysaudit.local_security_audit),
    ]),
]

PAGE_SIZE = 10


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


def by_key(key):
    wanted = str(key).strip().lower().replace("_", "-").replace(" ", "-")
    for item in entries():
        if item["key"].lower() == wanted or item["key"].lower().replace("-", "") == wanted.replace("-", ""):
            return item
    return None


def build_pages(size=PAGE_SIZE):
    pages = []
    for category, items in CATEGORIES:
        for index in range(0, len(items), size):
            chunk = items[index:index + size]
            label = category if index == 0 else category + " (suite)"
            pages.append((label, chunk))
    return pages


MODULE_COUNT = sum(len(items) for _, items in CATEGORIES)
