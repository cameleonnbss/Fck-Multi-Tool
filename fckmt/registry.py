from .modules import network, web, osint, crypto, system
from .modules import nettools, websec, intel, pwtools, sysaudit
from .modules import tracenet, webadv, osadv, cryptox, sysadv
from .modules import stress, shells, sniff, obfusc, hashid, wordlist

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
        (12, "Trace-HTTP", "Serveur de trace local (metadonnees visiteurs)", tracenet.trace_http),
        (13, "Stress-Test", "Test de charge multi-vecteurs, threads adaptatifs", stress.stress_test),
    ]),
    ("WEB & SECURITE WEB", [
        (14, "Website-Info-Scanner", "En-tetes, tech, robots, score", web.site_info),
        (15, "Website-Vuln-Scanner", "Fichiers sensibles, SQLi/XSS", web.vuln_scan),
        (16, "Website-Url-Scanner", "Liens, formulaires, mails", web.url_scan),
        (17, "SSL-Cert-Checker", "Certificat, chaine, expiration", web.ssl_check),
        (18, "Google-Dorking", "Requetes de recherche avancee", web.google_dorking),
        (19, "Directory-Brute", "Decouverte de chemins publics", websec.dir_brute),
        (20, "CORS-Scanner", "Verification Cross-Origin (ACAO)", websec.cors_scan),
        (21, "Tech-Fingerprint", "Detection CDN/WAF, CMS, frameworks", websec.tech_fingerprint),
        (22, "Wayback-URL-History", "URLs archivees par le Wayback CDX", websec.wayback_history),
        (23, "JWT-Analyzer", "Entete, claims et signature d'un JWT", websec.jwt_analyzer),
        (24, "Cert-Transparency", "Sous-domaines certifies (crt.sh) + CNAME", webadv.cert_transparency),
        (25, "Injection-Fuzzer", "Fuzzing SQLi / XSS / traversal", webadv.injection_fuzzer),
        (26, "URLScan-Search", "Scans publics urlscan.io d'un domaine", webadv.urlscan_search),
    ]),
    ("OSINT & INVESTIGATION", [
        (27, "Username-Tracker", "Pseudo sur 20+ plateformes", osint.username_tracker),
        (28, "Email-Lookup", "Syntaxe, MX, jetable, Gravatar", osint.email_lookup),
        (29, "Image-EXIF-Reader", "Metadonnees et GPS", osint.exif_reader),
        (30, "Phone-Lookup", "Indicatif pays et formatage", osint.phone_lookup),
        (31, "Roblox-User-Info", "Profil public API Roblox", osint.roblox_user),
        (32, "Discord-Invite-Info", "Infos publiques d'une invitation", osint.discord_invite),
        (33, "Discord-Webhook-Info", "Metadonnees webhook (lecture)", osint.discord_webhook),
        (34, "Discord-Bot-Invite-To-Id", "ID bot depuis une invitation", osint.discord_bot_id),
        (35, "Shodan-InternetDB", "Ports, services et CVE d'une IP", intel.shodan_internetdb),
        (36, "Password-Breach-Check", "Verification fuites (HIBP, k-anonymat)", intel.password_breach_check),
        (37, "Email-Header-Analyzer", "Trace Received, SPF/DKIM/DMARC", intel.email_header_analysis),
        (38, "CVE-Lookup", "Recherche NVD (base NIST)", intel.cve_lookup),
        (39, "Email-Accounts-Checker", "Comptes lies a un email (heuristique)", osadv.email_accounts_checker),
        (40, "Email-Breach-Check", "Fuites et pastes (XposedOrNot, sans cle)", osadv.email_breach_xon),
        (41, "Instagram-OSINT", "Profil public Instagram (sans cle API)", osadv.instagram_osint),
        (42, "Dork-Builder", "Dorks d'identite auto-generes", osadv.dork_builder),
        (43, "Roblox-ID-Info", "Fiche publique asset / place Roblox", osadv.roblox_id_info),
    ]),
    ("CRYPTO & MOTS DE PASSE", [
        (44, "Hash-Generator", "MD5 / SHA / BLAKE2", crypto.hash_generator),
        (45, "Hash-Cracker", "Wordlist ou force brute PIN", crypto.hash_cracker),
        (46, "Zip-Cracker", "Archive ZIP chiffree par wordlist", crypto.zip_cracker),
        (47, "Encodeur-Decodeur", "Base64, Hex, URL, ROT13, Caesar", crypto.encoders),
        (48, "Password-Generator", "Aleatoire + entropie", crypto.password_generator),
        (49, "Passphrase-Generator", "Phrase de passe memorisable", pwtools.passphrase_generator),
        (50, "Password-Strength", "Entropie, motifs faibles, temps de craquage", pwtools.password_strength),
        (51, "TOTP-2FA-Generator", "Code temporel RFC 6238", pwtools.totp_generator),
        (52, "Stegano-PNG", "Message cache dans un PNG (LSB)", cryptox.stegano_png),
        (53, "BIP39-Generator", "Seed phrase 12/24 mots + seed hex", cryptox.bip39_generator),
        (54, "Hash-Identifier", "Detection du type d'un hash (60+ signatures)", hashid.hash_identifier),
        (55, "Wordlist-Factory", "Mutations, leet, combinatorio pour craquage", wordlist.wordlist_factory),
    ]),
    ("PENTEST & OFFENSIVE", [
        (56, "Shell-Generator", "Payloads reverse/bind multi-plateformes", shells.shell_generator),
        (57, "Packet-Sniffer", "Capture locale (scapy ou socket brute)", sniff.packet_sniffer),
        (58, "Code-Obfuscator", "Minification / encodage de source Python", obfusc.code_obfuscator),
    ]),
    ("SYSTEME & FICHIERS", [
        (59, "System-Info", "Materiel, RAM, disques, IP publique", system.system_info),
        (60, "File-Analyzer", "Type reel, hashs, entropie", system.file_analyzer),
        (61, "Local-Ports", "Ports en ecoute + processus", system.local_ports),
        (62, "Strings-Extractor", "Chaines ASCII/UTF-16 et URLs cachees", sysaudit.strings_extractor),
        (63, "PE-Header-Parser", "En-tetes d'un executable Windows", sysaudit.pe_parser),
        (64, "Local-Security-Audit", "Etat de securite de la machine", sysaudit.local_security_audit),
        (65, "WiFi-Profils", "Profils WiFi (cles) + reseaux visibles", sysadv.wifi_profiles),
        (66, "MAC-Changer", "Adresse MAC locale : lecture / changement", sysadv.mac_changer),
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
