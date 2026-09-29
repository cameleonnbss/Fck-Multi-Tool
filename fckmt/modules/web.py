import concurrent.futures
import random
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .. import ui, net


def normalize_url(value):
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value


def _title(html):
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:80] if match else ""


SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking"),
    ("X-Content-Type-Options", "MIME sniffing"),
    ("Referrer-Policy", "Fuites de referrer"),
    ("Permissions-Policy", "Permissions navigateur"),
    ("X-XSS-Protection", "Filtre XSS legacy"),
]


def site_info():
    ui.module_header(14, "Website Info Scanner", "En-tetes, technologies, robots, score de securite")
    url = normalize_url(ui.ask_required("URL du site (ex : example.com)"))
    with ui.Spinner("Analyse de la page"):
        resp = net.http_get(url, timeout=12)
    if resp.status == 0:
        ui.err("Connexion impossible.")
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    pairs = [
        ("URL finale", resp.url or url),
        ("Status", str(resp.status)),
        ("Titre", _title(resp.text) or "-"),
        ("Serveur", headers.get("server", "-")),
        ("Powered-By", headers.get("x-powered-by", "-")),
        ("Type", headers.get("content-type", "-")),
        ("Taille", f"{len(resp.content)} octets"),
    ]
    ui.kv(pairs)
    print()
    ui.info("En-tetes de securite :")
    score = 0
    rows = []
    for header, purpose in SECURITY_HEADERS:
        value = headers.get(header.lower())
        if value:
            score += 1
            rows.append([header, "OK", purpose, value[:40]])
        else:
            rows.append([header, "ABSENT", purpose, "-"])
    ui.table(["ENTETE", "ETAT", "PROTECTION", "VALEUR"], rows, widths=[32, 9, 22, 34])
    ui.ok(f"Score : {score}/{len(SECURITY_HEADERS)} en-tetes de securite presents")
    cookies = headers.get("set-cookie", "")
    if cookies:
        flags = []
        low = cookies.lower()
        if "secure" in low:
            flags.append("Secure")
        if "httponly" in low:
            flags.append("HttpOnly")
        if "samesite" in low:
            flags.append("SameSite")
        ui.kv([
            ("Cookies", cookies[:70]),
            ("Attributs", ", ".join(flags) or "aucun (a ameliorer)"),
        ])
    tech = []
    body = resp.text[:40000]
    for marker, name in [
        ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
        ("drupal", "Drupal"), ("Joomla!", "Joomla"),
        ("laravel_session", "Laravel"), ("csrfmiddlewaretoken", "Django"),
        ("__next", "Next.js"), ("_nuxt", "Nuxt.js"),
        ("react", "React"), ("ng-app", "Angular"),
        ("woocommerce", "WooCommerce"), ("shopify", "Shopify"),
        ("cloudflare", "Cloudflare"), ("gstatic", "Google stack"),
    ]:
        if marker.lower() in body.lower() or marker.lower() in str(headers):
            tech.append(name)
    if tech:
        ui.info("Technologies detectees : " + ", ".join(sorted(set(tech))))
    robots = net.http_get(urljoin(resp.url or url, "/robots.txt"), timeout=8)
    if robots.status == 200 and robots.text.strip():
        ui.info("robots.txt present :")
        for row in robots.text.splitlines()[:12]:
            print("  " + ui.paint(f"    {row}", ui.X))
    sitemap = net.http_get(urljoin(resp.url or url, "/sitemap.xml"), timeout=8)
    if sitemap.status == 200:
        count = sitemap.text.count("<loc>")
        ui.info(f"sitemap.xml present ({count} URL)")
    ui.save_output("siteinfo", "\n".join(f"{k} : {v}" for k, v in pairs))


SENSITIVE_PATHS = [
    ("/.git/HEAD", "Depot Git expose", "critique"),
    ("/.git/config", "Configuration Git exposee", "critique"),
    ("/.env", "Fichier .env (secrets)", "critique"),
    ("/.svn/entries", "Depot SVN expose", "critique"),
    ("/.aws/credentials", "Identifiants AWS", "critique"),
    ("/phpinfo.php", "phpinfo() exposee", "haut"),
    ("/wp-config.php.bak", "Sauvegarde wp-config", "haut"),
    ("/wp-config.php~", "Sauvegarde wp-config", "haut"),
    ("/config.php.bak", "Sauvegarde de configuration", "haut"),
    ("/config.php.save", "Sauvegarde de configuration", "haut"),
    ("/backup.sql", "Base de donnees en clair", "haut"),
    ("/dump.sql", "Base de donnees en clair", "haut"),
    ("/.htpasswd", "Hashs HTTP auth", "haut"),
    ("/.DS_Store", "Index de fichiers macOS", "moyen"),
    ("/server-status", "Statut Apache", "moyen"),
    ("/server-info", "Infos Apache", "moyen"),
    ("/.well-known/security.txt", "security.txt", "info"),
    ("/crossdomain.xml", "Politique cross-domain", "info"),
    ("/actuator/env", "Spring Boot env", "haut"),
    ("/actuator/health", "Spring Boot health", "moyen"),
    ("/backup.zip", "Archive de sauvegarde", "haut"),
    ("/www.zip", "Archive du site", "haut"),
    ("/web.config", "IIS web.config", "moyen"),
    ("/adminer.php", "Adminer (BDD)", "critique"),
    ("/editor/filemanager", "File manager expose", "haut"),
    ("/elmah.axd", "Logs ELMAH", "moyen"),
    ("/trace.axd", "Trace ASP.NET", "moyen"),
    ("/.dockerenv", "Conteneur Docker", "info"),
    ("/debug/default/view", "Debug Yii", "haut"),
    ("/console", "Console exposee", "haut"),
]

SQLI_PATTERNS = [
    "sql syntax", "mysql_fetch", "mysqli_", "pg_query", "pg_exec", "sqlite3",
    "ORA-01756", "ORA-00933", "microsoft ole db", "odbc sql server",
    "unclosed quotation mark", "quoted string not properly terminated",
    "SQLSTATE[", "syntax error at line", "warning: mysql", "valid mysql result",
    "supplied argument is not a valid", "sqlite exception",
]


def vuln_scan():
    ui.module_header(15, "Website Vuln Scanner", "Fichiers sensibles, injections SQL/XSS, misconfig")
    url = normalize_url(ui.ask_required("URL du site a tester"))
    base = url.rstrip("/")
    findings = []
    lock = threading.Lock()

    def add(severity, title, detail=""):
        with lock:
            findings.append((severity, title, detail))

    paths = list(SENSITIVE_PATHS)

    def check_path(item):
        path, label, severity = item
        resp = net.http_get(base + path, timeout=6)
        if resp.status == 200:
            marker = ""
            if path == "/.git/HEAD" and resp.text.startswith("ref:"):
                marker = " ref: confirme"
            if path == "/.env" and re.search(r"(?i)(api_key|secret|password|token)=", resp.text):
                marker = " mots-cles secrets detectes"
            if path in ("/backup.sql", "/dump.sql") and ("CREATE TABLE" in resp.text.upper() or "INSERT INTO" in resp.text.upper()):
                marker = " SQL reel detecte"
            add(severity, f"{path} — {label}", f"HTTP 200{marker}")
        elif resp.status in (401, 403):
            add("info", f"{path} — {label}", f"HTTP {resp.status} (protege mais present)")

    with ui.Spinner("Fichiers sensibles"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(check_path, paths))

    with ui.Spinner("Structure de la page"):
        resp = net.http_get(base, timeout=10)
        html = resp.text
        if re.search(r"(?i)index of /", html):
            add("haut", "Directory listing actif", "Listage de fichiers visible")
        if "wp-login.php" in html:
            add("info", "Point d'entree WordPress", "/wp-login.php")
        params = re.findall(r"href=[\"']([^\"']*\?[^\"']+)[\"']", html, re.I)[:6]

    token = "fck" + hex(random.randint(0x100000, 0xFFFFFF))[2:]
    test_url = base + ("/" if not base.endswith("/") else "") + f"?q={token}&id=1&search={token}"
    with ui.Spinner("Tests d'injection (XSS reflet / SQLi par erreur)"):
        resp = net.http_get(test_url, timeout=10)
    if resp.status and token in resp.text:
        add("moyen", "Reflexion XSS possible", f"Le parametre reflete le input sans filtrage evident ({token})")
    if resp.status:
        low = resp.text.lower()
        for pattern in SQLI_PATTERNS:
            if pattern.lower() in low:
                add("haut", "Erreur SQL refletee", f"Signature detectee : {pattern}")
                break
        raw = net.http_get(base + "/?id=1'", timeout=8)
        if raw.status:
            low2 = raw.text.lower()
            for pattern in SQLI_PATTERNS:
                if pattern.lower() in low2:
                    add("haut", "Injection SQL par erreur", f"Apostrophe -> signature : {pattern}")
                    break
    for param_url in params:
        probe = net.http_get(base + "/" + param_url.split(base, 1)[-1] if param_url.startswith(base) else param_url, timeout=8)
        if probe.status:
            low = probe.text.lower()
            for pattern in SQLI_PATTERNS:
                if pattern.lower() in low:
                    add("haut", f"Erreur SQL via {param_url[:60]}", f"Signature : {pattern}")
                    break

    if not findings:
        ui.ok("Aucun signal d'alerte detecte sur les tests effectues.")
        return
    order = {"critique": 0, "haut": 1, "moyen": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f[0], 9))
    colors = {"critique": ui.R, "haut": ui.Y, "moyen": ui.C, "info": ui.X}
    ui.info(f"{len(findings)} resultat(s) :")
    lines = [f"# Vuln scan {base} — {time.strftime('%Y-%m-%d %H:%M:%S')}"]
    for severity, title, detail in findings:
        tag = severity.upper().ljust(9)
        print("  " + ui.paint(f"  [{tag}]", colors.get(severity, ui.W), ui.K) + f" {title}" + (ui.paint(f" — {detail}", ui.X) if detail else ""))
        lines.append(f"[{severity}] {title} — {detail}")
    ui.save_output("vulnscan", "\n".join(lines))


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.emails = set()
        self.forms = 0

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "a" and data.get("href"):
            self.links.add(data["href"])
        elif tag == "form":
            self.forms += 1
            if data.get("action"):
                self.links.add(data["action"])
        elif tag in ("script", "img", "link") and data.get("src"):
            self.links.add(data["src"])
        elif tag == "link" and data.get("href"):
            self.links.add(data["href"])

    def handle_data(self, data):
        for match in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", data):
            if len(match) < 60:
                self.emails.add(match)


def url_scan():
    ui.module_header(16, "Website URL Scanner", "Exploration des liens, forms et mails d'une page")
    url = normalize_url(ui.ask_required("URL de depart"))
    with ui.Spinner("Telechargement de la page"):
        resp = net.http_get(url, timeout=12)
    if resp.status == 0:
        ui.err("Connexion impossible.")
        return
    parser = _LinkParser()
    try:
        parser.feed(resp.text)
    except Exception:
        pass
    origin = urlparse(resp.url or url)
    same, external = set(), set()
    for link in parser.links:
        if link.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute = urljoin(resp.url or url, link)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc == origin.netloc:
            same.add(absolute)
        else:
            external.add(absolute)
    ui.ok(f"{len(same)} lien(s) interne(s) — {len(external)} externe(s) — {parser.forms} formulaire(s)")
    if parser.emails:
        ui.info("Adresses e-mail trouvees :")
        for mail in sorted(parser.emails)[:20]:
            print("  " + ui.paint(f"    {mail}", ui.C))
    rows = []
    checked = sorted(same)[:50]

    def probe(link):
        head = net.http_get(link, timeout=6)
        return [link.replace(origin.scheme + "://" + origin.netloc, "")[:60], str(head.status or "-")]

    with ui.Spinner(f"Verification de {len(checked)} lien(s)"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
            for row in pool.map(probe, checked):
                rows.append(row)
    if rows:
        ui.table(["CHEMIN", "STATUS"], rows, widths=[62, 10])
    if external:
        ui.info("Domaines externes :")
        for dom in sorted({urlparse(l).netloc for l in external})[:25]:
            print("  " + ui.paint(f"    {dom}", ui.Y))
    content = [f"# URL scan {url}", "", "Liens internes :"] + sorted(same) + ["", "Externes :"] + sorted(external)
    ui.save_output("urlscan", "\n".join(content))


def ssl_check():
    ui.module_header(17, "SSL Cert Checker", "Certificat, chaine de confiance et expiration")
    host = ui.ask_required("Domaine (ex : example.com)")
    port = ui.ask_int("Port TLS", 443, 1, 65535)
    with ui.Spinner("Connexion TLS"):
        try:
            info = net.cert_info(host, port)
        except Exception as exc:
            ui.err(f"Connexion TLS impossible : {exc}")
            return
    cert = info.get("cert") or {}
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_before = cert.get("notBefore", "-")
    not_after = cert.get("notAfter", "-")
    days_left = None
    try:
        expire = ssl.cert_time_to_seconds(not_after)
        days_left = int((expire - time.time()) // 86400)
    except Exception:
        pass
    san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    pairs = [
        ("Domaine", host),
        ("Sujet", ", ".join(f"{k}={v}" for k, v in subject.items()) or "-"),
        ("Emetteur", ", ".join(f"{k}={v}" for k, v in issuer.items()) or "-"),
        ("Valide du", str(not_before)),
        ("Valide jusqu'au", str(not_after)),
        ("Jours restants", str(days_left) if days_left is not None else "-"),
        ("TLS", str(info.get("tls", "-"))),
        ("Chiffrement", str((info.get("cipher") or ("-",))[0])),
        ("SAN", ", ".join(san[:8]) or "-"),
    ]
    ui.kv(pairs)
    if days_left is not None:
        if days_left < 0:
            ui.err("Certificat EXPIRE.")
        elif days_left < 15:
            ui.err(f"Certificat : expire dans {days_left} jours.")
        else:
            ui.ok(f"Certificat valide — {days_left} jours restants.")
    ui.save_output("ssl", "\n".join(f"{k} : {v}" for k, v in pairs))


DORK_TEMPLATES = [
    'site:{target} filetype:pdf',
    'site:{target} filetype:doc OR filetype:docx',
    'site:{target} filetype:xls OR filetype:xlsx',
    'site:{target} filetype:sql',
    'site:{target} filetype:env',
    'site:{target} filetype:log',
    'site:{target} intitle:"index of"',
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} inurl:?id=',
    'site:{target} ext:php inurl:backup',
    'site:{target} "powered by"',
    'site:{target} intext:"password" filetype:txt',
    'site:{target} allinurl:wp-content',
    'site:{target} cache:',
    'inurl:{target} ext:php',
    'filetype:env {target}',
    'filetype:bak {target}',
]


def google_dorking():
    ui.module_header(18, "Google Dorking", "Generation de requetes de recherche avancee")
    target = ui.ask_required("Cible (domaine ou mot-cle)")
    target = target.replace("https://", "").replace("http://", "").strip("/")
    dorks = [tpl.format(target=target) for tpl in DORK_TEMPLATES]
    ui.ok(f"{len(dorks)} dork(s) genere(s) pour : {target}")
    for i, dork in enumerate(dorks, 1):
        print("  " + ui.paint(f"  {i:02d}. ", ui.C, ui.K) + dork)
    if ui.ask_choice("Ouvrir le premier dork dans le navigateur ?", ["o", "n"], "n") == "o":
        from urllib.parse import quote_plus

        ui.open_url("https://www.google.com/search?q=" + quote_plus(dorks[0]))
    ui.save_output("dorks", "\n".join(dorks))
