import base64
import concurrent.futures
import hashlib
import hmac
import json
import random
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .. import ui, net
from .web import normalize_url

DIR_WORDLIST = [
    "admin", "admin/", "administrator", "login", "login/", "wp-admin", "wp-login.php",
    "wp-content", "wp-includes", "dashboard", "panel", "console", "manager",
    "backup", "backups", "old", "tmp", "temp", "test", "dev", "staging",
    "uploads", "upload", "files", "images", "img", "static", "assets", "js", "css",
    "api", "api/", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "docs",
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "crossdomain.xml",
    ".well-known/security.txt", ".well-known/assetlinks.json", "favicon.ico",
    "readme.md", "readme.txt", "license", "changelog.md", "version",
    ".git", ".git/", ".git/HEAD", ".git/config", ".gitignore", ".gitattributes",
    ".svn", ".svn/entries", ".hg", ".env", ".env.local", ".env.production",
    ".env.backup", ".env.example", ".DS_Store", ".idea", ".vscode", ".vs",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Makefile", "Dockerfile", "docker-compose.yml", ".dockerenv",
    "phpinfo.php", "info.php", "test.php", "i.php", "shell.php",
    "server-status", "server-info", "phpmyadmin", "pma", "myadmin",
    "adminer.php", "adminer", "elmah.axd", "trace.axd", "actuator", "actuator/health",
    "actuator/env", "actuator/info", "jmx-console", "webjars",
    "config", "config.php", "config.php.bak", "config.php.old", "config.php~",
    "settings.py", "settings.php", "web.config", "appsettings.json",
    "database.sql", "db.sql", "dump.sql", "backup.sql", "export.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "source.zip", "html.zip",
    "id_rsa", ".ssh/id_rsa", ".aws/credentials", ".netrc", ".npmrc", ".pypirc",
    "credentials", "secrets", "secret", "private.key", "cert.pem", "server.key",
    "error_log", "errors.log", "access.log", "debug.log", "laravel.log",
    "storage/logs/laravel.log", "var/log/system.log",
    "administrator/index.php", "cpanel", "webmail", "roundcube", "squirrelmail",
    "mail", "email", "webmail/login", "owa", "exchange",
    "reports", "report", "stats", "statistics", "status", "health",
    "search", "user", "users", "register", "signup", "forgot", "reset",
    "profile", "account", "settings", "dashboard/index", "home",
    "index.php", "index.php.bak", "index.html", "index.bak", "index.old",
]

SENSITIVE_PATTERNS = [
    "admin", "login", "dashboard", "backup", "env", "git", "svn", "sql",
    "dump", "config", "secret", "key", "credential", "password", "phpmyadmin",
    "actuator", "console", "shell", "id_rsa", "aws", "export", "old",
]

JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "12345678", "qwerty", "admin", "changeme",
    "your-256-bit-secret", "your-secret-key", "your-256-bit-secret-key",
    "supersecret", "mysecret", "jwtsecret", "jwt-secret", "secretkey",
    "secret123", "password123", "admin123", "letmein", "test", "test123",
    "development", "dev", "key", "apikey", "api-key", "insecure",
    "null", "none", "example", "example-secret", "random-secret",
    "keyboard cat", "fastcampus", "hs-secret", "spring", "shhh",
]


def _b64url_decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt(token):
    token = str(token).strip().strip('"').strip("'")
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise ValueError("JWT attendu : 3 parties separees par des points")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1])) if parts[1] else {}
    signature = parts[2] if len(parts) == 3 else ""
    return {"header": header, "payload": payload, "signature": signature, "parts": parts}


def _hs_verify(signing_input, secret, alg):
    alg = (alg or "HS256").upper()
    data = signing_input.encode("ascii")
    key = secret.encode("utf-8")
    if alg == "HS256":
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    if alg == "HS384":
        return hmac.new(key, data, hashlib.sha384).hexdigest()
    if alg == "HS512":
        return hmac.new(key, data, hashlib.sha512).hexdigest()
    return ""


def jwt_analyzer():
    ui.module_header(22, "JWT Analyzer", "Analyse d'un JSON Web Token (entete, claims, signature)")
    ui.info("Collez votre JWT (3 parties base64url). Entree seule pour annuler.")
    token = ui.ask("JWT")
    if not token:
        ui.info("Aucun token fourni.")
        return
    try:
        data = decode_jwt(token)
    except Exception as exc:
        ui.err(f"Token illisible : {exc}")
        return
    header = data["header"]
    payload = data["payload"]
    ui.kv([
        ("Algorithmme", str(header.get("alg", "?"))),
        ("Type", str(header.get("typ", "-"))),
        ("Header", json.dumps(header, ensure_ascii=False)),
    ])
    print()
    ui.info("Claims :")
    rows = []
    for key, value in payload.items():
        shown = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
        if key in ("iat", "nbf", "exp", "auth_time", "updated_at") and isinstance(value, (int, float)):
            try:
                shown = f"{value}  ({datetime.fromtimestamp(value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
            except Exception:
                pass
        rows.append([key, shown[:70]])
    ui.table(["CLAIM", "VALEUR"], rows, widths=[26, 66])
    findings = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        findings.append(("CRITIQUE", "alg='none' — signature ignoree par les serveurs non rigoureux"))
    if alg.startswith("hs") and payload:
        findings.append(("INFO", "Signature HMAC symétrique (HS) — secret partage a proteger"))
    if alg and alg.startswith("rs"):
        findings.append(("OK", "Signature asymetrique (RS) — verify RS* cote serveur"))
    if not data["signature"]:
        findings.append(("CRITIQUE", "Partie signature absente du token"))
    for claim, label in (("exp", "Expiration"), ("iat", "Emis le"), ("nbf", "Valide apres")):
        if claim in payload and isinstance(payload[claim], (int, float)):
            moment = datetime.fromtimestamp(payload[claim], tz=timezone.utc)
            delta = (datetime.now(timezone.utc) - moment).total_seconds()
            if claim == "exp" and delta > 0:
                findings.append(("ALERTE", f"{label} depasse depuis {int(delta)} secondes — token expire"))
            elif claim == "iat" and delta < -60:
                findings.append(("ALERTE", f"{label} dans le futur (horloge desynchronisee ?)"))
    for risky in ("kid", "jku", "x5u", "jwk"):
        if risky in header:
            value = str(header[risky])
            if any(ch in value for ch in ("../", "'", "\"", "*", "%00")):
                findings.append(("CRITIQUE", f"Header '{risky}' suspect (injection possible) : {value[:40]}"))
            else:
                findings.append(("INFO", f"Header '{risky}' present — a verifier côté serveur"))
    if "role" in payload or "admin" in payload or "is_admin" in payload:
        findings.append(("ALERTE", "Claims de privilege presents — verifier l'autorisation cote serveur"))
    if data["signature"] and alg.startswith("hs"):
        print()
        if ui.confirm("Tester des secrets courants sur ce token ?", False):
            signing_input = ".".join(data["parts"][:2])
            expected = data["signature"]
            found = None
            with ui.Spinner("Test des secrets"):
                for secret in JWT_COMMON_SECRETS:
                    if _hs_verify(signing_input, secret, header.get("alg", "HS256")) == expected:
                        found = secret
                        break
            if found:
                findings.append(("CRITIQUE", f"Secret faible detecte : '{found}'"))
            else:
                ui.info("Aucun secret courant ne correspond.")
    print()
    if findings:
        ui.info("Resultats de l'analyse :")
        for level, message in findings:
            color = {"CRITIQUE": ui.R, "ALERTE": ui.Y, "INFO": ui.C, "OK": ui.G}[level]
            print("  " + ui.paint(f"[{level}]".ljust(10), color, ui.K) + message)
    ui.save_output("jwt", json.dumps({"header": header, "payload": payload}, ensure_ascii=False, indent=2))


def dir_brute():
    ui.module_header(18, "Directory Brute", "Decouverte de chemins et fichiers publics")
    ui.note("A utiliser uniquement sur des sites dont vous etes autorise a tester la securite.")
    target = normalize_url(ui.ask_required("URL de base (ex : https://site.tld)"))
    custom = ui.ask("Fichier wordlist (Entree = liste integree)")
    wordlist = DIR_WORDLIST
    if custom:
        try:
            with open(custom, "r", encoding="utf-8", errors="replace") as handle:
                wordlist = [w.strip() for w in handle if w.strip() and not w.startswith("#")]
        except Exception as exc:
            ui.err(f"Lecture impossible : {exc}")
            return
    threads = ui.ask_int("Threads", 10, 1, 50)
    base = target.rstrip("/")
    with ui.Spinner("Recherche d'un referentiel (soft-404)"):
        decoy = net.http_get(f"{base}/fckmt-{random.randint(100000, 999999)}", timeout=8)
    decoy_status = decoy.status
    decoy_len = len(decoy.content)
    ui.ok(f"{len(wordlist)} chemin(s) a tester (soft-404 : status {decoy_status})")
    found = []
    tested = 0

    def probe(path):
        url = f"{base}/{path.lstrip('/')}"
        resp = net.http_get(url, timeout=8)
        return path, url, resp

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(probe, path) for path in wordlist]
        for future in concurrent.futures.as_completed(futures):
            tested += 1
            ui.progress("Analyse", tested, len(wordlist))
            try:
                path, url, resp = future.result()
            except Exception:
                continue
            if resp.status in (0, 404):
                continue
            size = len(resp.content)
            soft = (resp.status == decoy_status and decoy_status in (200, 301, 302)
                    and decoy_len and abs(size - decoy_len) <= max(200, int(decoy_len * 0.05)))
            if soft:
                continue
            final = resp.url or url
            found.append((path, resp.status, size, final))
    ui.progress_done()
    if not found:
        ui.info("Aucun chemin supplementaire detecte.")
        return
    found.sort(key=lambda row: (row[1], row[0]))
    rows = []
    for path, status, size, final in found:
        note = ""
        if final.rstrip("/") != f"{base}/{path}".rstrip("/") and final:
            note = " -> " + final
        rows.append([path, str(status), str(size), note[:40]])
    ui.ok(f"{len(found)} chemin(s) interessant(s) :")
    ui.table(["CHEMIN", "STATUS", "TAILLE", "REDIRECTION"], rows, widths=[44, 9, 10, 40])
    interesting = [r for r in found if any(p in r[0].lower() for p in SENSITIVE_PATTERNS)]
    if interesting:
        print()
        ui.note(f"{len(interesting)} chemin(s) a verifier manuellement (fichiers sensibles/admin).")
    ui.save_output("dirbrute", "\n".join(f"{p} {s} {n}" for p, s, _, n in found))


CORS_TEST_ORIGINS = [
    "https://evil-fckmt.example",
    "null",
    "https://sub.evil-fckmt.example",
]


def cors_scan():
    ui.module_header(19, "CORS Scanner", "Verification des en-tetes Cross-Origin")
    url = normalize_url(ui.ask_required("URL a tester"))
    extra = ui.ask("Origine custom (Entree = ignoree)")
    origins = list(CORS_TEST_ORIGINS)
    if extra:
        origins.insert(0, extra)
    rows = []
    worst = "AUCUNE"
    host = urlparse(url).netloc
    for origin in origins:
        resp = net.http_get(url, timeout=10, headers={"Origin": origin})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if not acao:
            verdict = "pas de CORS"
            level = "OK"
        elif acao == "*":
            verdict = "wildcard *" + (" + credentielles" if acac.lower() == "true" else "")
            level = "CRITIQUE" if acac.lower() == "true" else "ALERTE"
        elif acao == origin:
            verdict = "origine refletee" + (" + credentielles" if acac.lower() == "true" else "")
            level = "CRITIQUE" if acac.lower() == "true" else "ALERTE"
        elif acao in (host, f"https://{host}", f"http://{host}"):
            verdict = "origine du site autorisee"
            level = "OK"
        else:
            verdict = f"reflet partiel : {acao[:40]}"
            level = "ALERTE"
        rows.append([origin, acao or "-", acac or "-", verdict])
        if level == "CRITIQUE":
            worst = "CRITIQUE"
        elif level == "ALERTE" and worst != "CRITIQUE":
            worst = "ALERTE"
    ui.table(["ORIGINE TESTEE", "ACAO", "ACAC", "VERDICT"], rows, widths=[30, 34, 8, 40])
    print()
    if worst == "CRITIQUE":
        ui.err("Configuration CORS permissive — une page attaquante peut lire les reponses authentifiees.")
    elif worst == "ALERTE":
        ui.info("CORS permissif a verifier (reflet d'origines non fiables).")
    else:
        ui.ok("Aucune origine non fiable refletee.")
    ui.save_output("cors", "\n".join(" | ".join(r) for r in rows))


TECH_MARKERS = [
    ("CDN / WAF", "Cloudflare", ["cf-ray", "cf-cache-status"], "header"),
    ("CDN / WAF", "Akamai", ["x-akamai-transform", "akamai-grn"], "header"),
    ("CDN / WAF", "Fastly", ["x-fastly-request-id", "x-served-by"], "header"),
    ("CDN / WAF", "AWS CloudFront", ["x-amz-cf-id", "x-amz-cf-pop"], "header"),
    ("CDN / WAF", "Sucuri", ["x-sucuri-id", "x-sucuri-cache"], "header"),
    ("CDN / WAF", "Imperva / Incapsula", ["x-iinfo", "incap_ses"], "header"),
    ("CDN / WAF", "F5 BIG-IP", ["bigipserver", "ts0"], "header"),
    ("CDN / WAF", "Azure Front Door", ["x-azure-ref", "x-msedge-ref"], "header"),
    ("CDN / WAF", "Varnish", ["x-varnish", "x-cache"], "header"),
    ("Serveur", "nginx", ["nginx"], "server"),
    ("Serveur", "Apache", ["apache"], "server"),
    ("Serveur", "Microsoft IIS", ["microsoft-iis", "iis"], "server"),
    ("Serveur", "LiteSpeed", ["litespeed"], "server"),
    ("Serveur", "Caddy", ["caddy"], "server"),
    ("Langage", "PHP", ["php/", "x-powered-by php"], "header"),
    ("Langage", "ASP.NET", ["asp.net"], "header"),
    ("Langage", "Java", ["jsessionid"], "cookie"),
    ("Langage", "Node.js / Express", ["connect.sid", "express"], "cookie"),
    ("CMS", "WordPress", ["wp-content", "wp-includes", "wordpress"], "body"),
    ("CMS", "Joomla", ["joomla!", "/media/jui/"], "body"),
    ("CMS", "Drupal", ["drupal-settings-json", "/sites/default/", "drupal"], "body"),
    ("CMS", "Shopify", ["shopify", "cdn.shopify.com"], "body"),
    ("CMS", "Wix", ["wix.com", "wixstatic.com"], "body"),
    ("CMS", "PrestaShop", ["prestashop", "prestashop."], "body"),
    ("CMS", "Magento", ["mage/", "Magento"], "body"),
    ("Framework", "Laravel", ["laravel_session", "xsrf-token"], "cookie"),
    ("Framework", "Django", ["csrftoken", "django"], "cookie"),
    ("Framework", "Ruby on Rails", ["_rails_session"], "cookie"),
    ("Framework", "Next.js", ["__next", "_next/static"], "body"),
    ("Framework", "Nuxt.js", ["_nuxt", "__nuxt"], "body"),
    ("Framework", "Vue.js", ["vue.", "data-v-"], "body"),
    ("Framework", "React", ["react.production", "data-reactroot"], "body"),
    ("Analyse", "Google Analytics", ["googletagmanager", "google-analytics.com", "ga.js"], "body"),
    ("Analyse", "Matomo", ["matomo", "piwik"], "body"),
    ("Analyse", "Hotjar", ["hotjar"], "body"),
    ("Analyse", "Facebook Pixel", ["fbq(", "connect.facebook.net"], "body"),
]


def tech_fingerprint():
    ui.module_header(20, "Tech Fingerprint", "Detection CDN/WAF, CMS, frameworks et scripts")
    url = normalize_url(ui.ask_required("URL du site"))
    with ui.Spinner("Telechargement de la page"):
        resp = net.http_get(url, timeout=15)
    if resp.status == 0:
        ui.err("Connexion impossible.")
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = (resp.text or "")[:120000].lower()
    cookies = (headers.get("set-cookie") or "").lower()
    server_blob = (headers.get("server") or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()
    header_blob = " ".join(f"{k} {v}" for k, v in headers.items()).lower()
    rows = []
    for category, name, markers, where in TECH_MARKERS:
        hit = ""
        for marker in markers:
            marker_l = marker.lower()
            if where == "header" and marker_l in header_blob:
                hit = "en-tete " + marker
            elif where == "server" and marker_l in server_blob:
                hit = "server: " + headers.get("server", "")
            elif where == "cookie" and marker_l in cookies:
                hit = "cookie " + marker
            elif where == "body" and marker_l in body:
                hit = "corps de page"
            if hit:
                break
        if hit:
            rows.append([category, name, hit[:44]])
    ui.kv([
        ("URL finale", resp.url or url),
        ("Status", str(resp.status)),
        ("Serveur", headers.get("server", "-")),
        ("Powered-By", headers.get("x-powered-by", "-")),
        ("Titre", (re.search(r"<title[^>]*>(.*?)</title>", resp.text or "", re.I | re.S).group(1).strip()[:60]
                   if re.search(r"<title[^>]*>(.*?)</title>", resp.text or "", re.I | re.S) else "-")),
        ("Taille", f"{len(resp.content)} octets"),
    ])
    print()
    if not rows:
        ui.info("Aucune signature forte detectee.")
    else:
        ui.ok(f"{len(rows)} signature(s) detectee(s)")
        ui.table(["CATEGORIE", "TECHNOLOGIE", "INDICE"], rows, widths=[16, 30, 44])
    wafs = [r for r in rows if r[0] == "CDN / WAF"]
    if wafs:
        print()
        ui.note("Protection perimetrantee detectee : les tests agressifs seront ralentis/geo-bloques.")
    ui.save_output("fingerprint", "\n".join(" | ".join(r) for r in rows))


WAYBACK_SENSITIVE = [
    ".env", ".git", ".svn", "backup", ".bak", ".sql", ".zip", ".tar",
    ".rar", "password", "passwd", "admin", "login", "wp-admin", "config",
    "secret", "credential", "id_rsa", "dump", "export", ".php~", ".old",
]


def wayback_history():
    ui.module_header(21, "Wayback URL History", "URLs historisees par l'archive web (CDX)")
    domain = ui.ask_required("Domaine (ex : example.com)").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    limit = ui.ask_int("Nombre d'URLs a recuperer", 300, 10, 5000)
    year_from = annee_vers = ""
    if ui.confirm("Filtrer par periode (annees) ?", False):
        year_from = ui.ask("Annee de debut (ex : 2019)")
        annee_vers = ui.ask("Annee de fin (ex : 2024)")
    params = (f"url={domain}&matchType=domain&collapse=urlkey&limit={limit}"
              "&fl=timestamp,original,statuscode,mimetype&output=json")
    if year_from:
        params += f"&from={year_from}"
    if annee_vers:
        params += f"&to={annee_vers}"
    api = f"http://web.archive.org/cdx/search/cdx?{params}"
    with ui.Spinner("Interrogation de web.archive.org"):
        resp = net.http_get(api, timeout=45)
    if resp.status != 200:
        ui.err(f"Reponse HTTP {resp.status} de l'archive web.")
        return
    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse illisible (JSON attendu).")
        return
    if not data or len(data) < 2:
        ui.info("Aucune URL archivee pour ce domaine.")
        return
    header, raw_rows = data[0], data[1:]
    rows = []
    for item in raw_rows:
        rec = dict(zip(header, item))
        rows.append([rec.get("timestamp", "")[:8], rec.get("original", ""),
                     rec.get("statuscode", ""), rec.get("mimetype", "")])
    ui.ok(f"{len(rows)} URL(s) unique(s) archivee(s)")
    ext_count = {}
    for _, original, _, _ in rows:
        path = urlparse(original).path
        last = path.rsplit("/", 1)[-1]
        ext = last.rsplit(".", 1)[-1].lower() if "." in last else "-"
        ext_count[ext] = ext_count.get(ext, 0) + 1
    top_ext = sorted(ext_count.items(), key=lambda kv: -kv[1])[:10]
    ui.table(["EXTENSION", "NOMBRE"], [[k, str(v)] for k, v in top_ext], widths=[20, 12])
    sensitive = [r for r in rows if any(p in r[1].lower() for p in WAYBACK_SENSITIVE)]
    if sensitive:
        print()
        ui.note(f"{len(sensitive)} URL(s) a inspecter (fichiers/espaces sensibles) :")
        ui.table(["DATE", "URL", "ST", "TYPE"], sensitive[:25], widths=[10, 66, 6, 12])
    else:
        print()
        ui.ok("Aucune URL evidentement sensible dans l'echantillon.")
    ui.save_output("wayback", "\n".join(r[1] for r in rows))
