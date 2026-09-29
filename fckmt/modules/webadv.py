"""Modules 24-26 — avancee web : CT, fuzzing d'injection, urlscan.io."""
import concurrent.futures
import json
import time
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from .. import ui, net
from .web import normalize_url

TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure Cloud",
    "trafficmanager.net": "Azure Traffic Manager",
    "amazonaws.com": "AWS/S3",
    "cloudfront.net": "CloudFront",
    "elasticbeanstalk.com": "Elastic Beanstalk",
    "herokuapp.com": "Heroku",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com",
    "fastly.net": "Fastly",
    "edgekey.net": "Akamai",
    "zendesk.com": "Zendesk",
    "readthedocs.io": "ReadTheDocs",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket Pages",
    "webflow.io": "Webflow",
    "netlify.com": "Netlify",
    "wixsite.com": "Wix",
    "squarespace.com": "Squarespace",
}

SQL_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' OR 1=1--",
    "1' UNION SELECT NULL--",
    "1' AND '1'='1",
    "1); SELECT 1--",
    "1' ORDER BY 99--",
    "' OR ''='",
]

SQL_ERRORS = [
    "sql syntax", "mysql", "you have an error in your sql", "ora-",
    "postgresql", "pg_query", "sqlite", "sqlstate", "mysqli",
    "unclosed quotation mark", "quoted string not properly terminated",
    "microsoft oledb", "odbc sql server driver", "warning: mysql_",
    "syntax error at line", "unterminated string",
]

XSS_PAYLOADS = [
    "<script>fckxss7</script>",
    "\"><img src=x onerror=fckxss7>",
    "'-alert(fckxss7)-'",
    "<svg/onload=fckxss7()>",
    "javascript:fckxss7()",
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "..%252f..%252fetc%252fpasswd",
]

TRAVERSAL_SIGNATURES = [
    "root:x:", "root:*:", "daemon:", "/bin/bash", "/bin/sh",
    "[fonts]", "[extensions]", "[mci extensions]",
]


def cert_transparency():
    ui.module_header(24, "Cert-Transparency", "Sous-domaines certifies (crt.sh) + CNAME suspendus")
    raw = ui.ask_required("Domaine (exemple.com)")
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    domain = (parsed.hostname or "").lower().strip(".")
    if not domain or "." not in domain or " " in domain:
        ui.err("Domaine invalide.")
        return
    resp = None
    with ui.Spinner("Interrogation de crt.sh (10 a 30 s)"):
        for attempt in range(3):
            resp = net.http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=45)
            if resp.status == 200:
                break
            time.sleep(2.0)
    if resp is None or resp.status != 200:
        code = resp.status if resp else 0
        ui.err(f"crt.sh injoignable (HTTP {code}) — reessaie dans quelques minutes.")
        return
    try:
        rows = json.loads(resp.text)
    except Exception:
        ui.err("Reponse crt.sh illisible (pas du JSON).")
        return
    if not isinstance(rows, list):
        ui.err("Structure crt.sh inattendue.")
        return
    names = {}
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith("." + domain)):
                names.setdefault(name, str(row.get("not_before", ""))[:10])
    subs = sorted(names)
    if not subs:
        ui.info("Aucun certificat publie pour ce domaine.")
        return
    ui.ok(f"{len(subs)} nom(s) certifie(s) via crt.sh")
    ui.table(
        ["Nom certifie", "Premier certificat"],
        [[s, names[s] or "-"] for s in subs[:40]],
        widths=[46, 18],
    )
    if len(subs) > 40:
        ui.info(f"... +{len(subs) - 40} dans le fichier sauvegarde.")

    work = subs[:400]
    alive = []
    with ui.Spinner(f"Resolution DNS de {len(work)} noms (max 400)"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = {pool.submit(net.resolve, s): s for s in work}
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    if future.result():
                        alive.append(target)
                except Exception:
                    continue
    ui.ok(f"{len(alive)} nom(s) resolu(s) vers une IP")
    if alive:
        shown = ", ".join(sorted(alive)[:30])
        print("  " + ui.paint(shown + (" ..." if len(alive) > 30 else ""), ui.W))

    warns = []
    with ui.Spinner("Detection de CNAME suspendus (risque de prise de domaine)"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(net.dns_query, s, "CNAME"): s for s in alive}
            for future in concurrent.futures.as_completed(futures):
                source = futures[future]
                try:
                    targets = future.result() or []
                except Exception:
                    continue
                for value in targets:
                    pointee = str(value).lower().rstrip(".")
                    for suffix, label in TAKEOVER_SERVICES.items():
                        if pointee == suffix or pointee.endswith("." + suffix):
                            warns.append((source, pointee, label))
    if warns:
        warns = sorted(set(warns))
        ui.note(f"{len(warns)} CNAME oriente(s) vers un service a risque (a verifier manuellement) :")
        ui.table(["Nom", "CNAME", "Service"], warns, widths=[34, 36, 24])
    else:
        ui.ok("Aucun CNAME vers un service a risque de prise de domaine.")

    lines = [f"# crt.sh - {domain}", ""]
    lines += subs
    if warns:
        lines += ["", "# CNAME suspects :"] + [f"{a} -> {b} ({c})" for a, b, c in warns]
    ui.save_output("crtsh", "\n".join(lines))


def injection_fuzzer():
    ui.module_header(25, "Injection-Fuzzer", "Fuzzing de parametre d'URL : SQLi, XSS reflet, traversal")
    ui.note("A tester uniquement sur des systemes dont vous etes autorise a evaluer la securite.")
    target = ui.ask_required("URL avec parametre (https://site.tld/page?id=1)").strip()
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        ui.err("URL invalide.")
        return
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if not query:
        param = ui.ask_required("Nom du parametre a fuzz (ex : id)").strip()
        if not param:
            return
        query = [(param, "1")]
    elif len(query) > 1:
        param = ui.ask_choice("Parametre a fuzz", [k for k, _ in query], default=query[0][0])
    else:
        param = query[0][0]
    base_items = dict(query)

    def build_url(payload):
        items = dict(base_items)
        items[param] = payload
        return parsed._replace(query=urlencode(items, doseq=True)).geturl()

    def fetch(url):
        try:
            return net.http_get(url, timeout=12)
        except Exception:
            return None

    print()
    with ui.Spinner("Requete de base (benchmark)"):
        baseline = fetch(target)
    if baseline is None or baseline.status == 0:
        ui.err("Cible injoignable.")
        return
    baseline_text = baseline.text or ""
    baseline_len = len(baseline_text)
    baseline_lower = baseline_text.lower()
    ui.info(f"Base : HTTP {baseline.status}, {baseline_len} octets, parametre « {param} »")

    findings = []
    total = len(SQL_PAYLOADS) + len(XSS_PAYLOADS) + len(TRAVERSAL_PAYLOADS)
    step = 0
    limited = False

    for family, payloads in (("SQLi", SQL_PAYLOADS), ("XSS", XSS_PAYLOADS), ("Traversal", TRAVERSAL_PAYLOADS)):
        for payload in payloads:
            step += 1
            ui.progress(f"Fuzz {family}", step, total)
            resp = fetch(build_url(payload))
            time.sleep(0.12)
            if resp is None or resp.status == 0:
                findings.append([family, payload, "erreur reseau", "-"])
                continue
            if resp.status == 429:
                ui.progress_done()
                ui.note("Rate-limit HTTP 429 : arret premature du fuzz.")
                limited = True
                break
            text = resp.text or ""
            lower = text.lower()
            if family == "SQLi":
                hit = next((s for s in SQL_ERRORS if s in lower and s not in baseline_lower), None)
                if hit:
                    findings.append([family, payload, "SQLi probable", hit[:40]])
                elif resp.status != baseline.status and resp.status not in (301, 302, 403):
                    findings.append([family, payload, "statut change", f"{baseline.status} -> {resp.status}"])
            elif family == "XSS":
                marker = "fckxss7"
                if marker in text and marker not in baseline_lower:
                    escaped = ("&lt;script" in lower) or ("%3cscript" in lower)
                    verdict = "reflet echappe" if escaped else "reflet NON echappe"
                    findings.append([family, payload, verdict, marker])
            else:
                hit = next((s for s in TRAVERSAL_SIGNATURES if s in lower and s not in baseline_lower), None)
                if hit:
                    findings.append([family, payload, "fuite fichier probable", hit])
            if len(text) != baseline_len and abs(len(text) - baseline_len) > max(200, baseline_len // 2):
                findings.append([family, payload, "reponse alteree", f"{baseline_len} -> {len(text)} octets"])
        if limited:
            break
    ui.progress_done()

    real = [row for row in findings if row[2] in ("SQLi probable", "fuite fichier probable", "reflet NON echappe", "statut change")]
    if real:
        ui.note(f"{len(real)} indice(s) d'interet (vrais positifs possibles — confirmer manuellement) :")
        ui.table(["Famille", "Payload", "Verdict", "Preuve"], real, widths=[10, 34, 24, 34])
    else:
        ui.ok("Aucun indice exploitable sur les payloads essayes.")
    if findings and len(findings) != len(real):
        ui.info(f"{len(findings)} evenement(s) brut(s) dans le rapport.")
    ui.save_output(
        "fuzz",
        f"Cible : {target}\nParametre : {param}\nBase : HTTP {baseline.status}, {baseline_len} octets\n\n"
        + "\n".join(" | ".join(row) for row in findings),
    )


def urlscan_search():
    ui.module_header(26, "URLScan-Search", "Scans publics urlscan.io d'un domaine (captures, verdicts)")
    raw = ui.ask_required("Domaine ou URL (exemple.com)")
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    domain = (parsed.hostname or raw).lower().strip(".")
    if not domain or " " in domain:
        ui.err("Domaine invalide.")
        return
    query = quote(f"domain:{domain}")
    with ui.Spinner("Interrogation de l'API urlscan.io"):
        resp = net.http_get(
            f"https://urlscan.io/api/v1/search/?q={query}&size=20",
            timeout=25,
            headers={"User-Agent": "fck-multi-tool/1.2"},
        )
    if resp.status == 429:
        ui.note("Rate-limit urlscan.io — reessaie dans quelques minutes.")
        return
    if resp.status != 200:
        ui.err(f"urlscan.io : reponse HTTP {resp.status}.")
        return
    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse urlscan.io illisible.")
        return
    results = data.get("results", [])
    if not results:
        ui.info(f"Aucun scan public indexe pour {domain}.")
        return
    total = data.get("total", len(results))
    ui.ok(f"{len(results)} scan(s) public(s) (total indexe : {total})")
    rows = []
    report_lines = []
    for item in results:
        task = item.get("task", {})
        page = item.get("page", {})
        verdict = item.get("verdicts", {}).get("overall", {}) or {}
        score = verdict.get("score", 0) or 0
        malicious = bool(verdict.get("malicious"))
        if malicious:
            mark = "MALVEILLANT"
        elif score >= 50:
            mark = f"suspect ({score})"
        elif score > 0:
            mark = f"limite ({score})"
        else:
            mark = "propre"
        when = str(task.get("time", ""))[:19].replace("T", " ")
        url = page.get("url", item.get("result", ""))
        title = str(page.get("title", ""))[:38]
        rows.append([when, url[:52], title, mark])
        report_lines.append(f"{when} | {mark} | {url} | {title}")
    ui.table(["Date", "URL capturee", "Titre", "Verdict"], rows, widths=[18, 52, 38, 18])
    bad = [r for r in rows if r[3] in ("MALVEILLANT",) or r[3].startswith("suspect")]
    if bad:
        ui.note(f"{len(bad)} capture(s) avec verdict hostile ou suspect.")
    ui.save_output("urlscan", f"# urlscan.io - {domain}\n\n" + "\n".join(report_lines))
