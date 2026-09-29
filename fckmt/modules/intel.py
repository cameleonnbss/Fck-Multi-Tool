import hashlib
import json
import re
import sys

from .. import ui, net

IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]|(\b\d{1,3}(?:\.\d{1,3}){3})\b")


def _extract_ips(text):
    found = []
    for match in IP_RE.finditer(text):
        ip = match.group(1) or match.group(2)
        if ip:
            found.append(ip)
    return found


def shodan_internetdb():
    ui.module_header(35, "Shodan InternetDB", "Ports, services et CVE connus d'une IP (gratuit, sans cle)")
    value = ui.ask_required("Adresse IP ou domaine")
    ip = value.strip()
    if not net.is_ip(ip):
        resolved = net.resolve(ip)
        if not resolved:
            ui.err("Resolution DNS impossible.")
            return
        ui.info(f"{ip} -> {resolved}")
        ip = resolved
    with ui.Spinner("Interrogation de internetdb.shodan.io"):
        resp = net.http_get(f"https://internetdb.shodan.io/{ip}", timeout=15)
    if resp.status == 404:
        ui.info("Aucune donnee publique pour cette IP dans InternetDB.")
        return
    if resp.status != 200:
        ui.err(f"Reponse HTTP {resp.status}.")
        return
    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse illisible.")
        return
    ui.ok(f"Fiche InternetDB pour {ip}")
    ui.kv([
        ("Hotes", str(data.get("hostnames", "-")).strip("[]").replace("'", "")),
        ("Domaines", str(data.get("domains", "-")).strip("[]").replace("'", "")),
        ("Tags", ", ".join(data.get("tags", [])) or "-"),
        ("Operations", ", ".join(data.get("ops", [])) or "-"),
    ])
    ports = data.get("ports", [])
    if ports:
        print()
        ui.info(f"Ports ouverts ({len(ports)}) :")
        print("  " + ui.paint(", ".join(str(p) for p in sorted(ports)), ui.W))
    vulns = data.get("vulns", [])
    if vulns:
        print()
        ui.note(f"{len(vulns)} CVE connue(s) associee(s) :")
        for cve in sorted(vulns):
            print("  " + ui.paint(cve, ui.Y))
    else:
        print()
        ui.ok("Aucune CVE connue dans cette base.")
    ui.save_output("internetdb", json.dumps(data, indent=2, ensure_ascii=False))


def _pwned_range(prefix, timeout=15):
    resp = net.http_get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=timeout)
    if resp.status != 200:
        raise RuntimeError(f"HTTP {resp.status}")
    result = {}
    for line in resp.text.splitlines():
        if ":" in line:
            digest, count = line.split(":", 1)
            result[digest.strip().upper()] = int(count.strip() or 0)
    return result


def password_breach_check():
    ui.module_header(36, "Password Breach Check", "Verification k-anonymat via Have I Been Pwned")
    ui.note("Le mot de passe ne quitte jamais votre machine : seul son hash SHA-1 tronque (5 caracteres) part.")
    if sys.stdin.isatty():
        try:
            import getpass

            password = getpass.getpass("  Mot de passe (saisie masquee) : ")
        except Exception:
            password = ui.ask("Mot de passe")
    else:
        password = ui.ask("Mot de passe (saisie masquee)")
    if not password:
        ui.info("Aucun mot de passe fourni.")
        return
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    ui.info(f"Prehash SHA-1 : {prefix}...")
    try:
        with ui.Spinner("Consultation de l'API pwnedpasswords"):
            matches = _pwned_range(prefix)
    except Exception as exc:
        ui.err(f"API inaccessible : {exc}")
        return
    count = matches.get(suffix, 0)
    if count:
        ui.err(f"Mot de passe vu {count} fois dans les fuites connues — a changer immediatement.")
    else:
        ui.ok("Aucune occurrence dans les fuites connues (ne garantit pas qu'il soit robuste).")
    ui.kv([
        ("Longueur", str(len(password))),
        ("SHA-1 tronque", prefix),
        ("Occurrences", str(count)),
    ])


def _unfold(text):
    lines = []
    for line in str(text).splitlines():
        if line[:1] in (" ", "\t") and lines:
            lines[-1] += " " + line.strip()
        else:
            lines.append(line.rstrip())
    return lines


def parse_email_header(text):
    result = {
        "from": "", "to": "", "subject": "", "return_path": "", "message_id": "",
        "date": "", "auth": {}, "hops": [], "mailer": "", "list_unsubscribe": "",
    }
    for line in _unfold(text):
        low = line.lower().strip()
        if low.startswith("return-path:"):
            result["return_path"] = line.split(":", 1)[1].strip()
        elif low.startswith("from:"):
            result["from"] = line.split(":", 1)[1].strip()
        elif low.startswith("to:"):
            result["to"] = line.split(":", 1)[1].strip()
        elif low.startswith("subject:"):
            result["subject"] = line.split(":", 1)[1].strip()
        elif low.startswith("message-id:"):
            result["message_id"] = line.split(":", 1)[1].strip()
        elif low.startswith("date:"):
            result["date"] = line.split(":", 1)[1].strip()
        elif low.startswith("x-mailer:"):
            result["mailer"] = line.split(":", 1)[1].strip()
        elif low.startswith("list-unsubscribe:"):
            result["list_unsubscribe"] = line.split(":", 1)[1].strip()
        elif low.startswith("authentication-results:") or low.startswith("received-spf:"):
            for key in ("spf", "dkim", "dmarc"):
                match = re.search(rf"{key}\s*=\s*(\w+)", line, re.I)
                if match:
                    result["auth"][key] = match.group(1).lower()
    received = [l for l in _unfold(text) if l.lower().strip().startswith("received:")]
    for raw in received:
        ips = _extract_ips(raw)
        result["hops"].append({
            "raw": re.sub(r"\s+", " ", raw.strip())[:160],
            "ip": ips[-1] if ips else "",
        })
    return result


def email_header_analysis():
    ui.module_header(37, "Email Header Analyzer", "Trace Received, SPF/DKIM/DMARC et origine")
    ui.info("Collez l'en-tete complet puis une ligne vide pour terminer.")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    if not lines:
        ui.info("Aucun en-tete fourni.")
        return
    data = parse_email_header("\n".join(lines))
    ui.kv([
        ("De", data["from"] or "-"),
        ("Pour", data["to"] or "-"),
        ("Sujet", data["subject"] or "-"),
        ("Return-Path", data["return_path"] or "-"),
        ("Message-ID", data["message_id"] or "-"),
        ("Date", data["date"] or "-"),
        ("Mail-Client", data["mailer"] or "-"),
        ("List-Unsubscribe", data["list_unsubscribe"] or "-"),
    ])
    print()
    if data["auth"]:
        ui.info("Resultats d'authentification :")
        for key, value in data["auth"].items():
            color = ui.G if value in ("pass", "pass ") else ui.R if value == "fail" else ui.Y
            print("  " + ui.paint(f"{key.upper()}".ljust(8), color, ui.K) + value)
    else:
        ui.info("Aucun en-tete d'authentification (SPF/DKIM/DMARC) trouve.")
    if data["hops"]:
        print()
        ui.info(f"{len(data['hops'])} saut(s) Received :")
        rows = []
        for i, hop in enumerate(reversed(data["hops"]), 1):
            rows.append([str(i), hop["ip"] or "-", hop["raw"][:90]])
        ui.table(["#", "IP", "SAUT"], rows, widths=[4, 18, 84])
        origin = data["hops"][-1]["ip"] if data["hops"] else ""
        if origin:
            ui.note(f"Serveur d'origine (premier saut) : {origin}")
    ui.save_output("email_header", "\n".join(lines))


def cve_lookup():
    ui.module_header(38, "CVE Lookup", "Recherche de vulnerabilites (NVD, base officielle NIST)")
    query = ui.ask_required("Identifiant CVE (CVE-2024-1234) ou mot-cle")
    query = query.strip()
    if re.match(r"^CVE-\d{4}-\d{4,}$", query, re.I):
        api = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query.upper()}"
    else:
        from urllib.parse import quote_plus

        api = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(query)}&resultsPerPage=10"
    with ui.Spinner("Interrogation du NVD (peut prendre 5-10 s)"):
        resp = net.http_get(api, timeout=30)
    if resp.status == 403:
        ui.err("Rate-limit NVD (5 requetes / 30 s sans cle API). Reessayez dans un instant.")
        return
    if resp.status != 200:
        ui.err(f"Reponse HTTP {resp.status}.")
        return
    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse illisible.")
        return
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        ui.info("Aucun resultat.")
        return
    rows = []
    details = []
    for item in vulns[:10]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")
        published = (cve.get("published") or "")[:10]
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score, severity = "", ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                entry = metrics[key][0].get("cvssData", {})
                score = str(entry.get("baseScore", ""))
                severity = entry.get("baseSeverity", "") or metrics[key][0].get("baseSeverity", "")
                break
        rows.append([cve_id, published, score or "-", severity or "-", desc[:70]])
        details.append((cve_id, desc))
    ui.ok(f"{len(vulns)} resultat(s)")
    ui.table(["CVE", "PUBLIE", "SCORE", "SEVERITE", "DESCRIPTION"], rows,
             widths=[18, 12, 8, 12, 62])
    print()
    for cve_id, desc in details[:5]:
        ui.kv([(cve_id, desc[:300])])
    ui.save_output("cve", "\n".join(f"{r[0]} | {r[1]} | {r[2]} | {r[4]}" for r in rows))
