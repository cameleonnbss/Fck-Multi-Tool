"""Modules 38-42 — OSINT avance : comptes email, fuites, Instagram, dorks, Roblox."""
import json
import re
import time
from urllib.parse import quote, urlparse

from .. import ui, net

RESET_SITES = [
    ("Facebook", "https://www.facebook.com/recover/initiate", "post"),
    ("Instagram", "https://www.instagram.com/accounts/password/reset/", "post"),
    ("Snapchat", "https://accounts.snapchat.com/accounts/password/reset", "post"),
    ("Pinterest", "https://www.pinterest.com/reset/", "post"),
    ("TikTok", "https://www.tiktok.com/login/forgot-password", "post"),
    ("Reddit", "https://www.reddit.com/password", "post"),
    ("GitHub", "https://github.com/password_reset", "post"),
    ("LinkedIn", "https://www.linkedin.com/uas/request-password-reset", "post"),
    ("Discord", "https://discord.com/api/v9/auth/forgot", "post"),
    ("Spotify", "https://accounts.spotify.com/en/password-reset", "post"),
    ("Netflix", "https://www.netflix.com/password", "post"),
    ("Amazon", "https://www.amazon.com/ap/forgotpassword", "post"),
    ("Microsoft", "https://account.live.com/password/reset", "post"),
    ("Dropbox", "https://www.dropbox.com/forgot", "post"),
    ("Twitch", "https://www.twitch.tv/user/password_reset", "post"),
    ("Steam", "https://store.steampowered.com/login/forgotpassword", "post"),
]

RESET_KEYWORDS = [
    "sent", "check your email", "email has been", "recovery", "reset",
    "verify", "we've sent", "instructions have been", "un email",
    "veuillez verifier", "a ete envoye",
]

FCK_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def email_accounts_checker():
    ui.module_header(38, "Email-Accounts-Checker", "Quelles plateformes ont un compte pour cet email (heuristique)")
    ui.note("Heuristique via pages de reinitialisation : resultat probable, pas une preuve. Emails que vous etes autorise a tester.")
    email = ui.ask_required("Adresse email").strip()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        ui.err("Email invalide.")
        return
    headers = {"User-Agent": FCK_UA, "Accept": "text/html,application/xhtml+xml,application/json"}
    found, unknown, dead, errors = [], [], [], []
    total = len(RESET_SITES)
    for index, (name, url, method) in enumerate(RESET_SITES, 1):
        ui.progress(f"Verification {name}", index, total)
        try:
            if method == "post":
                resp = net.http_post(url, data={"email": email}, timeout=7, headers=headers)
            else:
                resp = net.http_get(url, timeout=7, headers=headers)
        except Exception:
            resp = None
        time.sleep(0.1)
        if resp is None or resp.status == 0:
            errors.append(name)
            continue
        text = (resp.text or "").lower()
        if resp.status == 404:
            dead.append(name)
        elif resp.status in (429, 403) or "captcha" in text or "cloudflare" in text[:2000]:
            unknown.append(name)
        elif any(word in text for word in RESET_KEYWORDS):
            found.append(name)
        else:
            unknown.append(name)
    ui.progress_done()

    rows = []
    for name, _url, _m in RESET_SITES:
        if name in found:
            verdict = "probablement inscrit"
        elif name in dead:
            verdict = "inconnu (404)"
        elif name in errors:
            verdict = "erreur reseau"
        else:
            verdict = "indecide"
        rows.append([name, verdict])
    ui.table(["Plateforme", "Resultat"], rows, widths=[26, 30])
    print()
    if found:
        ui.ok(f"{len(found)} plateforme(s) probablement liee(s) : {', '.join(found)}")
    else:
        ui.info("Aucun compte « probable » detecte (les heuristiques taillent beaucoup).")
    ui.save_output(
        "email_accounts",
        f"Email : {email}\n\n" + "\n".join(f"{n} | {v}" for n, v in rows),
    )


def email_breach_xon():
    ui.module_header(39, "Email-Breach-Check", "Fuites et pastes d'un email via XposedOrNot (gratuit, sans cle)")
    email = ui.ask_required("Adresse email").strip()
    if "@" not in email:
        ui.err("Email invalide.")
        return
    mode = ui.ask_choice("Contenu a verifier", ["Fuites (breaches)", "Pastes", "Les deux"], default="Fuites (breaches)")
    headers = {"User-Agent": "fck-multi-tool/1.2"}
    base = "https://api.xposedornot.com/v1"
    report = [f"Email : {email}", ""]

    if mode in ("Fuites (breaches)", "Les deux"):
        with ui.Spinner("Interrogation XposedOrNot (breaches)"):
            resp = net.http_get(f"{base}/check-email/{quote(email, safe='')}", timeout=15, headers=headers)
        if resp.status == 429:
            ui.note("Rate-limit XposedOrNot (100 requetes/jour/IP) — reessaie plus tard.")
        elif resp.status == 404:
            ui.ok("Email absent des fuites connues par XposedOrNot.")
            report.append("Breaches : aucune")
        elif resp.status == 200:
            try:
                data = json.loads(resp.text)
                breaches = data.get("breaches", [])
                flat = [b[0] if isinstance(b, list) else str(b) for b in breaches]
            except Exception:
                ui.err("Reponse XposedOrNot illisible.")
                return
            if flat:
                ui.note(f"{len(flat)} fuite(s) connue(s) :")
                for name in flat:
                    print("  " + ui.paint("[!] " + name, ui.R))
                report.append("Breaches : " + ", ".join(flat))
            else:
                ui.ok("Aucune fuite connue pour cet email.")
                report.append("Breaches : aucune")
        else:
            ui.err(f"XposedOrNot : HTTP {resp.status}.")
            report.append(f"Breaches : HTTP {resp.status}")

    if mode in ("Pastes", "Les deux"):
        with ui.Spinner("Recherche de pastes"):
            resp = net.http_get(f"{base}/pastes?email={quote(email, safe='')}", timeout=15, headers=headers)
        print()
        if resp.status == 429:
            ui.note("Rate-limit XposedOrNot sur les pastes.")
        elif resp.status == 404:
            ui.ok("Aucun paste publique indexe pour cet email.")
            report.append("Pastes : aucun")
        elif resp.status == 200:
            try:
                data = json.loads(resp.text)
                pastes = data.get("pastes", [])
            except Exception:
                pastes = []
            if pastes:
                ui.note(f"{len(pastes)} paste(s) :")
                for paste in pastes[:20]:
                    if isinstance(paste, dict):
                        src = paste.get("source", "?")
                        count = paste.get("email_count", paste.get("paste_count", "?"))
                        print(f"  {ui.paint('[+] ', ui.W)}{src} ({count} entrees)")
                        report.append(f"Paste : {src} ({count})")
                    else:
                        print(f"  {ui.paint('[+] ', ui.W)}{paste}")
                        report.append(f"Paste : {paste}")
            else:
                ui.ok("Reponse vide : aucun paste indexe.")
                report.append("Pastes : aucun")
        else:
            ui.err(f"Pastes : HTTP {resp.status}.")

    ui.save_output("email_breach", "\n".join(report))


def instagram_osint():
    ui.module_header(40, "Instagram-OSINT", "Profil public Instagram (API web, sans cle API)")
    login = ui.ask_required("Pseudo (sans @)").strip().lstrip("@")
    if not login or " " in login:
        ui.err("Pseudo invalide.")
        return
    headers = {
        "User-Agent": "Instagram 155.0.0.37.107 Android",
        "X-IG-App-ID": "567067343352427",
        "Accept": "*/*",
        "Accept-Language": "fr-FR,fr;q=0.9",
    }
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={quote(login)}"
    with ui.Spinner("Interrogation de instagram.com"):
        resp = net.http_get(url, timeout=15, headers=headers)
    if resp.status == 404:
        ui.err("Compte introuvable (ou pseudo retire).")
        return
    if resp.status != 200:
        ui.err(f"Instagram a refuse la requete (HTTP {resp.status}) — reessaie plus tard ou change de reseau.")
        return
    try:
        user = json.loads(resp.text)["data"]["user"]
    except Exception:
        ui.err("Reponse Instagram illisible.")
        return
    if not user:
        ui.info("Profil vide ou masque.")
        return
    ui.ok(f"@{user.get('username', login)}")
    edge_f = user.get("edge_followed_by", {}).get("count", 0)
    edge_t = user.get("edge_follow_to", {}).get("count", 0)
    edge_m = user.get("edge_owner_to_timeline_media", {}).get("count", 0)
    ui.kv([
        ("Nom complet", str(user.get("full_name") or "-")),
        ("ID utilisateur", str(user.get("id", "-"))),
        ("Biographie", (str(user.get("biography") or "-")).replace("\n", " ")[:90]),
        ("Categorie", str(user.get("category_name") or "-")),
        ("Abonnes", str(edge_f)),
        ("Abonnements", str(edge_t)),
        ("Publications", str(edge_m)),
        ("Verifie", "oui" if user.get("is_verified") else "non"),
        ("Profil prive", "oui" if user.get("is_private") else "non"),
        ("Site web", str(user.get("external_url") or "-")),
        ("Profile pic", str(user.get("profile_pic_url_hd") or "-")[:90]),
    ])
    ui.save_output("instagram", json.dumps(user, ensure_ascii=False, indent=2), ext="json")


def dork_builder():
    ui.module_header(41, "Dork-Builder", "Generateur de dorks d'identite (personne, compte, entreprise)")
    ui.info("Champs optionnels — Entree pour passer.")
    first = ui.ask("Prenom", default="").strip()
    last = ui.ask("Nom", default="").strip()
    username = ui.ask("Pseudo", default="").strip()
    email = ui.ask("Email", default="").strip()
    phone = ui.ask("Telephone", default="").strip()
    domain = ui.ask("Domaine / site", default="").strip()
    company = ui.ask("Entreprise", default="").strip()

    dorks = []
    names = []
    if first and last:
        names.append(f"{first} {last}")
    if first:
        names.append(first)
    if last:
        names.append(last)
    for name in names:
        dorks += [
            ("Identite", f'"{name}"'),
            ("LinkedIn", f'site:linkedin.com "{name}"'),
            ("X / Twitter", f'site:x.com "{name}" OR site:twitter.com "{name}"'),
            ("Facebook", f'site:facebook.com "{name}"'),
            ("GitHub", f'site:github.com "{name}"'),
            ("CV / resume", f'"{name}" (resume OR cv) filetype:pdf'),
            ("Medias", f'"{name}" (jpg OR png OR pdf)'),
        ]
        if company:
            dorks.append(("Identite + entreprise", f'"{name}" "{company}"'))
    if username:
        dorks += [
            ("Pseudo", f'"{username}"'),
            ("Pseudo inurl", f'inurl:"{username}"'),
            ("Pseudo mails", f'"{username}" (email OR mail OR contact)'),
        ]
    if email:
        dorks += [
            ("Email", f'"{email}"'),
            ("Email fuites", f'"{email}" (breach OR leak OR dump)'),
            ("Email pastebin", f'site:pastebin.com "{email}"'),
            ("Email github", f'site:github.com "{email}"'),
        ]
    if phone:
        digits = re.sub(r"\D", "", phone)
        dorks += [
            ("Telephone", f'"{phone}"'),
            ("Telephone chiffres", f'"{digits}"'),
        ]
    if domain:
        dorks += [
            ("Site complet", f"site:{domain}"),
            ("Connexion", f"site:{domain} inurl:login OR inurl:admin OR inurl:signin"),
            ("Fichiers sensibles", f"site:{domain} ext:env OR ext:bak OR ext:sql OR ext:log"),
            ("Certificats", f'site:crt.sh "{domain}"'),
        ]
    if company:
        dorks += [
            ("Entreprise", f'"{company}"'),
            ("Emplois entreprise", f'"{company}" (jobs OR hiring OR recruitment)'),
        ]

    dorks = [(label, dork) for label, dork in dorks if dork.strip()]
    if not dorks:
        ui.note("Rien a generer — remplis au moins un champ.")
        return
    print()
    ui.ok(f"{len(dorks)} dork(s) genere(s)")
    lines = []
    for label, dork in dorks:
        link = f"https://www.google.com/search?q={quote(dork)}"
        print(f"  {ui.paint(label + ':', ui.DR)} {dork}")
        print(f"    {ui.paint(link, ui.W)}")
        lines.append(f"{label} | {dork} | {link}")
    path = ui.save_output("dorks", "\n".join(lines))
    if path and ui.confirm("Ouvrir les dorks dans le navigateur ?"):
        for label, dork in dorks:
            ui.open_url(f"https://www.google.com/search?q={quote(dork)}")


def roblox_id_info():
    ui.module_header(42, "Roblox-ID-Info", "Fiche publique d'un asset ou d'une place Roblox")
    mode = ui.ask_choice("Type d'identifiant", ["Asset (modele, gamepass...)", "Place (jeu)"], default="Asset (modele, gamepass...)")
    raw = ui.ask_required("Identifiant numerique").strip()
    if not raw.isdigit():
        ui.err("Identifiant invalide (chiffres uniquement).")
        return
    headers = {"User-Agent": FCK_UA, "Accept": "application/json"}

    if mode.startswith("Asset"):
        with ui.Spinner("Validation de l'asset (API publique)"):
            valid = net.http_get(
                f"https://www.roblox.com/asset/?assetId={raw}",
                timeout=15,
                headers=headers,
            )
            thumb = net.http_get(
                f"https://thumbnails.roblox.com/v1/assets?assetIds={raw}&size=420x420&format=Png",
                timeout=15,
                headers=headers,
            )
        is_valid = False
        try:
            is_valid = bool(json.loads(valid.text).get("isValid")) if valid.status == 200 else False
        except Exception:
            pass
        image = "-"
        state = "-"
        try:
            data = json.loads(thumb.text).get("data", [])
            if data:
                image = data[0].get("imageUrl", "-")
                state = data[0].get("state", "-")
        except Exception:
            pass
        if state == "Invalid" and not is_valid:
            ui.err("Asset introuvable ou retire (thumbnail Invalid + isValid=false).")
            return
        ui.ok(f"Asset #{raw}")
        ui.kv([
            ("Asset ID", raw),
            ("Thumbnail", "valide" if state == "Completed" else state),
            ("Modere (isValid)", "oui" if is_valid else "non / inconnu"),
            ("Image", str(image)[:110]),
            ("Fiche publique", "nom/prix : API authentifiee requise (OAuth Roblox)"),
        ])
        ui.note("L'API publique ne expose plus nom/prix sans cle OAuth — verifie sur la page du catalogue.")
        ui.save_output("roblox_asset", f"assetId={raw}\nvalid={is_valid}\nstate={state}\nimage={image}")
        return

    with ui.Spinner("Resolution place -> univers"):
        resp = net.http_get(
            f"https://apis.roblox.com/universes/v1/places/{raw}/universe",
            timeout=15,
            headers=headers,
        )
    if resp.status != 200:
        ui.err(f"Place introuvable (HTTP {resp.status}).")
        return
    try:
        universe = json.loads(resp.text).get("universeId")
    except Exception:
        ui.err("Reponse Roblox illisible.")
        return
    if not universe:
        ui.err("Univers introuvable pour cette place.")
        return
    with ui.Spinner("Chargement de la fiche de jeu"):
        resp = net.http_get(f"https://games.roblox.com/v1/games?universeIds={universe}", timeout=15, headers=headers)
    if resp.status != 200:
        ui.err(f"API jeux Roblox : HTTP {resp.status}.")
        return
    try:
        game = json.loads(resp.text).get("data", [])[0]
    except Exception:
        ui.err("Reponse de jeu illisible.")
        return
    ui.ok(str(game.get("name", raw)))
    ui.kv([
        ("Place ID", raw),
        ("Univers ID", str(universe)),
        ("Createur", str((game.get("creator") or {}).get("name", "-"))),
        ("En train de jouer", str(game.get("playing", "-"))),
        ("Visites", str(game.get("visits", "-"))),
        ("Favoris", str(game.get("favoritedCount", "-"))),
        ("Joueurs max", str(game.get("maxPlayers", "-"))),
        ("Genre", str(game.get("genre", "-"))),
        ("Cree le", str(game.get("created", "-"))[:19]),
        ("Mis a jour le", str(game.get("updated", "-"))[:19]),
    ])
    desc = str(game.get("description") or "").replace("\n", " ").strip()
    if desc:
        print()
        ui.info(f"Description : {desc[:300]}" + (" ..." if len(desc) > 300 else ""))
    ui.save_output("roblox_place", json.dumps(game, ensure_ascii=False, indent=2), ext="json")
