import concurrent.futures
import hashlib
import re
import struct
import threading
import time

from .. import ui, net


USERNAME_SITES = [
    ("GitHub", "https://github.com/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("X (Twitter)", "https://x.com/{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
    ("Snapchat", "https://www.snapchat.com/add/{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Roblox", "https://www.roblox.com/user.aspx?username={u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
    ("Medium", "https://medium.com/@{u}"),
    ("Dev.to", "https://dev.to/{u}"),
    ("About.me", "https://about.me/{u}"),
    ("Linktree", "https://linktr.ee/{u}"),
    ("Keybase", "https://keybase.io/{u}"),
    ("HackerOne", "https://hackerone.com/{u}"),
    ("TryHackMe", "https://tryhackme.com/p/{u}"),
    ("Duolingo", "https://www.duolingo.com/profile/{u}"),
    ("Figma", "https://www.figma.com/@{u}"),
]


def username_tracker():
    ui.module_header(15, "Username Tracker", "Recherche d'un pseudo sur les plateformes publiques")
    username = ui.ask_required("Pseudo a rechercher")
    results = []

    def probe(site):
        name, template = site
        url = template.format(u=username)
        resp = net.http_get(url, timeout=7, headers={"Accept-Language": "fr,en"})
        status = resp.status
        if status == 200:
            verdict, color = "EXISTE", ui.G
        elif status in (404, 410):
            verdict, color = "LIBRE", ui.R
        elif status in (403, 401, 429, 301, 302, 503):
            verdict, color = "PROBABLE", ui.Y
        else:
            verdict, color = "INCONNU", ui.X
        return [name, str(status or "-"), verdict, url[:58]]

    with ui.Spinner(f"Verification sur {len(USERNAME_SITES)} plateforme(s)"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            for row in pool.map(probe, USERNAME_SITES):
                results.append(row)
    ui.table(["PLATEFORME", "HTTP", "VERDICT", "URL"], results, widths=[15, 7, 11, 58])
    found = sum(1 for r in results if r[2] == "EXISTE")
    ui.ok(f"{found} profil(s) probablement existant(s) pour '{username}'")
    ui.save_output("username", "\n".join(" | ".join(r) for r in results))


DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "maildrop.cc", "fakeinbox.com", "throwawaymail.com",
    "minutemail.com", "moakt.com", "emailondeck.com", "33mail.com",
    "tempail.com", "tmail.io", "dispostable.com", "linshiyouxiang.net",
    "mailnesia.com", "mailcatch.com", "mytemp.email", "tmpmail.net",
    "tempr.email", "tempmailo.com", "burnermail.io", "harakirimail.com",
    "courrieltemporaire.com", "jetable.org", "nospam.ze.tc", "courriel.fr",
}


def email_lookup():
    ui.module_header(16, "Email Lookup", "Syntaxe, MX, provider jetable et Gravatar")
    email = ui.ask_required("Adresse e-mail")
    valid = bool(re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email))
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    pairs = [
        ("Adresse", email),
        ("Syntaxe", "valide" if valid else "INVALIDE"),
        ("Domaine", domain or "-"),
    ]
    if valid:
        md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
        pairs.append(("Hash Gravatar", md5))
        with ui.Spinner("Verification MX et Gravatar"):
            try:
                mx = net.dns_query(domain, "MX")
            except Exception:
                mx = []
            try:
                a = net.dns_query(domain, "A")
            except Exception:
                a = []
            gravatar = net.http_get(f"https://www.gravatar.com/avatar/{md5}?d=404", timeout=6)
        pairs.append(("MX", ", ".join(mx[:4]) if mx else "AUCUN (domaine non configuré)"))
        pairs.append(("A", ", ".join(a[:2]) if a else "-"))
        if gravatar.status == 200:
            pairs.append(("Gravatar", "compte trouve"))
        elif gravatar.status == 404:
            pairs.append(("Gravatar", "aucun compte"))
        else:
            pairs.append(("Gravatar", "verification impossible"))
        pairs.append(("Jetable", "OUI" if domain.lower() in DISPOSABLE_DOMAINS else "non"))
        providers = {
            "gmail.com": "Google Gmail", "outlook.com": "Microsoft", "hotmail.com": "Microsoft",
            "yahoo.com": "Yahoo", "proton.me": "ProtonMail", "protonmail.com": "ProtonMail",
            "icloud.com": "Apple", "orange.fr": "Orange", "free.fr": "Free",
            "sfr.fr": "SFR", "laposte.net": "La Poste", "laposte.fr": "La Poste",
        }
        pairs.append(("Fournisseur", providers.get(domain.lower(), "-")))
    ui.kv(pairs)
    ui.save_output("email", "\n".join(f"{k} : {v}" for k, v in pairs))


IFD0_TAGS = {
    0x010F: "Appareil (Make)", 0x0110: "Modele (Model)", 0x0112: "Orientation",
    0x0131: "Logiciel", 0x0132: "Date", 0x013B: "Artiste", 0x8298: "Copyright",
    0x010E: "Description", 0x0135: "Horaire", 0x8769: "ExifIFD", 0x8825: "GPSIFD",
}
EXIF_TAGS = {
    0x9003: "Date originale", 0x9004: "Date numerique", 0xA002: "Largeur px",
    0xA003: "Hauteur px", 0x829A: "Exposition", 0x829D: "Ouverture",
    0x8827: "ISO", 0x920A: "Focale", 0xA434: "Objectif", 0xA433: "Boitier",
}
GPS_TAGS = {0x0001: "Lat ref", 0x0002: "Latitude", 0x0003: "Lon ref", 0x0004: "Longitude", 0x0006: "Altitude"}


def _read_ifd(blob, offset, endian, tag_map, depth=0):
    values = {}
    if depth > 3 or offset + 2 > len(blob):
        return values
    count = struct.unpack(endian + "H", blob[offset:offset + 2])[0]
    entry = offset + 2
    next_ifd = None
    for _ in range(count):
        if entry + 12 > len(blob):
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", blob[entry:entry + 8])
        raw = blob[entry + 8:entry + 12]
        entry += 12
        type_size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}.get(typ, 1)
        size = type_size * cnt
        if size <= 4:
            data = raw[:size]
        else:
            off = struct.unpack(endian + "I", raw)[0]
            data = blob[off:off + size] if off + size <= len(blob) else b""
        if not data:
            continue
        if typ == 2:
            value = data.split(b"\x00")[0].decode("utf-8", "replace")
        elif typ == 3:
            value = struct.unpack(endian + "H", data[:2])[0]
        elif typ == 4:
            value = struct.unpack(endian + "I", data[:4])[0]
        elif typ == 5:
            parts = struct.unpack(endian + "II", data[:8])
            value = f"{parts[0]}/{parts[1]}" if parts[1] else str(parts[0])
        else:
            value = data[:24].hex()
        name = tag_map.get(tag)
        if name:
            values[name] = value
        elif tag == 0x8769 and depth == 0 and typ == 4:
            values.update(_read_ifd(blob, struct.unpack(endian + "I", raw)[0], endian, EXIF_TAGS, depth + 1))
        elif tag == 0x8825 and depth == 0 and typ == 4:
            gps = _read_ifd(blob, struct.unpack(endian + "I", raw)[0], endian, GPS_TAGS, depth + 1)
            values.update({"GPS " + k: v for k, v in gps.items()})
    if entry + 4 <= len(blob):
        next_ifd = struct.unpack(endian + "I", blob[entry:entry + 4])[0]
    return values


def _gps_to_decimal(value, ref):
    try:
        parts = []
        for piece in value.split():
            if "/" in piece:
                num, den = piece.split("/", 1)
                parts.append(float(num) / float(den))
            else:
                parts.append(float(piece))
        if len(parts) != 3:
            return None
        decimal = parts[0] + parts[1] / 60 + parts[2] / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def _extract_jpeg_exif(data):
    if data[:2] != b"\xff\xd8":
        return {}
    i = 2
    while i + 4 < len(data):
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        if marker in (0xDA, 0xD9):
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            blob = data[i + 10:i + 2 + seg_len]
            if blob[:2] not in (b"II", b"MM"):
                return {}
            endian = "<" if blob[:2] == b"II" else ">"
            offset = struct.unpack(endian + "I", blob[4:8])[0]
            return _read_ifd(blob, offset, endian, IFD0_TAGS)
        i += 2 + seg_len
    return {}


def exif_reader():
    ui.module_header(17, "Image EXIF Reader", "Metadonnees et GPS d'une image JPEG/PNG")
    path = ui.ask_required("Chemin de l'image")
    path = path.strip('"')
    try:
        with open(path, "rb") as handle:
            data = handle.read(8_000_000)
    except Exception as exc:
        ui.err(f"Lecture impossible : {exc}")
        return
    pairs = [("Fichier", path), ("Taille", f"{len(data)} octets")]
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        width, height = struct.unpack(">II", data[16:24])
        pairs += [("Format", "PNG"), ("Dimensions", f"{width} x {height}")]
        ui.kv(pairs)
        ui.info("PNG : les chunks texte (tEXt/iTXt) sont analysables avec exiftool.")
        return
    if data[:2] != b"\xff\xd8":
        pairs.append(("Format", "non-JPEG (EXIF indisponible)"))
        ui.kv(pairs)
        return
    pairs.append(("Format", "JPEG"))
    exif = _extract_jpeg_exif(data)
    if not exif:
        ui.kv(pairs)
        ui.info("Aucun bloc EXIF trouve dans cette image.")
        return
    lat = _gps_to_decimal(exif.get("GPS Latitude", ""), exif.get("GPS Lat ref", ""))
    lon = _gps_to_decimal(exif.get("GPS Longitude", ""), exif.get("GPS Lon ref", ""))
    if lat is not None and lon is not None:
        exif["GPS Position"] = f"{lat}, {lon}"
        exif["GPS Maps"] = f"https://www.google.com/maps?q={lat},{lon}"
    ui.kv(pairs)
    print()
    ui.kv(list(exif.items()))
    ui.save_output("exif", "\n".join(f"{k} : {v}" for k, v in exif.items()))


DIAL_CODES = [
    ("+33", "France"), ("+32", "Belgique"), ("+41", "Suisse"), ("+43", "Autriche"),
    ("+49", "Allemagne"), ("+34", "Espagne"), ("+39", "Italie"), ("+351", "Portugal"),
    ("+353", "Irlande"), ("+44", "Royaume-Uni"), ("+31", "Pays-Bas"), ("+358", "Finlande"),
    ("+46", "Suede"), ("+47", "Norvege"), ("+45", "Danemark"), ("+48", "Pologne"),
    ("+420", "Republique tcheque"), ("+36", "Hongrie"), ("+40", "Roumanie"),
    ("+359", "Bulgarie"), ("+30", "Grece"), ("+90", "Turquie"), ("+7", "Russie"),
    ("+380", "Ukraine"), ("+353", "Irlande"), ("+1", "USA / Canada"), ("+52", "Mexique"),
    ("+55", "Bresil"), ("+54", "Argentine"), ("+56", "Chili"), ("+57", "Colombie"),
    ("+20", "Egypte"), ("+212", "Maroc"), ("+213", "Algerie"), ("+216", "Tunisie"),
    ("+213", "Algerie"), ("+237", "Cameroun"), ("+225", "Cote d'Ivoire"),
    ("+221", "Senegal"), ("+223", "Mali"), ("+228", "Togo"), ("+229", "Bénin"),
    ("+234", "Nigeria"), ("+254", "Kenya"), ("+27", "Afrique du Sud"), ("+230", "Maurice"),
    ("+91", "Inde"), ("+81", "Japon"), ("+82", "Coree du Sud"), ("+86", "Chine"),
    ("+852", "Hong Kong"), ("+886", "Taiwan"), ("+65", "Singapour"), ("+66", "Thailande"),
    ("+62", "Indonesie"), ("+63", "Philippines"), ("+60", "Malaisie"), ("+61", "Australie"),
    ("+64", "Nouvelle-Zelande"), ("+971", "EAU"), ("+966", "Arabie saoudite"),
    ("+974", "Qatar"), ("+965", "Koweit"), ("+973", "Bahrein"), ("+98", "Iran"),
    ("+964", "Irak"), ("+972", "Israel"), ("+421", "Slovaquie"), ("+386", "Slovenie"),
    ("+385", "Croatie"), ("+381", "Serbie"), ("+387", "Bosnie"), ("+355", "Albanie"),
    ("+389", "Macédoine"), ("+373", "Moldavie"), ("+370", "Lituanie"), ("+371", "Lettonie"),
    ("+372", "Estonie"), ("+352", "Luxembourg"), ("+356", "Malte"), ("+354", "Islande"),
]


def phone_lookup():
    ui.module_header(18, "Phone Lookup", "Formatage, indicatif pays et validation")
    raw = ui.ask_required("Numero (ex : +33612345678 ou 0612345678)")
    digits = re.sub(r"\D", "", raw)
    if not digits:
        ui.err("Aucun chiffre trouve.")
        return
    country = "-"
    national = digits
    if raw.strip().startswith("+") or len(digits) > 10:
        for code, name in sorted(DIAL_CODES, key=lambda x: -len(x[0])):
            if digits.startswith(code.lstrip("+")):
                country = f"{code} — {name}"
                national = digits[len(code.lstrip('+')):]
                break
    elif digits.startswith("00"):
        international = digits[2:]
        for code, name in sorted(DIAL_CODES, key=lambda x: -len(x[0])):
            if international.startswith(code.lstrip("+")):
                country = f"+{code.lstrip('+')} — {name}"
                national = international[len(code.lstrip('+')):]
                break
    elif digits.startswith("0") and len(digits) == 10:
        country = "+33 — France (supposition)"
        national = digits[1:]
    length = len(national)
    kind = "mobile probable" if length in (9, 10) else "longueur inhabituelle"
    pairs = [
        ("Saisie", raw),
        ("Chiffres", digits),
        ("Longueur", str(len(digits))),
        ("Indicatif", country),
        ("National", national),
        ("Nationalite numero", kind),
        ("Format international", "+" + digits if not raw.strip().startswith("+") else raw.strip()),
        ("Format espaces", " ".join([digits[i:i + 2] for i in range(0, len(digits), 2)])),
    ]
    ui.kv(pairs)
    ui.note("Indicatif deduit du prefixe — l'operateur reel n'est pas consulte (source publique uniquement).")


def _roblox_id(name_or_id):
    if name_or_id.isdigit():
        return int(name_or_id)
    resp = net.http_post(
        "https://users.roblox.com/v1/usernames/users",
        json_data={"usernames": [name_or_id], "excludeBannedUsers": False},
        timeout=10,
    )
    import json

    try:
        data = json.loads(resp.text)
        return data["data"][0]["id"]
    except Exception:
        return None


def roblox_user():
    ui.module_header(19, "Roblox User Info", "Profil public, avatar et compte (API officielle)")
    name = ui.ask_required("Username ou ID Roblox")
    with ui.Spinner("Interrogation de l'API Roblox"):
        uid = _roblox_id(name)
        if not uid:
            ui.err("Utilisateur introuvable.")
            return
        profile = net.http_get(f"https://users.roblox.com/v1/users/{uid}", timeout=10)
        friends = net.http_get(f"https://friends.roblox.com/v1/users/{uid}/friends/count", timeout=10)
        thumb = net.http_get(
            f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={uid}&size=150x150&format=Png",
            timeout=10,
        )
    import json

    try:
        data = json.loads(profile.text)
    except Exception:
        ui.err("Reponse Roblox illisible.")
        return
    pair_count = "-"
    try:
        pair_count = str(json.loads(friends.text)["count"])
    except Exception:
        pass
    avatar = "-"
    try:
        avatar = json.loads(thumb.text)["data"][0]["imageUrl"]
    except Exception:
        pass
    created = data.get("created", "-")
    if created != "-":
        created = created[:10]
    pairs = [
        ("ID", str(data.get("id", uid))),
        ("Username", data.get("name", "-")),
        ("Display name", data.get("displayName", "-")),
        ("Description", (data.get("description") or "-")[:80]),
        ("Cree le", created),
        ("Banni", "oui" if data.get("isBanned") else "non"),
        ("Amis", pair_count),
        ("Avatar", avatar),
    ]
    ui.kv(pairs)
    ui.save_output("roblox", "\n".join(f"{k} : {v}" for k, v in pairs))


def _extract_invite_code(value):
    value = value.strip()
    match = re.search(r"(?:discord\.gg/|discord(?:app)?\.com/invite/)([A-Za-z0-9-]+)", value)
    if match:
        return match.group(1)
    if re.fullmatch(r"[A-Za-z0-9-]+", value):
        return value
    return None


def discord_invite():
    ui.module_header(20, "Discord Invite Info", "Informations publiques d'une invitation")
    value = ui.ask_required("Lien d'invitation ou code (discord.gg/xxx)")
    code = _extract_invite_code(value)
    if not code:
        ui.err("Code d'invitation invalide.")
        return
    with ui.Spinner("Interrogation de l'API Discord"):
        resp = net.http_get(f"https://discord.com/api/v10/invites/{code}?with_counts=true", timeout=10)
    if resp.status == 404:
        ui.err("Invitation introuvable ou expiree.")
        return
    if resp.status != 200:
        ui.err(f"API Discord : HTTP {resp.status}")
        return
    import json

    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse illisible.")
        return
    guild = data.get("guild") or {}
    channel = data.get("channel") or {}
    invite_code = data.get("code", code)
    pairs = [
        ("Code", invite_code),
        ("Serveur", guild.get("name", "-")),
        ("ID serveur", guild.get("id", "-")),
        ("Description", (guild.get("description") or "-")[:80]),
        ("Emetteur", str(guild.get("vanity_url_code") or "-")),
        ("Categorie", str(channel.get("type", "-"))),
        ("Canal", channel.get("name", "-")),
        ("En ligne", str(data.get("approximate_presence_count", "-"))),
        ("Membres", str(data.get("approximate_member_count", "-"))),
        ("Verification", str(guild.get("verification_level", "-"))),
        ("Boosts", str(guild.get("premium_subscription_count", "-"))),
    ]
    ui.kv(pairs)
    ui.save_output("discord_invite", "\n".join(f"{k} : {v}" for k, v in pairs))


def discord_webhook():
    ui.module_header(21, "Discord Webhook Info", "Metadonnees d'un webhook (lecture seule)")
    url = ui.ask_required("URL du webhook (https://discord.com/api/webhooks/...)")
    if "discord.com/api/webhooks/" not in url and "discordapp.com/api/webhooks/" not in url:
        ui.err("URL de webhook invalide.")
        return
    with ui.Spinner("Lecture du webhook"):
        resp = net.http_get(url, timeout=10)
    if resp.status == 404:
        ui.err("Webhook inexistant ou supprime.")
        return
    if resp.status != 200:
        ui.err(f"Acces refuse (HTTP {resp.status}).")
        return
    import json

    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse illisible.")
        return
    avatar = ""
    if data.get("avatar"):
        avatar = f"https://cdn.discordapp.com/avatars/{data.get('id')}/{data['avatar']}.png"
    pairs = [
        ("ID", data.get("id", "-")),
        ("Nom", data.get("name", "-")),
        ("Token", (data.get("token") or "-")[:18] + "..."),
        ("Canal ID", data.get("channel_id", "-")),
        ("Serveur ID", data.get("guild_id", "-")),
        ("Avatar", avatar or "-"),
        ("Compte", str(data.get("user", {}).get("username", "-"))),
    ]
    ui.kv(pairs)
    ui.note("Lecture seule : aucun message n'est envoye.")


def discord_bot_id():
    ui.module_header(22, "Discord Bot Invite To ID", "ID du bot (et serveur) depuis une invitation")
    value = ui.ask_required("Lien d'invitation (discord.gg/xxx) ou code")
    code = _extract_invite_code(value)
    if not code:
        ui.err("Code invalide.")
        return
    import base64

    bot_id = None
    guild_id = None
    try:
        padded = code + "=" * (-len(code) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", "replace")
        parts = decoded.split("-")
        if len(parts) >= 2:
            guild_id = parts[0].strip()
            bot_id = parts[1].strip()
        elif len(parts) == 1 and parts[0].isdigit():
            bot_id = parts[0]
    except Exception:
        pass
    pairs = [("Code", code)]
    if bot_id and bot_id.isdigit():
        pairs.append(("ID bot", bot_id))
        pairs.append(("Avatar", f"https://cdn.discordapp.com/avatars/{bot_id}/avatar.png"))
    if guild_id and guild_id.isdigit():
        pairs.append(("ID serveur (invite)", guild_id))
    ui.kv(pairs)
    with ui.Spinner("Verification via l'API d'invitation"):
        resp = net.http_get(f"https://discord.com/api/v10/invites/{code}?with_counts=true", timeout=10)
    if resp.status == 200:
        import json

        try:
            data = json.loads(resp.text)
            guild = data.get("guild") or {}
            extra = [
                ("Serveur", guild.get("name", "-")),
                ("Membres", str(data.get("approximate_member_count", "-"))),
                ("En ligne", str(data.get("approximate_presence_count", "-"))),
            ]
            ui.kv(extra)
        except Exception:
            pass
    if not bot_id:
        ui.info("Aucun ID de bot encode dans ce code (invitation serveur standard).")
