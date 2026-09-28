import base64
import hashlib
import hmac
import math
import secrets
import string
import sys
import time

from .. import ui

WORDLIST = [
    "abricot", "altitude", "ancien", "ancre", "arbre", "archive", "atlas", "aurore",
    "avion", "azur", "bague", "balcon", "baleine", "banane", "bao", "beurre",
    "bijou", "biscuit", "bleu", "bloc", "bolide", "bombe", "bonheur", "bordel",
    "brique", "brume", "bulle", "bureau", "cafe", "cage", "caillou", "camion",
    "canal", "canyon", "capot", "carotte", "cascade", "ceinture", "chaine", "champ",
    "chapeau", "charbon", "chateau", "chemin", "cherry", "chocolat", "citation", "clair",
    "clavier", "cloche", "cobalt", "cocon", "code", "colibri", "colonne", "combat",
    "comet", "coquille", "corail", "couleur", "course", "cristal", "cube", "cygne",
    "daim", "danse", "decembre", "delta", "desert", "diamant", "dinosaure", "docteur",
    "dolphin", "dragon", "drapeau", "dune", "eclair", "ecole", "ecorce", "edifice",
    "egalite", "elague", "elephant", "encre", "enigma", "epaule", "epice", "epoque",
    "espace", "esprit", "estate", "etincelle", "etoffe", "etrange", "faience", "falcon",
    "famille", "fantome", "farine", "faucon", "femme", "ferme", "feuille", "fievre",
    "figure", "filtre", "finance", "fleche", "fleur", "foret", "forge", "fourmi",
    "fraise", "fusil", "gagnant", "galaxie", "garage", "gargouille", "gaufre", "geant",
    "genere", "glace", "goblin", "gorille", "goutte", "graine", "granit", "griffe",
    "grotte", "guerre", "guepard", "habitat", "harmonie", "herbe", "hibou", "histoire",
    "horizon", "hotel", "huile", "ici", "igloo", "image", "instrument", "iris",
    "ivoire", "jaguar", "jamais", "jardin", "jeton", "joaillier", "jungle", "jurassic",
    "kangourou", "karate", "kayak", "kiwi", "koala", "labo", "lacet", "lagon",
    "laure", "lecture", "legende", "lemurien", "lettre", "levier", "liberte", "lichen",
    "lied", "ligature", "lion", "lisere", "livre", "llama", "locomotive", "lotus",
    "lueur", "luge", "lundi", "lunette", "lynx", "machine", "magie", "magnolia",
    "maison", "malachite", "mammouth", "mandarine", "mangue", "manoir", "maree", "margot",
    "marin", "marmite", "marque", "marteau", "matin", "mechant", "medaille", "melodie",
    "menhir", "mercure", "mesange", "meteore", "miroir", "modele", "moine", "moment",
    "monde", "montagne", "moustache", "mousson", "murmure", "muscle", "mystere", "nature",
    "navire",     "nector", "neige", "nerf", "nid", "ninja", "nocturne",
    "noir", "nomade", "nord", "note", "nuage", "nucleaire", "oasis", "obus",
    "oceane", "odeur", "oiseau", "olive", "ombre", "ongle", "orange", "orbite",
    "orchidee", "oreille", "original", "oscar", "ouest", "ours", "outil", "ovalie",
    "ozone", "paille", "paix", "palace", "panda", "panthere", "papier", "paquebot",
    "parc", "pardon", "parole", "pastel", "patron", "paul", "peche", "pelage",
    "pendule", "penguin", "perle", "perruche", "petale", "peuple", "phrase", "piano",
    "pierre", "pigeon", "pilote", "piment", "pincer", "piste", "pivot", "plage",
    "planche", "plaque", "plume", "poeme", "point", "poison", "polar", "pomme",
    "portail", "possible", "poussiere", "prairie", "prelude", "princes", "prisme", "puce",
    "puits", "pulse", "pyramide", "quartz", "quete", "quiche", "quille", "quota",
    "radar", "raie", "raisin", "rampe", "range", "rapide", "raquette", "ravin",
    "rayon", "reflet", "regard", "reine", "rejet", "renard", "rende", "rex",
    "rhino", "rire", "rivage", "rive", "robe", "rocher", "rocket",
    "ronce", "rose", "roue", "rubis", "ruche", "ruisseau", "rumeur", "sable",
    "saison", "salade", "sardine", "saturne", "sauce", "sautoir", "scene", "scolaire",
    "secret", "seigne", "sensei", "serpent", "seuil", "sifflet", "signe", "simple",
    "sirene", "soie", "soleil", "sombre", "sophia", "sorcier", "souffle", "source",
    "sphinx", "sport", "square", "station", "style", "sucrerie", "suite", "sureau",
    "table", "tache", "talisman", "tambour", "tapis", "taupe", "tecture", "tele",
    "tempete", "tenant", "tigre", "timbre", "titan", "toile", "tomate", "tonnerre",
    "tornade", "toupie", "tournesol", "tracer", "train", "trapu", "treasure", "trefle",
    "tresse", "tribune", "triple", "trottoir", "trousse", "truite", "tulipe", "tunnel",
    "turbo", "tuteur", "type", "ulysse", "unique", "uranus", "uree", "usage",
    "utile", "vacance", "vague", "vaisseau", "valise", "vallon", "valoir", "vanille",
    "variable", "veille", "velo", "velours", "vent", "ventouse", "verger", "verre",
    "verso", "veste", "victoire", "vigne", "village", "violet", "vitesse", "vivier",
    "volcan", "volute", "vortex", "voyage", "wagon", "web", "whisky", "widget",
    "winter", "wolf", "xenon", "yacht", "yaourt", "yeti", "zebre", "zephyr",
    "zinc", "zodiac", "zombie",
]

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwerty123", "abc123", "iloveyou", "admin", "admin123",
    "welcome", "welcome1", "letmein", "monkey", "dragon", "football", "baseball",
    "superman", "batman", "shadow", "master", "michael", "sunshine", "princess",
    "flower", "trustno1", "starwars", "whatever", "zaq12wsx", "qazwsx", "1q2w3e4r",
    "1qaz2wsx", "asdfgh", "asdfghjkl", "zxcvbn", "passw0rd", "p@ssword", "p@ssw0rd",
    "azerty", "azertyuiop", "motdepasse", "soleil", "chocolat", "football1",
    "computer", "internet", "secret", "changeme", "default", "root", "toor",
    "test", "test123", "guest", "user", "oracle", "postgres", "mysql", "redhat",
    "freedom", "money", "love", "sex", "god", "hello", "hello123", "helloworld",
    "charlie", "donald", "thomas", "robert", "jordan", "harley", "ranger",
    "buster", "soccer", "killer", "george", "sexy", "andrew", "charlie1",
    "654321", "111111", "000000", "123123", "112233", "121212", "147258",
    "789456", "987654", "159753", "11111111", "1234", "12345", "1234567",
    "12345678910", "abcd1234", "qwe123", "love123", "babygirl", "babyboy",
    "ilovyou", "sunshine1", "chocolate", "internet1", "welcome123", "pass123",
    "temp", "temp123", "company", "system", "manager", "service", "server",
    "windows", "linux", "android", "iphone", "nokia", "samsung",
}

KEYBOARD_ROWS = ["azertyuiop", "qsdfghjklm", "wxcvbn", "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]

LEET = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "+": "t"}


def _generate_passphrase(count=5, separator="-", capitalize=True, digit=True, symbol=True):
    words = [secrets.choice(WORDLIST) for _ in range(count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if digit:
        phrase += str(secrets.randbelow(90) + 10)
    if symbol:
        phrase += secrets.choice("!?*.+#")
    entropy = count * math.log2(len(WORDLIST))
    if digit:
        entropy += math.log2(90)
    if symbol:
        entropy += math.log2(9)
    return phrase, entropy


def passphrase_generator():
    ui.module_header(48, "Passphrase Generator", "Phrase de passe memorisable + entropie")
    count = ui.ask_int("Nombre de mots", 5, 3, 12)
    separator = ui.ask("Separateur (- _ . espace)", "-")
    separator = {"_": "_", ".": ".", " ": " ", "-": "-"}.get(separator, "-")
    capitalize = ui.confirm("Majuscule en debut de mot ?", True)
    extras = ui.ask_choice("Extras", ["rien", "chiffre", "symbole", "les deux"], "les deux")
    number = ui.ask_int("Nombre de phrases", 5, 1, 20)
    rows = []
    best = 0.0
    for _ in range(number):
        phrase, entropy = _generate_passphrase(
            count, separator, capitalize,
            digit=extras in ("chiffre", "les deux"),
            symbol=extras in ("symbole", "les deux"),
        )
        best = max(best, entropy)
        rows.append([phrase, f"{entropy:.0f} bits"])
    ui.table(["PHRASE DE PASSE", "ENTROPIE"], rows, widths=[70, 14])
    level = "faible" if best < 50 else "moyen" if best < 70 else "fort" if best < 90 else "excellent"
    ui.ok(f"Entropie : {best:.0f} bits — robustesse {level}")
    ui.note("Memorisez-la, ne l'ecrivez pas en clair dans un fichier.")
    ui.save_output("passphrases", "\n".join(r[0] for r in rows))


def _analyze_password(password):
    length = len(password)
    classes = [
        bool(any(c in string.ascii_lowercase for c in password)),
        bool(any(c in string.ascii_uppercase for c in password)),
        bool(any(c in string.digits for c in password)),
        bool(any(c in string.punctuation for c in password)),
    ]
    pool_size = (26 if classes[0] else 0) + (26 if classes[1] else 0) + (10 if classes[2] else 0) + (33 if classes[3] else 0)
    entropy = length * math.log2(pool_size) if pool_size else 0.0
    lower = password.lower()
    issues = []
    suggestions = []
    effective = entropy
    if lower in COMMON_PASSWORDS or password in COMMON_PASSWORDS:
        issues.append("fige dans les mots de passe les plus courants")
        effective = min(effective, 8.0)
    if length < 8:
        issues.append("trop court (< 8 caracteres)")
        suggestions.append("visez 12 caracteres ou plus")
    if length >= 12:
        suggestions.append("bonne longueur — maintenez-la")
    if not classes[2]:
        issues.append("aucun chiffre")
    if not classes[3]:
        issues.append("aucun symbole")
    if classes[0] and not classes[1]:
        issues.append("uniquement des minuscules")
    sequence = False
    for i in range(length - 2):
        a, b, c = lower[i], lower[i + 1], lower[i + 2]
        if ord(b) == ord(a) + 1 == ord(c) - 1 or ord(b) == ord(a) - 1 == ord(c) + 1:
            sequence = True
            break
    if sequence:
        issues.append("sequence lineaire (abc / 321)")
        effective *= 0.6
    repeat = False
    for i in range(length - 2):
        if lower[i] == lower[i + 1] == lower[i + 2]:
            repeat = True
            break
    if repeat:
        issues.append("caracteres repetes (aaa)")
        effective *= 0.7
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i:i + 4]
            if chunk in lower or chunk[::-1] in lower:
                issues.append(f"motif clavier ({chunk})")
                effective *= 0.6
                break
    if re_year_search(password):
        issues.append("annee detectee (19xx/20xx)")
        effective *= 0.85
    repeated_block = False
    for size in range(2, max(2, length // 2) + 1):
        block = lower[:size]
        if block and block * (length // size) == lower[:size * (length // size)] and length >= size * 2:
            repeated_block = True
            break
    if repeated_block and not sequence:
        issues.append("motif repete (abab)")
        effective *= 0.65
    if any(lower.replace(k, v) in COMMON_PASSWORDS for k, v in LEET.items()):
        issues.append("variant leet d'un mot de passe courant")
        effective = min(effective, 14.0)
    effective = max(effective, 1.0)
    verdict = "tres faible" if effective < 25 else "faible" if effective < 40 else "moyen" if effective < 60 else "fort" if effective < 80 else "tres fort"
    return {
        "length": length,
        "classes": sum(classes),
        "pool": pool_size,
        "entropy": entropy,
        "effective": effective,
        "issues": issues,
        "suggestions": suggestions,
        "verdict": verdict,
    }


def re_year_search(password):
    for i in range(len(password) - 3):
        chunk = password[i:i + 4]
        if chunk.isdigit() and chunk[:2] in ("19", "20"):
            year = int(chunk)
            if 1900 <= year <= 2099:
                return True
    return False


def _format_duration(seconds):
    if seconds < 1:
        return "instantane"
    units = [
        (31536000, "ans"), (86400, "jours"), (3600, "heures"),
        (60, "minutes"), (1, "secondes"),
    ]
    for value, label in units:
        if seconds >= value:
            return f"{seconds / value:.3g} {label}"
    return f"{seconds:.3g} secondes"


def _ask_secret(message="Mot de passe (saisie masquee)"):
    if sys.stdin.isatty():
        try:
            import getpass

            return getpass.getpass(f"  {message} : ")
        except Exception:
            pass
    return ui.ask(message)


def password_strength():
    ui.module_header(49, "Password Strength", "Entropie, motifs faibles et temps de craquage estime")
    password = _ask_secret()
    if not password:
        ui.info("Aucun mot de passe fourni.")
        return
    report = _analyze_password(password)
    ui.kv([
        ("Longueur", str(report["length"])),
        ("Classes de caracteres", str(report["classes"]) + "/4"),
        ("Alphabet theorique", str(report["pool"])),
        ("Entropie brute", f"{report['entropy']:.1f} bits"),
        ("Entropie corrigee", f"{report['effective']:.1f} bits"),
        ("Verdict", report["verdict"]),
    ])
    print()
    ui.info("Temps de craquage estime (hors ligne, arbitraire) :")
    ui.table(["METHODE", "DEBIT", "TEMPS"], [
        ["MD5 / SHA1 rapide", "100 milliards/s", _format_duration(2 ** report["effective"] / 2 / 1e11)],
        ["NTLM GPU", "100 milliards/s", _format_duration(2 ** report["effective"] / 2 / 1e11)],
        ["bcrypt (lent)", "100 milliers/s", _format_duration(2 ** report["effective"] / 2 / 1e4)],
    ], widths=[24, 22, 26])
    if report["issues"]:
        print()
        ui.note("Points faibles detects : " + "; ".join(report["issues"]))
    if report["suggestions"]:
        print()
        ui.ok("Suggestions : " + "; ".join(report["suggestions"]))


def _b32decode(secret):
    clean = str(secret).strip().replace(" ", "").replace("-", "").upper()
    clean += "=" * (-len(clean) % 8)
    return base64.b32decode(clean)


def _hotp(secret_b32, counter, digits=6, algorithm="sha1"):
    key = _b32decode(secret_b32)
    algo = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}[algorithm]
    mac = hmac.new(key, counter.to_bytes(8, "big"), algo).digest()
    offset = mac[-1] & 0x0F
    code = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
    return str(code % (10 ** digits)).zfill(digits)


def _totp(secret_b32, for_time=None, step=30, digits=6, algorithm="sha1"):
    moment = time.time() if for_time is None else for_time
    counter = int(moment // step)
    remaining = step - (moment % step)
    return _hotp(secret_b32, counter, digits, algorithm), remaining


def _generate_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_generator():
    ui.module_header(50, "TOTP 2FA Generator", "Code temporel RFC 6238 (Google Authenticator...)")
    mode = ui.ask_choice("Mode", ["generer", "utiliser", "verifier"], "generer")
    if mode == "generer":
        secret = _generate_secret()
        ui.ok("Secret Base32 genere (a enregistrer dans votre application 2FA) :")
        ui.kv([("Secret", secret)])
        print()
        ui.kv([("URI d'ajout", f"otpauth://totp/FCK:{secret[:8]}...?secret={secret}&issuer=FCK")])
    elif mode == "utiliser":
        secret = ui.ask_required("Secret Base32")
    else:
        secret = ui.ask_required("Secret Base32")
        code = ui.ask("Code a verifier")
        good, remaining = _totp(secret)
        if code.strip() in (good, _totp(secret, time.time() - 30)[0]):
            ui.ok(f"Code valide (encore {int(remaining)} s).")
        else:
            ui.err(f"Code invalide (attendu : {good}).")
        return
    for _ in range(3):
        code, remaining = _totp(secret)
        width = 30
        filled = int(width * (30 - remaining) / 30)
        bar = "#" * filled + "-" * (width - filled)
        print("  " + ui.paint(f"[{bar}]", ui.R) + ui.paint(f" {int(remaining):2d}s  code : {code}", ui.W, ui.K))
        if remaining > 28:
            break
        time.sleep(1)
    ui.note("Ce code change toutes les 30 secondes (RFC 6238).")
