"""Module 55 — Wordlist-Factory : generation et mutations de wordlists pour craquage."""
import time

from .. import ui

LEET = {
    "a": ("@", "4"),
    "e": ("3",),
    "i": ("1", "!"),
    "o": ("0",),
    "s": ("5", "$"),
    "t": ("7",),
    "l": ("1",),
}
SUFFIXES = ("!", "!1", "123", "1234", "2024", "2025", "2026", ".", "*")
SEPS = ("", "1", "123", "@", ".")
MAX_LEET = 256
ANNEES = [str(y) for y in range(1990, 2027)]


def mutate_leet(word):
    """Variantes leet par produit cartesien (sans l'original), plafonnees a 256."""
    acc = [""]
    for char in word:
        options = (char,) + LEET.get(char.lower(), ())
        acc = [prefix + option for prefix in acc for option in options]
        if len(acc) > MAX_LEET * 4:
            acc = acc[:MAX_LEET * 4]
    seen = set()
    out = []
    for variant in acc:
        if variant != word and variant not in seen:
            seen.add(variant)
            out.append(variant)
        if len(out) >= MAX_LEET:
            break
    return out


def case_variants(word):
    """Casse de base : bas, haut, premiere lettre, casse alternee du 1er caractere."""
    candidates = [
        word.lower(),
        word.upper(),
        word[:1].upper() + word[1:].lower(),
        word[:1].lower() + word[1:].upper() if len(word) > 1 else word,
    ]
    out = []
    for variant in candidates:
        if variant and variant not in out:
            out.append(variant)
    return out


def combinator(lefts, rights, seps=SEPS):
    """Croise gauche x droite avec separateurs, dedoublonne en ordre stable."""
    out = []
    seen = set()
    for left in lefts:
        for right in rights:
            for sep in seps:
                item = f"{left}{sep}{right}"
                if item not in seen:
                    seen.add(item)
                    out.append(item)
    return out


def wordlist_factory():
    ui.module_header(55, "Wordlist-Factory", "Generation et mutations de wordlists pour craquage")
    ui.note("Wordlist d'attaque pour VOS audits (hash a vous, cibles autorisees).")

    source = ui.ask_choice("Source", ["Saisie manuelle", "Fichier"], default="Saisie manuelle")
    if source == "Fichier":
        path = ui.ask_required("Fichier (un mot par ligne)")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                words = [line.strip() for line in handle if line.strip()][:10000]
        except OSError as exc:
            ui.err(f"Lecture impossible : {exc}")
            return
        if not words:
            ui.err("Fichier vide.")
            return
    else:
        raw = ui.ask_required("Mots de base (separes par virgule)")
        words = [w.strip() for w in raw.split(",") if w.strip()]
        if not words:
            ui.err("Aucun mot saisi.")
            return

    profil = ui.ask_choice(
        "Profil",
        ["Complet", "Rapide (leet+case)", "Leet seul", "Annees+suffixes"],
        default="Complet",
    )
    limite = ui.ask_int("Nombre max de lignes", default=500000, minimum=100, maximum=5000000)

    estimation = len(words) * 300
    if profil == "Complet":
        estimation += len(words) * len(words) * len(SEPS)
    if estimation > limite:
        ui.note(f"Estimation ~{estimation} lignes > limite {limite} : troncature a la limite.")
        if not ui.confirm("Continuer quand meme ?", default=True):
            ui.info("Annule.")
            return

    debut = time.time()
    out = []
    seen = set()

    def push(item):
        if item and item not in seen and len(out) < limite:
            seen.add(item)
            out.append(item)

    for index, word in enumerate(words, 1):
        push(word)
        if profil in ("Complet", "Rapide (leet+case)", "Leet seul"):
            for variant in mutate_leet(word):
                push(variant)
        if profil in ("Complet", "Rapide (leet+case)"):
            for variant in case_variants(word):
                push(variant)
        if profil in ("Complet", "Annees+suffixes"):
            for year in ANNEES:
                push(word + year)
                push(year + word)
            for suffix in SUFFIXES:
                push(word + suffix)
        ui.progress("Generation", index, len(words))

    if profil == "Complet" and len(out) < limite:
        for item in combinator(words, words):
            push(item)
            if len(out) >= limite:
                break
    ui.progress_done()

    path_out = ui.save_output("wordlist", "\n".join(out) + "\n", ext="txt")
    ui.kv([
        ("Mots de base", len(words)),
        ("Lignes finales", len(out)),
        ("Profil", profil),
        ("Fichier", path_out or "erreur"),
        ("Duree", f"{time.time() - debut:.2f}s"),
    ])
    if len(out) >= limite:
        ui.note("Limite atteinte : augmentez 'max de lignes' ou affinez les mots de base.")
