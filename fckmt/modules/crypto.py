import base64
import hashlib
import itertools
import os
import re
import secrets
import string
import time
import zipfile

from .. import ui


HASH_ALGOS = [
    ("MD5", "md5"), ("SHA1", "sha1"), ("SHA224", "sha224"),
    ("SHA256", "sha256"), ("SHA384", "sha384"), ("SHA512", "sha512"),
    ("BLAKE2b", "blake2b"), ("BLAKE2s", "blake2s"),
    ("SHA3-256", "sha3_256"), ("SHA3-512", "sha3_512"),
]


def _digest(algo, data):
    h = hashlib.new(algo)
    h.update(data)
    if algo == "blake2b":
        return h.hexdigest()
    return h.hexdigest()


def hash_generator():
    ui.module_header(23, "Hash Generator", "Hashs MD5/SHA/BLAKE2 d'un texte ou d'un fichier")
    mode = ui.ask_choice("Source : texte (t) ou fichier (f)", ["t", "f"], "t")
    if mode == "t":
        text = ui.ask_required("Texte a hacher")
        data = text.encode("utf-8")
    else:
        path = ui.ask_required("Chemin du fichier").strip('"')
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except Exception as exc:
            ui.err(f"Lecture impossible : {exc}")
            return
    rows = []
    for label, algo in HASH_ALGOS:
        try:
            rows.append([label, _digest(algo, data)])
        except Exception:
            pass
    ui.table(["ALGORITHME", "HASH"], rows, widths=[14, 76])
    ui.save_output("hash", "\n".join(f"{r[0]} {r[1]}" for r in rows))


def identify_hash(value):
    length = len(value)
    mapping = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
    if not re.fullmatch(r"[0-9a-fA-F]+", value):
        return []
    candidates = mapping.get(length)
    if candidates:
        return [candidates]
    return []


def hash_cracker():
    ui.module_header(24, "Hash Cracker", "Identification et craquage par wordlist / force brute")
    target = ui.ask_required("Hash a craquer").strip().lower()
    identified = identify_hash(target)
    if identified:
        ui.info("Algorithme probable : " + ", ".join(identified))
    algos = identified or ["md5", "sha1", "sha256"]
    mode = ui.ask_choice("Methode : wordlist (w) ou brute PIN (b)", ["w", "b"], "w")
    started = time.time()
    cracked = None
    tried = 0
    if mode == "w":
        wordlist = ui.ask_required("Chemin de la wordlist").strip('"')
        try:
            handle = open(wordlist, "r", encoding="utf-8", errors="replace")
        except Exception as exc:
            ui.err(f"Lecture impossible : {exc}")
            return
        with handle:
            with ui.Spinner("Comparaison en cours"):
                for row in handle:
                    word = row.strip("\n").rstrip("\r")
                    if not word:
                        continue
                    tried += 1
                    raw = word.encode("utf-8", "replace")
                    for algo in algos:
                        try:
                            if _digest(algo, raw) == target:
                                cracked = word
                                break
                        except Exception:
                            pass
                    if cracked is not None:
                        break
                    if tried % 5000 == 0:
                        ui.progress("Wordlist", tried, 0)
        ui.progress_done()
    else:
        length = ui.ask_int("Longueur du PIN (1 a 6)", 4, 1, 6)
        charset = string.digits if ui.ask_choice("Chiffres seuls ?", ["o", "n"], "o") == "o" else string.digits + string.ascii_lowercase
        total = len(charset) ** length
        ui.info(f"{total} combinaisons a tester...")
        with ui.Spinner("Force brute en cours"):
            for combo in itertools.product(charset, repeat=length):
                word = "".join(combo)
                tried += 1
                raw = word.encode()
                for algo in algos:
                    try:
                        if _digest(algo, raw) == target:
                            cracked = word
                            break
                    except Exception:
                        pass
                if cracked is not None:
                    break
                if tried % 20000 == 0:
                    ui.progress("Brute force", tried, total)
        ui.progress_done()
    elapsed = time.time() - started
    if cracked is not None:
        ui.ok(f"CRACKE en {elapsed:.2f}s apres {tried} essais : {cracked}")
        ui.save_output("hashcracked", f"{target} = {cracked}")
    else:
        ui.err(f"Non craque ({tried} essais, {elapsed:.1f}s). Essayez une plus grande wordlist.")


def zip_cracker():
    ui.module_header(25, "Zip Cracker", "Ouverture d'une archive ZIP chiffree par wordlist")
    path = ui.ask_required("Chemin de l'archive .zip").strip('"')
    if not os.path.isfile(path):
        ui.err("Fichier introuvable.")
        return
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        ui.err(f"Archive illisible : {exc}")
        return
    encrypted = [i.filename for i in zf.infolist() if i.flag_bits & 0x1]
    if not encrypted:
        ui.info("Cette archive n'est pas chiffree.")
        return
    ui.info(f"{len(encrypted)} fichier(s) chiffre(s) — ex : {encrypted[0]}")
    wordlist = ui.ask_required("Chemin de la wordlist").strip('"')
    tried = 0
    started = time.time()
    cracked = None
    try:
        first = encrypted[0]
        with open(wordlist, "r", encoding="utf-8", errors="replace") as handle:
            with ui.Spinner("Essai des mots de passe"):
                for row in handle:
                    word = row.strip("\n").rstrip("\r")
                    if not word:
                        continue
                    tried += 1
                    try:
                        zf.read(first, pwd=word.encode("utf-8"))
                        cracked = word
                        break
                    except RuntimeError:
                        continue
                    except NotImplementedError:
                        ui.err("Chiffrement AES/ZIPX non supporte par le module standard (pyzipper requis).")
                        return
                    except Exception:
                        continue
                    if tried % 2000 == 0:
                        ui.progress("Zip cracker", tried, 0)
        ui.progress_done()
    finally:
        zf.close()
    elapsed = time.time() - started
    if cracked is not None:
        ui.ok(f"MOT DE PASSE TROUVE en {elapsed:.2f}s ({tried} essais) : {cracked}")
        ui.save_output("zipcracked", f"{path} -> {cracked}")
    else:
        ui.err(f"Echec ({tried} essais, {elapsed:.1f}s).")


def encoders():
    ui.module_header(26, "Encodeur / Decodeur", "Base64, Base32, Hex, URL, ROT13, Binaire, Caesar")
    operations = [
        ("1", "Base64 encoder"), ("2", "Base64 decoder"),
        ("3", "Base32 encoder"), ("4", "Base32 decoder"),
        ("5", "Hex encoder"), ("6", "Hex decoder"),
        ("7", "URL encoder"), ("8", "URL decoder"),
        ("9", "ROT13"), ("10", "Binaire encoder"), ("11", "Binaire decoder"),
        ("12", "Inverser"), ("13", "Caesar (decalage)"),
    ]
    for key, label in operations:
        print("  " + ui.paint(f"  [{key:>2}]", ui.C, ui.K) + f" {label}")
    choice = ui.ask_required("Choix")
    data = ui.ask_required("Entree")
    try:
        if choice == "1":
            out = base64.b64encode(data.encode()).decode()
        elif choice == "2":
            out = base64.b64decode(data, validate=False).decode("utf-8", "replace")
        elif choice == "3":
            out = base64.b32encode(data.encode()).decode()
        elif choice == "4":
            out = base64.b32decode(data.upper() + "=" * (-len(data) % 8)).decode("utf-8", "replace")
        elif choice == "5":
            out = data.encode().hex()
        elif choice == "6":
            out = bytes.fromhex(data.strip().replace(" ", "")).decode("utf-8", "replace")
        elif choice == "7":
            from urllib.parse import quote_plus

            out = quote_plus(data)
        elif choice == "8":
            from urllib.parse import unquote_plus

            out = unquote_plus(data)
        elif choice == "9":
            out = _rot13(data)
        elif choice == "10":
            out = " ".join(format(b, "08b") for b in data.encode())
        elif choice == "11":
            out = bytes(int(b, 2) for b in data.split()).decode("utf-8", "replace")
        elif choice == "12":
            out = data[::-1]
        elif choice == "13":
            shift = ui.ask_int("Decalage", 13, 0, 25)
            out = _caesar(data, shift)
        else:
            ui.err("Choix invalide.")
            return
    except Exception as exc:
        ui.err(f"Erreur : {exc}")
        return
    print()
    print("  " + ui.paint(out, ui.G))
    ui.save_output("encode", out)


def _rot13(text):
    def shift(char):
        if "a" <= char <= "z":
            return chr((ord(char) - ord("a") + 13) % 26 + ord("a"))
        if "A" <= char <= "Z":
            return chr((ord(char) - ord("A") + 13) % 26 + ord("A"))
        return char

    return "".join(shift(c) for c in text)


def _caesar(text, shift):
    def shift_char(char):
        if "a" <= char <= "z":
            return chr((ord(char) - ord("a") + shift) % 26 + ord("a"))
        if "A" <= char <= "Z":
            return chr((ord(char) - ord("A") + shift) % 26 + ord("A"))
        return char

    return "".join(shift_char(c) for c in text)


def password_generator():
    ui.module_header(27, "Password Generator", "Mots de passe aleatoires avec entropie mesuree")
    length = ui.ask_int("Longueur", 16, 4, 128)
    count = ui.ask_int("Nombre de mots de passe", 5, 1, 50)
    use_upper = ui.ask_choice("Majuscules ?", ["o", "n"], "o") == "o"
    use_lower = ui.ask_choice("Minuscules ?", ["o", "n"], "o") == "o"
    use_digits = ui.ask_choice("Chiffres ?", ["o", "n"], "o") == "o"
    use_symbols = ui.ask_choice("Symboles ?", ["o", "n"], "o") == "o"
    no_ambiguous = ui.ask_choice("Exclure 0/O 1/l/I ?", ["o", "n"], "o") == "o"

    pool = ""
    if use_lower:
        pool += string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += "!@#$%^&*()-_=+[]{};:,.?/"
    if no_ambiguous:
        for ch in "0O1lI":
            pool = pool.replace(ch, "")
    if not pool:
        ui.err("Jeu de caracteres vide.")
        return

    import math

    entropy = length * math.log2(len(pool))
    rows = []
    for _ in range(count):
        while True:
            password = "".join(secrets.choice(pool) for _ in range(length))
            if use_lower and not any(c in string.ascii_lowercase for c in password):
                continue
            if use_upper and not any(c in string.ascii_uppercase for c in password):
                continue
            if use_digits and not any(c in string.digits for c in password):
                continue
            if use_symbols and not any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in password):
                continue
            break
        rows.append([password, f"{len(pool)}"])
    ui.table(["MOT DE PASSE", "ALPHABET"], rows, widths=[80, 10])
    level = "faible" if entropy < 40 else "moyen" if entropy < 60 else "fort" if entropy < 80 else "excellent"
    ui.ok(f"Entropie : {entropy:.1f} bits — robustesse {level}")
    ui.save_output("passwords", "\n".join(r[0] for r in rows))
