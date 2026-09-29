"""Module 58 — Code-Obfuscator : minification et encodage de source Python (protection de code).

Modes :
  - minify : suppression des commentaires et lignes vides (semantique preservee),
  - strings : litteraux str encodes en base64 (f-strings et docstrings laisses tels quels),
  - zlib    : wrapper complet zlib+base64+exec (source initiale invisible),
  - hex     : wrapper bytes.fromhex+exec.
"""
import ast
import base64
import io
import os
import token
import tokenize
import zlib

from .. import ui

MODES = ("minify", "strings", "zlib", "hex")


def _rebuild(code, drop_comments=False, replacer=None):
    """Reconstruit le source depuis les tokens (un statement par ligne)."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except Exception:
        return code
    out_lines = []
    current = ""
    prev_type = None

    def flush():
        nonlocal current
        if current.strip():
            out_lines.append(current.rstrip())
        current = ""

    for index, tok in enumerate(tokens):
        ttype, tstr = tok.type, tok.string
        if drop_comments and ttype == token.COMMENT:
            continue
        if ttype in (token.NEWLINE, token.NL, token.ENDMARKER):
            flush()
            prev_type = None
            continue
        if ttype == token.INDENT:
            current += "    "
            prev_type = ttype
            continue
        if ttype == token.DEDENT:
            prev_type = ttype
            continue
        text = tstr
        if replacer is not None:
            text = replacer(index, tokens, tok) or tstr
        # evite les fusions de mots : "return 1" -> "return1" serait invalide
        if prev_type in (token.NAME, token.NUMBER) and ttype in (token.NAME, token.NUMBER, token.STRING):
            current += " "
        current += text
        prev_type = ttype
    flush()
    return "\n".join(out_lines)


def _minify(code):
    return _rebuild(code, drop_comments=True)


def _string_replacer(index, tokens, tok):
    if tok.type != token.STRING:
        return None
    # concatenation implicite de literals adjacents : on n'y touche pas
    if index > 0 and tokens[index - 1].type == token.STRING:
        return None
    if index + 1 < len(tokens) and tokens[index + 1].type == token.STRING:
        return None
    text = tok.string
    prefix_end = 0
    while prefix_end < len(text) and text[prefix_end] in "rbufRBUF":
        prefix_end += 1
    if "f" in text[:prefix_end].lower():
        return None
    try:
        value = ast.literal_eval(text)
    except Exception:
        return None
    if isinstance(value, str):
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return f"__import__('base64').b64decode('{encoded}').decode()"
    if isinstance(value, bytes):
        encoded = base64.b64encode(value).decode("ascii")
        return f"__import__('base64').b64decode('{encoded}')"
    return None


def _encode_strings(code):
    return _rebuild(code, drop_comments=False, replacer=_string_replacer)


def _wrap_zlib(code):
    packed = base64.b64encode(zlib.compress(code.encode("utf-8"))).decode("ascii")
    return (
        "import zlib, base64 as _b64\n"
        f"exec(zlib.decompress(_b64.b64decode('{packed}')).decode('utf-8'))\n"
    )


def _wrap_hex(code):
    packed = code.encode("utf-8").hex()
    return f"exec(bytes.fromhex('{packed}').decode('utf-8'))\n"


def obfuscate(code, mode="minify"):
    if mode == "minify":
        return _minify(code)
    if mode == "strings":
        return _encode_strings(code)
    if mode == "zlib":
        return _wrap_zlib(code)
    if mode == "hex":
        return _wrap_hex(code)
    raise ValueError(f"mode inconnu : {mode}")


def code_obfuscator():
    ui.module_header(58, "Code-Obfuscator", "Minification / encodage de source Python (protection du code)")
    ui.note("Transformation du code QUE VOUS fournissez : protection de votre propre source.")

    path = ui.ask_required("Fichier .py a traiter")
    if not os.path.isfile(path):
        ui.err(f"Fichier introuvable : {path}")
        return
    mode = ui.ask_choice("Mode", list(MODES), default="minify")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            source = handle.read()
    except OSError as exc:
        ui.err(f"Lecture impossible : {exc}")
        return

    try:
        result = obfuscate(source, mode)
    except Exception as exc:
        ui.err(f"Transformation impossible : {exc}")
        return
    if result == source:
        ui.info("Aucun changement : le code est deja dans cette forme.")
        return
    try:
        compile(result, "<obf>", "exec")
    except SyntaxError as exc:
        ui.err(f"Source genere invalide, ecriture annulee : {exc}")
        return

    base, _ext = os.path.splitext(path)
    sortie = base + "_obf.py"
    saisie = ui.ask("Chemin de sortie", default=sortie).strip()
    if saisie:
        sortie = saisie
    if os.path.exists(sortie) and not ui.confirm(f"{sortie} existe, ecraser ?", default=False):
        ui.info("Annule.")
        return
    try:
        with open(sortie, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(result)
    except OSError as exc:
        ui.err(f"Ecriture impossible : {exc}")
        return
    ui.ok(f"Ecrit : {sortie} ({len(result)} octets, mode {mode})")
    ui.kv([
        ("Entree", f"{len(source)} octets"),
        ("Sortie", f"{len(result)} octets"),
        ("Ratio", f"{len(result) / max(len(source), 1) * 100:.0f}%"),
        ("Executable", "oui (compile verifie)"),
    ])
