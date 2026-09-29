"""Module 54 — Hash-Identifier : identification de type de hash (longueur, format, regex)."""
import base64
import re

from .. import ui

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

HEX_TYPES = {
    8: [("crc32", "basse", "8 hex = CRC-32 (32 bits)"),
        ("adler32", "basse", "8 hex = Adler-32 (32 bits)")],
    32: [("md5", "haute", "32 hex = MD5 (128 bits)"),
         ("md4", "moyenne", "32 hex = MD4 (128 bits)"),
         ("ntlm", "moyenne", "32 hex = NTLM (MD4)"),
         ("md2", "basse", "32 hex = MD2 (128 bits)")],
    40: [("sha1", "haute", "40 hex = SHA-1 (160 bits)"),
         ("ripemd160", "moyenne", "40 hex = RIPEMD-160"),
         ("mysql41", "basse", "40 hex = MySQL 4.1 (SHA-1)")],
    56: [("sha224", "haute", "56 hex = SHA-224"),
         ("sha3-224", "basse", "56 hex = SHA3-224")],
    64: [("sha256", "haute", "64 hex = SHA-256 (256 bits)"),
         ("double-md5", "basse", "64 hex = md5(md5(x)) ou sha1 double"),
         ("blake2s", "basse", "64 hex = BLAKE2s-256")],
    96: [("sha384", "haute", "96 hex = SHA-384"),
         ("sha3-384", "basse", "96 hex = SHA3-384")],
    128: [("sha512", "haute", "128 hex = SHA-512"),
          ("whirlpool", "moyenne", "128 hex = Whirlpool"),
          ("sha3-512", "basse", "128 hex = SHA3-512")],
}


def _candidates(value):
    v = (value or "").strip()
    rows = []
    if not v:
        return rows

    def add(name, conf, hint):
        rows.append((name, conf, hint))

    # --- formats a prefixe (signatures fortes) ---
    if v[:4] in ("$2a$", "$2b$", "$2y$"):
        add("bcrypt", "haute", "prefixe $2x$ + sel/cost")
        return rows
    if v.startswith("$argon2"):
        add("argon2id", "haute", "prefixe $argon2 (id/i/d)")
        return rows
    if v.startswith("$scrypt"):
        add("scrypt", "haute", "prefixe $scrypt")
        return rows
    if v.startswith("$1$"):
        add("md5crypt", "haute", "prefixe $1$ (FreeBSD md5crypt)")
        return rows
    if v.startswith("$5$"):
        add("sha256crypt", "haute", "prefixe $5$ (glibc)")
        return rows
    if v.startswith("$6$"):
        add("sha512crypt", "haute", "prefixe $6$ (glibc)")
        return rows
    if v[:3] in ("$P$", "$H$"):
        add("phpass", "haute", "prefixe $P$/$H$ (WordPress/phpass)")
        return rows
    if v.startswith(("pbkdf2_sha256$", "pbkdf2_sha1$")):
        add("django-pbkdf2", "haute", "prefixe pbkdf2_shaXXX$ (Django)")
        return rows
    if v.startswith("$y$"):
        add("yescrypt", "haute", "prefixe $y$")
        return rows
    if v.startswith("$dynamic$"):
        add("john-dynamic", "haute", "format John the Ripper $dynamic$")
        return rows
    if v.upper().startswith("$NETNTLM"):
        add("netntlm", "haute", "hash NetNTLMv1/v2")
        return rows

    # --- JWT : 3 segments base64url ---
    parts = v.split(".")
    if len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", p or "") for p in parts):
        add("jwt", "haute", "3 segments base64url separes par des points")
        return rows

    # --- hex pur ---
    if HEX_RE.fullmatch(v):
        if len(v) == 40 and v.isupper():
            add("mysql41", "moyenne", "40 hex majuscules (MySQL 4.1)")
        rows.extend(HEX_TYPES.get(len(v),
                                  [("hash-hex-long", "basse",
                                    f"{len(v)} hex = {len(v) * 4} bits (type inconnu)")]))
        return rows

    # --- base64 d'un hash ---
    if B64_RE.fullmatch(v) and len(v) % 4 == 0:
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception:
            raw = b""
        sizes = {16: "b64-md5", 20: "b64-sha1", 32: "b64-sha256"}
        if len(raw) in sizes:
            add(sizes[len(raw)], "moyenne", f"base64 de {len(raw)} octets ({len(raw) * 8} bits)")
            inner = raw.hex()
            rows.extend(HEX_TYPES.get(len(inner), []))
            return rows

    add("inconnu", "basse", "aucune signature reconnue")
    return rows


def identify(value):
    """Liste ordonnee de noms de types probables pour une entree de hash."""
    return [name for name, _conf, _hint in _candidates(value)]


def hash_identifier():
    ui.module_header(54, "Hash-Identifier", "Detection du type d'un hash (longueur, format, regex)")
    value = ui.ask_required("Hash a identifier")
    rows = _candidates(value)
    ui.table(
        ["Type", "Confiance", "Indices"],
        [[name, conf, hint] for name, conf, hint in rows],
        widths=[26, 12, 52],
    )
    print()
    charset = "hex" if HEX_RE.fullmatch(value) else ("base64" if B64_RE.fullmatch(value) else "melange")
    ui.kv([
        ("Longueur", f"{len(value)} caracteres"),
        ("Charset", charset),
        ("Candidats", len(rows)),
    ])
    ui.note("Un hash n'a pas de signature unique : longueur + contexte (produit, sel) tranchent.")
