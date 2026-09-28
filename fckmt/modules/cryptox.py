"""Modules 51-52 — crypto : steganographie PNG (LSB) et BIP39."""
import hashlib
import os
import struct
import zlib

from .. import ui

BIP39_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "fckmt",
    "data",
    "bip39_english.txt",
)

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _png_parse(data):
    if not data.startswith(_PNG_SIG):
        raise ValueError("signature PNG absente")
    offset = len(_PNG_SIG)
    meta = None
    idat = bytearray()
    while offset + 8 <= len(data):
        length, ctype = struct.unpack("!I4s", data[offset:offset + 8])
        body = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        if ctype == b"IHDR":
            meta = struct.unpack("!IIBBBBB", body)
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
    if meta is None:
        raise ValueError("IHDR manquant")
    width, height, depth, color, comp, filt, interlace = meta
    if depth != 8:
        raise ValueError(f"profondeur {depth} bits non supportee (8 bits max)")
    if interlace != 0:
        raise ValueError("PNG interlace non supporte")
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
    if channels is None:
        raise ValueError("PNG palettes (type 3) non supporte — reencode en RGB/RGBA")
    raw = zlib.decompress(bytes(idat))
    stride = width * channels
    if len(raw) != height * (stride + 1):
        raise ValueError("flux PNG incoherent")
    out = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _y in range(height):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if ftype == 1:
            for x in range(channels, stride):
                line[x] = (line[x] + line[x - channels]) & 0xFF
        elif ftype == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif ftype == 3:
            for x in range(stride):
                left = line[x - channels] if x >= channels else 0
                line[x] = (line[x] + ((left + prev[x]) >> 1)) & 0xFF
        elif ftype == 4:
            for x in range(stride):
                left = line[x - channels] if x >= channels else 0
                up_left = prev[x - channels] if x >= channels else 0
                line[x] = (line[x] + _paeth(left, prev[x], up_left)) & 0xFF
        elif ftype != 0:
            raise ValueError(f"filtre PNG inconnu {ftype}")
        out += line
        prev = line
    return width, height, color, channels, bytes(out)


def _png_encode(width, height, color, channels, pixels):
    stride = width * channels
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw += pixels[y * stride:(y + 1) * stride]

    def chunk(ctype, body):
        return (struct.pack("!I", len(body)) + ctype + body
                + struct.pack("!I", zlib.crc32(ctype + body) & 0xFFFFFFFF))

    ihdr = struct.pack("!IIBBBBB", width, height, 8, color, 0, 0, 0)
    return (_PNG_SIG + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def _usable_channel_indexes(color, channels):
    if color == 6:
        return (0, 1, 2)
    if color == 4:
        return (0,)
    if color == 2:
        return (0, 1, 2)
    return (0,)


def png_lsb_embed(png_bytes, message):
    """Insert un message UTF-8 dans les LSB (canaux RGB). Retourne un nouveau PNG."""
    width, height, color, channels, pixels = _png_parse(png_bytes)
    usable = _usable_channel_indexes(color, channels)
    payload = message.encode("utf-8")
    header = b"FCK1" + len(payload).to_bytes(4, "big")
    blob = header + payload
    need = len(blob) * 8
    stride = width * channels
    slots = width * height * len(usable)
    if slots < need:
        raise ValueError(
            f"capacite insuffisante : {slots // 8} octets max, {len(blob)} requis "
            f"(image de {width}x{height})"
        )
    buf = bytearray(pixels)
    bit_index = 0
    for pixel in range(width * height):
        base = pixel * channels
        for channel in usable:
            if bit_index >= need:
                break
            byte_i = bit_index // 8
            bit = 7 - (bit_index % 8)
            value = (blob[byte_i] >> bit) & 1
            idx = base + channel
            buf[idx] = (buf[idx] & 0xFE) | value
            bit_index += 1
        if bit_index >= need:
            break
    return _png_encode(width, height, color, channels, bytes(buf))


def png_lsb_extract(png_bytes):
    """Retourne le message cache, ou None si aucun en-tete FCK1."""
    width, height, color, channels, pixels = _png_parse(png_bytes)
    usable = _usable_channel_indexes(color, channels)
    stride = width * channels

    def read_bits(count, start=0):
        out = bytearray()
        bit_index = start
        limit = width * height * len(usable)
        while len(out) * 8 < count and bit_index < limit:
            value = 0
            for _ in range(8):
                if bit_index >= limit:
                    break
                pixel = bit_index // len(usable)
                channel = usable[bit_index % len(usable)]
                value = (value << 1) | (pixels[pixel * channels + channel] & 1)
                bit_index += 1
            out.append(value)
        return bytes(out)

    header = read_bits(64, 0)
    if header[:4] != b"FCK1":
        return None
    length = int.from_bytes(header[4:], "big")
    if length <= 0 or length > len(pixels) // 8 + 8:
        return None
    body = read_bits(length * 8, 64)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def png_lsb_roundtrip_test():
    """Auto-test interne : construction d'un PNG, embedding, extraction."""
    width, height = 24, 24
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            pixels += bytes(((x * 9) & 0xFF, (y * 7) & 0xFF, ((x + y) * 5) & 0xFF))
    png = _png_encode(width, height, 2, 3, bytes(pixels))
    message = "salut c'est potato 6767"
    hidden = png_lsb_embed(png, message)
    return png_lsb_extract(hidden) == message


def _bip39_words():
    with open(BIP39_PATH, "r", encoding="utf-8") as handle:
        words = [line.strip() for line in handle if line.strip()]
    if len(words) != 2048:
        raise ValueError(f"wordlist BIP39 invalide ({len(words)} mots)")
    return words


def bip39_mnemonic(entropy, words=None):
    words = words or _bip39_words()
    ent_bits = len(entropy) * 8
    if ent_bits not in (128, 160, 192, 224, 256):
        raise ValueError("entropie BIP39 : 16/20/24/28/32 octets attendus")
    checksum_len = ent_bits // 32
    digest = hashlib.sha256(entropy).digest()
    bits = (bin(int.from_bytes(entropy, "big"))[2:].zfill(ent_bits)
            + bin(int.from_bytes(digest, "big"))[2:].zfill(256)[:checksum_len])
    indexes = [int(bits[i:i + 11], 2) for i in range(0, len(bits), 11)]
    return " ".join(words[i] for i in indexes)


def bip39_seed(mnemonic, passphrase=""):
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"),
                               ("mnemonic" + passphrase).encode("utf-8"), 2048)


def bip39_validate(mnemonic):
    words = _bip39_words()
    tokens = mnemonic.strip().lower().split()
    if len(tokens) not in (12, 15, 18, 21, 24):
        return False, "nombre de mots invalide"
    lookup = {w: i for i, w in enumerate(words)}
    try:
        indexes = [lookup[t] for t in tokens]
    except KeyError as exc:
        return False, f"mot hors wordlist : {exc.args[0]}"
    total_bits = len(tokens) * 11
    ent_bits = total_bits * 32 // 33
    bits = "".join(bin(i)[2:].zfill(11) for i in indexes)
    entropy = bytes.fromhex(hex(int(bits[:ent_bits], 2))[2:].zfill(ent_bits // 4))
    checksum_len = total_bits - ent_bits
    digest = hashlib.sha256(entropy).digest()
    expected = bin(int.from_bytes(digest, "big"))[2:].zfill(256)[:checksum_len]
    if bits[ent_bits:] != expected:
        return False, "checksum incorrect"
    return True, entropy.hex()


def stegano_png():
    ui.module_header(51, "Stegano-PNG", "Dissimuler / extraire un message dans un PNG (LSB)")
    mode = ui.ask_choice("Mode", ["Encoder un message", "Decoder un message"], default="Encoder un message")
    path = ui.ask_required("Chemin du fichier PNG").strip().strip('"')
    try:
        with open(path, "rb") as handle:
            png = handle.read()
    except OSError as exc:
        ui.err(f"Lecture impossible : {exc}")
        return

    if mode.startswith("Decoder"):
        message = png_lsb_extract(png)
        if message is None:
            ui.info("Aucun message FCK1 trouve dans ce PNG.")
            return
        ui.ok("Message extrait :")
        print()
        print("  " + ui.paint(message, ui.W))
        print()
        ui.save_output("stegano", message)
        return

    message = ui.ask("Message a dissimuler", default="")
    if not message:
        ui.note("Message vide.")
        return
    try:
        hidden = png_lsb_embed(png, message)
    except ValueError as exc:
        ui.err(str(exc))
        return
    except Exception as exc:
        ui.err(f"Encodage impossible : {exc}")
        return
    out_dir = os.path.dirname(path) or "."
    base = os.path.splitext(os.path.basename(path))[0]
    out_path = os.path.join(out_dir, f"{base}.stego.png")
    counter = 1
    while os.path.exists(out_path):
        out_path = os.path.join(out_dir, f"{base}.stego{counter}.png")
        counter += 1
    try:
        with open(out_path, "wb") as handle:
            handle.write(hidden)
    except OSError as exc:
        ui.err(f"Ecriture impossible : {exc}")
        return
    ui.ok(f"Message insere — {len(hidden)} octets ecrits")
    ui.kv([
        ("Sortie", out_path),
        ("Capacite utilisee", f"{len(message.encode('utf-8')) + 8} octets (LSB RGB)"),
    ])
    check = png_lsb_extract(hidden)
    if check == message:
        ui.info("Verification : extraction reussie apres encodage.")
    else:
        ui.err("Verification d'extraction echouee.")


def bip39_generator():
    ui.module_header(52, "BIP39-Generator", "Seed phrase BIP39 (12/24 mots) — generation locale, rien n'est envoye")
    mode = ui.ask_choice("Mode", ["Generer", "Verifier une phrase"], default="Generer")

    if mode.startswith("Verifier"):
        mnemonic = ui.ask("Phrase (12/24 mots)").strip().lower()
        if not mnemonic:
            return
        valid, info = bip39_validate(mnemonic)
        if valid:
            ui.ok(f"Phrase VALIDE — entropie {info}")
            passphrase = ui.ask("Passphrase (Entree = aucune)", default="")
            seed = bip39_seed(mnemonic, passphrase)
            print()
            ui.kv([("Seed (hex)", seed.hex())])
            ui.note("Seed sensible : jamais partagee, jamais sauvegardee automatiquement.")
        else:
            ui.err(f"Phrase invalide : {info}")
        return

    words_count = ui.ask_choice("Nombre de mots", ["12", "24"], default="12")
    entropy = os.urandom(16 if words_count == "12" else 32)
    mnemonic = bip39_mnemonic(entropy)
    passphrase = ui.ask("Passphrase optionnelle (Entree = aucune)", default="")

    print()
    ui.ok(f"Phrase BIP39 ({words_count} mots) :")
    print()
    tokens = mnemonic.split()
    for i in range(0, len(tokens), 6):
        chunk = " ".join(f"{j + 1:2d} {w}" for j, w in enumerate(tokens[i:i + 6], i))
        print("  " + ui.paint(chunk, ui.W))
    print()
    seed = bip39_seed(mnemonic, passphrase)
    ui.kv([
        ("Entropie (hex)", entropy.hex()),
        ("Checksum", "integre (SHA-256)"),
        ("Seed (hex, PBKDF2-SHA512 2048)", seed.hex()),
    ])
    ui.note("Phrase et seed affichees a l'ecran uniquement — sauvegarde manuelle recommandee.")
    ui.save_output("bip39", f"Phrase : {mnemonic}\nEntropie : {entropy.hex()}\nSeed : {seed.hex()}")
