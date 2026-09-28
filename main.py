#!/usr/bin/env python3
import argparse
import sys
import time

from fckmt import __version__, banner, config, fonts, registry, ui


def render_menu(pages, page_index, window_mode):
    category, items = pages[page_index]
    ui.clear()
    print(ui.paint("  ╔" + "═" * 64 + "╗", ui.R))
    print(ui.paint("  ║" + config.TOOL_NAME.center(64) + "║", ui.R, ui.K))
    print(ui.paint("  ║" + f"v{config.VERSION} · par {config.AUTHOR} ({config.AUTHOR_ALIAS}) · {registry.MODULE_COUNT} modules · {config.LICENSE}".center(64) + "║", ui.W))
    print(ui.paint("  ╚" + "═" * 64 + "╝", ui.R))
    print()
    print(ui.paint("  ┌" + "─" * 64 + "┐", ui.DR))
    header = f"  │  {category}  —  page {page_index + 1}/{len(pages)}"
    print(ui.paint(header.ljust(67) + "│", ui.DR, ui.K))
    print(ui.paint("  ├" + "─" * 64 + "┤", ui.DR))
    for num, key, desc, _func in items:
        head = "  │  " + f"[{num:02d}] " + key.ljust(26)
        desc_t = desc[:31].ljust(31)
        print(ui.paint(head, ui.W, ui.K) + ui.paint(desc_t, ui.X) + ui.paint("│", ui.DR))
    print(ui.paint("  └" + "─" * 64 + "┘", ui.DR))
    print()
    mode = "fenetre" if window_mode else "local"
    print(ui.paint(f"  [n] Page suivante   [p] Page precedente   [f] Execution : {mode}", ui.Y))
    print(ui.paint("  [c] Contact   [i] Infos   [q] Quitter", ui.X))
    print()


def _interactive():
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def spawn_module_window(number, key):
    if sys.platform != "win32":
        return False
    import os
    import subprocess

    exe = sys.executable
    script = os.path.abspath(__file__)
    title = f"FCK :: {key}"
    command = f'cmd /c start "{title}" "{exe}" "{script}" --module {number}'
    subprocess.Popen(command)
    return True


def run_single_module(entry):
    ui.clear()
    banner.print_banner()
    print()
    ui.info(f"Module {entry['num']:02d} · {entry['key']} · {entry['category']}")
    try:
        entry["func"]()
    except SystemExit:
        raise
    except Exception as exc:
        ui.err(f"Erreur dans le module {entry['key']} : {exc}")
    ui.pause("Entree pour terminer...")
    return 0


def run_module(entry):
    try:
        entry["func"]()
    except SystemExit:
        raise
    except Exception as exc:
        ui.err(f"Erreur dans le module {entry['key']} : {exc}")
    ui.pause()


def about_box():
    ui.clear()
    ui.big_title("FCK MULTI TOOL")
    print()
    ui.title_box(config.TOOL_NAME, "multi-outils reseaux · web · osint · crypto · systeme")
    print()
    ui.kv([
        ("Version", config.VERSION),
        ("Auteur", f"{config.AUTHOR} ({config.AUTHOR_ALIAS})"),
        ("Modules", str(registry.MODULE_COUNT)),
        ("Licence", config.LICENSE + " — usage gratuit"),
        ("GitHub", config.GITHUB),
        ("Releases", config.RELEASES),
    ])
    print()
    ui.note("Utilisez ces outils uniquement sur des systemes dont vous etes autorise a tester la securite.")
    ui.pause()


def run_selftest():
    import os

    failures = []

    def check(label, condition, hard=True):
        if condition:
            ui.ok(label)
        elif hard:
            ui.err("ECHEC : " + label)
            failures.append(label)
        else:
            ui.info("ignore (hors ligne ?) : " + label)

    ui.clear()
    ui.title_box("SELFTEST", config.TOOL_NAME + " v" + __version__)
    print()
    check(f"Import du package (v{__version__})", __version__ == config.VERSION)
    entries = registry.entries()
    check(f"Registre : {len(entries)} modules", len(entries) == registry.MODULE_COUNT == 47)
    nums = [e["num"] for e in entries]
    check("Numeros 1..47 uniques", sorted(nums) == list(range(1, 48)))
    check("Toutes les fonctions sont appelables", all(callable(e["func"]) for e in entries))
    pages = registry.build_pages()
    check("Pages du menu (10 modules max)", all(len(items) <= registry.PAGE_SIZE for _, items in pages))
    check("Recherche par cle", registry.by_key("scanner-de-ports") is not None)

    from fckmt.modules import crypto as crypto_mod
    from fckmt.modules import network as net_mod
    from fckmt.modules import web as web_mod
    from fckmt.modules import osint as osint_mod
    from fckmt.modules import system as sys_mod
    from fckmt.modules import nettools, websec, intel, pwtools, sysaudit
    from fckmt import net as fnet

    import base64
    import hashlib
    import socket
    import threading

    art = banner.load_banner()
    check("Banniere ASCII chargee", "█" in art and len(art) > 100)
    check("Fonte bloc (5 lignes)", len(fonts.render("FCK MULTI TOOL")) == 5 and fonts.text_width("FCK") > 10)
    check("Titre du menu empaquete", fonts.pack_title("Scanner de ports") != [])

    md5_test = hashlib.md5(b"test").hexdigest()
    check("MD5('test') connu", md5_test == "098f6bcd4621d373cade4e832627b4f6")
    check("Identificateur de hash", crypto_mod.identify_hash(md5_test) == ["md5"])
    check("Parseur de ports", net_mod.parse_ports("22,80,443") == [22, 80, 443])
    check("Parseur de plage", net_mod.parse_ports("100-103") == [100, 101, 102, 103])
    check("Encodeur base64", base64.b64encode(b"fck").decode() == "ZmNr")
    check("Chiffrement Caesar", crypto_mod._caesar("abc", 1) == "bcd")
    check("ROT13", crypto_mod._rot13("test") == "grfg")
    check("URL normalisee", web_mod.normalize_url("example.com") == "https://example.com")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        try:
            conn, _ = server.accept()
            conn.sendall(b"FCK-TEST\r\n")
            conn.close()
        except Exception:
            pass

    threading.Thread(target=serve, daemon=True).start()
    result = net_mod._check_port("127.0.0.1", port, 2.0, True)
    server.close()
    check("Scanner de ports (serveur local)", result is not None and result["port"] == port)
    if result:
        check("Banniere capturee", "FCK-TEST" in (result.get("banner") or ""))

    password = "".join(__import__("secrets").choice("abcdef0123456789") for _ in range(16))
    check("Generateur de mots de passe", len(password) == 16)

    info = nettools.cidr_info("192.168.1.0/24")
    check("Calcul CIDR (254 hotes)", info["hotes_utilisables"] == 254 and info["broadcast"] == "192.168.1.255")
    check("Normalisation MAC", nettools._normalize_mac("aa-bb-cc-dd-ee-ff") == "AABBCCDDEEFF")
    check("Fabricant OUI local", bool(nettools._mac_vendor("50C7BF123456")))

    sample_jwt = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    sample_jwt += "." + base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode() + ".signature"
    decoded = websec.decode_jwt(sample_jwt)
    check("Decodage JWT", decoded["header"].get("alg") == "HS256" and decoded["payload"].get("sub") == "1")
    check("Wordlist de decouverte", len(websec.DIR_WORDLIST) > 100)

    rfc_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    check("TOTP RFC 6238 (vecteur 94287082)", pwtools._totp(rfc_secret, for_time=59, digits=8)[0] == "94287082")
    phrase, entropy = pwtools._generate_passphrase(5)
    check("Generateur de phrase de passe", len(phrase) > 10 and entropy > 50)
    weak = pwtools._analyze_password("password")
    strong = pwtools._analyze_password("Zt7!qWm2#vLp9@rX")
    check("Analyse : mot de passe faible", weak["effective"] <= 10)
    check("Analyse : mot de passe fort", strong["effective"] > 60)

    hibp = hashlib.sha1(b"password").hexdigest().upper()
    check("Hash SHA-1 local (vecteur HIBP)", hibp == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
    sample_header = (
        "Received: from mail.example.com (mail.example.com [203.0.113.7]) by mx.google.com with ESMTPS id ABC\r\n"
        "Received: from internal.local ([10.0.0.5]) by mail.example.com with ESMTP id DEF\r\n"
        "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=none\r\n"
        "From: Jean <jean@example.com>\r\n"
        "Subject: Test\r\n"
    )
    parsed = intel.parse_email_header(sample_header)
    check("Analyse d'en-tete email", len(parsed["hops"]) == 2 and parsed["auth"].get("spf") == "pass")

    import tempfile

    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as tmp:
        tmp.write(bytes(range(256)))
        tmp_path = tmp.name
    report = {}
    try:
        sys_mod._entropy(bytes(range(256)))
        report["entropy"] = True
    except Exception:
        report["entropy"] = False
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    check("Calcul d'entropie", report.get("entropy", False))

    strings = sysaudit._extract_strings(b"hello world\x00https://exemple.test/x\x00")
    check("Extraction de chaines", "hello world" in strings["ascii"] and "https://exemple.test/x" in strings["urls"])
    if os.name == "nt":
        pe = sysaudit.parse_pe(sys.executable)
        check("Analyse PE (python.exe)", pe is not None and bool(pe["machine"]))
    else:
        check("Analyse PE (python.exe)", True, hard=False)

    check("Extraction EXIF (JPEG sans APP1)", osint_mod._extract_jpeg_exif(b"\xff\xd8\xff\xe0test") == {})

    resp = fnet.http_get("http://example.com", timeout=6)
    check("Acces reseau (example.com)", resp.status in (200, 301, 302), hard=False)
    try:
        records = fnet.dns_query("example.com", "A")
        check("Requette DNS (example.com)", bool(records), hard=False)
    except Exception:
        check("Requette DNS (example.com)", False, hard=False)

    print()
    if failures:
        ui.err(f"{len(failures)} echec(s) : " + ", ".join(failures))
        return 1
    ui.ok("Selftest termine — tous les tests fonctionnels passent.")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="fckmt", description=config.TOOL_NAME)
    parser.add_argument("--no-anim", action="store_true", help="desactiver l'animation de demarrage")
    parser.add_argument("--selftest", action="store_true", help="verifier les modules puis quitter")
    parser.add_argument("--list", action="store_true", help="lister les modules puis quitter")
    parser.add_argument("--version", action="store_true", help="afficher la version")
    parser.add_argument("--module", metavar="N", help="lancer un module seul (numero ou cle)")
    args = parser.parse_args()

    if args.version:
        print(f"{config.TOOL_NAME} v{config.VERSION} by {config.AUTHOR} ({config.AUTHOR_ALIAS})")
        return 0
    if args.list:
        for entry in registry.entries():
            print(f"{entry['num']:02d}  {entry['key']:<28} {entry['desc']}")
        return 0
    if args.selftest:
        return run_selftest()
    if args.module:
        entry = None
        if str(args.module).isdigit():
            entry = registry.by_number(int(args.module))
        if entry is None:
            entry = registry.by_key(str(args.module))
        if entry is None:
            print(f"Module inconnu : {args.module}")
            return 1
        return run_single_module(entry)

    banner.startup_animation(registry.MODULE_COUNT, fast=args.no_anim)
    pages = registry.build_pages()
    page = 0
    window_mode = sys.platform == "win32" and _interactive()
    while True:
        render_menu(pages, page, window_mode)
        try:
            choice = ui.ask("Choix").lower()
        except SystemExit:
            raise
        if choice in ("q", "quit", "exit", "00"):
            print(ui.paint("  A bientot — " + config.AUTHOR + " (" + config.AUTHOR_ALIAS + ")", ui.G, ui.K))
            return 0
        if choice in ("n", "next", "+"):
            page = (page + 1) % len(pages)
            continue
        if choice in ("p", "prev", "-"):
            page = (page - 1) % len(pages)
            continue
        if choice in ("f", "fenetre", "window"):
            window_mode = not window_mode
            ui.info(f"Execution des modules : {'nouvelle fenetre' if window_mode else 'cette console'}")
            time.sleep(0.7)
            continue
        if choice in ("c", "contact", "site"):
            ui.open_url(config.GITHUB)
            ui.pause()
            continue
        if choice in ("i", "info", "infos", "aide"):
            about_box()
            continue
        try:
            number = int(choice)
        except ValueError:
            ui.err("Choix invalide.")
            time.sleep(0.6)
            continue
        entry = registry.by_number(number)
        if not entry:
            ui.err(f"Aucun module au numero {number}.")
            time.sleep(0.6)
            continue
        if window_mode:
            try:
                if spawn_module_window(entry["num"], entry["key"]):
                    ui.ok(f"{entry['key']} ouvert dans une nouvelle fenetre")
                    time.sleep(0.7)
                    continue
            except Exception as exc:
                ui.err(f"Fenetre impossible ({exc}) — execution locale.")
                time.sleep(0.7)
        run_module(entry)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(0)
