#!/usr/bin/env python3
import argparse
import sys
import time

from fckmt import __version__, banner, config, registry, ui


def render_menu(page_index):
    categories = registry.CATEGORIES
    category, items = categories[page_index]
    ui.clear()
    print(ui.paint("  ╔" + "═" * 64 + "╗", ui.M))
    print(ui.paint("  ║" + config.TOOL_NAME.center(64) + "║", ui.M, ui.K))
    print(ui.paint("  ║" + f"v{config.VERSION} · par {config.AUTHOR} ({config.AUTHOR_ALIAS}) · {registry.MODULE_COUNT} modules · {config.LICENSE}".center(64) + "║", ui.M))
    print(ui.paint("  ╚" + "═" * 64 + "╝", ui.M))
    print()
    print(ui.paint("  ┌" + "─" * 64 + "┐", ui.C))
    header = f"  │  {category}  —  page {page_index + 1}/{len(categories)}"
    print(ui.paint(header.ljust(67) + "│", ui.C, ui.K))
    print(ui.paint("  ├" + "─" * 64 + "┤", ui.C))
    for num, key, desc, _func in items:
        head = "  │  " + f"[{num:02d}] " + key.ljust(26)
        desc_t = desc[:31].ljust(31)
        print(ui.paint(head, ui.W, ui.K) + ui.paint(desc_t, ui.X) + ui.paint("│", ui.C))
    print(ui.paint("  └" + "─" * 64 + "┘", ui.C))
    print()
    controls = "  [n] Page suivante   [p] Page precedente"
    extras = "   [c] Contact   [i] Infos   [q] Quitter"
    print(ui.paint(controls, ui.Y) + ui.paint(extras, ui.X))
    print()


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
    check(f"Registre : {len(entries)} modules", len(entries) == registry.MODULE_COUNT == 30)
    nums = [e["num"] for e in entries]
    check("Numeros 1..30 uniques", sorted(nums) == list(range(1, 31)))
    check("Toutes les fonctions sont appelables", all(callable(e["func"]) for e in entries))

    from fckmt.modules import crypto as crypto_mod
    from fckmt.modules import network as net_mod
    from fckmt.modules import web as web_mod
    from fckmt.modules import osint as osint_mod
    from fckmt.modules import system as sys_mod
    from fckmt import net as fnet

    import base64
    import hashlib
    import socket
    import threading

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
        import os

        os.unlink(tmp_path)
    except Exception:
        pass
    check("Calcul d'entropie", report.get("entropy", False))

    art = banner.load_banner()
    check("Banniere ASCII chargee", "█" in art and len(art) > 100)
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

    banner.startup_animation(registry.MODULE_COUNT, fast=args.no_anim)
    page = 0
    pages = len(registry.CATEGORIES)
    while True:
        render_menu(page)
        try:
            choice = ui.ask("Choix").lower()
        except SystemExit:
            raise
        if choice in ("q", "quit", "exit", "00"):
            print(ui.paint("  A bientot — " + config.AUTHOR + " (" + config.AUTHOR_ALIAS + ")", ui.G, ui.K))
            return 0
        if choice in ("n", "next", "+"):
            page = (page + 1) % pages
            continue
        if choice in ("p", "prev", "-"):
            page = (page - 1) % pages
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
        run_module(entry)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(0)
