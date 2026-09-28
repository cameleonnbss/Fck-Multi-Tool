import os
import sys
import time
import threading
import random

try:
    import colorama
    colorama.init()
    _HAS_COLORAMA = True
except Exception:
    _HAS_COLORAMA = False

if sys.platform.startswith("win"):
    try:
        os.system("")
    except Exception:
        pass

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

R = "\033[91m"
DR = "\033[31m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
X = "\033[2m"
K = "\033[1m"
U = "\033[4m"
Z = "\033[0m"

PALETTE = [R, W, R, DR, R]


def paint(text, *styles):
    return "".join(styles) + str(text) + Z


def clear():
    os.system("cls" if sys.platform.startswith("win") else "clear")


def line(char="─", width=66, color=None):
    print(paint(char * width, color or X))


def title_box(title, subtitle=None):
    inner = 64
    print(paint("  ╔" + "═" * inner + "╗", R))
    print(paint("  ║" + title.center(inner) + "║", R, K))
    if subtitle:
        print(paint("  ║" + subtitle.center(inner) + "║", W))
    print(paint("  ╚" + "═" * inner + "╝", R))


def big_title(name, indent="  ", color=None):
    from . import fonts

    lines = fonts.pack_title(name)
    if not lines:
        return 0
    count = 0
    for chunk in lines:
        for row in fonts.render(chunk):
            if row:
                print(paint(indent + row, color or R, K))
                count += 1
    return count


def module_header(num, name, desc=""):
    print()
    big_title(name)
    print()
    l1 = f"  [{num:02d}]  {name}"
    l2 = f"      {desc}" if desc else ""
    width = max(len(l1), len(l2), 36)
    print(paint("  ╔" + "═" * width + "╗", R))
    print(paint("  ║" + l1.ljust(width) + "║", R, K))
    if l2:
        print(paint("  ║" + l2.ljust(width) + "║", W))
    print(paint("  ╚" + "═" * width + "╝", R))
    print()


def info(msg):
    print(paint(f"  [!]", Y, K) + paint(f" | {msg}", W))


def ok(msg):
    print(paint(f"  [+]", G, K) + paint(f" | {msg}", W))


def err(msg):
    print(paint(f"  [x]", R, K) + paint(f" | {msg}", W))


def add(msg):
    print(paint(f"  [+]", G, K) + paint(f" | {msg}", W))


def wait(msg):
    print(paint(f"  [~]", R, K) + paint(f" | {msg}", W))


def note(msg):
    print(paint(f"  [NOTE]", DR, K) + paint(f" | {msg}", W))


def prompt_label():
    return paint("  [>]", R, K) + paint(" | ", W)


def ask(message, default=None):
    try:
        suffix = f" [{default}]" if default not in (None, "") else ""
        value = input(prompt_label() + message + suffix + " ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)
    if not value and default is not None:
        return str(default)
    return value


def ask_required(message):
    while True:
        value = ask(message)
        if value:
            return value
        err("Champ obligatoire.")


def ask_int(message, default=None, minimum=None, maximum=None):
    while True:
        raw = ask(message, default)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            err("Nombre invalide.")
            continue
        if minimum is not None and value < minimum:
            err(f"Minimum : {minimum}")
            continue
        if maximum is not None and value > maximum:
            err(f"Maximum : {maximum}")
            continue
        return value


def ask_choice(message, choices, default=None):
    joined = "/".join(choices)
    while True:
        raw = ask(f"{message} ({joined})", default).lower()
        for choice in choices:
            if raw == choice.lower():
                return choice
        err(f"Choix invalide : {joined}")


def confirm(message, default=True):
    raw = ask_choice(message, ["o", "n"], "o" if default else "n")
    return raw == "o"


def pause(message="Appuyez sur Entree pour revenir au menu..."):
    try:
        input(paint("  [>]", R, K) + paint(f" | {message}", X))
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0)


def table(headers, rows, widths=None, color=None):
    if not rows:
        info("Aucun resultat.")
        return
    if widths is None:
        widths = []
        for i, head in enumerate(headers):
            longest = max([len(str(head))] + [len(str(r[i])) for r in rows])
            widths.append(min(longest + 2, 44))
    head_line = "  " + "".join(str(h).ljust(w) for h, w in zip(headers, widths))
    print(paint(head_line, color or K, U))
    print(paint("  " + "─" * min(sum(widths) + 2, 110), X))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            text = str(cell)
            if len(text) > widths[i] - 1:
                text = text[: widths[i] - 2] + "…"
            cells.append(text.ljust(widths[i]))
        print("  " + "".join(cells))


def kv(pairs, key_color=None, val_color=None):
    width = max(len(str(k)) for k, _ in pairs) + 2
    for key, value in pairs:
        print("  " + paint(str(key).ljust(width), key_color or C, K) + paint(str(value), val_color or W))


class Spinner:
    def __init__(self, message="Traitement en cours"):
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def _run(self):
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        i = 0
        while not self._stop.is_set():
            frame = frames[i % len(frames)]
            sys.stdout.write("\r  " + paint(frame, R) + paint(f" {self.message}... ", X))
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r" + " " * (len(self.message) + 14) + "\r")
        sys.stdout.flush()


def progress(label, current, total):
    if not total:
        sys.stdout.write("\r  " + paint(f"[{current}]", R) + paint(f"  {label}...", X))
        sys.stdout.flush()
        return
    width = 30
    filled = int(width * current / max(total, 1))
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * current / max(total, 1))
    sys.stdout.write("\r  " + paint(f"[{bar}]", R) + paint(f" {pct:3d}%  {label}", X))
    sys.stdout.flush()


def progress_done():
    sys.stdout.write("\r" + " " * 90 + "\r")
    sys.stdout.flush()


def save_output(name, content, ext="txt"):
    from datetime import datetime

    out_dir = os.path.join(os.getcwd(), "output")
    try:
        os.makedirs(out_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"{name}_{stamp}.{ext}")
        with open(path, "w", encoding="utf-8", errors="replace") as handle:
            handle.write(content if isinstance(content, str) else str(content))
        ok(f"Resultat sauvegarde : {path}")
        return path
    except Exception as exc:
        err(f"Sauvegarde impossible : {exc}")
        return None


def open_url(url):
    import webbrowser

    try:
        webbrowser.open(url)
        ok(f"Ouverture de {url}")
        return True
    except Exception as exc:
        err(f"Impossible d'ouvrir le lien : {exc}")
        return False


def center(text, width=66):
    return text.center(width)


def glitch_line(text, ratio=0.18):
    glyphs = "▒▓░█▄▀▌▐╱╲"
    out = []
    for ch in text:
        if ch != " " and random.random() < ratio:
            out.append(random.choice(glyphs))
        else:
            out.append(ch)
    return "".join(out)
