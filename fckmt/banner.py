import os
import shutil
import sys
import time
import random

from . import ui
from . import config
from . import fonts

DEFAULT_BANNER = "\n".join(fonts.render("FCK MULTI TOOL"))

ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
BANNER_PATH = os.path.join(ASSETS_DIR, "banner.txt")
BANNER_BIG_PATH = os.path.join(ASSETS_DIR, "banner_big.txt")

BOOT_LINES = [
    "[SYSTEM] Initialisation de FCK MULTI TOOL...",
    "[SYSTEM] Chargement du registre de modules...",
    "[SYSTEM] Activation du theme rouge...",
    "[SYSTEM] Synchro banniere / fonte bloc...",
    "[SYSTEM] Handshake termine — pret.",
]

BOOT_RGB = [(255, 70, 90), (255, 255, 255), (210, 35, 60), (150, 15, 35)]


def load_banner():
    try:
        with open(BANNER_PATH, "r", encoding="utf-8") as handle:
            content = handle.read().strip("\n")
            if content.strip():
                return content
    except Exception:
        pass
    return DEFAULT_BANNER


def load_big_banner():
    """Banniere heros (assets/banner_big.txt) — art ASCII sur mesure du depot."""
    try:
        with open(BANNER_BIG_PATH, "r", encoding="utf-8") as handle:
            content = handle.read().strip("\n")
            if content.strip():
                return content
    except Exception:
        pass
    return None


def _center_line(text, width=78):
    visible = len(text)
    pad = max(0, (width - visible) // 2)
    return " " * pad + text


def print_banner(color=None, width=78):
    """Banniere statique (sans animation) — utilisee par --module."""
    for row in load_banner().split("\n"):
        print(ui.paint(_center_line(row, width), color or ui.R, ui.K))


def _print_rows(rows, color, ratio=0.0):
    for row in rows:
        text = ui.glitch_line(row, ratio) if ratio else row
        print(ui.paint(text, color, ui.K))


def _rgb(red, green, blue):
    return f"\033[38;2;{red};{green};{blue}m"


def _colored(text, phase):
    out = []
    for char in text:
        red, green, blue = BOOT_RGB[(phase + ord(char)) % len(BOOT_RGB)]
        out.append(_rgb(red, green, blue) + char)
    return "".join(out) + ui.Z


def _boot_phase(frames=14, delay=0.085):
    """Boot cyber colore (colonne de texte + barre + semis hex, theme rouge)."""
    term = shutil.get_terminal_size((80, 30))
    width = min(term.columns, 100)
    for step in range(frames):
        ui.clear()
        progress = (step + 1) / frames
        shown = max(1, int(len(BOOT_LINES) * progress))
        print()
        for index in range(shown):
            line = BOOT_LINES[index]
            pad = max(0, (width - len(line)) // 2)
            print(" " * pad + _colored(line, step + index))
        print()
        bar_width = min(52, max(20, width - 24))
        filled = int(bar_width * progress)
        bar = (
            "["
            + _rgb(255, 60, 85) + "█" * filled
            + _rgb(70, 22, 30) + "░" * (bar_width - filled)
            + ui.Z + "]"
        )
        label = " chargement "
        pad = max(0, (width - bar_width - len(label)) // 2)
        print(" " * pad + bar + ui.paint(label, ui.X))
        for _ in range(3):
            hexline = " ".join("%04X" % random.randrange(65536) for _ in range(6))
            column = random.randrange(0, max(1, width - 45))
            print(ui.paint(" " * column + hexline, ui.DR))
        time.sleep(delay)
    ui.clear()


def startup_animation(module_count=66, fast=False):
    ui.clear()
    term = shutil.get_terminal_size((80, 30))

    if not fast:
        big = load_big_banner()
        big_width = 0
        if big:
            big_width = max(len(row) for row in big.split("\n"))
        hero = bool(big) and term.columns >= big_width + 2 and term.lines >= 22

        # Phase 1 — boot cyber colore
        if term.lines >= 18 and term.columns >= 60:
            _boot_phase()

        # Phase 2 — banniere heros + glitch 4 frames
        if hero:
            lines = big.split("\n")
            frames = (
                (0.55, ui.DR),
                (0.30, ui.W),
                (0.14, ui.R),
                (0.0, ui.R),
            )
            for ratio, color in frames:
                ui.clear()
                _print_rows(lines, color, ratio)
                time.sleep(0.17)
            time.sleep(0.12)
        else:
            lines = load_banner().split("\n")
            for index, row in enumerate(lines):
                color = ui.PALETTE[index % len(ui.PALETTE)]
                print(ui.paint(_center_line(row), color, ui.K))
                time.sleep(0.055)
        print()
        sub = f"{config.TOOL_NAME}  v{config.VERSION}  —  by {config.AUTHOR} ({config.AUTHOR_ALIAS})"
        for char in sub:
            sys.stdout.write(ui.paint(char, ui.R, ui.K))
            sys.stdout.flush()
            time.sleep(0.010)
        print(ui.paint("   [ MIT · gratuit · " + str(module_count) + " modules ]", ui.W))
        print()

        label = "Chargement des modules"
        for pct in range(0, 101, 3):
            filled = int(30 * pct / 100)
            bar = "█" * filled + "░" * (30 - filled)
            sys.stdout.write("\r  " + ui.paint(f"[{bar}]", ui.R) + ui.paint(f" {pct:3d}%  {label}", ui.W))
            sys.stdout.flush()
            time.sleep(0.016)
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()
        source = big.split("\n") if hero else load_banner().split("\n")
        for _ in range(2):
            index = random.randrange(len(source))
            sys.stdout.write("\r" + ui.paint(_center_line(ui.glitch_line(source[index], 0.3)), ui.R, ui.K))
            sys.stdout.flush()
            time.sleep(0.07)
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()

    print(ui.paint(f"  [{module_count} modules charges · pret.]", ui.R, ui.K))
    time.sleep(0.25 if not fast else 0)
