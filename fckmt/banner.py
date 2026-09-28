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
    """Banniere ANSI Shadow grand format (assets/banner_big.txt)."""
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


def startup_animation(module_count=59, fast=False):
    ui.clear()
    term = shutil.get_terminal_size((80, 30))

    if not fast:
        big = load_big_banner()
        if big and term.columns >= 66 and term.lines >= 24:
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
            for i, row in enumerate(lines):
                color = ui.PALETTE[i % len(ui.PALETTE)]
                print(ui.paint(_center_line(row), color, ui.K))
                time.sleep(0.055)
        print()
        sub = f"{config.TOOL_NAME}  v{config.VERSION}  —  by {config.AUTHOR} ({config.AUTHOR_ALIAS})"
        for ch in sub:
            sys.stdout.write(ui.paint(ch, ui.R, ui.K))
            sys.stdout.flush()
            time.sleep(0.012)
        print(ui.paint("   [ MIT · gratuit · " + str(module_count) + " modules ]", ui.W))
        print()

        label = "Chargement des modules"
        for pct in range(0, 101, 2):
            filled = int(30 * pct / 100)
            bar = "█" * filled + "░" * (30 - filled)
            sys.stdout.write("\r  " + ui.paint(f"[{bar}]", ui.R) + ui.paint(f" {pct:3d}%  {label}", ui.W))
            sys.stdout.flush()
            time.sleep(0.018)
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()
        source = big.split("\n") if (big and term.columns >= 66) else load_banner().split("\n")
        for _ in range(2):
            idx = random.randrange(len(source))
            sys.stdout.write("\r" + ui.paint(_center_line(ui.glitch_line(source[idx], 0.3)), ui.R, ui.K))
            sys.stdout.flush()
            time.sleep(0.07)
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()

    print(ui.paint(f"  [{module_count} modules charges · pret.]", ui.R, ui.K))
    time.sleep(0.25 if not fast else 0)
