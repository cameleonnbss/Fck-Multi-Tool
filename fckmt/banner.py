import os
import sys
import time
import random

from . import ui
from . import config
from . import fonts

DEFAULT_BANNER = "\n".join(fonts.render("FCK MULTI TOOL"))

BANNER_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "banner.txt")


def load_banner():
    try:
        with open(BANNER_PATH, "r", encoding="utf-8") as handle:
            content = handle.read().strip("\n")
            if content.strip():
                return content
    except Exception:
        pass
    return DEFAULT_BANNER


def _center_line(text, width=78):
    visible = len(text)
    pad = max(0, (width - visible) // 2)
    return " " * pad + text


def print_banner(color=None, width=78):
    """Banniere statique (sans animation) — utilisee par --module."""
    for row in load_banner().split("\n"):
        print(ui.paint(_center_line(row, width), color or ui.R, ui.K))


def startup_animation(module_count=30, fast=False):
    art = load_banner()
    lines = art.split("\n")
    ui.clear()

    if not fast:
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
        for _ in range(2):
            idx = random.randrange(len(lines))
            sys.stdout.write("\r" + ui.paint(_center_line(ui.glitch_line(lines[idx], 0.3)), ui.R, ui.K))
            sys.stdout.flush()
            time.sleep(0.07)
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()

    print(ui.paint(f"  [{module_count} modules charges · pret.]", ui.R, ui.K))
    time.sleep(0.25 if not fast else 0)
