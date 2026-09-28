import os
import sys
import time
import random

from . import ui
from . import config

DEFAULT_BANNER = """\
   █████▒▄████▄   ██ ▄█▀    
███▄ ▄███▓ █    ██  ██▓  ▄▄▄█████▓ ██▓   ▄▄▄█████▓ ▒█████   ▒█████   ██▓     
▓██   ▒▒██▀ ▀█   ██▄█▒    ▓██▒▀█▀ ██▒ ██  ▓██▒▓██▒  ▓  ██▒ ▓▒▓██▒   ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    
▒████ ░▒▓█    ▄ ▓███▄░    ▓██    ▓██░▓██  ▒██░▒██░  ▒ ▓██░ ▒░▒██▒   ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    
░▓█▒  ░▒▓▓▄ ▄██▒▓██ █▄    ▒██    ▒██ ▓▓█  ░██░▒██░  ░ ▓██▓ ░ ░██░   ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    
░▒█░   ▒ ▓███▀ ░▒██▒ █▄   ▒██▒   ░██▒▒▒█████▓ ░██████▒▒██▒ ░ ░██░     ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒
 ▒ ░   ░ ░▒ ▒  ░▒ ▒▒ ▓▒   ▒ ░░   ░  ░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ░░   ░▓       ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░
 ░       ░  ▒   ░ ░▒ ▒░   ░  ░      ░░░▒░ ░ ░ ░ ░ ▒  ░  ░     ▒ ░       ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░
 ░ ░   ░        ░ ░░ ░    ░      ░    ░░░ ░ ░   ░ ░   ░       ▒ ░     ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   
       ░ ░      ░  ░             ░      ░         ░  ░        ░                  ░ ░      ░ ░      ░  ░
       ░                                                                                                \
"""

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
    try:
        visible = sum(2 if ord(ch) > 0x2500 else 1 for ch in text)
    except Exception:
        visible = len(text)
    pad = max(0, (width - visible) // 2)
    return " " * pad + text


def startup_animation(module_count=30, fast=False):
    art = load_banner()
    lines = art.split("\n")
    ui.clear()

    if not fast:
        for i, row in enumerate(lines):
            color = ui.PALETTE[i % len(ui.PALETTE)]
            shown = row
            if i in (0, len(lines) - 1):
                shown = ui.glitch_line(row, 0.08)
            print(ui.paint(_center_line(shown), color, ui.K))
            time.sleep(0.055)
        print()
        sub = f"{config.TOOL_NAME}  v{config.VERSION}  —  by {config.AUTHOR} ({config.AUTHOR_ALIAS})"
        for ch in sub:
            sys.stdout.write(ui.paint(ch, ui.Y, ui.K))
            sys.stdout.flush()
            time.sleep(0.012)
        print(ui.paint("   [ MIT · gratuit · " + str(module_count) + " modules ]", ui.X))
        print()

        label = "Chargement des modules"
        for pct in range(0, 101, 2):
            filled = int(30 * pct / 100)
            bar = "█" * filled + "░" * (30 - filled)
            sys.stdout.write("\r  " + ui.paint(f"[{bar}]", ui.G) + ui.paint(f" {pct:3d}%  {label}", ui.X))
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

    print(ui.paint(f"  [{module_count} modules charges · pret.]", ui.G, ui.K))
    time.sleep(0.25 if not fast else 0)
