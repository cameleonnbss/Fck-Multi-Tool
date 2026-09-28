"""Module 59 — WiFi-Profils : profils et reseaux WiFi connus de la machine."""
import os
import re
import shutil
import subprocess

from .. import ui


def _run(args, timeout=25):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding="utf-8",
                                errors="replace")
        return result.stdout or ""
    except Exception:
        return ""


def _windows_profiles():
    names = []
    out = _run(["netsh", "wlan", "show", "profiles"])
    if not out.strip():
        ui.note("Aucun profil WiFi (netsh wlan vide — service WLAN desactive ?).")
        return [], []
    for line in out.splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        if not (stripped.startswith("Profil") or stripped.startswith("All User Profile")):
            continue
        value = stripped.split(":", 1)[-1].strip()
        if value:
            names.append(value)
    rows = []
    for index, name in enumerate(names, 1):
        ui.progress(f"Profil {name}", index, len(names))
        detail = _run(["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"])
        fields = {}
        for line in detail.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key in ("Authentication", "Authentification"):
                fields["auth"] = value
            elif key in ("Cipher", "Chiffrement"):
                fields["cipher"] = value
            elif key in ("Security key", "Clé de sécurité"):
                fields["key"] = value
            elif key in ("Key Content", "Contenu de la clé") and value:
                fields["psk"] = value
            elif key in ("BSSID", "SSID"):
                fields.setdefault("bssid", value)
        rows.append([
            name,
            fields.get("auth", "-"),
            fields.get("cipher", "-"),
            fields.get("psk", "-"),
        ])
    ui.progress_done()
    return names, rows


def _windows_visible():
    out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    blocks = []
    current = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("SSID") and ":" in stripped:
            if current:
                blocks.append(current)
            current = {"ssid": stripped.split(":", 1)[1].strip(), "signal": "-", "auth": "-"}
        elif current is not None:
            if stripped.startswith("Signal") and ":" in stripped:
                current["signal"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Authentication") or stripped.startswith("Authentification"):
                current["auth"] = stripped.split(":", 1)[1].strip()
    if current:
        blocks.append(current)
    return blocks


def _linux_visible():
    if not shutil.which("nmcli"):
        return []
    out = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"])
    blocks = []
    for line in out.splitlines():
        parts = line.split(":")
        if parts and parts[0]:
            blocks.append({
                "ssid": parts[0],
                "signal": (parts[1] + "%") if len(parts) > 1 else "-",
                "auth": parts[2] if len(parts) > 2 else "-",
            })
    return blocks


def _linux_profiles():
    if not shutil.which("nmcli"):
        return [], []
    out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    names = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[1] == "802-11-wireless":
            names.append(parts[0])
    rows = []
    for index, name in enumerate(names, 1):
        ui.progress(f"Profil {name}", index, len(names))
        detail = _run(["nmcli", "-s", "-t", "-f", "802-11-wireless-security.psk", "connection", "show", name])
        psk = "-"
        if ":" in detail:
            psk = detail.rsplit(":", 1)[-1].strip() or "-"
        rows.append([name, "wifi", "-", psk])
    ui.progress_done()
    return names, rows


def wifi_profiles():
    ui.module_header(59, "WiFi-Profils", "Profils WiFi enregistres (cles) et reseaux visibles de CETTE machine")
    ui.note("Lecture locale uniquement : vos propres profils, jamais une cible externe.")
    choice = ui.ask_choice(
        "Source",
        ["Profils enregistres", "Reseaux visibles", "Les deux"],
        default="Les deux",
    )
    is_windows = os.name == "nt"
    lines = []

    if choice in ("Profils enregistres", "Les deux"):
        print()
        ui.info("Profils enregistres :")
        if is_windows:
            names, rows = _windows_profiles()
        else:
            names, rows = _linux_profiles()
        if rows:
            ui.table(["SSID", "Auth", "Chiffrement", "Cle"], rows, widths=[30, 16, 16, 34])
            secured = [r for r in rows if r[3] != "-"]
            ui.ok(f"{len(secured)} cle(s) WiFi lue(s) sur cette machine.")
            lines.append("# Profils enregistres")
            lines += [" | ".join(r) for r in rows]
        elif not names:
            ui.info("Aucun profil WiFi enregistre.")
        else:
            ui.note("Profils trouves mais cles non lisibles (droits admin requis).")

    if choice in ("Reseaux visibles", "Les deux"):
        print()
        ui.info("Reseaux visibles :")
        blocks = _windows_visible() if is_windows else _linux_visible()
        if blocks:
            rows = [[b["ssid"], b.get("signal", "-"), b.get("auth", "-")] for b in blocks]
            ui.table(["SSID", "Signal", "Authentification"], rows, widths=[36, 12, 30])
            lines.append("# Reseaux visibles")
            lines += [" | ".join(r) for r in rows]
        else:
            ui.info("Aucun reseau visible (radio eteinte ou service WiFi absent).")

    if lines:
        ui.save_output("wifi", "\n".join(lines))
