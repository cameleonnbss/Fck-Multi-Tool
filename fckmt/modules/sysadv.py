"""Modules 65-66 - systeme avance : profils WiFi et adresse MAC locale."""
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
    ui.module_header(65, "WiFi-Profils", "Profils WiFi enregistres (cles) et reseaux visibles de CETTE machine")
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


def _valid_mac(value):
    """Normalise une adresse MAC ; retourne None si invalide."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(cleaned) != 12:
        return None
    return cleaned.upper()


def _random_mac():
    """MAC aleatoire a bit local administre (U/L = 1 sur le 2e octet)."""
    import secrets

    octets = [secrets.randbelow(256) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE
    return "".join("%02X" % octet for octet in octets)


def _mac_rows():
    """Liste (interface, mac, detail) des interfaces de CETTE machine."""
    rows = []
    if os.name == "nt":
        out = _run(["getmac", "/fo", "csv", "/v"])
        try:
            import csv
            import io

            for row in csv.reader(io.StringIO(out)):
                if len(row) < 2:
                    continue
                mac = next((cell for cell in row if _valid_mac(cell)), None)
                if mac:
                    rows.append((row[0] or "?", mac, row[1] if len(row) > 1 else ""))
        except Exception:
            pass
    else:
        out = _run(["ip", "-o", "link", "show"])
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            name = parts[1].split("@")[0].strip()
            match = re.search(r"link/ether\s+([0-9A-Fa-f:]{17})", line)
            if match and name:
                rows.append((name, _valid_mac(match.group(1)), ""))
    return rows


def mac_changer():
    ui.module_header(66, "MAC-Changer", "Adresse MAC de CETTE machine : lecture et changement local")
    ui.note("Lecture seule par defaut : aucun changement sans confirmation explicite.")
    rows = _mac_rows()
    if not rows:
        ui.err("Aucune interface lisible (getmac/ip absent ou droits insuffisants).")
        return
    ui.table(
        ["Interface", "MAC", "Detail"],
        [[name, mac, detail[:40]] for name, mac, detail in rows],
        widths=[28, 20, 46],
    )
    ui.info("Changer d'adresse MAC peut deconnecter cette machine de ses reseaux.")
    if not ui.confirm("Changer l'adresse MAC d'une interface ?", default=False):
        ui.info("Lecture seule terminee.")
        return

    names = [name for name, _, _ in rows]
    name = ui.ask("Interface (nom exact)", default=names[0] if names else "")
    if name not in names:
        ui.err(f"Interface inconnue : {name}")
        return
    target = ui.ask("Nouvelle MAC (Entree = aleatoire locale)")
    mac = _valid_mac(target) or _random_mac()
    if not ui.confirm(f"Appliquer {mac} sur {name} ?", default=False):
        ui.info("Annule.")
        return

    if os.name == "nt":
        _run(
            ["powershell", "-NoProfile", "-Command",
             f"Set-NetMacAddress -Name '{name}' -MacAddress '{mac}'"],
            timeout=30,
        )
    else:
        _run(["ip", "link", "set", "dev", name, "down"], timeout=15)
        _run(["ip", "link", "set", "dev", name, "address", mac], timeout=15)
        _run(["ip", "link", "set", "dev", name, "up"], timeout=15)

    applied = any(m == mac for _, m, _ in _mac_rows())
    if applied:
        ui.ok(f"Adresse MAC appliquee : {name} -> {mac}")
    else:
        ui.err("MAC non appliquee — droits admin/root requis.")
        if os.name == "nt":
            ui.note("Manuel (PowerShell admin) : Set-NetMacAddress -Name 'X' -MacAddress 'YY...'")
        else:
            ui.note("Manuel (root) : ip link set dev X down && ip link set dev X address YY && ip link set dev X up")
