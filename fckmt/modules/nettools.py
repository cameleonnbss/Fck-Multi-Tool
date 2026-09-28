import ipaddress
import re
import shutil
import subprocess

from .. import ui, net

OUI_VENDORS = {
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "080027": "Oracle VirtualBox",
    "00155D": "Microsoft (Hyper-V)",
    "0050F2": "Microsoft",
    "00000C": "Cisco Systems",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "00E04C": "Realtek Semiconductor",
    "F09FC2": "Ubiquiti Networks",
    "001D0F": "TP-Link Technologies",
    "50C7BF": "TP-Link Technologies",
    "001A2B": "Nokia",
    "00265A": "ASUSTek Computer",
    "001B63": "Apple (registre IEEE)",
    "000422": "IBM",
    "0001E3": "Siemens AG",
    "002586": "Thomson Telecom",
}

MAC_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


def _normalize_mac(value):
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if not MAC_RE.match(cleaned):
        return None
    return cleaned.upper()


def _format_mac(compact):
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def _mac_vendor(compact):
    return OUI_VENDORS.get(compact[:6].upper(), "")


def _lookup_mac_online(compact, timeout=8):
    formatted = _format_mac(compact)
    resp = net.http_get(f"https://api.macvendors.com/{formatted}", timeout=timeout)
    if resp.status == 200 and resp.text and len(resp.text) < 120:
        return resp.text.strip()
    return ""


def cidr_info(value):
    value = str(value).strip()
    if "/" not in value:
        addr = ipaddress.ip_address(value)
        if addr.version == 4:
            first = int(str(addr).split(".")[0])
            prefix = 8 if first < 128 else 16 if first < 192 else 24 if first < 224 else 32
        else:
            prefix = 128
        value = f"{value}/{prefix}"
    network = ipaddress.ip_network(value, strict=False)
    hosts = list(network.hosts()) if network.version == 4 and network.num_addresses > 2 else []
    return {
        "saisie": str(value),
        "reseau": str(network.network_address),
        "masque": str(network.netmask),
        "wildcard": str(network.hostmask),
        "broadcast": str(network.broadcast_address) if network.version == 4 else "-",
        "prefixe": f"/{network.prefixlen}",
        "premiere_ip": str(hosts[0]) if hosts else str(network.network_address),
        "derniere_ip": str(hosts[-1]) if hosts else str(network.network_address),
        "total_adresses": network.num_addresses,
        "hotes_utilisables": len(hosts),
        "version": f"IPv{network.version}",
        "prive": network.is_private,
        "multicast": network.is_multicast,
        "reserve": network.is_reserved,
        "loopback": network.is_loopback,
    }


def cidr_calculator():
    ui.module_header(10, "CIDR Calculator", "Sous-reseau, masque, broadcast et plage d'hotes")
    value = ui.ask_required("Adresse reseau (ex : 192.168.1.0/24 ou 10.0.0.5)")
    try:
        info = cidr_info(value)
    except ValueError as exc:
        ui.err(f"CIDR invalide : {exc}")
        return
    ui.ok(f"Sous-reseau {info['saisie']} ({info['version']})")
    ui.kv([
        ("Reseau", info["reseau"]),
        ("Masque", f"{info['masque']}  ({info['prefixe']})"),
        ("Wildcard", info["wildcard"]),
        ("Broadcast", info["broadcast"]),
        ("Premiere IP", info["premiere_ip"]),
        ("Derniere IP", info["derniere_ip"]),
        ("Adresses totales", str(info["total_adresses"])),
        ("Hotes utilisables", str(info["hotes_utilisables"])),
        ("Type", "privee (RFC1918)" if info["prive"] else "publique"),
    ])
    print()
    if 0 < info["hotes_utilisables"] <= 32:
        rows = []
        hosts = list(ipaddress.ip_network(info["saisie"], strict=False).hosts())
        for i, host in enumerate(hosts[:32], 1):
            rows.append([str(i), str(host)])
        ui.table(["#", "HOTE"], rows, widths=[6, 24])
    elif info["hotes_utilisables"] > 32:
        ui.info(f"Plage trop grande pour un detail ({info['hotes_utilisables']} hotes).")
    if info["multicast"]:
        ui.note("Plage multicast.")
    elif info["reserve"]:
        ui.note("Plage reservee.")


def _arp_neighbors():
    rows = []
    try:
        if shutil.which("arp"):
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="replace", timeout=10)
            for row in (out.stdout or "").splitlines():
                parts = row.split()
                if len(parts) >= 3 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[0]):
                    mac = _normalize_mac(parts[1])
                    if mac:
                        rows.append([parts[0], _format_mac(mac), mac])
        elif shutil.which("ip"):
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, errors="replace", timeout=10)
            for row in (out.stdout or "").splitlines():
                parts = row.split()
                if len(parts) >= 5 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[0]):
                    mac = _normalize_mac(parts[4])
                    if mac:
                        rows.append([parts[0], _format_mac(mac), mac])
    except Exception:
        pass
    return rows


def mac_vendor():
    ui.module_header(11, "MAC Vendor Lookup", "Fabricant d'une carte reseau (base locale + ARP)")
    choice = ui.ask_choice("Mode", ["mac", "arp", "auto"], "mac")
    if choice in ("arp", "auto"):
        neighbors = _arp_neighbors()
        if not neighbors:
            ui.info("Table ARP vide ou inaccessible (essaiez le mode 'mac').")
            if choice == "auto":
                return
        else:
            rows = []
            for ip, formatted, compact in neighbors:
                rows.append([ip, formatted, _mac_vendor(compact) or "?"])
            ui.ok(f"{len(rows)} voisin(s) detecte(s)")
            ui.table(["IP", "MAC", "FABRICANT"], rows, widths=[18, 20, 44])
            if choice == "auto":
                ui.save_output("arp_vendors", "\n".join(" | ".join(r) for r in rows))
                return
    value = ui.ask_required("Adresse MAC (aa:bb:cc:dd:ee:ff)")
    compact = _normalize_mac(value)
    if not compact:
        ui.err("Adresse MAC invalide (12 chiffres hexadecimaux attendus).")
        return
    vendor = _mac_vendor(compact)
    ui.kv([
        ("MAC normalisee", _format_mac(compact)),
        ("OUI", compact[:6]),
        ("Fabricant (base locale)", vendor or "inconnu"),
    ])
    if not vendor and ui.confirm("Interroger l'API publique macvendors.com ?", True):
        with ui.Spinner("Recherche en ligne"):
            vendor = _lookup_mac_online(compact)
        if vendor:
            ui.ok(f"Fabricant : {vendor}")
        else:
            ui.info("Aucun resultat en ligne.")
