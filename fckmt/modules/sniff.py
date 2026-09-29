"""Module 57 — Packet-Sniffer : capture locale (scapy si present, sinon socket brute)."""
import select
import socket
import struct
import time

from .. import ui

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def parse_ipv4(data):
    """En-tete IPv4 minimal ; None si le paquet n'est pas un IPv4 valide."""
    if not data or len(data) < 20:
        return None
    if data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = struct.unpack("!H", data[2:4])[0]
    return {
        "src": socket.inet_ntoa(data[12:16]),
        "dst": socket.inet_ntoa(data[16:20]),
        "proto": data[9],
        "ttl": data[8],
        "len": total if total else len(data),
        "ihl": ihl,
    }


def parse_l4(info, data, fallback="IP"):
    """Ports TCP/UDP si presents ; sinon nom de protocole brut."""
    proto = info["proto"]
    if proto in (6, 17) and len(data) >= info["ihl"] + 4:
        sport, dport = struct.unpack("!HH", data[info["ihl"]:info["ihl"] + 4])
        name = PROTO_NAMES.get(proto, str(proto))
        return {"proto": name, "sport": sport, "dport": dport}
    return {"proto": PROTO_NAMES.get(proto, fallback), "sport": "-", "dport": "-"}


def _match(info, l4, host_filter, port_filter):
    if host_filter and host_filter not in (info["src"], info["dst"]):
        return False
    if port_filter and str(port_filter) not in (str(l4["sport"]), str(l4["dport"])):
        return False
    return True


def _emit(info, l4, counter):
    line = (f"{l4['proto']:<5} {info['src']}:{l4['sport']} > "
            f"{info['dst']}:{l4['dport']}  {info['len']} octets")
    print("  " + ui.paint(f"[{counter:05d}]", ui.R, ui.K) + " " + ui.paint(line, ui.W))
    return line


def _capture_raw(host_filter, port_filter, duree, stats):
    socks = []
    for proto, label in ((socket.IPPROTO_TCP, "TCP"), (socket.IPPROTO_UDP, "UDP")):
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
            raw.setblocking(False)
            socks.append(raw)
        except (PermissionError, OSError):
            continue
    if not socks:
        ui.err("Capture brute refusee : droits administrateur/root requis.")
        ui.note("Alternative : pip install scapy (+ Npcap sous Windows) pour une capture complete.")
        return
    start = time.time()
    lines = []
    counter = 0
    try:
        while time.time() - start < duree:
            readable, _, _ = select.select(socks, [], [], 0.5)
            for raw in readable:
                try:
                    data, _addr = raw.recvfrom(65535)
                except OSError:
                    continue
                info = parse_ipv4(data)
                if not info:
                    continue
                l4 = parse_l4(info, data)
                if not _match(info, l4, host_filter, port_filter):
                    continue
                counter += 1
                stats[l4["proto"] if l4["proto"] in ("TCP", "UDP") else "AUTRES"] += 1
                lines.append(_emit(info, l4, counter))
    except KeyboardInterrupt:
        ui.info("Capture arretee (Ctrl+C).")
    finally:
        for raw in socks:
            raw.close()
    return lines


def _capture_scapy(host_filter, port_filter, duree, stats):
    try:
        from scapy.all import IP, sniff as scapy_sniff  # type: ignore
    except Exception:
        return None
    lines = []
    counter = [0]

    def _callback(packet):
        if not packet.haslayer(IP):
            return
        layer = packet[IP]
        info = {"src": layer.src, "dst": layer.dst, "proto": layer.proto,
                "ttl": layer.ttl, "len": int(layer.len or 0), "ihl": int(layer.ihl or 5) * 4}
        l4 = {"proto": PROTO_NAMES.get(layer.proto, str(layer.proto)), "sport": "-", "dport": "-"}
        if packet.haslayer("TCP"):
            l4.update(proto="TCP", sport=packet["TCP"].sport, dport=packet["TCP"].dport)
        elif packet.haslayer("UDP"):
            l4.update(proto="UDP", sport=packet["UDP"].sport, dport=packet["UDP"].dport)
        if not _match(info, l4, host_filter, port_filter):
            return
        counter[0] += 1
        stats[l4["proto"] if l4["proto"] in ("TCP", "UDP") else "AUTRES"] += 1
        lines.append(_emit(info, l4, counter[0]))

    try:
        scapy_sniff(prn=_callback, store=False, timeout=duree)
    except KeyboardInterrupt:
        ui.info("Capture arretee (Ctrl+C).")
    except Exception as exc:
        ui.err(f"scapy en echec ({exc}) — passage en socket brute.")
        return None
    return lines


def packet_sniffer():
    ui.module_header(57, "Packet-Sniffer", "Capture de paquets locale (scapy si present, sinon socket brute)")
    ui.note("Lecture sur VOTRE machine uniquement — rien n'est envoye ni modifie.")

    host_filter = ui.ask("Filtre host (IP, Entree = tous)", default="").strip()
    port_filter = ui.ask("Filtre port (Entree = tous)", default="").strip()
    duree = ui.ask_int("Duree (secondes)", default=30, minimum=1, maximum=600)

    stats = {"TCP": 0, "UDP": 0, "AUTRES": 0}
    ui.info("Demarrage de la capture...")
    lines = _capture_scapy(host_filter, port_filter, duree, stats)
    if lines is None:
        lines = _capture_raw(host_filter, port_filter, duree, stats) or []
    if not lines:
        ui.info("Aucun paquet correspondant au filtre pendant la duree donnee.")
        return

    total = sum(stats.values())
    print()
    ui.kv([
        ("Paquets affiches", len(lines)),
        ("TCP / UDP / autres", f"{stats['TCP']} / {stats['UDP']} / {stats['AUTRES']}"),
        ("Duree", f"{duree}s"),
        ("Filtre", f"host={host_filter or '-'} port={port_filter or '-'}"),
    ])
    if ui.confirm("Sauvegarder la capture ?", default=False):
        ui.save_output("sniff", "\n".join(lines))
