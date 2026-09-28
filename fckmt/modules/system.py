import hashlib
import math
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import time

from .. import ui, net


def _memory_info():
    try:
        if platform.system().lower().startswith("win"):
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return stat.ullTotalPhys, stat.ullAvailPhys
        with open("/proc/meminfo", "r") as handle:
            values = {}
            for row in handle:
                key, _, value = row.partition(":")
                values[key.strip()] = value.strip()
            total = int(values.get("MemTotal", "0 kB").split()[0]) * 1024
            avail = int(values.get("MemAvailable", "0 kB").split()[0]) * 1024
            return total, avail
    except Exception:
        return 0, 0


def _drives():
    result = []
    if platform.system().lower().startswith("win"):
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            root = letter + ":\\"
            if os.path.exists(root):
                try:
                    usage = shutil.disk_usage(root)
                    result.append((root, usage.total, usage.free))
                except Exception:
                    pass
    else:
        for mount in ("/", "/home", "/tmp"):
            if os.path.exists(mount):
                try:
                    usage = shutil.disk_usage(mount)
                    result.append((mount, usage.total, usage.free))
                except Exception:
                    pass
    return result


def _uptime():
    try:
        if platform.system().lower().startswith("win"):
            millis = ctypes_uptime()
            seconds = millis / 1000
        else:
            with open("/proc/uptime", "r") as handle:
                seconds = float(handle.read().split()[0])
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{days}j {hours}h {minutes}m"
    except Exception:
        return "-"


def ctypes_uptime():
    import ctypes

    try:
        return ctypes.windll.kernel32.GetTickCount64()
    except Exception:
        return 0


def system_info():
    ui.module_header(42, "System Info", "Materiel, memoire, disques et reseau de la machine")
    hostname = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = os.environ.get("USERNAME", "-")
    pairs = [
        ("Machine", f"{hostname} ({platform.machine()})"),
        ("Utilisateur", user),
        ("Systeme", f"{platform.system()} {platform.release()} {platform.version()}"),
        ("Noyau", platform.release()),
        ("Python", sys.version.split()[0]),
        ("Processeur", platform.processor() or platform.machine()),
        ("Coeurs logiques", str(os.cpu_count() or "-")),
        ("Uptime", _uptime()),
        ("IP locale", net.local_ip()),
    ]
    ui.kv(pairs)
    print()
    total, avail = _memory_info()
    if total:
        used = total - avail
        pct = 100 * used / total
        ui.kv([
            ("RAM totale", f"{total / 1024**3:.1f} Go"),
            ("RAM utilisee", f"{used / 1024**3:.1f} Go ({pct:.0f}%)"),
            ("RAM libre", f"{avail / 1024**3:.1f} Go"),
        ])
    print()
    rows = []
    for mount, total_d, free_d in _drives():
        used = total_d - free_d
        pct = 100 * used / total_d if total_d else 0
        rows.append([mount, f"{total_d / 1024**3:.0f} Go", f"{used / 1024**3:.0f} Go", f"{pct:.0f}%", f"{free_d / 1024**3:.0f} Go"])
    if rows:
        ui.table(["DISQUE", "TOTAL", "UTILISE", "%", "LIBRE"], rows, widths=[12, 12, 12, 8, 12])
    print()
    with ui.Spinner("IP publique"):
        resp = net.http_get("https://api.ipify.org?format=json", timeout=8)
    if resp.status == 200:
        import json

        try:
            ui.ok(f"IP publique : {json.loads(resp.text).get('ip', '-')}")
        except Exception:
            pass
    else:
        ui.info("IP publique : inaccessible (hors ligne).")
    ui.save_output("systeminfo", "\n".join(f"{k} : {v}" for k, v in pairs))


MAGIC_SIGNATURES = [
    (b"MZ", "Executable Windows (PE)"),
    (b"\x7fELF", "Executable Linux (ELF)"),
    (b"%PDF", "Document PDF"),
    (b"PK\x03\x04", "Archive ZIP / Office / JAR"),
    (b"Rar!\x1a\x07", "Archive RAR"),
    (b"\x1f\x8b", "Archive GZIP"),
    (b"7z\xbc\xaf\x27\x1c", "Archive 7-Zip"),
    (b"\x89PNG\r\n\x1a\n", "Image PNG"),
    (b"\xff\xd8\xff", "Image JPEG"),
    (b"GIF8", "Image GIF"),
    (b"BM", "Image BMP"),
    (b"RIFF", "Fichier RIFF (WAV/WEBP/AVI)"),
    (b"\x00\x00\x01\x00", "Icone Windows (ICO)"),
    (b"\xd0\xcf\x11\xe0", "Document Office ancien (OLE)"),
    (b"SQLite format 3", "Base SQLite"),
    (b"\x04\x22\x4d\x18", "Archive LZ4"),
    (b"BZh", "Archive BZIP2"),
    (b"\xfd7zXZ", "Archive XZ"),
    (b"ustar", "Archive TAR"),
    (b"#!", "Script (shebang)"),
    (b"\xca\xfe\xba\xbe", "Executable Java / Mach-O fat"),
    (b"MSCF", "Installeur Windows (CAB)"),
    (b"\x0a\x0d\x0d\x0a", "Capture reseau (PCAP)"),
]


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    result = 0.0
    for count in counts:
        if count:
            p = count / length
            result -= p * math.log2(p)
    return result


def file_analyzer():
    ui.module_header(43, "File Analyzer", "Type reel, hashs, entropie et apercu hexadecimal")
    path = ui.ask_required("Chemin du fichier").strip('"')
    if not os.path.isfile(path):
        ui.err("Fichier introuvable.")
        return
    size = os.path.getsize(path)
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
            rest_hash = hashlib.md5()
            sha256 = hashlib.sha256()
            sha1 = hashlib.sha1()
            handle.seek(0)
            chunks = 0
            entropy_data = b""
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                rest_hash.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                if len(entropy_data) < 262144:
                    entropy_data += chunk[:262144 - len(entropy_data)]
                chunks += 1
    except Exception as exc:
        ui.err(f"Lecture impossible : {exc}")
        return
    ftype = "Inconnu"
    for signature, label in MAGIC_SIGNATURES:
        if head.startswith(signature) or signature in head[:64]:
            ftype = label
            break
    entropy = _entropy(entropy_data)
    level = "normal" if entropy < 4.5 else "elevee (potentiellement chiffre/compresse)" if entropy > 7.2 else "moderee"
    pairs = [
        ("Fichier", os.path.abspath(path)),
        ("Taille", f"{size} octets ({size / 1024:.1f} Ko)"),
        ("Type reel", ftype),
        ("Extension", os.path.splitext(path)[1] or "-"),
        ("Entropie", f"{entropy:.2f} / 8.0 — {level}"),
        ("Lus", f"{chunks} bloc(s)"),
    ]
    ui.kv(pairs)
    print()
    ui.table(["ALGORITHME", "HASH"], [
        ["MD5", rest_hash.hexdigest()],
        ["SHA1", sha1.hexdigest()],
        ["SHA256", sha256.hexdigest()],
    ], widths=[14, 76])
    print()
    ui.info("Apercu (64 premiers octets) :")
    for offset in range(0, min(64, len(head)), 16):
        block = head[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in block)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
        print("  " + ui.paint(f"  {offset:08x}  ", ui.X) + ui.paint(hexpart.ljust(47), ui.C) + ui.paint(asc, ui.Y))
    report = "\n".join(f"{k} : {v}" for k, v in pairs) + f"\nMD5 {rest_hash.hexdigest()}\nSHA1 {sha1.hexdigest()}\nSHA256 {sha256.hexdigest()}"
    ui.save_output("fileanalysis", report)


def local_ports():
    ui.module_header(44, "Local Ports", "Ports en ecoute sur cette machine + processus")
    rows = []
    if platform.system().lower().startswith("win"):
        try:
            out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, errors="replace", timeout=20)
            tasks = {}
            try:
                tl = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, errors="replace", timeout=20)
                for row in tl.stdout.splitlines():
                    parts = [p.strip('"') for p in row.split('","')]
                    if len(parts) >= 2:
                        tasks[parts[1]] = parts[0]
            except Exception:
                pass
            for row in out.stdout.splitlines():
                parts = row.split()
                if len(parts) >= 5 and parts[0] in ("TCP", "UDP") and parts[3] == "LISTENING":
                    local = parts[1]
                    pid = parts[4]
                    name = tasks.get(pid, "-")
                    rows.append([parts[0], local, name, pid])
        except Exception as exc:
            ui.err(f"netstat impossible : {exc}")
    else:
        cmd = ["ss", "-tuln"] if shutil.which("ss") else ["netstat", "-tuln"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=20)
            for row in out.stdout.splitlines()[1:]:
                parts = row.split()
                if len(parts) >= 5 and ("LISTEN" in row or "UNCONN" in row):
                    rows.append([parts[0], parts[4] if len(parts) > 4 else "-", parts[1], "-"])
        except Exception as exc:
            ui.err(f"Lecture impossible : {exc}")
    if not rows:
        ui.info("Aucun port en ecoute detecte (ou droits insuffisants).")
        return
    rows.sort(key=lambda r: r[1])
    ui.ok(f"{len(rows)} port(s) en ecoute")
    ui.table(["PROTOCOLE", "ADRESSE LOCALE", "PROCESSUS", "PID"], rows, widths=[12, 28, 30, 10])
    ui.save_output("localports", "\n".join(" | ".join(r) for r in rows))
