import json
import math
import os
import re
import shutil
import struct
import subprocess
from datetime import datetime, timezone

from .. import ui

PE_MACHINE = {0x14C: "x86 (i386)", 0x8664: "x64 (AMD64)", 0xAA64: "ARM64", 0x1C0: "ARM", 0x200: "IA64"}
PE_SUBSYSTEM = {1: "Native", 2: "Windows GUI", 3: "Windows Console", 5: "OS/2", 7: "POSIX", 9: "Windows CE", 10: "EFI application"}
DLL_FLAGS = [
    (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE (ASLR)"), (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT (DEP)"), (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"), (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"), (0x8000, "TERMINAL_SERVER_AWARE"),
]


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return result


def _extract_strings(data, min_len=4):
    found = {"ascii": [], "utf16": [], "urls": [], "paths": [], "emails": [], "ips": []}
    for run in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data):
        found["ascii"].append(run.decode("ascii", "replace"))
    i = 0
    while i + 1 < len(data):
        if 32 <= data[i] < 127 and data[i + 1] == 0:
            chars = []
            while i + 1 < len(data) and 32 <= data[i] < 127 and data[i + 1] == 0:
                chars.append(chr(data[i]))
                i += 2
            if len(chars) >= max(min_len, 4):
                found["utf16"].append("".join(chars))
        else:
            i += 1
    all_text = found["ascii"] + found["utf16"]
    for text in all_text:
        for url in re.findall(r"https?://[^\s\"'<>]{4,}", text):
            found["urls"].append(url)
        for path in re.findall(r"[A-Za-z]:\\[^\s\"'<>|]{3,}|/(?:usr|etc|var|opt|home)/[^\s\"'<>]{3,}", text):
            found["paths"].append(path)
        for mail in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
            found["emails"].append(mail)
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
            found["ips"].append(ip)
    for key in ("urls", "paths", "emails", "ips"):
        seen = set()
        deduped = []
        for item in found[key]:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        found[key] = deduped
    return found


def strings_extractor():
    ui.module_header(56, "Strings Extractor", "Chaines ASCII/UTF-16 et URLs cachees dans un fichier")
    path = ui.ask_required("Chemin du fichier")
    if not os.path.isfile(path):
        ui.err("Fichier introuvable.")
        return
    min_len = ui.ask_int("Longueur minimale", 4, 3, 32)
    with ui.Spinner("Lecture du fichier"):
        with open(path, "rb") as handle:
            data = handle.read(50 * 1024 * 1024)
    found = _extract_strings(data, min_len)
    ui.ok(f"{len(found['ascii'])} chaine(s) ASCII, {len(found['utf16'])} chaine(s) UTF-16")
    for key, label in (("urls", "URLs"), ("paths", "Chemins"), ("emails", "Emails"), ("ips", "Adresses IP")):
        if found[key]:
            print()
            ui.info(f"{label} ({len(found[key])}) :")
            for item in found[key][:15]:
                print("  " + ui.paint(item[:110], ui.W))
            if len(found[key]) > 15:
                print("  " + ui.paint(f"... +{len(found[key]) - 15}", ui.X))
    print()
    ui.info("Apercu des chaines (30 premieres) :")
    for text in (found["ascii"] + found["utf16"])[:30]:
        print("  " + ui.paint(text[:110], ui.X))
    ui.save_output("strings", "\n".join(found["ascii"] + found["utf16"]))


def _rva_to_offset(rva, sections):
    for section in sections:
        span = max(section["vsize"], section["rsize"])
        if section["vaddr"] <= rva < section["vaddr"] + span:
            return rva - section["vaddr"] + section["raw"]
    return None


def parse_pe(path, max_section_read=4 * 1024 * 1024):
    with open(path, "rb") as handle:
        blob = handle.read()
    if len(blob) < 64 or blob[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    machine, n_sections, timestamp, _, _, size_opt, characteristics = struct.unpack_from("<HHIIIHH", blob, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", blob, opt)[0]
    is_pe32plus = magic == 0x20B
    entry = struct.unpack_from("<I", blob, opt + 16)[0]
    subsystem = struct.unpack_from("<H", blob, opt + 68)[0]
    dll_flags = struct.unpack_from("<H", blob, opt + 70)[0]
    if is_pe32plus:
        image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
        num_dirs = struct.unpack_from("<I", blob, opt + 108)[0]
        dir_offset = opt + 112
    else:
        image_base = struct.unpack_from("<I", blob, opt + 28)[0]
        num_dirs = struct.unpack_from("<I", blob, opt + 92)[0]
        dir_offset = opt + 96
    import_rva = struct.unpack_from("<I", blob, dir_offset + 8)[0] if num_dirs > 1 else 0
    sections = []
    section_off = opt + size_opt
    for i in range(n_sections):
        off = section_off + i * 40
        if off + 40 > len(blob):
            break
        name = blob[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", blob, off + 8)
        characteristics_s = struct.unpack_from("<I", blob, off + 36)[0]
        data = blob[raw:raw + min(rsize, max_section_read)]
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr, "rsize": rsize, "raw": raw,
            "chars": characteristics_s, "entropy": _entropy(data),
        })
    imports = []
    if import_rva:
        desc_off = _rva_to_offset(import_rva, sections)
        if desc_off is not None:
            for i in range(64):
                base = desc_off + i * 20
                if base + 20 > len(blob):
                    break
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", blob, base)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                name_off = _rva_to_offset(name_rva, sections)
                if name_off is None:
                    continue
                end = blob.find(b"\x00", name_off)
                dll_name = blob[name_off:end].decode("ascii", "replace") if end > name_off else ""
                if dll_name:
                    imports.append(dll_name)
    try:
        stamp = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        stamp = str(timestamp)
    return {
        "machine": PE_MACHINE.get(machine, f"0x{machine:04X}"),
        "sections_count": n_sections,
        "timestamp": stamp,
        "format": "PE32+" if is_pe32plus else "PE32",
        "entry": f"0x{entry:08X}",
        "image_base": f"0x{image_base:X}",
        "subsystem": PE_SUBSYSTEM.get(subsystem, str(subsystem)),
        "flags": [name for bit, name in DLL_FLAGS if dll_flags & bit],
        "sections": sections,
        "imports": imports,
        "signed_hint": bool(characteristics & 0x0020),
    }


def pe_parser():
    ui.module_header(57, "PE Header Parser", "Structure d'un executable Windows (lecture seule)")
    path = ui.ask_required("Chemin du .exe/.dll")
    if not os.path.isfile(path):
        ui.err("Fichier introuvable.")
        return
    with ui.Spinner("Analyse des en-tetes"):
        try:
            info = parse_pe(path)
        except Exception as exc:
            ui.err(f"Lecture impossible : {exc}")
            return
    if not info:
        ui.err("Fichier PE invalide (MZ/PE absents).")
        return
    ui.ok(f"{os.path.basename(path)} — {info['format']} {info['machine']}")
    ui.kv([
        ("Machine", info["machine"]),
        ("Sous-systeme", info["subsystem"]),
        ("Date du binaire", info["timestamp"]),
        ("Point d'entree", info["entry"]),
        ("ImageBase", info["image_base"]),
        ("Sections", str(info["sections_count"])),
        ("Drapeaux DLL", ", ".join(info["flags"]) or "-"),
    ])
    if info["sections"]:
        print()
        rows = []
        for section in info["sections"]:
            entropy = section["entropy"]
            mark = " (suspect > 7)" if entropy > 7 else ""
            rows.append([section["name"], str(section["vsize"]), str(section["rsize"]),
                         f"{entropy:.2f}{mark}"])
        ui.table(["SECTION", "TAILLE VIRT.", "TAILLE RAW", "ENTROPIE"], rows,
                 widths=[14, 16, 16, 18])
    if info["imports"]:
        print()
        ui.info(f"{len(info['imports'])} DLL importee(s) :")
        print("  " + ui.paint(", ".join(info["imports"][:30]), ui.W))
    ui.save_output("peheader", str(info))
    if any(s["entropy"] > 7.4 for s in info["sections"]):
        ui.note("Section(s) fortement chiffreee(s) — comportement courant des packers.")


def _run(cmd, timeout=25):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return (out.stdout or "") + (out.stderr or "")
    except Exception as exc:
        return f"[erreur] {exc}"


def _windows_audit():
    results = []
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if ps:
        defender = _run([ps, "-NoProfile", "-NonInteractive", "-Command",
                         "try { Get-MpComputerStatus | Select-Object -Property AMRunningMode,AntivirusEnabled,"
                         "RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress } catch { 'ABSENT' }"])
        if "ABSENT" in defender or not defender.strip().startswith("{"):
            results.append(("Antivirus (Defender)", "non actif ou non expose (AV tierce ?)", "ALERTE"))
        else:
            try:
                data = json.loads(defender.strip())
                enabled = bool(data.get("AntivirusEnabled"))
                realtime = bool(data.get("RealTimeProtectionEnabled"))
                results.append(("Antivirus (Defender)", f"actif={enabled} temps-reel={realtime}",
                                "OK" if enabled and realtime else "ALERTE"))
            except Exception:
                results.append(("Antivirus (Defender)", defender.strip()[:60], "?"))
        firewall = _run([ps, "-NoProfile", "-NonInteractive", "-Command",
                         "try { (Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }) -join '; ' } catch { 'ABSENT' }"])
        if firewall.strip() and "ABSENT" not in firewall:
            ok_all = "true" in firewall.lower()
            results.append(("Pare-feu (profils)", firewall.strip()[:80], "OK" if ok_all else "ALERTE"))
    uac = _run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "/v", "EnableLUA"], timeout=15)
    match = re.search(r"EnableLUA\s+REG_DWORD\s+0x([0-9a-fA-F]+)", uac)
    if match:
        value = int(match.group(1), 16)
        results.append(("UAC (EnableLUA)", "active" if value else "desactive", "OK" if value else "ALERTE"))
    rdp = _run(["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                "/v", "fDenyTSConnections"], timeout=15)
    match = re.search(r"fDenyTSConnections\s+REG_DWORD\s+0x([0-9a-fA-F]+)", rdp)
    if match:
        denied = int(match.group(1), 16) == 1
        results.append(("RDP (distance)", "ferme" if denied else "OUVERT", "OK" if denied else "ALERTE"))
    if ps:
        smb1 = _run([ps, "-NoProfile", "-NonInteractive", "-Command",
                     "try { (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { 'ABSENT' }"], timeout=20)
        if "True" in smb1:
            results.append(("SMBv1", "active (protocole vulnerable a ETERNALBLUE)", "ALERTE"))
        elif "False" in smb1:
            results.append(("SMBv1", "desactive", "OK"))
    autoruns = 0
    for hive in (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                 r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                 r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"):
        out = _run(["reg", "query", hive], timeout=15)
        autoruns += len(re.findall(r"REG_\w+\s+", out))
    results.append(("Programmes au demarrage", f"{autoruns} entree(s) dans les cles Run", "INFO"))
    listen = _run(["netstat", "-an"], timeout=30)
    established = len(re.findall(r"ESTABLISHED", listen))
    listening = len(re.findall(r"LISTENING|LISTEN\b", listen))
    results.append(("Connexions", f"{listening} en ecoute, {established} etablies", "INFO"))
    return results


def _unix_audit():
    results = []
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("PRETTY_NAME="):
                    results.append(("Systeme", line.split("=", 1)[1].strip().strip('"'), "INFO"))
                    break
    if shutil.which("ufw"):
        out = _run(["ufw", "status"], timeout=15)
        active = "active" in out.lower()
        results.append(("Pare-feu UFW", "actif" if active else "inactif", "OK" if active else "ALERTE"))
    elif shutil.which("firewall-cmd"):
        out = _run(["firewall-cmd", "--state"], timeout=15)
        active = "running" in out.lower()
        results.append(("Pare-feu firewalld", "actif" if active else "inactif", "OK" if active else "ALERTE"))
    else:
        results.append(("Pare-feu", "aucun outil standard detecte (ufw/firewalld)", "ALERTE"))
    if os.path.exists("/etc/ssh/sshd_config"):
        with open("/etc/ssh/sshd_config", "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        match = re.search(r"^\s*PermitRootLogin\s+(\w+)", text, re.M)
        if match:
            value = match.group(1)
            results.append(("SSH PermitRootLogin", value, "ALERTE" if value == "yes" else "OK"))
        match = re.search(r"^\s*PasswordAuthentication\s+(\w+)", text, re.M)
        if match:
            value = match.group(1)
            results.append(("SSH PasswordAuthentication", value, "ALERTE" if value == "yes" else "OK"))
    listening = _run(["ss", "-tuln"], timeout=20)
    count = len([l for l in listening.splitlines() if "LISTEN" in l or "UNCONN" in l])
    if not count:
        listening = _run(["netstat", "-tuln"], timeout=20)
        count = len([l for l in listening.splitlines() if "LISTEN" in l])
    results.append(("Ports en ecoute", str(count), "INFO"))
    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as handle:
            shells = [l.split(":")[0] for l in handle
                      if l.rstrip().split(":")[-1] in ("/bin/bash", "/bin/sh", "/bin/zsh")]
        results.append(("Utilisateurs avec shell", str(len(shells)), "INFO"))
    except Exception:
        pass
    return results


def local_security_audit():
    ui.module_header(58, "Local Security Audit", "Etat de securite de cette machine (lecture seule)")
    ui.note("Audit strictement en lecture : aucune configuration n'est modifiee.")
    with ui.Spinner("Collecte des etats systeme"):
        if os.name == "nt":
            results = _windows_audit()
        else:
            results = _unix_audit()
    if not results:
        ui.info("Aucune information collectee (droits insuffisants ?).")
        return
    rows = []
    alerts = 0
    for label, value, status in results:
        if status == "ALERTE":
            alerts += 1
        rows.append([label, str(value)[:60], status])
    ui.table(["CRITERE", "ETAT", "VERDICT"], rows, widths=[30, 66, 10])
    print()
    if alerts:
        ui.note(f"{alerts} point(s) a renforcer.")
    else:
        ui.ok("Aucun point faible majeur detecte sur les criteres verifies.")
    ui.save_output("secaudit", "\n".join(" | ".join(r) for r in rows))
