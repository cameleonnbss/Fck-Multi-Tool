import concurrent.futures
import os
import platform
import re
import socket
import subprocess
import threading
import time

from .. import ui, net


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 3000,
    3306, 3389, 4444, 5000, 5432, 5900, 5985, 6379, 6667, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 10000, 11211, 27017,
]


def parse_ports(spec):
    if not spec or spec.lower() in ("top", "common", "defaut", "défaut"):
        return sorted(set(COMMON_PORTS))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            if end - start > 20000:
                raise ValueError("Plage trop grande (max 20000 ports).")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def _grab_banner(sock, timeout=0.6):
    try:
        sock.settimeout(timeout)
        data = b""
        try:
            data = sock.recv(768)
        except Exception:
            data = b""
        if not data:
            try:
                sock.sendall(b"\r\n\r\n")
                data = sock.recv(768)
            except Exception:
                data = b""
        return data.decode("utf-8", "replace").strip().replace("\x00", " ")[:160]
    except Exception:
        return ""


def _service_name(port):
    try:
        return socket.getservbyport(port)
    except Exception:
        return ""


def _check_port(host, port, timeout, grab):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return None
    banner = _grab_banner(sock) if grab else ""
    try:
        sock.close()
    except Exception:
        pass
    return {"port": port, "service": _service_name(port), "banner": banner}


def scan_ports():
    ui.module_header(1, "Scanner de ports", "Scan TCP multi-threads avec recuperation de banniere")
    target = ui.ask_required("Hote ou IP cible")
    ui.note("Exemples : 22,80,443  |  1-1024  |  1-100,443,8080-8090  |  top")
    spec = ui.ask("Ports a scanner", "top")
    try:
        ports = parse_ports(spec)
    except Exception as exc:
        ui.err(f"Specification invalide : {exc}")
        return
    timeout = 0.6 if len(ports) > 2000 else 1.0
    threads = 1 if len(ports) <= 64 else 100
    ip = net.resolve(target) or target
    if not ip:
        ui.err("Resolution DNS impossible.")
        return
    ui.info(f"Cible : {target} ({ip}) — {len(ports)} port(s), {threads} threads")
    found = []
    lock = threading.Lock()
    done = [0]
    started = time.time()

    with ui.Spinner(f"Scan de {len(ports)} ports"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(_check_port, ip, p, timeout, len(ports) <= 512) for p in ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                done[0] += 1
                if result:
                    with lock:
                        found.append(result)
    ui.progress_done()
    found.sort(key=lambda item: item["port"])
    elapsed = time.time() - started
    ui.ok(f"Scan termine en {elapsed:.1f}s — {len(found)} port(s) ouvert(s)")
    if found:
        rows = []
        lines = [f"# Scan de ports {target} — {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        for item in found:
            rows.append([str(item["port"]), item["service"] or "-", item["banner"] or "-"])
            lines.append(f"{item['port']}/{item['service'] or '?'} {item['banner']}".rstrip())
        ui.table(["PORT", "SERVICE", "BANNIERE"], rows, widths=[8, 14, 58])
        ui.save_output("portscan", "\n".join(lines))
    else:
        ui.info("Aucun port ouvert trouve sur la plage testee.")


def _ping_once(host, timeout_ms=700):
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 3)
        text = (out.stdout or "") + (out.stderr or "")
        match = re.search(r"time[=<](\d+)\s*ms", text, re.I) or re.search(r"time=(\d+\.?\d*)\s*ms", text, re.I)
        if out.returncode == 0:
            return float(match.group(1)) if match else 0.0
    except Exception:
        pass
    return None


def ping_sweep():
    ui.module_header(2, "Ping Sweep", "Decouverte d'hotes actifs sur un sous-reseau")
    target = ui.ask_required("Reseau (ex : 192.168.1.0/24)")
    try:
        network = __import__("ipaddress").ip_network(target, strict=False)
    except Exception as exc:
        ui.err(f"Reseau invalide : {exc}")
        return
    hosts = list(network.hosts())
    if not hosts:
        hosts = [network.network_address]
    if len(hosts) > 1024:
        ui.err("Sous-reseau trop grand (max /22 soit 1024 hotes).")
        return
    ui.info(f"Verification de {len(hosts)} adresse(s)...")
    alive = []
    lock = threading.Lock()
    done = [0]
    total = len(hosts)

    def worker(host):
        latency = _ping_once(str(host))
        done[0] += 1
        ui.progress("Ping sweep", done[0], total)
        if latency is not None:
            name = ""
            try:
                name = socket.gethostbyaddr(str(host))[0]
            except Exception:
                pass
            with lock:
                alive.append((str(host), name, latency))

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(worker, hosts))
    ui.progress_done()
    ui.ok(f"{len(alive)} hote(s) actif(s) sur {total}")
    if alive:
        rows = [[h, n or "-", f"{l:.0f} ms"] for h, n, l in sorted(alive, key=lambda x: __import__("ipaddress").ip_address(x[0]))]
        ui.table(["IP", "HOSTNAME", "LATENCE"], rows, widths=[18, 40, 12])
        ui.save_output("pingsweep", "\n".join(f"{h} {n} {l:.1f}ms" for h, n, l in alive))


def ip_pinger():
    ui.module_header(3, "IP Pinger", "Latence moyenne sur 4 paquets")
    host = ui.ask_required("Hote ou IP a pinger")
    latencies = []
    lost = 0
    with ui.Spinner("Envoi des paquets"):
        for i in range(4):
            result = _ping_once(host, 1500)
            if result is None:
                lost += 1
                print("  " + ui.paint(f"  paquet {i + 1} : perdu", ui.R))
            else:
                latencies.append(result)
                print("  " + ui.paint(f"  paquet {i + 1} : {result:.0f} ms", ui.G))
            time.sleep(0.25)
    ui.ok(f"{4 - lost}/4 paquets recus")
    if latencies:
        ui.kv([
            ("Minimum", f"{min(latencies):.0f} ms"),
            ("Moyenne", f"{sum(latencies) / len(latencies):.0f} ms"),
            ("Maximum", f"{max(latencies):.0f} ms"),
            ("Perte", f"{lost * 25}%"),
        ])
    else:
        ui.err("Aucun paquet recu.")


def ip_lookup():
    ui.module_header(4, "IP Lookup", "Geolocalisation et FAI d'une IP ou d'un domaine")
    target = ui.ask_required("IP ou domaine")
    host = target
    if not net.is_ip(target):
        resolved = net.resolve(target)
        if not resolved:
            ui.err("Resolution DNS impossible.")
            return
        host = resolved
        ui.info(f"{target} -> {host}")
    with ui.Spinner("Interrogation ip-api.com"):
        resp = net.http_get(f"http://ip-api.com/json/{host}?fields=66846719", timeout=8)
    if resp.status != 200:
        ui.err("API ip-api inaccessible (hors ligne ?).")
        return
    import json

    try:
        data = json.loads(resp.text)
    except Exception:
        ui.err("Reponse illisible.")
        return
    if data.get("status") != "success":
        ui.err(data.get("message", "Echec de la recherche."))
        return
    pairs = [
        ("IP", data.get("query", "-")),
        ("Domaine", data.get("reverse", "-") or "-"),
        ("Pays", f"{data.get('country', '-')} ({data.get('countryCode', '-')})"),
        ("Region", f"{data.get('regionName', '-')} / {data.get('city', '-')}"),
        ("Code postal", data.get("zip", "-") or "-"),
        ("Coordonnees", f"{data.get('lat', '-')} , {data.get('lon', '-')}"),
        ("FAI", data.get("isp", "-")),
        ("Organisation", data.get("org", "-")),
        ("AS", data.get("as", "-")),
        ("Fuseau", data.get("timezone", "-")),
    ]
    ui.kv(pairs)
    ui.save_output("iplookup", "\n".join(f"{k} : {v}" for k, v in pairs))


def whois_module():
    ui.module_header(5, "Whois Lookup", "Registrar, dates et reseaux enregistres")
    query = ui.ask_required("Domaine ou IP (ex : example.com / 8.8.8.8)")
    with ui.Spinner("Interrogation des serveurs whois"):
        try:
            text = net.whois_lookup(query)
        except Exception as exc:
            ui.err(f"Whois impossible : {exc}")
            return
    if not text.strip():
        ui.err("Aucune reponse whois.")
        return
    keywords = (
        "registrar:", "domain name:", "creation date:", "created:", "updated date:",
        "registry expiry", "name server:", "nserver:", "registrant country:",
        "netrange:", "cidr:", "orgname:", "org:", "country:", "netname:",
        "owner:", "descr:", "admin contact:", "abuse contact:", "status:",
    )
    seen = set()
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        if any(low.startswith(k) for k in keywords) and line not in seen:
            seen.add(line)
            key, _, value = line.partition(":")
            rows.append([key.strip()[:28], value.strip()[:70] or " "])
    if rows:
        ui.table(["CHAMP", "VALEUR"], rows, widths=[30, 66])
    else:
        for line in text.splitlines()[:30]:
            print("  " + line)
    choice = ui.ask_choice("Voir la reponse complete ?", ["o", "n"], "n")
    if choice == "o":
        print()
        print(text[:8000])
    ui.save_output("whois", text)


def dns_recon():
    ui.module_header(6, "DNS Recon", "Enregistrements DNS + brute-force de sous-domaines")
    domain = ui.ask_required("Domaine (ex : example.com)")
    types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
    records = {}
    with ui.Spinner(f"Requetes DNS sur {domain}"):
        for qtype in types:
            try:
                records[qtype] = net.dns_query(domain, qtype)
            except Exception:
                records[qtype] = []
    for qtype in types:
        values = records.get(qtype) or []
        if values:
            for i, value in enumerate(values):
                label = qtype if i == 0 else ""
                print("  " + ui.paint(f"  {label:<6}", ui.C, ui.K) + ui.paint(value, ui.W))
        else:
            print("  " + ui.paint(f"  {qtype:<6}", ui.X) + ui.paint("-", ui.X))
    brute = ui.ask_choice("Brute-force de sous-domaines ?", ["o", "n"], "o")
    if brute == "o":
        words = [
            "www", "mail", "smtp", "pop", "imap", "ftp", "api", "dev", "test", "staging",
            "admin", "administrator", "portal", "blog", "shop", "store", "cdn", "static",
            "img", "images", "media", "video", "files", "download", "dl", "ns1", "ns2",
            "dns", "db", "database", "sql", "mysql", "redis", "mongo", "elastic", "vpn",
            "remote", "git", "gitlab", "github", "ci", "jenkins", "jira", "confluence",
            "webmail", "roundcube", "sso", "auth", "login", "app", "m", "mobile", "beta",
            "alpha", "demo", "panel", "cpanel", "whm", "webdisk", "autodiscover", "office",
            "owa", "exchange", "intranet", "wiki", "docs", "status", "monitor", "grafana",
            "kibana", "metrics", "backup", "bak", "old", "new", "v2", "v3", "cloud",
            "aws", "azure", "gcp", "s3", "bucket", "proxy", "gateway", "ws", "wss",
            "chat", "meet", "zoom", "calendar", "crm", "erp", "billing", "pay", "secure",
            "vpn1", "vpn2", "fw", "edge", "node", "server", "srv", "host", "data",
            "search", "solr", "ldap", "ad", "mx", "mx1", "mx2", "relay", "news", "forum",
            "support", "help", "helpdesk", "ticket", "kb", "base", "internal", "hidden",
            "private", "public", "open", "home", "whois", "dns1", "dns2", "time", "ntp",
            "sip", "voip", "pbx", "vm", "vdi", "citrix", "rdp", "ts", "jump", "bastion",
            "tor", "onion", "test1", "test2", "stage", "uat", "qa", "lab", "sandbox",
        ]
        found = []
        lock = threading.Lock()

        def probe(word):
            host = f"{word}.{domain}"
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                return
            with lock:
                found.append((host, ip))

        total = len(words)

        def probe_word(word):
            probe(word)
            done[0] += 1
            ui.progress("Brute-force DNS", done[0], total)

        done = [0]
        with ui.Spinner("Brute-force DNS"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
                list(pool.map(probe_word, words))
        ui.progress_done()
        if found:
            ui.ok(f"{len(found)} sous-domaine(s) trouve(s)")
            ui.table(["SOUS-DOMAINE", "IP"], sorted(found), widths=[44, 20])
            ui.save_output("dnsrecon", "\n".join(f"{h} {ip}" for h, ip in sorted(found)))
        else:
            ui.info("Aucun sous-domaine supplémentaire trouve dans la liste courante.")


def traceroute():
    ui.module_header(7, "Traceroute", "Chemin des paquets jusqu'a la cible")
    host = ui.ask_required("Hote ou IP")
    if platform.system().lower().startswith("win"):
        cmd = ["tracert", "-d", "-w", "600", host]
    else:
        cmd = ["traceroute", "-n", "-w", "2", host] if _has_bin("traceroute") else ["tracepath", "-n", host]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    except Exception as exc:
        ui.err(f"Impossible de lancer la commande : {exc}")
        return
    hops = []
    for row in proc.stdout:
        row = row.rstrip()
        if not row.strip():
            continue
        print("  " + ui.paint(row, ui.W))
        hops.append(row)
    proc.wait()
    ui.ok(f"Trace termine — {max(0, len(hops) - 4)} saut(s)")
    if hops:
        ui.save_output("traceroute", "\n".join(hops))


def _has_bin(name):
    import shutil

    return shutil.which(name) is not None


PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
]


def proxy_scraper():
    ui.module_header(8, "Proxy Scraper", "Collecte et test de proxys HTTP publics")
    proxies = set()
    with ui.Spinner("Telechargement des listes publiques"):
        for url in PROXY_SOURCES:
            resp = net.http_get(url, timeout=12)
            if resp.status == 200 and resp.text:
                for row in resp.text.splitlines():
                    row = row.strip()
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{2,5}$", row):
                        proxies.add(row)
    if not proxies:
        ui.err("Aucune liste accessible (hors ligne ?).")
        return
    ui.ok(f"{len(proxies)} proxy(s) collecte(s)")
    choice = ui.ask_choice("Tester les proxys ? (limité a 150)", ["o", "n"], "o")
    if choice == "o":
        sample = sorted(proxies)[:150]
        alive = []
        lock = threading.Lock()
        done = [0]

        def test(proxy):
            url = f"http://{proxy}"
            try:
                import requests

                r = requests.get("http://api.ipify.org?format=json", proxies={"http": url, "https": url}, timeout=5)
                if r.status_code == 200:
                    with lock:
                        alive.append(proxy)
            except Exception:
                pass
            finally:
                done[0] += 1
                ui.progress("Test des proxys", done[0], len(sample))

        with ui.Spinner("Test en cours"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=60) as pool:
                list(pool.map(test, sample))
        ui.progress_done()
        ui.ok(f"{len(alive)} proxy(s) fonctionnel(s) / {len(sample)} testes")
        if alive:
            for proxy in alive[:30]:
                print("  " + ui.paint(f"  {proxy}", ui.G))
            ui.save_output("proxys", "\n".join(alive))
    else:
        ui.save_output("proxys", "\n".join(sorted(proxies)))


def reseau_local():
    ui.module_header(9, "Reseau Local", "Interfaces, adresses locales et passerelle")
    pairs = [
        ("Hostname", socket.gethostname()),
        ("IP locale", net.local_ip()),
        ("Python", platform.python_version()),
        ("Systeme", f"{platform.system()} {platform.release()}"),
    ]
    ui.kv(pairs)
    print()
    if platform.system().lower().startswith("win"):
        cmd = ["ipconfig", "/all"]
    else:
        cmd = ["ip", "addr"] if _has_bin("ip") else ["ifconfig"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
        text = out.stdout or ""
        for row in text.splitlines()[:70]:
            if any(key in row for key in ("IPv4", "IPv6", "Adresse physique", "Physical Address",
                                          "Passerelle", "Gateway", "DNS", "adapter", "eth", "wlan",
                                          "Description", "Carte", "mtu")):
                print("  " + ui.paint(row.strip(), ui.C))
    except Exception as exc:
        ui.err(f"Lecture impossible : {exc}")
    if platform.system().lower().startswith("win") and _has_bin("arp"):
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="replace", timeout=10)
            rows = []
            for row in (out.stdout or "").splitlines():
                parts = row.split()
                if len(parts) >= 3 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[0]):
                    rows.append(parts[:3])
            if rows:
                ui.info("Table ARP (voisins detectes) :")
                ui.table(["IP", "MAC", "TYPE"], rows[:25], widths=[18, 20, 10])
        except Exception:
            pass
