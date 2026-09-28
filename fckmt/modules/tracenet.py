"""Module 12 — Trace-HTTP : serveur de trace local (metadonnees visiteurs)."""
import http.server
import json
import os
import threading
from datetime import datetime

from .. import ui, net


def trace_http():
    ui.module_header(12, "Trace-HTTP", "Serveur de trace local : journalise les metadonnees de VOS liens (tests autorises)")
    ui.note("Metadonnees visiteurs uniquement : IP, navigateur, langue, refereur. Aucune page de collecte de cle.")
    port = ui.ask_int("Port d'ecoute", default=8080, minimum=1024, maximum=65535)
    redirect = ui.ask("URL de redirection finale (Entree = page neutre)", default="").strip()

    out_dir = os.path.join(os.getcwd(), "output")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        out_dir = os.getcwd()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(out_dir, f"httplog_{stamp}.jsonl")

    state = {
        "entries": [],
        "geo": {},
        "lock": threading.Lock(),
        "redirect": redirect,
        "path": log_path,
    }

    def geo_lookup(ip):
        with state["lock"]:
            if ip in state["geo"]:
                return state["geo"][ip]
        data = {}
        try:
            resp = net.http_get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as",
                timeout=4,
            )
            if resp.status == 200:
                parsed = json.loads(resp.text)
                if parsed.get("status") == "success":
                    data = {
                        "pays": parsed.get("country", ""),
                        "ville": parsed.get("city", ""),
                        "fa": parsed.get("isp", ""),
                        "asn": parsed.get("as", ""),
                    }
        except Exception:
            pass
        with state["lock"]:
            state["geo"][ip] = data
        return data

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "FCK-TRACE"

        def log_message(self, *args):
            return

        def _client_ip(self):
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
            return self.client_address[0]

        def _record(self, path):
            ip = self._client_ip()
            entry = {
                "horodatage": datetime.now().isoformat(timespec="seconds"),
                "ip": ip,
                "methode": self.command,
                "chemin": path,
                "agent": self.headers.get("User-Agent", ""),
                "refereur": self.headers.get("Referer", ""),
                "langue": self.headers.get("Accept-Language", ""),
            }
            entry.update(geo_lookup(ip))
            with state["lock"]:
                state["entries"].append(entry)
                try:
                    with open(state["path"], "a", encoding="utf-8") as handle:
                        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                except Exception:
                    pass
            return entry

        def _send(self, code, body, content_type="text/html; charset=utf-8", extra=None):
            payload = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def _landing(self, entry):
            if state["redirect"]:
                self._send(302, "", extra={"Location": state["redirect"]})
                return
            html = (
                "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
                "<title>FCK TRACE</title>"
                "<style>body{background:#0b0406;color:#ff2d3f;font-family:monospace;"
                "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
                "h1{border:3px solid #ff2d3f;padding:18px 26px;letter-spacing:6px}</style></head>"
                f"<body><h1>FCK TRACE #{entry['horodatage']}</h1></body></html>"
            )
            self._send(200, html)

        def _dashboard(self):
            with state["lock"]:
                rows = list(state["entries"])
            tr = []
            for e in rows[::-1][:100]:
                geo = " ".join(filter(None, [e.get("ville", ""), e.get("pays", "")])) or "-"
                tr.append(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        e["horodatage"], e["ip"], geo, e.get("fa", "") or e.get("asn", "") or "-",
                        e["chemin"], (e["agent"] or "-")[:60],
                    )
                )
            html = (
                "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
                "<meta http-equiv='refresh' content='3'>"
                "<title>FCK TRACE - Dashboard</title>"
                "<style>body{background:#0b0406;color:#eee;font-family:monospace;padding:22px}"
                "h1{color:#ff2d3f;letter-spacing:3px}table{border-collapse:collapse;width:100%;font-size:13px}"
                "th,td{border:1px solid #3a0d14;padding:6px;text-align:left}"
                "th{background:#1a070b;color:#ff2d3f}tr:nth-child(even){background:#140609}"
                "a{color:#ff6b81}</style></head><body>"
                f"<h1>FCK TRACE &mdash; {len(rows)} visite(s)</h1>"
                "<p><a href='/'>Page traquee</a> &middot; journal : " + state["path"] + "</p>"
                "<table><tr><th>Horodatage</th><th>IP</th><th>Geo</th><th>FA / ASN</th>"
                "<th>Chemin</th><th>User-Agent</th></tr>" + "".join(tr) + "</table>"
                "</body></html>"
            )
            self._send(200, html)

        def _handle(self):
            path = self.path.split("?")[0]
            if path == "/dashboard":
                self._dashboard()
                return
            entry = self._record(path)
            self._landing(entry)

        def do_GET(self):
            self._handle()

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(min(length, 65536))
            self._handle()

        def do_HEAD(self):
            self._handle()

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        server = Server(("0.0.0.0", port), Handler)
    except OSError as exc:
        ui.err(f"Port {port} indisponible : {exc}")
        return

    local = net.local_ip()
    print()
    ui.ok(f"Trace actif sur le port {port}")
    ui.kv([
        ("Local", f"http://localhost:{port}/"),
        ("Reseau", f"http://{local}:{port}/"),
        ("Dashboard", f"http://localhost:{port}/dashboard"),
        ("Journal", log_path),
    ])
    ui.note(f"Tunnel public optionnel : cloudflared tunnel --url http://localhost:{port}")
    ui.info("Ctrl+C pour arreter le serveur.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
    with state["lock"]:
        count = len(state["entries"])
    ui.ok(f"Trace arrete — {count} visite(s) journalisee(s) dans {log_path}")
