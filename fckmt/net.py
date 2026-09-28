import socket
import struct
import ssl
import time
import ipaddress

from . import config


class Resp:
    def __init__(self, status=0, text="", content=b"", headers=None, url=""):
        self.status = status
        self.text = text
        self.content = content
        self.headers = headers or {}
        self.url = url


def http_get(url, timeout=10, headers=None, stream=False):
    try:
        import requests

        h = {"User-Agent": config.USER_AGENT}
        if headers:
            h.update(headers)
        r = requests.get(url, timeout=timeout, headers=h, allow_redirects=True)
        return Resp(r.status_code, r.text, r.content, dict(r.headers), r.url)
    except ImportError:
        return _urllib_request(url, timeout, headers, None)
    except Exception:
        try:
            return _urllib_request(url, timeout, headers, None)
        except Exception:
            return Resp(0, "", b"", {}, url)


def http_post(url, data=None, json_data=None, timeout=10, headers=None):
    try:
        import requests

        h = {"User-Agent": config.USER_AGENT}
        if headers:
            h.update(headers)
        if json_data is not None:
            r = requests.post(url, json=json_data, timeout=timeout, headers=h)
        else:
            r = requests.post(url, data=data, timeout=timeout, headers=h)
        return Resp(r.status_code, r.text, r.content, dict(r.headers), r.url)
    except Exception:
        return _urllib_request(url, timeout, headers, json_data if json_data is not None else data)


def _urllib_request(url, timeout, headers, data):
    import json as _json
    import urllib.request
    import urllib.error

    h = {"User-Agent": config.USER_AGENT}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = _json.dumps(data).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = data
    req = urllib.request.Request(url, data=body, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read()
            try:
                text = content.decode("utf-8", "replace")
            except Exception:
                text = ""
            return Resp(getattr(r, "status", 200), text, content, dict(r.headers), url)
    except urllib.error.HTTPError as exc:
        content = exc.read() if hasattr(exc, "read") else b""
        try:
            text = content.decode("utf-8", "replace")
        except Exception:
            text = ""
        return Resp(exc.code, text, content, dict(exc.headers or {}), url)
    except Exception:
        return Resp(0, "", b"", {}, url)


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


_QTYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255,
}

_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(data, offset):
    labels = []
    jumped = False
    start = offset
    hops = 0
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                start = offset + 2
                jumped = True
            offset = pointer
            hops += 1
            if hops > 20:
                break
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (start if jumped else offset)


def dns_query(name, qtype="A", server=None, timeout=3.0, port=53):
    qtype = qtype.upper()
    if qtype not in _QTYPES:
        raise ValueError(f"Type DNS inconnu : {qtype}")
    servers = [server] if server else _DNS_SERVERS
    last_error = None
    for srv in servers:
        try:
            tid = int(time.time() * 1000) & 0xFFFF
            header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            question = _encode_name(name) + struct.pack("!HH", _QTYPES[qtype], 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(header + question, (srv, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return _parse_response(data, qtype)
        except Exception as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error
    return []


def _parse_response(data, qtype):
    if len(data) < 12:
        return []
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = _decode_name(data, offset)
        offset += 4
    results = []
    for _ in range(an + ns + ar):
        if offset >= len(data):
            break
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rclass != 1 or rtype != _QTYPES.get(qtype):
            continue
        try:
            if rtype == 1 and len(rdata) == 4:
                results.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and len(rdata) == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype == 15 and len(rdata) >= 3:
                pref = struct.unpack("!H", rdata[:2])[0]
                exchange, _ = _decode_name(data, offset - rdlength + 2)
                results.append(f"{pref} {exchange}")
            elif rtype in (2, 5, 12):
                target, _ = _decode_name(data, offset - rdlength)
                results.append(target)
            elif rtype == 16:
                txt = b""
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    txt += rdata[i + 1:i + 1 + ln]
                    i += 1 + ln
                results.append(txt.decode("utf-8", "replace"))
            elif rtype == 6:
                mname, off = _decode_name(data, offset - rdlength)
                rname, _ = _decode_name(data, off)
                results.append(f"{mname} {rname}")
            else:
                results.append(rdata.hex())
        except Exception:
            continue
    return results


def dns_records(name, types=("A", "AAAA", "MX", "NS", "TXT", "CNAME")):
    out = {}
    for qtype in types:
        try:
            out[qtype] = dns_query(name, qtype)
        except Exception:
            out[qtype] = []
    return out


def whois_query(query, server="whois.iana.org", timeout=6.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 43))
        sock.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 200_000:
                break
        return b"".join(chunks).decode("utf-8", "replace")
    finally:
        sock.close()


def whois_lookup(query, max_follow=3):
    servers_done = []
    server = "whois.iana.org"
    text_total = ""
    current = query
    for _ in range(max_follow):
        try:
            text = whois_query(current, server)
        except Exception as exc:
            if not text_total:
                raise exc
            break
        servers_done.append(server)
        text_total += text + "\n"
        referral = None
        for raw in text.splitlines():
            line = raw.strip()
            low = line.lower()
            if low.startswith("whois:") or low.startswith("refer:"):
                candidate = line.split(":", 1)[1].strip()
                if candidate and candidate not in servers_done:
                    referral = candidate
        if not referral:
            break
        server = referral
        if "%" not in query and ("domain" in text.lower() or "Registrar WHOIS Server" in text):
            pass
    return text_total.strip()


def cert_info(host, port=443, timeout=8.0):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert_bin = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            version = tls.version()
    pem = ssl.DER_cert_to_PEM_cert(cert_bin)
    decoded = {}
    try:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
            tmp.write(pem)
            path = tmp.name
        decoded = ssl._ssl._test_decode_cert(path)
        try:
            import os

            os.unlink(path)
        except Exception:
            pass
    except Exception:
        decoded = {}
    return {"cert": decoded, "cipher": cipher, "tls": version, "der": cert_bin, "pem": pem}


def local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        sock.close()
