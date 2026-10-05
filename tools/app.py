"""Werkzeug-Dienst: führt eine feste Liste lokaler Tools (whois, dig, openssl, curl) aus.

Der Dienst ist nur im internen Docker-Netz erreichbar und verlangt ein Token. Er nimmt keine
Kommandozeilen entgegen, sondern nur benannte Aktionen mit streng geprüften Zielen. Verbindungen
zu nicht-öffentlichen Adressen (LAN, Docker-Netz, Loopback, Link-Local) werden abgelehnt, damit der
Dienst nicht gegen interne Systeme missbraucht werden kann.

Stufe 0 (nur Registries und DNS, kein Kontakt zum Ziel): whois, asn, dns
Stufe 1 (ein normaler Zugriff auf das Ziel, taucht in dessen Log auf): tls, web
"""

import hmac
import html
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = os.environ.get("TOOLS_TOKEN", "")
MAX_OUTPUT = 200_000
SLOTS = threading.BoundedSemaphore(6)  # gleichzeitige Tool-Aufrufe
TLS_PORTS = {443, 8443}
WEB_PORTS = {80, 443, 8080, 8443}
HTTPS_PORTS = {443, 8443}
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0 Safari/537.36"
HOSTNAME = re.compile(r"(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")


class Refused(ValueError):
    """Eingabe oder Ziel ist unzulässig (nicht öffentlich, ungültig, nicht erlaubter Port)."""


# --- Zielprüfung -----------------------------------------------------------------------------

def parse_ip(value):
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise Refused("Keine gültige IP-Adresse.") from None
    if getattr(addr, "scope_id", None):
        raise Refused("IPv6-Adressen mit Zonen-Angabe werden nicht unterstützt.")
    return addr


def public_ip(value):
    addr = parse_ip(value)
    effective = addr.ipv4_mapped if addr.version == 6 and addr.ipv4_mapped else addr
    if not effective.is_global or effective.is_multicast:
        raise Refused(f"{addr} ist keine öffentliche Adresse; Abfragen interner Ziele sind gesperrt.")
    return addr


def hostname(value):
    host = str(value).strip().lower().rstrip(".")
    if not HOSTNAME.fullmatch(host):
        raise Refused("Kein gültiger Hostname.")
    return host


def classify(value):
    """("ip", Adresse) für öffentliche IPs, ("host", Name) für Hostnamen."""
    text = str(value).strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return "host", hostname(text)  # kein IP-Literal
    return "ip", public_ip(text)


def port_of(params, allowed, default):
    try:
        port = int(params.get("port", default))
    except (TypeError, ValueError):
        raise Refused("Ungültiger Port.") from None
    if port not in allowed:
        raise Refused(f"Port {port} ist nicht erlaubt (erlaubt: {sorted(allowed)}).")
    return port


# --- Prozesse --------------------------------------------------------------------------------

def run(cmd, timeout, input_text=None):
    kwargs = {"capture_output": True, "timeout": timeout, "text": True, "errors": "replace"}
    if input_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_text
    try:
        done = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]}: Zeitüberschreitung nach {timeout} s") from None
    except FileNotFoundError:
        raise RuntimeError(f"{cmd[0]} ist im Container nicht installiert") from None
    return done.stdout[:MAX_OUTPUT], done.stderr[:2000], done.returncode


# --- whois -----------------------------------------------------------------------------------

WHOIS_KEYS = {
    "inetnum", "inet6num", "netrange", "cidr", "netname", "nethandle", "organization", "orgname", "org-name",
    "descr", "country", "route", "route6", "origin", "originas", "abuse-mailbox", "orgabuseemail", "admin-c",
    "status", "created", "last-modified", "regdate", "updated", "domain name", "registrar", "registrar url",
    "creation date", "registry expiry date", "updated date", "name server", "nserver", "domain status", "dnssec",
    "registrant organization", "registrant country", "registrant state/province",
}
WHOIS_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /_.-]{1,40}?)\s*:\s*(\S.*)$")


def parse_whois(text):
    fields = {}
    for line in text.splitlines():
        if line.lstrip().startswith(("%", "#", ">")):
            continue
        match = WHOIS_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1).strip().lower(), match.group(2).strip()[:200]
        if key in WHOIS_KEYS and value.lower() not in ("redacted for privacy", "not disclosed"):
            values = fields.setdefault(key, [])
            if value not in values and len(values) < 6:
                values.append(value)
    return {key: values[0] if len(values) == 1 else values for key, values in list(fields.items())[:40]}


def whois_query(name):
    out, err, _ = run(["whois", name], 25)
    return out, err


def tool_whois(params):
    kind, target = classify(params.get("target", ""))
    name = str(target)
    out, err = whois_query(name)
    fields = parse_whois(out)
    if kind == "host":
        # Für Subdomains kennt die Registry nur die übergeordnete Domain: schrittweise kürzen.
        labels = name.split(".")
        while not fields and len(labels) > 2:
            labels = labels[1:]
            name = ".".join(labels)
            out, err = whois_query(name)
            fields = parse_whois(out)
    if not fields:
        raise RuntimeError("Keine auswertbare WHOIS-Antwort" + (f": {err.strip()[:200]}" if err.strip() else ""))
    return {"abgefragt": name, "felder": fields}


# --- ASN über Team Cymru (DNS) ---------------------------------------------------------------

def cymru_name(addr):
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
    return ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"


def dig_values(name, rtype):
    out, err, code = run(["dig", "+short", "+time=3", "+tries=1", rtype, name], 12)
    if code != 0:
        raise RuntimeError(f"dig {rtype} {name}: " + (err.strip() or out.strip() or f"Exit-Code {code}")[:200])
    return parse_dig(out)


def parse_dig(out):
    values = []
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            value = re.sub(r'"\s+"', "", line).strip('"')
            if value:  # leere TXT-Einträge ("") weglassen
                values.append(value)
    return values


def split_cymru(record):
    return [part.strip() for part in record.split("|")]


def tool_asn(params):
    addr = public_ip(params.get("ip", ""))
    records = dig_values(cymru_name(addr), "TXT")
    if not records:
        return {"hinweis": "Keine Zuordnung (Adresse wird nicht geroutet oder Team Cymru kennt sie nicht)."}
    asns, prefix, country, registry, allocated = [], None, None, None, None
    for record in records:
        parts = split_cymru(record)
        if len(parts) >= 5:
            asns += [a for a in parts[0].split() if a.isdigit() and a not in asns]
            prefix, country, registry, allocated = parts[1], parts[2], parts[3], parts[4]
    result = {"asn": [f"AS{a}" for a in asns], "praefix": prefix, "land": country, "registry": registry, "zugeteilt": allocated}
    names = {}
    for asn in asns[:3]:
        info = dig_values(f"AS{asn}.asn.cymru.com", "TXT")
        if info:
            parts = split_cymru(info[0])
            if len(parts) >= 5:
                names[f"AS{asn}"] = parts[4]
    if names:
        result["name"] = names
    return result


# --- DNS-Einträge ----------------------------------------------------------------------------

DNS_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CAA")


def tool_dns(params):
    host = hostname(params.get("target", ""))
    queries = [(rtype, host) for rtype in DNS_TYPES] + [("DMARC", f"_dmarc.{host}")]

    def one(query):
        rtype, name = query
        try:
            return rtype, dig_values(name, "TXT" if rtype == "DMARC" else rtype)
        except RuntimeError as exc:
            return rtype, f"Fehler: {exc}"

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(pool.map(one, queries))
    return {"hostname": host, **{rtype: values for rtype, values in results.items() if values}}


# --- TLS-Zertifikat (Stufe 1) ----------------------------------------------------------------

PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def describe_cert(pem):
    out, err, code = run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-serial", "-dates", "-fingerprint", "-sha256",
         "-ext", "subjectAltName"],
        10, input_text=pem,
    )
    if code != 0:
        raise RuntimeError("Zertifikat nicht lesbar: " + err.strip()[:200])
    fields = {}
    for line in out.splitlines():
        for key in ("subject", "issuer", "serial", "notBefore", "notAfter"):
            if line.startswith(key + "="):
                fields[key] = line.split("=", 1)[1].strip()
        if "Fingerprint=" in line:
            fields["sha256"] = line.split("=", 1)[1].strip()
    names = re.findall(r"(?:DNS|IP Address):([^,\s]+)", out.split("Subject Alternative Name", 1)[-1]) if "Subject Alternative Name" in out else []
    result = {
        "inhaber": fields.get("subject"),
        "aussteller": fields.get("issuer"),
        "selbstsigniert": fields.get("subject") == fields.get("issuer"),
        "gueltig_ab": fields.get("notBefore"),
        "gueltig_bis": fields.get("notAfter"),
        "seriennummer": fields.get("serial"),
        "sha256": fields.get("sha256"),
        "alternative_namen": names[:50],
    }
    try:
        expires = datetime.strptime(fields["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        result["tage_bis_ablauf"] = days
        result["abgelaufen"] = days < 0
    except (KeyError, ValueError):
        pass
    return result


def tool_tls(params):
    addr = public_ip(params.get("ip", ""))
    port = port_of(params, TLS_PORTS, 443)
    sni = hostname(params["sni"]) if params.get("sni") else None
    endpoint = f"[{addr}]:{port}" if addr.version == 6 else f"{addr}:{port}"
    cmd = ["openssl", "s_client", "-connect", endpoint, "-showcerts"] + (["-servername", sni] if sni else [])
    out, err, _ = run(cmd, 12)
    certs = PEM.findall(out)
    if not certs:
        raise RuntimeError("Kein TLS-Handshake möglich (Port geschlossen, gefiltert oder kein TLS)")
    protocol = re.search(r"New, (\S+), Cipher is (\S+)", out)
    return {
        "port": port,
        "sni": sni,
        "protokoll": protocol.group(1) if protocol else None,
        "cipher": protocol.group(2) if protocol else None,
        "zertifikate_in_kette": len(certs),
        **describe_cert(certs[0]),
    }


# --- Web-Kopfzeilen (Stufe 1) ----------------------------------------------------------------

HEADERS_OF_INTEREST = (
    "server", "x-powered-by", "location", "content-type", "via", "x-served-by", "x-generator", "x-aspnet-version",
    "strict-transport-security", "www-authenticate", "refresh", "x-frame-options", "content-security-policy",
)


def parse_headers(text):
    """Letzten Antwortblock einer curl-Kopfzeilendatei auswerten."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text.strip()) if b.strip()]
    if not blocks:
        return None, {}, []
    lines = blocks[-1].splitlines()
    status = re.match(r"HTTP/\S+\s+(\d{3})", lines[0])
    headers, cookies = {}, []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name, value = name.strip().lower(), value.strip()
        if name == "set-cookie":
            cookies.append(value.split("=", 1)[0])
        else:
            headers[name] = value
    return (int(status.group(1)) if status else None), headers, cookies


def tool_web(params):
    addr = public_ip(params.get("ip", ""))
    port = port_of(params, WEB_PORTS, 443)
    sni = hostname(params["sni"]) if params.get("sni") else None
    scheme = "https" if port in HTTPS_PORTS else "http"
    ip_text = f"[{addr}]" if addr.version == 6 else str(addr)
    url = f"{scheme}://{sni or ip_text}:{port}/"
    with tempfile.TemporaryDirectory() as tmp:
        header_file, body_file = Path(tmp, "headers"), Path(tmp, "body")
        cmd = ["curl", "-sS", "-k", "-m", "12", "--connect-timeout", "6", "--max-filesize", "65536", "--max-redirs", "0",
               "-A", USER_AGENT, "-D", str(header_file), "-o", str(body_file)]
        if sni:
            cmd += ["--resolve", f"{sni}:{port}:{ip_text}"]
        out, err, code = run(cmd + [url], 15)
        headers_text = header_file.read_text(errors="replace") if header_file.exists() else ""
        body = body_file.read_bytes()[:65536].decode("utf-8", "replace") if body_file.exists() else ""
    status, headers, cookies = parse_headers(headers_text)
    if status is None:
        raise RuntimeError("Keine HTTP-Antwort: " + (err.strip() or f"curl Exit-Code {code}")[:200])
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    return {
        "url": url,
        "status": status,
        "titel": " ".join(html.unescape(title.group(1)).split())[:200] if title else None,
        "header": {name: headers[name][:300] for name in HEADERS_OF_INTEREST if name in headers},
        "cookie_namen": cookies[:10],
        "alle_header_namen": sorted(headers)[:40],
    }


TOOLS = {"whois": tool_whois, "asn": tool_asn, "dns": tool_dns, "tls": tool_tls, "web": tool_web}


# --- HTTP-Schnittstelle ----------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    timeout = 30
    server_version = "tools"

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"ok": False, "error": "nicht gefunden"})

    def do_POST(self):
        if self.path != "/run":
            return self._send(404, {"ok": False, "error": "nicht gefunden"})
        supplied = self.headers.get("Authorization", "").encode()
        if not TOKEN or not hmac.compare_digest(supplied, f"Bearer {TOKEN}".encode()):
            return self._send(401, {"ok": False, "error": "nicht autorisiert"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 4096:
                return self._send(413, {"ok": False, "error": "Anfrage zu groß"})
            request = json.loads(self.rfile.read(length))
            name = request["tool"]
            tool = TOOLS[name]
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"ok": False, "error": "ungültige Anfrage oder unbekanntes Tool"})
        if not SLOTS.acquire(timeout=5):
            return self._send(429, {"ok": False, "error": "ausgelastet"})
        target = request.get("target") or request.get("ip")
        try:
            data = tool(request)
        except Refused as exc:
            print(f"{name} {target!r} -> abgelehnt: {exc}", flush=True)
            self._send(400, {"ok": False, "error": str(exc), "refused": True})
        except Exception as exc:  # Tool-Fehler sind erwartbar (Timeouts, geschlossene Ports)
            print(f"{name} {target!r} -> Fehler: {exc}", flush=True)
            self._send(502, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        else:
            print(f"{name} {target!r} -> ok", flush=True)
            self._send(200, {"ok": True, "data": data})
        finally:
            SLOTS.release()

    def log_message(self, *args):
        pass  # eigene Zeilen oben; kein Zugriffslog pro Request


def main():
    if not TOKEN:
        sys.exit("TOOLS_TOKEN ist nicht gesetzt; der Dienst startet nicht ohne Zugangsschutz.")
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    server.daemon_threads = True
    print("tools bereit auf :8000", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
