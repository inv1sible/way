"""Werkzeug-Dienst: führt eine feste Liste lokaler Tools (whois, dig, openssl, curl) aus.

Der Dienst ist nur im internen Docker-Netz erreichbar und verlangt ein Token. Er nimmt keine
Kommandozeilen entgegen, sondern nur benannte Aktionen mit streng geprüften Zielen. Verbindungen
zu nicht-öffentlichen Adressen (LAN, Docker-Netz, Loopback, Link-Local) werden abgelehnt, damit der
Dienst nicht gegen interne Systeme missbraucht werden kann.

Stufe 0 (nur Registries und DNS, kein Kontakt zum Ziel): whois, asn, dns
Stufe 1 (ein normaler Zugriff auf das Ziel, taucht in dessen Log auf): tls, web
Stufe 2 (Portscan, nur für eigene Systeme): scan

Ob ein Ziel scannen darf, entscheidet die Anwendung anhand der Liste "Eigene Systeme"; dieser Dienst
begrenzt nur das Wie: ausschließlich öffentliche Adressen, festes Profil, ein Scan zur Zeit.
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
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = os.environ.get("TOOLS_TOKEN", "")
MAX_OUTPUT = 200_000
MAX_HTTP_BODY = 65_536
SLOTS = threading.BoundedSemaphore(6)  # gleichzeitige Tool-Aufrufe
TLS_PORTS = {443, 8443}
WEB_PORTS = {80, 443, 8080, 8443}
HTTPS_PORTS = {443, 8443}
FRITZ_DEFAULT_PORTS = (443, 8443)
SPEEDPORT_DEFAULT_PORTS = (80, 443)
FRITZ_MAX_PORTS = 4
FRITZ_DEFAULT_TIMEOUT = 8
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


def fritz_ports(params, default=FRITZ_DEFAULT_PORTS):
    """Kleine explizite Portliste; 80/8080 sind HTTP, alle anderen Ports HTTPS."""
    values = params.get("ports", default)
    if not isinstance(values, (list, tuple)) or not values or len(values) > FRITZ_MAX_PORTS:
        raise Refused(f"Es sind 1 bis {FRITZ_MAX_PORTS} Ports erlaubt.")
    ports = []
    for value in values:
        if isinstance(value, bool):
            raise Refused("Ungültiger Port.")
        try:
            port = int(value)
        except (TypeError, ValueError):
            raise Refused("Ungültiger Port.") from None
        if not 1 <= port <= 65535:
            raise Refused(f"Port {port} liegt außerhalb von 1 bis 65535.")
        if port not in ports:
            ports.append(port)
    return ports


def fritz_timeout(params):
    try:
        timeout = int(params.get("timeout", FRITZ_DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        raise Refused("Ungültiger Timeout.") from None
    if not 2 <= timeout <= 20:
        raise Refused("Der Timeout muss zwischen 2 und 20 Sekunden liegen.")
    return timeout


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


def probe_tls(addr, port, sni=None, timeout=12):
    endpoint = f"[{addr}]:{port}" if addr.version == 6 else f"{addr}:{port}"
    identity = ["-servername", sni, "-verify_hostname", sni] if sni else ["-verify_ip", str(addr)]
    cmd = ["openssl", "s_client", "-connect", endpoint, "-showcerts", *identity]
    out, err, _ = run(cmd, timeout)
    certs = PEM.findall(out)
    if not certs:
        raise RuntimeError("Kein TLS-Handshake möglich (Port geschlossen, gefiltert oder kein TLS)")
    protocol = re.search(r"New, (\S+), Cipher is (\S+)", out)
    verify = re.search(r"Verify return code:\s*(\d+)", out + "\n" + err)
    return {
        "port": port,
        "sni": sni,
        "protokoll": protocol.group(1) if protocol else None,
        "cipher": protocol.group(2) if protocol else None,
        "vertrauenswuerdig": int(verify.group(1)) == 0 if verify else None,
        "zertifikate_in_kette": len(certs),
        **describe_cert(certs[0]),
    }


def tool_tls(params):
    addr = public_ip(params.get("ip", ""))
    port = port_of(params, TLS_PORTS, 443)
    sni = hostname(params["sni"]) if params.get("sni") else None
    return probe_tls(addr, port, sni)


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


# --- FRITZ!Box-Fingerprint (Stufe 1, defensiv) -------------------------------------------------

BOXINFO_FIELDS = {
    "name": "name",
    "hw": "hardwareId",
    "version": "rawFirmwareVersion",
    "revision": "revision",
    "oem": "oem",
    "lang": "language",
    "annex": "annex",
    "lab": "labBuild",
}
FRITZ_MARKER = re.compile(r"\b(?:avm|fritz!?box|fritz!os|myfritz)\b", re.I)
# Allgemeine Produktwörter sind nur ein vorsichtiges Indiz. Sie reichen weder
# für eine Hersteller- noch für eine Modellzuordnung und lösen keine weiteren Abrufe aus.
ROUTER_MARKER = re.compile(r"\b(?:router|gateway|modem|speedport|home\s*network)\b", re.I)
SPEEDPORT_MARKER = re.compile(r"\bspeedport(?:\b|_)", re.I)
SPEEDPORT_MODEL_FIELDS = ("device_name", "model_name", "domain_name", "device_model", "model")
SPEEDPORT_FIRMWARE_FIELDS = ("firmware_version", "firmwareversion", "software_version", "softwareversion")


def _status_value(data, names, depth=0):
    """Nur explizit erlaubte, kleine Statusfelder aus JSON übernehmen; nie die Antwort selbst speichern."""
    if depth > 5:
        return None
    if isinstance(data, dict):
        for key, value in data.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in names and isinstance(value, (str, int, float)) and not isinstance(value, bool):
                text = " ".join(str(value).split())[:150]
                if text:
                    return text
        for value in data.values():
            found = _status_value(value, names, depth + 1)
            if found:
                return found
    elif isinstance(data, list):
        for value in data[:100]:
            found = _status_value(value, names, depth + 1)
            if found:
                return found
    return None


def parse_speedport_status(data):
    """Verarbeitet nur den unauthentifizierten, optionalen Speedport-Statuspfad.

    Die Antwort kann je Firmware verschieden aussehen. Das Profil wertet daher ausschließlich bekannte
    Modell- und Firmware-Feldnamen aus und verwirft alle anderen (potenziell privaten) Statusdaten.
    """
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8", "replace")
    if len(data) > MAX_HTTP_BODY:
        raise ValueError("Speedport-Statusantwort ist zu groß")
    try:
        parsed = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Antwort ist kein gültiges Speedport-Status-JSON") from None
    model_raw = _status_value(parsed, SPEEDPORT_MODEL_FIELDS)
    model = model_raw.replace("_", " ") if model_raw and SPEEDPORT_MARKER.search(model_raw) else None
    firmware = _status_value(parsed, SPEEDPORT_FIRMWARE_FIELDS)
    return {
        "device": {"vendor": "Telekom" if model else None, "model": model, "rawFirmwareVersion": firmware},
        # Ein Modell allein ist ein direkter Herstellerhinweis; für Modell + Firmware ist die Zuordnung stark.
        "plausible": bool(model),
    }


def derive_fritz_os(raw):
    """AVM-Firmwareformat <Hardware>.<Major>.<Minor>; nur eindeutige Formen ableiten."""
    value = str(raw or "").strip()
    match = re.fullmatch(r"\d{2,4}\.0?(\d{1,2})\.(\d{2,3})(?:[-+][A-Za-z0-9._-]+)?", value)
    if match:
        return f"{int(match.group(1))}.{match.group(2)}"
    if re.fullmatch(r"\d{1,2}\.\d{2}", value):
        return value
    return None


def parse_boxinfo(data):
    """Kleine, erwartete XML-Antwort parsen; DTD/Entities sind ausdrücklich verboten."""
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8", "replace")
    if len(data) > MAX_HTTP_BODY:
        raise ValueError("boxinfo-Antwort ist zu groß")
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.I):
        raise ValueError("DTD- und Entity-Deklarationen sind nicht erlaubt")
    stripped = bytes(data).lstrip()
    if not stripped.startswith(b"<") or re.match(br"<(?:!doctype\s+html|html|head|body)\b", stripped, re.I):
        raise ValueError("Antwort ist kein boxinfo-XML")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Ungültiges boxinfo-XML ({exc})") from None
    root_name = root.tag.rsplit("}", 1)[-1].lower() if isinstance(root.tag, str) else ""
    if root_name not in ("boxinfo", "jason_boxinfo"):
        raise ValueError("XML-Wurzelelement ist kein BoxInfo")

    values = {}
    serial_present = False
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1].lower() if isinstance(element.tag, str) else ""
        value = " ".join((element.text or "").split())[:300]
        if local == "serial" and value:
            serial_present = True
        output_name = BOXINFO_FIELDS.get(local)
        if output_name and value and output_name not in values:
            values[output_name] = value

    name = values.pop("name", None)
    model = name if name and re.search(r"fritz!?box", name, re.I) else None
    raw_version = values.get("rawFirmwareVersion")
    device = {
        "model": model,
        "hardwareId": values.get("hardwareId"),
        "fritzOsVersion": derive_fritz_os(raw_version),
        "rawFirmwareVersion": raw_version,
        "revision": values.get("revision"),
        "oem": values.get("oem"),
        "language": values.get("language"),
        "annex": values.get("annex"),
        "labBuild": values.get("labBuild"),
    }
    known = sum(value is not None for value in device.values())
    return {
        "device": device,
        "deviceName": name,
        # Schwache Felder wie Sprache/OEM allein reichen nicht für einen hohen Nachweis.
        "plausible": known >= 2 and bool(model or raw_version),
        "serialRedacted": serial_present,
    }


def _curl_fetch(addr, sni, port, scheme, path, timeout):
    """HEAD-Vorprüfung und ggf. GET ohne Redirect/DNS-Neuauflösung; Body bleibt hart begrenzt."""
    ip_text = f"[{addr}]" if addr.version == 6 else str(addr)
    url = f"{scheme}://{sni or ip_text}:{port}{path}"
    def request(head=False):
        with tempfile.TemporaryDirectory() as tmp:
            header_file, body_file = Path(tmp, "headers"), Path(tmp, "body")
            cmd = [
                "curl", "-sS", "-k", "--max-time", str(timeout), "--connect-timeout", str(min(timeout, 6)),
                "--max-filesize", str(MAX_HTTP_BODY), "--max-redirs", "0", "--proto", "=http,https",
                "-A", USER_AGENT, "-H", "Accept: application/xml,text/xml,text/html;q=0.5,*/*;q=0.1",
                "-D", str(header_file), "-o", str(body_file),
            ]
            if head:
                cmd.append("--head")
            if sni:
                cmd += ["--resolve", f"{sni}:{port}:{ip_text}"]
            _, err, code = run(cmd + [url], timeout + 3)
            headers_text = header_file.read_text(errors="replace") if header_file.exists() else ""
            raw = body_file.read_bytes() if body_file.exists() else b""
        status, headers, cookies = parse_headers(headers_text)
        if status is None:
            raise RuntimeError("Keine HTTP-Antwort: " + (err.strip() or f"curl Exit-Code {code}")[:200])
        return status, headers, cookies, raw, code

    status, headers, cookies, _, _ = request(head=True)
    content_type = headers.get("content-type", "").lower()
    textual = not content_type or any(kind in content_type for kind in ("text/", "xml", "json", "xhtml"))
    # Fehler/Redirects benötigen keinen Body. Binär deklarierte Inhalte werden gar nicht abgerufen.
    if status >= 300 or not textual:
        return {
            "url": url, "status": status, "headers": headers, "cookieNames": cookies[:10], "body": b"",
            "oversized": False, "binarySkipped": not textual,
        }
    status, headers, cookies, raw, code = request(head=False)
    oversized = code == 63 or len(raw) > MAX_HTTP_BODY
    return {
        "url": url,
        "status": status,
        "headers": headers,
        "cookieNames": cookies[:10],
        "body": raw[:MAX_HTTP_BODY],
        "oversized": oversized,
        "binarySkipped": False,
    }


def _public_http(fetch):
    headers = fetch["headers"]
    body = fetch["body"]
    content_type = headers.get("content-type", "").lower()
    textual = not content_type or any(kind in content_type for kind in ("text/", "xml", "json", "xhtml"))
    title = None
    if textual and not fetch["oversized"]:
        decoded = body.decode("utf-8", "replace")
        match = re.search(r"<title[^>]*>(.*?)</title>", decoded, re.S | re.I)
        title = " ".join(html.unescape(match.group(1)).split())[:200] if match else None
    return {
        "url": fetch["url"],
        "status": fetch["status"],
        "title": title,
        "headers": {name: headers[name][:300] for name in HEADERS_OF_INTEREST if name in headers},
        "cookieNames": fetch["cookieNames"],
        "bodyOversized": fetch["oversized"],
        "binaryBodySkipped": fetch.get("binarySkipped", False),
    }


def tool_router(params):
    """Leichter Router-Fingerprint: generisch, FRITZ!Box oder Speedport, stets ohne Anmeldung."""
    addr = public_ip(params.get("ip", ""))
    sni = hostname(params["sni"]) if params.get("sni") else None
    profile = params.get("profile", "generic")
    if profile not in ("generic", "fritzbox", "speedport"):
        raise Refused("Ungültiges Router-Prüfprofil.")
    default_ports = {
        "generic": (443,), "fritzbox": FRITZ_DEFAULT_PORTS, "speedport": SPEEDPORT_DEFAULT_PORTS,
    }[profile]
    ports = fritz_ports(params, default=default_ports)
    timeout = fritz_timeout(params)
    services, observations, warnings = [], [], []
    boxinfo = None
    speedport = None
    tls_summary = {
        "certificateSubject": None, "certificateIssuer": None, "dnsNames": [], "trusted": None,
        "validFrom": None, "validTo": None,
    }

    for port in ports:
        scheme = "http" if port in (80, 8080) else "https"
        service = {"port": port, "scheme": scheme, "reachable": False, "endpoints": []}
        if scheme == "https":
            try:
                cert = probe_tls(addr, port, sni, timeout)
                # Die Zertifikats-Seriennummer ist für den Fingerprint nicht nötig und könnte mit der bewusst
                # redigierten Geräte-Seriennummer verwechselt werden.
                service["tls"] = {key: value for key, value in cert.items() if key != "seriennummer"}
                if tls_summary["certificateSubject"] is None:
                    tls_summary = {
                        "certificateSubject": cert.get("inhaber"),
                        "certificateIssuer": cert.get("aussteller"),
                        "dnsNames": cert.get("alternative_namen", []),
                        "trusted": cert.get("vertrauenswuerdig"),
                        "validFrom": cert.get("gueltig_ab"),
                        "validTo": cert.get("gueltig_bis"),
                    }
                if cert.get("vertrauenswuerdig") is False:
                    warnings.append(f"Das TLS-Zertifikat auf Port {port} ist nicht vertrauenswürdig.")
            except Exception as exc:
                service["tlsError"] = str(exc)[:240]

        paths = {
            "generic": ("/",),
            "fritzbox": ("/", "/jason_boxinfo.xml"),
            "speedport": ("/", "/data/Status.json"),
        }[profile]
        for path in paths:
            endpoint = {"path": path}
            if path != "/" and not service["reachable"]:
                endpoint.update({"result": "negative", "reason": "Kein HTTP-Dienst am Port festgestellt"})
                service["endpoints"].append(endpoint)
                continue
            try:
                fetched = _curl_fetch(addr, sni, port, scheme, path, timeout)
                public = _public_http(fetched)
                endpoint.update({key: value for key, value in public.items() if key not in ("url",)})
                service["reachable"] = True
                if path == "/":
                    service.update({key: value for key, value in public.items() if key not in ("status",)})
                    text = " ".join(filter(None, [public.get("title"), *public.get("headers", {}).values()]))
                    marker = {
                        "fritzbox": FRITZ_MARKER, "speedport": SPEEDPORT_MARKER, "generic": ROUTER_MARKER,
                    }[profile]
                    if marker.search(text):
                        evidence = (
                            f"FRITZ!/AVM-Merkmal in HTTP-Metadaten auf Port {port}"
                            if profile == "fritzbox" else
                            f"Speedport-Merkmal in HTTP-Metadaten auf Port {port}"
                            if profile == "speedport" else
                            f"Router-/Gateway-Merkmal in HTTP-Metadaten auf Port {port}"
                        )
                        observations.append({"evidence": evidence})
                elif profile == "fritzbox" and fetched["status"] == 200 and not fetched["oversized"]:
                    content_type = fetched["headers"].get("content-type", "").lower()
                    if not content_type or "xml" in content_type or "text/plain" in content_type:
                        try:
                            parsed = parse_boxinfo(fetched["body"])
                        except ValueError as exc:
                            endpoint["result"] = "negative"
                            endpoint["reason"] = str(exc)[:200]
                        else:
                            endpoint["result"] = "boxinfo"
                            if parsed["plausible"]:
                                boxinfo = parsed
                    else:
                        endpoint["result"] = "negative"
                        endpoint["reason"] = "Antwort ist kein XML-Inhalt"
                elif profile == "speedport" and fetched["status"] == 200 and not fetched["oversized"]:
                    content_type = fetched["headers"].get("content-type", "").lower()
                    if not content_type or "json" in content_type or "text/plain" in content_type:
                        try:
                            parsed = parse_speedport_status(fetched["body"])
                        except ValueError as exc:
                            endpoint["result"] = "negative"
                            endpoint["reason"] = str(exc)[:200]
                        else:
                            endpoint["result"] = "speedport-status"
                            if parsed["plausible"]:
                                speedport = parsed
                    else:
                        endpoint["result"] = "negative"
                        endpoint["reason"] = "Antwort ist kein JSON-Inhalt"
                elif path != "/":
                    endpoint["result"] = "negative"
            except Exception as exc:
                endpoint["result"] = "negative"
                endpoint["reason"] = str(exc)[:240]
            service["endpoints"].append(endpoint)
        services.append(service)

    return {
        "resolvedAddress": str(addr),
        "addressFamily": f"IPv{addr.version}",
        "ports": ports,
        "timeoutSeconds": timeout,
        "services": services,
        "tls": tls_summary,
        "boxinfo": boxinfo,
        "speedport": speedport,
        "observations": observations,
        "warnings": list(dict.fromkeys(warnings)),
        "profile": profile,
        "requestPolicy": (
            "sequenziell; HEAD vor optionalem GET für /, höchstens zwei HTTP-Anfragen je Port; "
            "keine Redirects oder Anmeldung"
            if profile == "generic" else
            "sequenziell; HEAD vor optionalem GET für / und /jason_boxinfo.xml, höchstens vier HTTP-Anfragen "
            "je Port; keine Redirects oder Anmeldung"
            if profile == "fritzbox" else
            "sequenziell; HEAD vor optionalem GET für / und /data/Status.json, höchstens vier HTTP-Anfragen "
            "je Port; keine Redirects, Anmeldung oder weitere Statuspfade"
        ),
    }


def tool_fritzbox(params):
    """Abwärtskompatibler FRITZ!Box-Adapter des generischen Router-Tools."""
    values = dict(params)
    values["profile"] = "fritzbox"
    return tool_router(values)


# --- Portscan (Stufe 2, nur eigene Systeme) --------------------------------------------------

SCAN_SLOT = threading.BoundedSemaphore(1)
SCAN_PROFILE = "Top-1000-TCP-Ports, Verbindungs-Scan (-sT), Diensterkennung leicht"


# Offene Ports mit bekanntem Risiko, wenn sie aus dem Internet erreichbar sind: (Stufe, Hinweis).
PORT_HINTS = {
    21: ("hoch", "FTP überträgt Passwörter unverschlüsselt"),
    22: ("mittel", "SSH aus dem Internet erreichbar: nur Schlüssel-Login zulassen, Passwort-Login abschalten, "
                   "Zugriff möglichst per VPN oder Firewall begrenzen"),
    23: ("hoch", "Telnet ist unverschlüsselt und veraltet"),
    25: ("mittel", "SMTP offen: eigener Mailserver? Offenes Relay prüfen"),
    110: ("mittel", "POP3 unverschlüsselt"),
    111: ("hoch", "rpcbind/portmapper gehört nicht ins Internet"),
    135: ("hoch", "Windows-RPC gehört nicht ins Internet"),
    139: ("hoch", "NetBIOS gehört nicht ins Internet"),
    143: ("mittel", "IMAP unverschlüsselt"),
    445: ("hoch", "SMB-Dateifreigabe gehört nicht ins Internet"),
    548: ("mittel", "AFP-Dateifreigabe"),
    631: ("mittel", "CUPS-Druckdienst"),
    873: ("hoch", "rsync offen"),
    1433: ("hoch", "Microsoft SQL Server offen"),
    1521: ("hoch", "Oracle-Datenbank offen"),
    1883: ("mittel", "MQTT unverschlüsselt"),
    2049: ("hoch", "NFS offen"),
    2375: ("hoch", "Docker-API ohne TLS: Vollzugriff auf den Host"),
    3306: ("hoch", "MySQL/MariaDB offen"),
    3389: ("hoch", "Remote Desktop (RDP) aus dem Internet"),
    5060: ("mittel", "SIP offen"),
    5432: ("hoch", "PostgreSQL offen"),
    5900: ("hoch", "VNC offen"),
    5984: ("hoch", "CouchDB offen"),
    6379: ("hoch", "Redis offen, meist ohne Anmeldung"),
    6789: ("mittel", "Wird u. a. von Ubiquiti UniFi (Speedtest) und IBM DB2-Admin genutzt: Zweck prüfen"),
    7547: ("mittel", "TR-069 Router-Fernwartung"),
    8080: ("mittel", "Webdienst auf Alternativport, oft eine Verwaltungsoberfläche (z. B. UniFi, Tomcat, Router)"),
    8291: ("mittel", "MikroTik Winbox"),
    8443: ("mittel", "HTTPS auf Alternativport, oft eine Verwaltungsoberfläche (z. B. UniFi, Tomcat, Router)"),
    8728: ("mittel", "MikroTik API"),
    9100: ("mittel", "Druckerport"),
    9200: ("hoch", "Elasticsearch offen"),
    10000: ("mittel", "Webmin-Verwaltungsoberfläche"),
    11211: ("hoch", "Memcached offen"),
    27017: ("hoch", "MongoDB offen"),
}


def flag_ports(open_ports):
    flagged = []
    for entry in open_ports:
        hint = PORT_HINTS.get(entry["port"]) or (PORT_HINTS[5900] if 5901 <= entry["port"] <= 5902 else None)
        if hint:
            flagged.append({"port": entry["port"], "stufe": hint[0], "hinweis": hint[1]})
    return flagged


def parse_nmap(xml_text):
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return {"hinweis": "nmap hat keinen Host gemeldet."}
    ports_el = host.find("ports")
    open_ports, counts = [], {}
    for extra in (ports_el.findall("extraports") if ports_el is not None else []):
        counts[extra.get("state", "?")] = counts.get(extra.get("state", "?"), 0) + int(extra.get("count", 0))
    for port in (ports_el.findall("port") if ports_el is not None else []):
        state = port.find("state").get("state", "?")
        if state != "open":
            counts[state] = counts.get(state, 0) + 1
            continue
        service = port.find("service")
        attrs = service.attrib if service is not None else {}
        open_ports.append({
            "port": int(port.get("portid")),
            "proto": port.get("protocol"),
            "dienst": attrs.get("name"),
            "produkt": attrs.get("product"),
            "version": attrs.get("version"),
            "zusatz": attrs.get("extrainfo"),
            "tunnel": attrs.get("tunnel"),
        })
    finished = root.find("runstats/finished")
    open_ports.sort(key=lambda e: e["port"])
    return {
        "profil": SCAN_PROFILE,
        "offen": [{k: v for k, v in entry.items() if v} for entry in open_ports],
        "auffaellig": flag_ports(open_ports),
        "anzahl_offen": len(open_ports),
        "geschlossen": counts.get("closed", 0),
        "gefiltert": counts.get("filtered", 0),
        "dauer_s": float(finished.get("elapsed")) if finished is not None and finished.get("elapsed") else None,
    }


def tool_scan(params):
    addr = public_ip(params.get("ip", ""))
    if not SCAN_SLOT.acquire(timeout=5):
        raise RuntimeError("Es läuft bereits ein Portscan; bitte später erneut versuchen")
    try:
        # --unprivileged: Verbindungs-Scan ohne Raw-Sockets (der Container hat keine Capabilities)
        cmd = ["nmap", "--unprivileged", "-sT", "-Pn", "-n", "--top-ports", "1000", "-sV", "--version-intensity", "2",
               "--max-retries", "1", "--host-timeout", "240s"] + (["-6"] if addr.version == 6 else [])
        out, err, code = run(cmd + ["-oX", "-", str(addr)], 270)
    finally:
        SCAN_SLOT.release()
    if code != 0 or "<nmaprun" not in out:
        raise RuntimeError("nmap fehlgeschlagen: " + (err.strip() or f"Exit-Code {code}")[:300])
    return {"ziel": str(addr), **parse_nmap(out)}


TOOLS = {
    "whois": tool_whois,
    "asn": tool_asn,
    "dns": tool_dns,
    "tls": tool_tls,
    "web": tool_web,
    "fritzbox": tool_fritzbox,
    "router": tool_router,
    "scan": tool_scan,
}


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
