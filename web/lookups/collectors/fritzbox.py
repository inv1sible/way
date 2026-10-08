"""Defensiver FRITZ!Box-Fingerprint aus passiven Quellen und optionalem leichtem Direktabruf."""

import ipaddress
import json
import re
from datetime import datetime, timezone

from django.utils.translation import get_language

from . import tools

SOURCE = "FRITZ!Box Fingerprint"
DEFAULT_PORTS = [443, 8443]
MAX_PORTS = 4
DEFAULT_TIMEOUT = 8
MARKER = re.compile(r"\b(?:avm|fritz!?box|fritz!os|myfritz)\b", re.I)


def _message(german, english):
    return english if (get_language() or "de").startswith("en") else german


def parse_ports(value, default=None):
    """Kommagetrennte kleine Portliste; leer verwendet nur 443 und 8443."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return list(default or DEFAULT_PORTS)
    parts = re.split(r"[,;\s]+", value.strip()) if isinstance(value, str) else value
    if not isinstance(parts, (list, tuple)) or not 1 <= len(parts) <= MAX_PORTS:
        raise ValueError(_message(
            f"Bitte 1 bis {MAX_PORTS} Web-Ports angeben.", f"Enter between 1 and {MAX_PORTS} web ports."
        ))
    result = []
    for part in parts:
        if isinstance(part, bool):
            raise ValueError(_message("Ungültiger Web-Port.", "Invalid web port."))
        try:
            port = int(part)
        except (TypeError, ValueError):
            raise ValueError(_message(f"„{part}“ ist kein gültiger Web-Port.", f"“{part}” is not a valid web port.")) from None
        if not 1 <= port <= 65535:
            raise ValueError(_message(
                f"Port {port} liegt außerhalb von 1 bis 65535.", f"Port {port} is outside the range 1 to 65535."
            ))
        if port not in result:
            result.append(port)
    if not result:
        raise ValueError(_message("Mindestens ein Web-Port ist erforderlich.", "At least one web port is required."))
    return result


def parse_timeout(value):
    if value in (None, ""):
        return DEFAULT_TIMEOUT
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        raise ValueError(_message("Der Timeout muss eine ganze Zahl sein.", "The timeout must be an integer.")) from None
    if not 2 <= timeout <= 20:
        raise ValueError(_message(
            "Der Timeout muss zwischen 2 und 20 Sekunden liegen.", "The timeout must be between 2 and 20 seconds."
        ))
    return timeout


def public_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    effective = address.ipv4_mapped if address.version == 6 and address.ipv4_mapped else address
    return not getattr(address, "scope_id", None) and effective.is_global and not effective.is_multicast


def validate_resolved_addresses(addresses):
    """Alle A/AAAA-Ergebnisse müssen öffentlich sein; Mischantworten schlagen geschlossen fehl."""
    if not addresses:
        return "Der Hostname hat keine A- oder AAAA-Adresse."
    invalid = [address for address in addresses if not public_address(address)]
    if invalid:
        return "Mindestens eine aufgelöste Adresse ist nicht öffentlich routbar; aktive Prüfung wurde gesperrt."
    return None


def _text(data):
    try:
        return json.dumps(data, ensure_ascii=False, sort_keys=True)[:20_000]
    except (TypeError, ValueError):
        return str(data)[:20_000]


def _passive_evidence(target, sources, timestamp):
    observations = []
    if isinstance(target, str) and (target == "myfritz.net" or target.endswith(".myfritz.net")):
        observations.append({
            "source": "dns", "timestamp": timestamp,
            "evidence": "Hostname liegt unter myfritz.net; dies ist ein AVM-DynDNS-Indiz, aber kein Gerätenachweis.",
            "sensitive": False,
        })
    candidates = (
        ("Reverse DNS", "dns"),
        ("Shodan InternetDB", "shodan"),
        ("Censys (Internet-Scan-Daten)", "censys"),
    )
    for source_name, label in candidates:
        source = next((item for item in sources if item.get("source") == source_name and item.get("ok")), None)
        if source and MARKER.search(_text(source.get("data"))):
            observations.append({
                "source": label, "timestamp": timestamp,
                "evidence": f"{source_name} enthält ein ausdrückliches AVM-/FRITZ!-Merkmal.",
                "sensitive": False,
            })
    return observations


def build(target, resolved_address, sources, active_confirmed=False, direct=None, active_error=None,
          active_blocked=None):
    timestamp = datetime.now(timezone.utc).isoformat()
    address = ipaddress.ip_address(resolved_address)
    device = {
        "model": None,
        "hardwareId": None,
        "fritzOsVersion": None,
        "rawFirmwareVersion": None,
        "revision": None,
        "oem": None,
        "language": None,
        "labBuild": None,
    }
    tls = {
        "certificateSubject": None, "certificateIssuer": None, "dnsNames": [], "trusted": None,
        "validFrom": None, "validTo": None,
    }
    observations = _passive_evidence(target, sources, timestamp)
    warnings = []
    services = []
    boxinfo = None
    if direct:
        services = direct.get("services", [])
        tls.update(direct.get("tls") or {})
        warnings.extend(direct.get("warnings") or [])
        boxinfo = direct.get("boxinfo")
        for item in direct.get("observations", []):
            observations.append({
                "source": "direct", "timestamp": timestamp,
                "evidence": str(item.get("evidence", "Direktes FRITZ!/AVM-Merkmal erkannt."))[:300],
                "sensitive": False,
            })
    if boxinfo and boxinfo.get("plausible"):
        for key in device:
            if key in boxinfo.get("device", {}):
                device[key] = boxinfo["device"][key]
        observations.append({
            "source": "direct", "timestamp": timestamp,
            "evidence": "/jason_boxinfo.xml lieferte ein plausibles BoxInfo-Dokument; Geräteseriennummer wurde redigiert.",
            "sensitive": False,
        })
    if active_error:
        warnings.append(f"Leichte aktive Prüfung nicht vollständig möglich: {active_error}")
    if active_blocked:
        warnings.append(active_blocked)

    independent_sources = {item["source"] for item in observations}
    if boxinfo and boxinfo.get("plausible"):
        confidence = "high"
        likely = True
    elif len(independent_sources) >= 2:
        confidence = "medium"
        likely = True
    elif independent_sources:
        confidence = "low"
        likely = False
    else:
        confidence = "none"
        likely = False

    limitations = [
        "Eine öffentliche IPv4-Adresse kann wegen CGNAT oder DS-Lite beim Provider enden.",
        "Ein offener Port kann auf ein anderes internes Gerät weitergeleitet sein.",
        "Bei IPv6 kann die untersuchte Adresse zu einem internen Gerät statt zur FRITZ!Box gehören.",
        "Wenn kein WAN-Dienst erreichbar ist, lässt sich die Firmware von außen normalerweise nicht feststellen.",
        "Passive Suchmaschinen-Daten können veraltet sein; ihr Abfragezeitpunkt ist kein Scanzeitpunkt.",
    ]
    if confidence == "high":
        summary = "FRITZ!Box sehr wahrscheinlich: plausibles öffentlich abrufbares BoxInfo-Dokument erkannt."
    elif confidence == "medium":
        summary = "FRITZ!Box wahrscheinlich: mehrere unabhängige Indizien, aber kein direkter BoxInfo-Nachweis."
    elif confidence == "low":
        summary = "Ein einzelnes FRITZ!/AVM-Indiz wurde gefunden; das reicht nicht für eine verlässliche Zuordnung."
    else:
        summary = "Kein belastbarer öffentlicher Hinweis auf eine FRITZ!Box gefunden."

    return {
        "target": {
            "input": target,
            "resolvedAddress": str(address),
            "addressFamily": f"IPv{address.version}",
            "publiclyRoutable": public_address(str(address)),
        },
        "authorization": {
            "activeChecksConfirmed": bool(active_confirmed),
            "activeChecksPerformed": bool(active_confirmed and direct and not active_blocked),
        },
        "classification": {
            "likelyFritzBox": likely,
            "confidence": confidence,
            "reasons": [item["evidence"] for item in observations],
        },
        "summary": summary,
        "device": device,
        "services": services,
        "tls": tls,
        "observations": observations,
        "limitations": limitations,
        "warnings": list(dict.fromkeys(warnings)),
    }


async def fingerprint(client, target, address, sources, active=False, ports=None, timeout=DEFAULT_TIMEOUT,
                      active_blocked=None):
    direct = None
    error = None
    if active and not active_blocked:
        try:
            direct = await tools.fritzbox(client, address, sni=target if target != address else None,
                                          ports=ports or DEFAULT_PORTS, timeout=timeout)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
    return build(target, address, sources, active_confirmed=active, direct=direct,
                 active_error=error, active_blocked=active_blocked)
