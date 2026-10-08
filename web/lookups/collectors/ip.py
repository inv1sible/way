"""IP-Adressen: Zuordnung und Reputation aus freien Quellen."""

import asyncio
import ipaddress
import socket
import time

from django.conf import settings

from . import censys, fritzbox, history, router, run_source, speedport, threatintel, tools

CGNAT = ipaddress.ip_network("100.64.0.0/10")
IP_BINDING_SOURCE = "IP-Zielbindung (ASN)"
IP_DNS_BINDING_SOURCE = "IP-Zielbindung (DNS)"

ZEN_CODES = {
    "127.0.0.2": "SBL: bekannte Spam-Quelle",
    "127.0.0.3": "SBL CSS: Snowshoe-Spam",
    "127.0.0.4": "XBL: kompromittiertes System / Exploit",
    "127.0.0.5": "XBL: kompromittiertes System / Exploit",
    "127.0.0.6": "XBL: kompromittiertes System / Exploit",
    "127.0.0.7": "XBL: kompromittiertes System / Exploit",
    "127.0.0.9": "DROP: gekapertes oder kriminelles Netz",
    "127.0.0.10": "PBL: Endkunden-Adressbereich laut Provider (kein Missbrauchsnachweis)",
    "127.0.0.11": "PBL: Endkunden-Adressbereich laut Spamhaus (kein Missbrauchsnachweis)",
}

_tor_cache = {"at": None, "ips": frozenset()}


def classify(ip):
    addr = ipaddress.ip_address(ip)
    if getattr(addr, "scope_id", None):
        raise ValueError("IPv6-Adressen mit Zonen-Angabe werden nicht unterstützt.")
    info = {
        "version": addr.version,
        "oeffentlich": addr.is_global,
        "privat": addr.is_private,
        "loopback": addr.is_loopback,
        "multicast": addr.is_multicast,
    }
    if addr.version == 4 and addr in CGNAT:
        info["hinweis"] = "Carrier-Grade-NAT-Bereich: Adresse aus dem internen Netz eines Providers."
    elif not addr.is_global:
        info["hinweis"] = "Keine öffentliche Adresse, nur im lokalen bzw. privaten Netz gültig."
    return info


async def reverse_dns(ip):
    try:
        name, aliases, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
    except (socket.herror, socket.gaierror):
        return {"ptr": None}
    return {"ptr": name, "aliase": aliases}


def verify_ip_binding(ip, expected_asns, sources):
    """Fail-closed-Schranke für IP-Assets mit explizit gespeichertem ASN.

    Das ist kein Besitzbeweis (ein ASN enthält viele Kunden), verhindert aber aktive Anfragen,
    wenn eine vormals eigene dynamische IP inzwischen in ein unerwartetes Netz umgezogen ist.
    Die ASN-Quelle wurde in demselben Lauf passiv abgefragt, bevor ein Direktzugriff startet.
    """
    if not expected_asns:
        return None
    asn_source = next((item for item in sources if item.get("source", "").startswith("ASN und Netzbetreiber")), None)
    if not asn_source or not asn_source.get("ok"):
        raise RuntimeError("Aktuelles ASN konnte nicht ermittelt werden.")
    found = {str(value) for value in (asn_source.get("data") or {}).get("asn", []) if value}
    if not found & set(expected_asns):
        raise RuntimeError(
            f"{ip} liegt in {', '.join(sorted(found)) or 'einem unbekannten Netz'}, erwartet sind "
            f"{', '.join(sorted(expected_asns))}."
        )
    return {
        "address": ip,
        "originAsns": sorted(found),
        "expectedOriginAsns": sorted(expected_asns),
        "warning": "Die ASN-Prüfung ist eine Sicherheitsgrenze, kein Eigentumsnachweis.",
    }


async def verify_ip_dns_binding(ip, dns_name):
    """Prüft eine vom Admin bestätigte IP↔DNS-Beziehung vor aktivem Kontakt."""
    infos = await asyncio.to_thread(socket.getaddrinfo, dns_name, None, proto=socket.IPPROTO_TCP)
    addresses = sorted({item[4][0] for item in infos})
    invalid = fritzbox.validate_resolved_addresses(addresses)
    if invalid:
        raise RuntimeError(invalid)
    if ip not in addresses:
        raise RuntimeError(f"{dns_name} löst aktuell nicht auf {ip} auf.")
    return {
        "address": ip,
        "hostname": dns_name,
        "resolvedAddresses": addresses,
        "warning": "Die DNS-Bindung ist zeitgebunden und kein Eigentumsnachweis.",
    }


def _contacts(entities):
    out = []
    for entity in entities:
        name = email = None
        vcard = entity.get("vcardArray") or []
        for prop in vcard[1] if len(vcard) > 1 else []:
            if prop[0] == "fn":
                name = prop[3]
            elif prop[0] == "email" and not email:
                email = prop[3]
        out.append({"rollen": entity.get("roles", []), "name": name, "email": email, "handle": entity.get("handle")})
        out.extend(_contacts(entity.get("entities", [])))
    return out


async def rdap(client, ip):
    response = await client.get(f"https://rdap.org/ip/{ip}", follow_redirects=True)
    response.raise_for_status()
    data = response.json()
    remarks = " ".join(line for r in data.get("remarks", []) for line in r.get("description", []))
    return {
        "netzname": data.get("name"),
        "handle": data.get("handle"),
        "bereich": f"{data.get('startAddress')} – {data.get('endAddress')}",
        "land": data.get("country"),
        "typ": data.get("type"),
        "beschreibung": remarks[:500] or None,
        "kontakte": _contacts(data.get("entities", []))[:10],
        "quelle": str(response.url),
    }


async def ip_api(client, ip):
    response = await client.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,regionName,city,isp,org,as,asname,mobile,proxy,hosting", "lang": "de"},
    )
    response.raise_for_status()
    data = response.json()
    if data.pop("status", None) != "success":
        raise RuntimeError(data.get("message", "unbekannter Fehler"))
    return data


async def internetdb(client, ip):
    response = await client.get(f"https://internetdb.shodan.io/{ip}")
    if response.status_code == 404:
        return {"hinweis": "Keine Daten: Shodan hat hier keine offenen Dienste gesehen."}
    response.raise_for_status()
    return response.json()


async def greynoise(client, ip):
    headers = {"key": settings.OSINT_GREYNOISE_KEY} if settings.OSINT_GREYNOISE_KEY else {}
    response = await client.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    if response.status_code == 429:
        raise RuntimeError("Rate-Limit erreicht; ggf. kostenlosen GREYNOISE_KEY hinterlegen.")
    if response.status_code not in (200, 404):
        response.raise_for_status()
    return response.json()


async def abuseipdb(client, ip):
    response = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.OSINT_ABUSEIPDB_KEY, "Accept": "application/json"},
    )
    response.raise_for_status()
    data = response.json()["data"]
    keep = (
        "abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt",
        "usageType", "isp", "domain", "isTor", "isWhitelisted", "countryCode",
    )
    return {key: data.get(key) for key in keep}


async def tor_exit(client, ip):
    if _tor_cache["at"] is None or time.monotonic() - _tor_cache["at"] > 3600:
        response = await client.get("https://check.torproject.org/torbulkexitlist")
        response.raise_for_status()
        _tor_cache["ips"] = frozenset(response.text.split())
        _tor_cache["at"] = time.monotonic()
    return {"tor_exit_node": ip in _tor_cache["ips"]}


async def spamhaus(ip):
    query = ".".join(reversed(ip.split("."))) + ".zen.spamhaus.org"
    try:
        _, _, addrs = await asyncio.to_thread(socket.gethostbyname_ex, query)
    except socket.gaierror:
        return {"gelistet": False}
    if any(a.startswith("127.255.255.") for a in addrs):
        raise RuntimeError("Spamhaus beantwortet keine Anfragen über öffentliche DNS-Resolver.")
    return {"gelistet": True, "listen": [ZEN_CODES.get(a, a) for a in addrs]}


async def collect(client, ip, active=False, sni=None, active_ports=None, active_timeout=8, active_profile="fritzbox",
                  active_blocked=None, scan=False, active_asns=None, active_dns_name=None, as_of=None):
    info = classify(ip)
    results = [{"source": "Adressklassifizierung", "ok": True, "data": info}]
    if not info["oeffentlich"]:
        fingerprint = await fritzbox.fingerprint(
            client, sni or ip, ip, results, active=active and active_profile == "fritzbox", ports=active_ports, timeout=active_timeout,
            active_blocked=active_blocked or "Das Ziel ist nicht öffentlich routbar; aktive Prüfung wurde gesperrt.",
        )
        results.append(await run_source(fritzbox.SOURCE, lambda: fingerprint))
        if active and active_profile == "generic-router":
            results.append(await run_source(router.SOURCE, lambda: router.fingerprint(
                client, sni or ip, ip, ports=active_ports, timeout=active_timeout,
                active_blocked=active_blocked or "Das Ziel ist nicht öffentlich routbar; aktive Prüfung wurde gesperrt.",
            )))
        if active and active_profile == "speedport":
            results.append(await run_source(speedport.SOURCE, lambda: speedport.fingerprint(
                client, sni or ip, ip, ports=active_ports, timeout=active_timeout,
                active_blocked=active_blocked or "Das Ziel ist nicht öffentlich routbar; aktive Prüfung wurde gesperrt.",
            )))
        return results

    jobs = [
        ("Reverse DNS", reverse_dns, ip),
        ("RDAP (Regional Internet Registry)", rdap, client, ip),
        ("ip-api.com (Geo/ASN)", ip_api, client, ip),
        ("Shodan InternetDB", internetdb, client, ip),
        ("GreyNoise Community", greynoise, client, ip),
        ("Tor-Exit-Liste", tor_exit, client, ip),
    ]
    if info["version"] == 4:
        jobs.append(("Spamhaus ZEN", spamhaus, ip))
    if settings.OSINT_ABUSEIPDB_KEY:
        jobs.append(("AbuseIPDB", abuseipdb, client, ip))
    jobs += threatintel.jobs(client, ip, "ip")
    if settings.OSINT_CENSYS_TOKEN:
        jobs.append(("Censys (Internet-Scan-Daten)", censys.host, client, ip))
    jobs += tools.passive_ip_jobs(client, ip)
    if scan:
        jobs.append(tools.scan_job(client, ip))
    if as_of:
        jobs += history.ip_jobs(client, ip, as_of)

    results += await asyncio.gather(*(run_source(name, fn, *args) for name, fn, *args in jobs))
    if active and active_asns:
        binding = await run_source(IP_BINDING_SOURCE, verify_ip_binding, ip, active_asns, results)
        results.append(binding)
        if not binding["ok"]:
            active_blocked = (
                "Die aktuelle IP-/ASN-Bindung konnte nicht bestätigt werden; aktive Prüfung wurde gesperrt."
            )
    if active and active_dns_name:
        binding = await run_source(IP_DNS_BINDING_SOURCE, verify_ip_dns_binding, ip, active_dns_name)
        results.append(binding)
        if not binding["ok"]:
            active_blocked = (
                "Die aktuelle IP-/DNS-Bindung konnte nicht bestätigt werden; aktive Prüfung wurde gesperrt."
            )
    fingerprint = await fritzbox.fingerprint(
        client, sni or ip, ip, results, active=active and active_profile == "fritzbox", ports=active_ports, timeout=active_timeout,
        active_blocked=active_blocked,
    )
    result = await run_source(fritzbox.SOURCE, lambda: fingerprint)
    results.append(result)
    if active and active_profile == "generic-router":
        results.append(await run_source(router.SOURCE, lambda: router.fingerprint(
            client, sni or ip, ip, ports=active_ports, timeout=active_timeout, active_blocked=active_blocked,
        )))
    if active and active_profile == "speedport":
        results.append(await run_source(speedport.SOURCE, lambda: speedport.fingerprint(
            client, sni or ip, ip, ports=active_ports, timeout=active_timeout, active_blocked=active_blocked,
        )))
    return results
