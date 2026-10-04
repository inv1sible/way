"""IP-Adressen: Zuordnung und Reputation aus freien Quellen."""

import asyncio
import ipaddress
import socket
import time

from django.conf import settings

from . import run_source

CGNAT = ipaddress.ip_network("100.64.0.0/10")

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


async def collect(client, ip):
    info = classify(ip)
    results = [{"source": "Adressklassifizierung", "ok": True, "data": info}]
    if not info["oeffentlich"]:
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

    results += await asyncio.gather(*(run_source(name, fn, *args) for name, fn, *args in jobs))
    return results
