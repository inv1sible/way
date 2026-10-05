"""Client für den tools-Container (whois, dig, openssl, curl).

Stufe 0 (whois, asn, dns): fragt nur Registries und DNS, das Ziel selbst wird nicht kontaktiert.
Stufe 1 (tls, web): ein normaler Zugriff auf das Ziel; er erscheint in dessen Log.
"""

from django.conf import settings

from . import run_source


async def call(client, tool, timeout=45, **params):
    if not settings.OSINT_TOOLS_TOKEN:
        raise RuntimeError("TOOLS_TOKEN ist nicht gesetzt")
    response = await client.post(
        f"{settings.OSINT_TOOLS_URL}/run",
        json={"tool": tool, **params},
        headers={"Authorization": f"Bearer {settings.OSINT_TOOLS_TOKEN}"},
        timeout=timeout,
    )
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f"tools-Container: unerwartete Antwort (HTTP {response.status_code})") from None
    if response.status_code != 200 or not body.get("ok"):
        raise RuntimeError(body.get("error") or f"tools-Container: HTTP {response.status_code}")
    return body["data"]


async def whois(client, target):
    return await call(client, "whois", target=target)


async def asn(client, ip):
    return await call(client, "asn", ip=ip)


async def dns(client, host):
    return await call(client, "dns", target=host)


async def tls(client, ip, sni=None, port=443):
    return await call(client, "tls", ip=ip, port=port, **({"sni": sni} if sni else {}))


async def web(client, ip, sni=None, port=443):
    return await call(client, "web", ip=ip, port=port, **({"sni": sni} if sni else {}))


async def scan(client, ip):
    return await call(client, "scan", timeout=300, ip=ip)


def passive_ip_jobs(client, ip):
    return [
        ("WHOIS (lokal)", whois, client, ip),
        ("ASN und Netzbetreiber (dig, Team Cymru)", asn, client, ip),
    ]


def active_ip_jobs(client, ip, sni=None):
    """Direkter Kontakt zum Ziel (Stufe 1)."""
    return [
        ("TLS-Zertifikat (openssl, Port 443)", tls, client, ip, sni),
        ("Web-Kopfzeilen (curl, Port 443)", web, client, ip, sni, 443),
        ("Web-Kopfzeilen (curl, Port 80)", web, client, ip, sni, 80),
    ]


def scan_job(client, ip):
    """Portscan (Stufe 2); nur für Ziele aus der Liste der eigenen Systeme."""
    return ("Portscan (nmap, Top-1000-Ports)", scan, client, ip)


async def run_jobs(jobs):
    import asyncio

    return list(await asyncio.gather(*(run_source(name, fn, *args) for name, fn, *args in jobs)))
