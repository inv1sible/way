"""Hostnamen: DNS-Auflösung, danach Analyse der IP-Adresse."""

import asyncio
import socket

from . import ip, run_source, threatintel, tools

DYNDNS = {
    "myfritz.net": "AVM MyFRITZ!, zeigt auf den Internetanschluss einer FRITZ!Box (meist privat)",
    "dyndns.org": "Dyn DynDNS",
    "duckdns.org": "Duck DNS, kostenloser DynDNS-Dienst",
    "ddns.net": "No-IP DynDNS",
    "no-ip.com": "No-IP DynDNS",
    "dynv6.net": "dynv6 DynDNS",
}


async def resolve(host):
    infos = await asyncio.to_thread(socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP)
    data = {"hostname": host, "adressen": sorted({info[4][0] for info in infos}, key=lambda a: (":" in a, a))}
    suffix = next((s for s in DYNDNS if host == s or host.endswith("." + s)), None)
    if suffix:
        data["hinweis"] = (
            f"Dynamischer DNS-Dienst: {DYNDNS[suffix]}. Die IP wechselt; der Netzinhaber ist der "
            "Internetprovider des Anschlusses, nicht der Betreiber."
        )
    return data


async def collect(client, host, active=False, scan=False):
    domain_jobs = [(f"{name} (Hostname)", fn, *args) for name, fn, *args in threatintel.jobs(client, host, "domain")]
    domain_jobs += [("DNS-Einträge (dig)", tools.dns, client, host), ("WHOIS Domain (lokal)", tools.whois, client, host)]
    dns, domain_results = await asyncio.gather(
        run_source("DNS-Auflösung", resolve, host),
        asyncio.gather(*(run_source(*job) for job in domain_jobs)),
    )
    results = [dns, *domain_results]
    if dns["ok"] and dns["data"]["adressen"]:
        target = dns["data"]["adressen"][0]
        dns["data"]["analysierte_adresse"] = target
        results += await ip.collect(client, target, active=active, sni=host, scan=scan)
    return results
