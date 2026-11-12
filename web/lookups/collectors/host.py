"""Hostnamen: DNS-Auflösung, danach Analyse der IP-Adresse."""

import asyncio
import socket

from . import fritzbox, history, ip, run_source, threatintel, tools

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


SCAN_SOURCE = "Portscan (nmap, Top-1000-Ports)"


async def collect(client, host, active=False, active_ports=None, active_timeout=8, active_profile="fritzbox",
                  scan=False, as_of=None):
    domain_jobs = [(f"{name} (Hostname)", fn, *args) for name, fn, *args in threatintel.jobs(client, host, "domain")]
    domain_jobs += [("DNS-Einträge (dig)", tools.dns, client, host), ("WHOIS Domain (lokal)", tools.whois, client, host)]
    if as_of:
        domain_jobs.append(("Passive DNS (OTX, Adressen des Namens)", history.otx_passive_dns, client, host, "host", as_of))
    dns, domain_results = await asyncio.gather(
        run_source("DNS-Auflösung", resolve, host),
        asyncio.gather(*(run_source(*job) for job in domain_jobs)),
    )
    results = [dns, *domain_results]
    if as_of:
        # Auf welche Adresse zeigte der Name zum Stichtag? Für diese die BGP-Historie nachschlagen.
        passive = next((r for r in domain_results if r["source"].startswith("Passive DNS") and r["ok"]), None)
        then = history.address_at(passive["data"]) if passive else None
        if then:
            results.append(await run_source("RIPEstat Routing-Historie (Adresse zum Stichtag)",
                                            history.ripestat_routing, client, then, as_of))
    if dns["ok"] and dns["data"]["adressen"]:
        addresses = dns["data"]["adressen"]
        target = addresses[0]
        dns["data"]["analysierte_adresse"] = target
        active_blocked = fritzbox.validate_resolved_addresses(addresses) if active else None
        results += await ip.collect(
            client, target, active=active, sni=host, active_ports=active_ports, active_timeout=active_timeout,
            active_profile=active_profile, active_blocked=active_blocked, scan=scan,
        )
    return results
