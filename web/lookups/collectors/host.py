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
BINDING_SOURCE = "Dynamische Zielbindung (DNS/ASN)"


async def verify_host_binding(client, host, addresses, allowed):
    """Prüft die indirekte Eigentumsbindung eines dynamischen Hostnamens fail-closed.

    Ein Name beweist nicht, wem die Adresse gehört, auf die er zeigt (CDN, Cloud, geänderter
    DNS-Eintrag): Alle Adressen müssen aktuell in den beim Asset erlaubten Origin-ASNs liegen.
    Die Daten dokumentieren eine zeitgebundene Namensbindung, niemals eine dauerhafte IP-Identität.
    """
    if not allowed:
        raise RuntimeError("Für diesen Hostnamen ist kein Netz (Origin-ASN) hinterlegt.")
    resolved = []
    for address in addresses:
        try:
            found = set((await tools.asn(client, address)).get("asn", []))
        except Exception as exc:
            raise RuntimeError(f"Origin-ASN-Prüfung für {address} fehlgeschlagen ({exc}).") from None
        if not found & allowed:
            raise RuntimeError(
                f"{address} liegt in {', '.join(sorted(found)) or 'einem unbekannten Netz'}, erlaubt sind "
                f"{', '.join(sorted(allowed))}: Der Name zeigt auf ein fremdes Netz."
            )
        resolved.append({"address": address, "originAsns": sorted(found)})
    return {
        "hostname": host,
        "method": "exakter eingetragener Hostname + aktuelle DNS-Auflösung + Origin-ASN-Abgleich",
        "resolvedAddresses": resolved,
        "allowedOriginAsns": sorted(allowed),
        "bindingIsIndirect": True,
        "warning": "Der Hostname folgt der dynamischen IP. Das belegt keine unveränderliche Geräteidentität.",
    }


async def scan_scope_problem(client, addresses, allowed):
    """Warum der Portscan für diesen Hostnamen nicht erlaubt ist (None = erlaubt)."""
    try:
        await verify_host_binding(client, "(Hostname)", addresses, allowed)
    except RuntimeError as exc:
        return f"{exc} Der Scan wurde nicht ausgeführt."
    return None


async def collect(client, host, active=False, active_ports=None, active_timeout=8, active_profile="fritzbox",
                  scan=False, scan_asns=None, active_asns=None, as_of=None):
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
        refusal = await scan_scope_problem(client, addresses, scan_asns) if scan else None
        active_blocked = fritzbox.validate_resolved_addresses(addresses) if active else None
        if active:
            if active_blocked:
                binding = {"source": BINDING_SOURCE, "ok": False, "error": active_blocked}
            else:
                binding = await run_source(BINDING_SOURCE, verify_host_binding, client, host, addresses, active_asns)
                if not binding["ok"]:
                    active_blocked = (
                        "Dynamische Zielbindung über Hostname und Origin-ASN konnte nicht bestätigt werden; "
                        "aktive Prüfung wurde gesperrt."
                    )
            results.append(binding)
        results += await ip.collect(
            client, target, active=active, sni=host, active_ports=active_ports, active_timeout=active_timeout,
            active_profile=active_profile,
            active_blocked=active_blocked, scan=scan and not refusal,
        )
        if refusal:
            results.append({"source": SCAN_SOURCE, "ok": False, "error": refusal})
    return results
