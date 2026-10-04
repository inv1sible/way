"""Reputationsdienste für IP-Adressen und Hostnamen.

AlienVault OTX funktioniert ohne Key; alle anderen Quellen laufen nur, wenn ihr kostenloser
API-Key gesetzt ist.
"""

from datetime import datetime, timezone

from django.conf import settings


def jobs(client, indicator, kind):
    """kind ist "ip" oder "domain"; liefert (Name, Funktion, *Argumente) für run_source."""
    out = [("AlienVault OTX", otx, client, indicator, kind)]
    if settings.OSINT_VIRUSTOTAL_KEY:
        out.append(("VirusTotal", virustotal, client, indicator, kind))
    if settings.OSINT_ABUSECH_KEY:
        out.append(("abuse.ch ThreatFox", threatfox, client, indicator))
        out.append(("abuse.ch URLhaus", urlhaus, client, indicator))
    if kind == "ip" and settings.OSINT_CROWDSEC_KEY:
        out.append(("CrowdSec CTI", crowdsec, client, indicator))
    return out


def _date(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).date().isoformat() if timestamp else None


async def virustotal(client, indicator, kind):
    path = "ip_addresses" if kind == "ip" else "domains"
    response = await client.get(
        f"https://www.virustotal.com/api/v3/{path}/{indicator}",
        headers={"x-apikey": settings.OSINT_VIRUSTOTAL_KEY},
    )
    if response.status_code == 404:
        return {"hinweis": "Bei VirusTotal unbekannt."}
    response.raise_for_status()
    attrs = response.json()["data"]["attributes"]
    keep = ("last_analysis_stats", "reputation", "total_votes", "as_owner", "asn", "country",
            "network", "tags", "categories", "registrar")
    data = {key: attrs[key] for key in keep if key in attrs}
    data["erstellt"] = _date(attrs.get("creation_date"))
    data["letzte_analyse"] = _date(attrs.get("last_analysis_date"))
    data["auffaellig_bei"] = [
        f"{engine}: {result.get('result')}"
        for engine, result in attrs.get("last_analysis_results", {}).items()
        if result.get("category") in ("malicious", "suspicious")
    ][:15]
    return data


async def otx(client, indicator, kind):
    section = "hostname" if kind == "domain" else ("IPv6" if ":" in indicator else "IPv4")
    headers = {"X-OTX-API-KEY": settings.OSINT_OTX_KEY} if settings.OSINT_OTX_KEY else {}
    response = await client.get(
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general", headers=headers
    )
    response.raise_for_status()
    data = response.json()
    pulses = data.get("pulse_info") or {}
    return {
        "pulse_anzahl": pulses.get("count", 0),
        "pulses": [
            {"name": p.get("name"), "erstellt": (p.get("created") or "")[:10], "tags": p.get("tags", [])[:8]}
            for p in pulses.get("pulses", [])[:8]
        ],
        "reputation": data.get("reputation"),
        "bekannt_gutartig": [v.get("name") for v in data.get("validation", [])],
    }


async def threatfox(client, indicator):
    response = await client.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "search_ioc", "search_term": indicator, "exact_match": True},
        headers={"Auth-Key": settings.OSINT_ABUSECH_KEY},
    )
    response.raise_for_status()
    data = response.json()
    if data.get("query_status") != "ok":
        return {"treffer": [], "status": data.get("query_status")}
    keep = ("ioc", "threat_type_desc", "malware_printable", "confidence_level", "first_seen", "last_seen", "tags")
    return {"treffer": [{key: ioc.get(key) for key in keep} for ioc in data["data"][:10]]}


async def urlhaus(client, indicator):
    response = await client.post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data={"host": indicator},
        headers={"Auth-Key": settings.OSINT_ABUSECH_KEY},
    )
    response.raise_for_status()
    data = response.json()
    if data.get("query_status") != "ok":
        return {"url_anzahl": 0, "status": data.get("query_status")}
    keep = ("url", "url_status", "threat", "date_added", "tags")
    return {
        "url_anzahl": data.get("url_count"),
        "erstmals_gesehen": data.get("firstseen"),
        "blocklisten": data.get("blacklists"),
        "urls": [{key: url.get(key) for key in keep} for url in data.get("urls", [])[:10]],
    }


async def crowdsec(client, ip):
    response = await client.get(
        f"https://cti.api.crowdsec.net/v2/smoke/{ip}", headers={"x-api-key": settings.OSINT_CROWDSEC_KEY}
    )
    if response.status_code == 404:
        return {"hinweis": "CrowdSec hat zu dieser IP keine Angriffe gemeldet bekommen."}
    response.raise_for_status()
    data = response.json()
    history = data.get("history") or {}
    return {
        "reputation": data.get("reputation"),
        "hintergrundrauschen": data.get("background_noise"),
        "verhalten": [b.get("label") for b in data.get("behaviors", [])],
        "klassifizierung": [c.get("label") for c in (data.get("classifications") or {}).get("classifications", [])],
        "angriffe": [a.get("label") for a in data.get("attack_details", [])][:10],
        "zuerst_gesehen": history.get("first_seen"),
        "zuletzt_gesehen": history.get("last_seen"),
        "bewertung": (data.get("scores") or {}).get("overall"),
    }
