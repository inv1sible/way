"""Historische Quellen für einen Stichtag: BGP-Historie (RIPEstat) und Passive DNS (AlienVault OTX).

Passive DNS kennt nur, was irgendwo gemessen wurde; für kleine, dynamische Namen ist die Abdeckung
lückenhaft. Die BGP-Historie zeigt, welches Netz (AS) eine Adresse an einem Tag angekündigt hat; sie
sagt nichts darüber, wer die Adresse im Netz des Providers gerade nutzte (das weiß nur der Provider).
"""

from datetime import date, timedelta

import httpx
from django.conf import settings

RIPESTAT = "https://stat.ripe.net/data"
SOURCEAPP = "who-are-you"
MAX_LISTED = 25


def _day(text):
    return date.fromisoformat(str(text)[:10])


def ip_jobs(client, ip, day):
    return [
        ("RIPEstat Routing-Historie (Stichtag)", ripestat_routing, client, ip, day),
        ("Passive DNS (OTX, Namen auf dieser IP)", otx_passive_dns, client, ip, "ip", day),
    ]


# --- RIPEstat ----------------------------------------------------------------------------------

def summarize_routing(data, day):
    covering, others = [], []
    for origin in data.get("by_origin", []):
        for prefix in origin.get("prefixes", []):
            spans = [(_day(t["starttime"]), _day(t["endtime"])) for t in prefix.get("timelines", [])]
            if not spans:
                continue
            entry = {
                "as": f"AS{origin.get('origin')}",
                "praefix": prefix.get("prefix"),
                "gesehen_von": min(s[0] for s in spans).isoformat(),
                "gesehen_bis": max(s[1] for s in spans).isoformat(),
            }
            (covering if any(a <= day <= b for a, b in spans) else others).append(entry)
    covering.sort(key=lambda e: -int(str(e["praefix"]).split("/")[-1]))  # spezifischstes Präfix zuerst
    return {
        "stichtag": day.isoformat(),
        "angekuendigt_zum_stichtag": covering[:5],
        "andere_ursprungs_as_im_zeitraum": others[:5],
        "hinweis": None if covering else
        "Zum Stichtag wurde keine Ankündigung gefunden (Adresse damals nicht geroutet oder Datenlücke).",
    }


async def ripestat_routing(client, ip, day):
    response = await client.get(
        f"{RIPESTAT}/routing-history/data.json",
        params={
            "resource": ip, "sourceapp": SOURCEAPP,
            "starttime": (day - timedelta(days=370)).isoformat(),
            "endtime": min(day + timedelta(days=370), date.today()).isoformat(),
        },
        timeout=40,
    )
    response.raise_for_status()
    return summarize_routing(response.json()["data"], day)


# --- Passive DNS (OTX) -------------------------------------------------------------------------

def _distance(record, day):
    return min(abs((record["von"] - day).days), abs((record["bis"] - day).days))


def _out(record, **extra):
    return {"wert": record["wert"], "typ": record["typ"], "von": record["von"].isoformat(),
            "bis": record["bis"].isoformat(), **extra}


def summarize_passive(rows, day, kind):
    """kind "ip": Namen, die auf der Adresse lagen; kind "host": Adressen, auf die der Name zeigte."""
    records = []
    for row in rows:
        value = row.get("hostname") if kind == "ip" else row.get("address")
        try:
            first, last = _day(row["first"]), _day(row["last"])
        except (KeyError, ValueError):
            continue
        if value:
            records.append({"wert": value, "typ": row.get("record_type"), "von": first, "bis": last})

    covering, seen = [], set()
    for record in sorted((r for r in records if r["von"] <= day <= r["bis"]), key=lambda r: r["wert"]):
        if record["wert"] not in seen:
            seen.add(record["wert"])
            covering.append(record)
    result = {"stichtag": day.isoformat(), "eintraege_gesamt": len(records),
              "zum_stichtag": [_out(r) for r in covering[:MAX_LISTED]]}
    if len(covering) > MAX_LISTED:
        result["zum_stichtag_weitere"] = len(covering) - MAX_LISTED
    if not covering and records:
        nearest = sorted(records, key=lambda r: _distance(r, day))[:6]
        result["naechste_eintraege"] = [_out(r, abstand_tage=_distance(r, day)) for r in nearest]
    if not records:
        result["hinweis"] = "Passive DNS kennt dazu nichts (Abdeckung ist lückenhaft)."
    elif not covering:
        result["hinweis"] = "Zum Stichtag liegt kein Eintrag vor; angegeben sind die zeitlich nächsten."
    if kind == "host" and records:
        # Zeitleiste aller bekannten Adressen: zeigt Wechsel dynamischer Adressen
        spans = {}
        for record in records:
            span = spans.setdefault(record["wert"], [record["von"], record["bis"]])
            span[0], span[1] = min(span[0], record["von"]), max(span[1], record["bis"])
        timeline = sorted(spans.items(), key=lambda item: item[1][0])
        result["alle_adressen"] = [{"wert": v, "von": s[0].isoformat(), "bis": s[1].isoformat()} for v, s in timeline[:30]]
    return result


async def otx_passive_dns(client, indicator, kind, day):
    section = "hostname" if kind == "host" else ("IPv6" if ":" in indicator else "IPv4")
    # OTX beendet Antworten dieses Endpunkts bei Komprimierung oder Keep-Alive nicht sauber (ReadTimeout):
    # deshalb unkomprimiert und mit Connection: close.
    headers = {"Accept-Encoding": "identity", "Connection": "close"}
    if settings.OSINT_OTX_KEY:
        headers["X-OTX-API-KEY"] = settings.OSINT_OTX_KEY
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/passive_dns"
    # OTX hängt gelegentlich ohne erkennbaren Grund (und bei Hostnamen mit sehr vielen Einträgen: HTTP 504):
    # ein zweiter Versuch mit neuer Verbindung, danach aufgeben.
    try:
        response = await client.get(url, headers=headers, timeout=30)
    except httpx.TimeoutException:
        response = await client.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return summarize_passive(response.json().get("passive_dns", []), day, kind)


def address_at(passive, day=None):
    """Erste IP-Adresse (A/AAAA), auf die der Name zum Stichtag zeigte, aus dem Ergebnis von otx_passive_dns."""
    for record in (passive or {}).get("zum_stichtag", []):
        if record.get("typ") in ("A", "AAAA") and record.get("wert"):
            return record["wert"]
    return None
