"""Optional Shodan Host API enrichment, distinct from the keyless InternetDB summary."""

from datetime import datetime, timezone

from django.conf import settings
from django.core.cache import cache

BASE_URL = "https://api.shodan.io/shodan/host"
CACHE_SECONDS = 24 * 3600
MAX_SERVICES = 25


def summarize(payload):
    services = []
    for item in (payload.get("data") or [])[:MAX_SERVICES]:
        if not isinstance(item, dict):
            continue
        services.append({key: value for key, value in {
            "port": item.get("port"), "transport": item.get("transport"),
            "product": item.get("product"), "version": item.get("version"),
            "timestamp": item.get("timestamp"), "banner": (item.get("data") or "")[:160] or None,
        }.items() if value not in (None, "")})
    return {key: value for key, value in {
        "ip": payload.get("ip_str"), "hostnames": (payload.get("hostnames") or [])[:20],
        "domains": (payload.get("domains") or [])[:20], "ports": (payload.get("ports") or [])[:50],
        "tags": (payload.get("tags") or [])[:20], "letzte_aktualisierung": payload.get("last_update"),
        "asn": payload.get("asn"), "isp": payload.get("isp"), "organisation": payload.get("org"),
        "dienste": services,
    }.items() if value not in (None, "", [])} or {"hinweis": "Antwort ohne verwertbare Felder"}


async def host(client, ip):
    cached = await cache.aget(f"shodan:host:{ip}")
    if cached is not None:
        return {**cached, "aus_zwischenspeicher": True}
    month_key = f"shodan:calls:{datetime.now(timezone.utc):%Y-%m}"
    await cache.aadd(month_key, 0, 40 * 24 * 3600)
    limit = settings.OSINT_SHODAN_MONTHLY_LIMIT
    if (await cache.aget(month_key) or 0) >= limit:
        raise RuntimeError(f"Monatliche Obergrenze von {limit} Abfragen erreicht")
    await cache.aincr(month_key)
    response = await client.get(f"{BASE_URL}/{ip}", params={"key": settings.OSINT_SHODAN_KEY})
    if response.status_code in (401, 403):
        detail = ""
        try:
            detail = response.json().get("error", "")
        except Exception:
            pass
        msg = f"Shodan lehnt den Zugang ab: {detail}" if detail else "Shodan lehnt den Zugang ab: API-Schlüssel ungültig oder nicht berechtigt"
        raise RuntimeError(msg)
    if response.status_code == 429:
        raise RuntimeError("Shodan Rate-Limit oder Kontingent erreicht")
    if response.status_code == 404:
        result = {"hinweis": "Shodan hat zu dieser Adresse keine Host-API-Daten"}
    else:
        response.raise_for_status()
        result = summarize(response.json())
    await cache.aset(f"shodan:host:{ip}", result, CACHE_SECONDS)
    return result
