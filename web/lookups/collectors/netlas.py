"""Bounded Netlas public-host summary.  Netlas is a third-party passive observation source."""

from datetime import datetime, timezone

from django.conf import settings
from django.core.cache import cache

BASE_URL = "https://app.netlas.io/api/host"
CACHE_SECONDS = 24 * 3600
MAX_PORTS = 30


def summarize(payload):
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return {"hinweis": "Antwort in unbekanntem Format"}
    ports = data.get("ports") or data.get("open_ports") or []
    if not isinstance(ports, list):
        ports = []
    geo = data.get("geo") if isinstance(data.get("geo"), dict) else {}
    privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
    result = {
        "ip": data.get("ip"), "reverse_dns": (data.get("ptr") or [])[:10],
        "ports": ports[:MAX_PORTS],
        "land": geo.get("country"), "stadt": geo.get("city"),
        "privacy": {key: privacy[key] for key in ("vpn", "proxy", "tor") if key in privacy},
    }
    return {key: value for key, value in result.items() if value not in (None, "", [], {})} or {
        "hinweis": "Antwort ohne verwertbare, freigegebene Felder", "felder_der_antwort": sorted(data)[:25]
    }


async def host(client, target):
    cached = await cache.aget(f"netlas:host:{target}")
    if cached is not None:
        return {**cached, "aus_zwischenspeicher": True}
    month_key = f"netlas:calls:{datetime.now(timezone.utc):%Y-%m}"
    await cache.aadd(month_key, 0, 40 * 24 * 3600)
    limit = settings.OSINT_NETLAS_MONTHLY_LIMIT
    if (await cache.aget(month_key) or 0) >= limit:
        raise RuntimeError(f"Monatliche Obergrenze von {limit} Abfragen erreicht")
    await cache.aincr(month_key)
    response = await client.get(
        f"{BASE_URL}/{target}/", headers={"Authorization": f"Bearer {settings.OSINT_NETLAS_KEY}"},
        params={"public_indices_only": "true", "fields": "ip,ptr,geo,privacy,ports"},
    )
    if response.status_code in (402, 429):
        raise RuntimeError("Netlas-Kontingent oder Rate-Limit erreicht")
    if response.status_code in (401, 403):
        raise RuntimeError("Netlas lehnt den Zugang ab: API-Schlüssel ungültig oder nicht berechtigt")
    if response.status_code in (404, 500):
        result = {"hinweis": "Netlas hat zu diesem Ziel keine Daten"}
    else:
        response.raise_for_status()
        result = summarize(response.json())
    await cache.aset(f"netlas:host:{target}", result, CACHE_SECONDS)
    return result
