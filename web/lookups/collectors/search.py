"""Websuche über die selbst gehostete SearXNG-Instanz."""

import hashlib

from django.conf import settings
from django.core.cache import cache

CACHE_SECONDS = 24 * 3600


async def searx(client, query, limit=10, pageno=1, meta=None):
    """Sucht über SearXNG. Ergebnisse werden 24 h zwischengespeichert, damit Wiederholungen die
    Suchmaschinen nicht erneut belasten (sie sperren sonst schneller).

    meta (optional) sammelt, welche Suchmaschinen Ergebnisse geliefert haben und welche gestört waren.
    """
    key = "searx:" + hashlib.sha256(f"{pageno}|{query}".encode()).hexdigest()
    data = await cache.aget(key)
    if data is None:
        response = await client.get(
            f"{settings.OSINT_SEARXNG_URL}/search",
            params={"q": query, "format": "json", "language": "de", "pageno": pageno},
            timeout=30,
        )
        response.raise_for_status()
        raw = response.json()
        data = {
            "results": raw.get("results", []),
            "unresponsive": {name: reason for name, reason in raw.get("unresponsive_engines", [])},
        }
        if data["results"]:  # leere Antworten (z. B. alle Engines gesperrt) nicht festschreiben
            await cache.aset(key, data, CACHE_SECONDS)
    if meta is not None:
        meta.setdefault("ok", set()).update(e for hit in data["results"] for e in hit.get("engines", []))
        meta.setdefault("gestoert", {}).update(data["unresponsive"])
    return [
        {"titel": hit.get("title"), "url": hit.get("url"), "auszug": (hit.get("content") or "")[:400]}
        for hit in data["results"][:limit]
    ]
