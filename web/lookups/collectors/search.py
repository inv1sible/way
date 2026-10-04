"""Websuche über die selbst gehostete SearXNG-Instanz."""

from django.conf import settings


async def searx(client, query, limit=10):
    response = await client.get(
        f"{settings.OSINT_SEARXNG_URL}/search",
        params={"q": query, "format": "json", "language": "de"},
    )
    response.raise_for_status()
    return [
        {"titel": hit.get("title"), "url": hit.get("url"), "auszug": (hit.get("content") or "")[:400]}
        for hit in response.json().get("results", [])[:limit]
    ]
