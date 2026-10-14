"""Email breach metadata and public web searches for the complete email address."""

import hashlib
from urllib.parse import quote
from urllib.parse import urlencode, urlsplit

import httpx

from django.conf import settings
from django.core.cache import cache

from . import run_source, search

SOURCE = "Have I Been Pwned (breach exposure)"
CACHE_SECONDS = 24 * 3600
MAX_BREACHES = 30
PUBLIC_WEB_SOURCE = "Öffentliche Web-Referenzen (SearXNG)"
MAX_PUBLIC_REFERENCES = 10
MAX_REVIEW_RESULTS = 20
GOOGLE_CSE_URL = "https://customsearch.googleapis.com/customsearch/v1"


def _summary(item):
    return {
        key: item.get(key)
        for key in ("Name", "Title", "Domain", "BreachDate", "AddedDate", "PwnCount", "DataClasses",
                    "IsVerified", "IsSensitive", "IsRetired", "IsSpamList")
        if item.get(key) not in (None, "", [])
    }


async def hibp(client, address):
    """Return breach metadata only. 404 is a normal negative result; pastes are never queried."""
    cached = await cache.aget(f"hibp:email:{address}")
    if cached is not None:
        return {**cached, "aus_zwischenspeicher": True}
    response = await client.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(address, safe=""),
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": settings.OSINT_HIBP_KEY, "User-Agent": "who-are-you/0.1"},
    )
    if response.status_code == 404:
        result = {"breaches": [], "hinweis": "Keine bekannten Datenpannen für diese Adresse bei HIBP."}
    elif response.status_code in (401, 403):
        raise RuntimeError("HIBP lehnt den Zugang ab: API-Schlüssel ungültig oder nicht berechtigt")
    elif response.status_code == 429:
        raise RuntimeError("HIBP Rate-Limit erreicht; später erneut versuchen")
    else:
        response.raise_for_status()
        payload = response.json()
        result = {"breaches": [_summary(item) for item in payload[:MAX_BREACHES]], "anzahl": len(payload)}
        if len(payload) > MAX_BREACHES:
            result["hinweis"] = f"Auf {MAX_BREACHES} Einträge begrenzt."
    await cache.aset(f"hibp:email:{address}", result, CACHE_SECONDS)
    return result


def _public_reference(hit, address):
    """Keep only an exact, public search-index reference; never retrieve the result page."""
    url = str(hit.get("url") or "")
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        return None
    title, snippet = str(hit.get("titel") or ""), str(hit.get("auszug") or "")
    if address.casefold() not in f"{url}\n{title}\n{snippet}".casefold():
        return None
    return {"url": url, "titel": title[:200] or None, "fundstelle": snippet[:400] or None}


def _review_result(hit):
    """Retain returned search metadata, including the engines that supplied it."""
    url = str(hit.get("url") or "")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    title, snippet = str(hit.get("titel") or ""), str(hit.get("auszug") or "")
    result = {"url": url, "titel": title[:200] or None, "auszug": snippet[:400] or None}
    if hit.get("suchmaschinen"):
        result["suchmaschinen"] = hit["suchmaschinen"]
    return result


async def google_exact_search(client, address):
    """Google Programmable Search can require the full address as a phrase via exactTerms."""
    if not settings.OSINT_GOOGLE_CSE_API_KEY or not settings.OSINT_GOOGLE_CSE_ID:
        return {"status": "not_configured", "references": []}

    cache_key = "email-google-cse:v2:" + hashlib.sha256(address.casefold().encode()).hexdigest()
    cached = await cache.aget(cache_key)
    if cached is not None:
        return {**cached, "aus_zwischenspeicher": True}
    try:
        response = await client.get(
            GOOGLE_CSE_URL,
            params={
                "key": settings.OSINT_GOOGLE_CSE_API_KEY,
                "cx": settings.OSINT_GOOGLE_CSE_ID,
                "q": address,
                "exactTerms": address,
                "num": MAX_PUBLIC_REFERENCES,
                "hl": "de",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        # Avoid returning the request URL: it contains the API key as a query parameter.
        code = getattr(getattr(exc, "response", None), "status_code", None)
        return {"status": "error", "error": f"{type(exc).__name__}" + (f" (HTTP {code})" if code else ""),
                "references": []}

    references = []
    for item in payload.get("items", [])[:MAX_PUBLIC_REFERENCES]:
        reference = _review_result({"url": item.get("link"), "titel": item.get("title"),
                                    "auszug": item.get("snippet")})
        if not reference:
            continue
        references.append({**reference, "exact_phrase_required": True, "suchmaschinen": ["google cse api"]})
    result = {"status": "ok", "exact_terms": address, "references": references}
    await cache.aset(cache_key, result, CACHE_SECONDS)
    return result


async def public_web_search(client, address):
    """Quoted SearXNG search plus Google's exactTerms API when configured."""
    meta = {}
    query = f'"{address}"'
    try:
        hits = await search.searx(client, query, limit=MAX_PUBLIC_REFERENCES, meta=meta, language="all")
    except httpx.HTTPError as exc:
        hits = []
        meta["gestoert"] = {"searxng": type(exc).__name__}
    searx_references = [reference for hit in hits if (reference := _public_reference(hit, address))]
    exact_search = await google_exact_search(client, address)
    google_hits = exact_search.get("references", [])
    if google_hits:
        meta.setdefault("ok", set()).add("google cse api")
    if exact_search.get("status") == "error":
        meta.setdefault("gestoert", {})["google cse api"] = exact_search["error"]
    references = searx_references + [reference for hit in google_hits if (reference := _public_reference(hit, address))]
    review = [result for hit in hits + google_hits if (result := _review_result(hit))]
    unique_review = list({item["url"]: item for item in review}.values())[:MAX_REVIEW_RESULTS]
    return {
        "references": references,
        "exact_suche": {key: value for key, value in exact_search.items() if key != "references"},
        "suchergebnisse_zur_pruefung": unique_review,
        "suchanfrage": f'"{address}"',
        "searxng_anfrage": meta.get("request", {"q": query, "language": "all", "categories": "general"}),
        "searxng_empfangene_suchanfrage": meta.get("received_query"),
        "suchlinks": [
            {"titel": "Google (Verbatim)", "url": "https://www.google.com/search?" +
             urlencode({"q": query, "tbs": "li:1", "nfpr": "1", "udm": "14"})},
            {"titel": "Bing", "url": "https://www.bing.com/search?" + urlencode({"q": query})},
            {"titel": "DuckDuckGo", "url": "https://duckduckgo.com/?" + urlencode({"q": query})},
        ],
        "suchmaschinen": sorted(set(meta.get("ok", set())) | set(meta.get("gestoert", {}))),
        "suchmaschinen_mit_ergebnissen": sorted(meta.get("ok", ())),
        "gestoerte_suchmaschinen": meta.get("gestoert", {}),
    }


async def collect(client, address, active=False, scan=False, as_of=None, public_web=False):
    del active, scan, as_of
    results = []
    if settings.OSINT_HIBP_KEY:
        results.append(await run_source(SOURCE, hibp, client, address))
    else:
        results.append({"source": SOURCE, "ok": False,
                        "error": "Nicht konfiguriert: HIBP_API_KEY fehlt (optionale Quelle)."})
    if public_web:
        results.append(await run_source(PUBLIC_WEB_SOURCE, public_web_search, client, address))
    return results
