"""Privacy-preserving email exposure checks for an explicitly authorised address.

This deliberately does not enumerate accounts, search social networks, or retrieve breach pastes.
An exposure record says that an address appeared in a disclosed incident; it is not proof of a
person's identity, ownership of an account, or current compromise.
"""

from urllib.parse import quote
from urllib.parse import urlsplit

from django.conf import settings
from django.core.cache import cache

from . import run_source, search

SOURCE = "Have I Been Pwned (breach exposure)"
CACHE_SECONDS = 24 * 3600
MAX_BREACHES = 30
PUBLIC_WEB_SOURCE = "Öffentliche Web-Referenzen (SearXNG)"
MAX_PUBLIC_REFERENCES = 10
# No social/messenger/account-discovery pages, people directories, or paste/leak hosts. This is a
# defensive allow-by-exclusion layer; the collector never opens result URLs in the first place.
EXCLUDED_PUBLIC_WEB_HOSTS = (
    "facebook.com", "instagram.com", "tiktok.com", "x.com", "twitter.com", "telegram.org",
    "whatsapp.com", "signal.org", "pastebin.com", "ghostbin.com", "github.com", "haveibeenpwned.com",
)


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
            result["hinweis"] = f"Aus Datenschutz- und Anzeigegründen auf {MAX_BREACHES} Einträge begrenzt."
    await cache.aset(f"hibp:email:{address}", result, CACHE_SECONDS)
    return result


def _public_reference(hit, address):
    """Keep only an exact, public search-index reference; never retrieve the result page."""
    url = str(hit.get("url") or "")
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        return None
    if any(host == excluded or host.endswith("." + excluded) for excluded in EXCLUDED_PUBLIC_WEB_HOSTS):
        return None
    title, snippet = str(hit.get("titel") or ""), str(hit.get("auszug") or "")
    if address.casefold() not in f"{url}\n{title}\n{snippet}".casefold():
        return None
    return {"url": url, "titel": title[:200] or None, "fundstelle": snippet[:400] or None}


async def public_web_search(client, address):
    """At most two exact-address SearXNG queries. Result pages are never fetched or crawled."""
    meta = {}
    hits = await search.searx(client, f'"{address}"', limit=MAX_PUBLIC_REFERENCES, meta=meta)
    references = [reference for hit in hits if (reference := _public_reference(hit, address))]
    if not references:
        # Some engines ignore quoting or only index an address in a URL. The exact-address filter above
        # still applies, so this broader fallback cannot turn a mere name match into a result.
        hits = await search.searx(client, address, limit=MAX_PUBLIC_REFERENCES, meta=meta)
        references = [reference for hit in hits if (reference := _public_reference(hit, address))]
    return {
        "references": references,
        "suchmaschinen_mit_ergebnissen": sorted(meta.get("ok", ())),
        "gestoerte_suchmaschinen": meta.get("gestoert", {}),
        "grenzen": [
            "Höchstens zwei Suchanfragen nach der exakten Adresse; Ergebnis-Webseiten werden nicht automatisiert geöffnet oder gecrawlt.",
            "Messenger-, Personenverzeichnis- sowie Paste-/Leak-Domains werden ausgeschlossen; öffentliche berufliche Profil-Snippets können erscheinen.",
            "Eine öffentliche Referenz belegt weder die Identität einer Person noch die Inhaberschaft eines Kontos.",
        ],
    }


async def collect(client, address, active=False, scan=False, as_of=None, public_web=False):
    del active, scan, as_of
    results = [{
        "source": "E-Mail-Prüfgrenze", "ok": True,
        "data": {"authorizedOnly": True, "warning": "Nur eigene oder ausdrücklich freigegebene E-Mail-Adressen. "
                 "Keine Konto-, Personen- oder Messenger-Suche; Datenpannen belegen keine Identität."},
    }]
    if settings.OSINT_HIBP_KEY:
        results.append(await run_source(SOURCE, hibp, client, address))
    else:
        results.append({"source": SOURCE, "ok": False,
                        "error": "Nicht konfiguriert: HIBP_API_KEY fehlt (optionale Quelle)."})
    if public_web:
        results.append(await run_source(PUBLIC_WEB_SOURCE, public_web_search, client, address))
    return results
