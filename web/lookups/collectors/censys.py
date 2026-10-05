"""Censys Platform API (v3): Dienste, Banner und Zertifikatsnamen, die Censys im Internet gescannt hat.

Der Gratis-Tarif erlaubt nur Nachschläge (Host, Webseite, Zertifikat), 100 Credits im Monat und eine
Anfrage gleichzeitig; Historie, CVEs und Anreicherungen fehlen dort. Deshalb: Ergebnisse 24 h im
Zwischenspeicher, ein Monatszähler als Notbremse und ein Wiederholungsversuch bei Überlast (429).
"""

import asyncio
from datetime import datetime, timezone

from django.conf import settings
from django.core.cache import cache

BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"
ACCEPT = "application/vnd.censys.api.v3.host.v1+json"
CACHE_SECONDS = 24 * 3600
MAX_SERVICES = 25


def _get(data, *path):
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _names(items):
    """Namen aus Listen, deren Einträge Strings oder Objekte mit "name"/"product" sind."""
    out = []
    for item in items or []:
        value = item if isinstance(item, str) else (item.get("name") or item.get("product") if isinstance(item, dict) else None)
        if value and value not in out:
            out.append(str(value))
    return out


def summarize(payload):
    """Antwort auf die für Berichte relevanten Felder verdichten. Defensiv geschrieben: Fehlt ein Feld,
    wird es ausgelassen; erkennt nichts das Format, steht das im Ergebnis (statt eines leeren Berichts)."""
    resource = _get(payload, "result", "resource") or _get(payload, "resource") or payload
    if not isinstance(resource, dict):
        return {"hinweis": "Antwort in unbekanntem Format"}

    services = []
    for service in (resource.get("services") or [])[:MAX_SERVICES]:
        if not isinstance(service, dict):
            continue
        cert_names = _names(_get(service, "cert", "names") or _get(service, "cert", "parsed", "names"))
        services.append({key: value for key, value in {
            "port": service.get("port"),
            "protokoll": service.get("protocol") or service.get("extended_service_name") or service.get("service_name"),
            "transport": service.get("transport_protocol"),
            "software": _names(service.get("software")),
            "banner": (service.get("banner") or "")[:160] or None,
            "zertifikat_namen": cert_names[:10],
        }.items() if value not in (None, "", [])})

    summary = {key: value for key, value in {
        "ip": resource.get("ip"),
        "as_nummer": _get(resource, "autonomous_system", "asn"),
        "as_name": _get(resource, "autonomous_system", "name"),
        "praefix": _get(resource, "autonomous_system", "bgp_prefix"),
        "land": _get(resource, "location", "country") or _get(resource, "location", "country_code"),
        "stadt": _get(resource, "location", "city"),
        "reverse_dns": _names(_get(resource, "dns", "reverse_dns", "names")),
        "labels": _names(resource.get("labels")),
        "anzahl_dienste": resource.get("service_count", len(resource.get("services") or [])),
        "dienste": services,
    }.items() if value not in (None, "", [])}
    if not services and not summary.get("as_nummer"):
        summary["hinweis"] = "Antwort ohne erkennbare Dienste oder Netzangaben"
        summary["felder_der_antwort"] = sorted(resource)[:30]
    return summary


async def host(client, ip):
    token = settings.OSINT_CENSYS_TOKEN
    limit = settings.OSINT_CENSYS_MONTHLY_LIMIT

    cached = await cache.aget(f"censys:host:{ip}")
    if cached is not None:
        return {**cached, "aus_zwischenspeicher": True}

    month_key = f"censys:calls:{datetime.now(timezone.utc):%Y-%m}"
    await cache.aadd(month_key, 0, 40 * 24 * 3600)
    if (await cache.aget(month_key) or 0) >= limit:
        raise RuntimeError(f"Monatliche Obergrenze von {limit} Abfragen erreicht (schützt das kostenlose Kontingent)")
    await cache.aincr(month_key)  # vor dem Aufruf zählen: auch fehlgeschlagene Anfragen können Credits kosten

    headers = {"Authorization": f"Bearer {token}", "Accept": ACCEPT}
    if settings.OSINT_CENSYS_ORG_ID:
        headers["X-Organization-ID"] = settings.OSINT_CENSYS_ORG_ID
    response = await client.get(f"{BASE_URL}/{ip}", headers=headers)
    if response.status_code == 429:  # Gratis-Tarif: eine Anfrage gleichzeitig
        await asyncio.sleep(3)
        response = await client.get(f"{BASE_URL}/{ip}", headers=headers)

    if response.status_code == 404:
        result = {"hinweis": "Censys hat zu dieser Adresse keine Daten"}
    elif response.status_code in (401, 403):
        raise RuntimeError("Censys lehnt den Zugang ab: Token ungültig, Organisations-ID fehlt oder Tarif ohne Zugriff")
    elif response.status_code == 429:
        raise RuntimeError("Censys: zu viele gleichzeitige Anfragen (Gratis-Tarif erlaubt eine)")
    else:
        response.raise_for_status()
        result = summarize(response.json())

    await cache.aset(f"censys:host:{ip}", result, CACHE_SECONDS)
    return result
