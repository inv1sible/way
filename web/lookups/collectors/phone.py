"""Rufnummern: lokale Auswertung mit libphonenumber und Websuche nach Erfahrungsberichten."""

import asyncio
import html
import re

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from . import bnetza, run_source, search

TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "Festnetz",
    PhoneNumberType.MOBILE: "Mobilfunk",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Festnetz oder Mobilfunk",
    PhoneNumberType.TOLL_FREE: "gebührenfrei",
    PhoneNumberType.PREMIUM_RATE: "Premium-/Mehrwertdienst (teuer)",
    PhoneNumberType.SHARED_COST: "Service-Rufnummer mit geteilten Kosten",
    PhoneNumberType.VOIP: "VoIP / standortunabhängig",
    PhoneNumberType.PERSONAL_NUMBER: "persönliche Rufnummer",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "Unternehmensrufnummer (UAN)",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "unbekannt",
}

# Deutsche Nummernbereiche laut Nummernplan der Bundesnetzagentur; der längste Präfix gewinnt.
DE_RANGES = {
    "115": "Behördennummer 115",
    "116": "Harmonisierter Dienst von sozialem Wert (z. B. 116 116 Sperr-Notruf)",
    "118": "Auskunftsdienst, meist teuer",
    "137": "Massenverkehrsdienst (Televoting/Gewinnspiele), kostenpflichtig",
    "15": "Mobilfunk",
    "16": "Mobilfunk",
    "17": "Mobilfunk",
    "180": "Service-Dienst (Shared Cost), erhöhte Kosten",
    "32": "Nationale Teilnehmerrufnummer, standortunabhängig, oft VoIP",
    "700": "Persönliche Rufnummer, standortunabhängig",
    "800": "Gebührenfreier Dienst",
    "900": "Premium-Dienst, teuer",
}

# Vorwahlen, die in Verbraucherwarnungen häufig im Zusammenhang mit Ping-Anrufen
# (kurz klingeln lassen, teurer Rückruf) genannt werden. Heuristik, keine Gewissheit.
PING_CALL_CODES = {
    216: "Tunesien",
    222: "Mauretanien",
    224: "Guinea",
    225: "Elfenbeinküste",
    232: "Sierra Leone",
    252: "Somalia",
    682: "Cookinseln",
    688: "Tuvalu",
    870: "Inmarsat (Satellit)",
    881: "Globales Satellitensystem",
    882: "Internationale Netze",
    883: "Internationale Netze",
}


def analyze(e164):
    number = phonenumbers.parse(e164)
    nsn = phonenumbers.national_significant_number(number)
    hints = []
    if number.country_code == 49:
        prefix = next((p for p in sorted(DE_RANGES, key=len, reverse=True) if nsn.startswith(p)), None)
        if prefix:
            hints.append(f"Nummernbereich 0{prefix}: {DE_RANGES[prefix]}")
    elif number.country_code in PING_CALL_CODES:
        hints.append(
            f"Vorwahl +{number.country_code} ({PING_CALL_CODES[number.country_code]}) wird häufig "
            "in Warnungen vor Ping-Anrufen genannt; Rückruf kann teuer sein (Heuristik)."
        )

    return {
        "e164": e164,
        "international": phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL),
        "gueltig": phonenumbers.is_valid_number(number),
        "land": geocoder.country_name_for_number(number, "de") or None,
        "laendercode": phonenumbers.region_code_for_number(number),
        "ort_region": geocoder.description_for_number(number, "de") or None,
        "typ": TYPE_NAMES.get(phonenumbers.number_type(number), "unbekannt"),
        "netzbetreiber_urspruenglich": carrier.name_for_number(number, "de") or None,
        "zeitzonen": [tz for tz in timezone.time_zones_for_number(number) if tz != "Etc/Unknown"],
        "hinweise": hints,
    }


DIGIT_SEPARATORS = re.compile(r"(?<=\d)[\s/().\-]+(?=\d)")


def mentions_number(hit, variants):
    """Suchmaschinen ignorieren Phrasensuche oft; nur Treffer behalten, die die Nummer wirklich enthalten."""
    text = DIGIT_SEPARATORS.sub("", " ".join(filter(None, (hit["titel"], hit["auszug"], hit["url"]))))
    return any(v in text for v in variants)


def _formats(e164):
    """Schreibweisen für die Suche: Suchmaschinen finden "069 90009123" oft, die reinen Ziffern
    "06990009123" dagegen kaum."""
    number = phonenumbers.parse(e164)
    national = phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL)
    international = phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL)
    digits = re.sub(r"\D", "", national)
    return national, international, digits, {digits, e164.lstrip("+")}


# Pause zwischen zwei Suchanfragen; schnelle Folgen lösen Sperren bei den Suchmaschinen aus.
SEARCH_PAUSE = 1.5


async def _search_all(client, queries, variants, limit, meta):
    """Fragt nacheinander ab und behält nur Treffer, in denen die Nummer wirklich vorkommt.
    queries: Liste von (Suchbegriff, Seite, Bedingung); Bedingung erhält die bisherigen Treffer."""
    seen, hits, errors, asked = set(), [], [], 0
    for query, page, condition in queries:
        if condition and not condition(hits):
            continue
        if asked:
            await asyncio.sleep(SEARCH_PAUSE)
        asked += 1
        try:
            batch = await search.searx(client, query, limit=20, pageno=page, meta=meta)
        except Exception as exc:
            errors.append(f"{query}: {type(exc).__name__}")
            continue
        for hit in batch:
            if hit["url"] not in seen and mentions_number(hit, variants):
                seen.add(hit["url"])
                hits.append(hit)
    if errors and len(errors) == asked:
        raise RuntimeError("Websuche nicht erreichbar: " + "; ".join(errors))
    return hits[:limit]


def _coverage(meta):
    return {
        "suchmaschinen_mit_ergebnissen": sorted(meta.get("ok", ())),
        "gestoerte_suchmaschinen": meta.get("gestoert", {}),
    }


async def web_search(client, e164):
    national, international, _, variants = _formats(e164)
    meta = {}
    queries = [
        (f'"{national}"', 1, None),
        (f'"{international}"', 1, None),
        (f'"{national}"', 2, lambda hits: len(hits) >= 5),  # zweite Seite nur, wenn die erste ergiebig war
    ]
    hits = await _search_all(client, queries, variants, limit=30, meta=meta)
    return {"treffer": hits, **_coverage(meta)}


# Portale mit Nutzerbewertungen und Rückwärtssuche; gesucht wird über SearXNG, nicht per Scraping.
SPAM_PORTALS = (
    "tellows.de", "cleverdialer.de", "wemgehoert.de", "werruft.info", "anruferauskunft.de",
    "dasoertliche.de", "dastelefonbuch.de",
)


async def spam_portals(client, e164):
    national, _, digits, variants = _formats(e164)
    sites = " OR ".join(f"site:{domain}" for domain in SPAM_PORTALS)
    # Ziffernfolge zusätzlich, weil Portale die Nummer oft so in der URL führen (tellows.de/num/0211…)
    queries = [(f'"{national}" ({sites})', 1, None), (f"{digits} ({sites})", 1, None)]
    hits = await _search_all(client, queries, variants, limit=20, meta={})
    result = {domain: [] for domain in SPAM_PORTALS}
    for hit in hits:
        domain = next((d for d in SPAM_PORTALS if d in hit["url"]), None)
        if domain:
            result[domain].append(hit)
    return {domain: found or "kein Treffer" for domain, found in result.items()}


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0 Safari/537.36"


def parse_clever_dialer(page):
    title = re.search(r"<title>(.*?)</title>", page, re.S)
    text = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", page, flags=re.S))))
    place = re.search(r"Telefonnummer aus ([^<|]+)", html.unescape(title.group(1)) if title else "")
    rating = re.search(r"(\d(?:[.,]\d)?) von 5 Sternen\s*•?\s*(\d+) Bewertung", text)
    calls = re.search(r"(?<!Blockierte )Anrufe letzte 30 Tage:\s*(\d+)", text)
    blocked = re.search(r"Blockierte Anrufe letzte 30 Tage:\s*(\d+)", text)
    return {
        "ort": place.group(1).strip() if place else None,
        "sterne": float(rating.group(1).replace(",", ".")) if rating else None,
        "bewertungen": int(rating.group(2)) if rating else None,
        "anrufe_letzte_30_tage": int(calls.group(1)) if calls else None,
        "blockiert_letzte_30_tage": int(blocked.group(1)) if blocked else None,
    }


async def clever_dialer(client, e164):
    number = phonenumbers.parse(e164)
    if number.country_code != 49:
        return {"hinweis": "Clever Dialer wird nur für deutsche Rufnummern abgefragt."}
    url = f"https://www.cleverdialer.de/telefonnummer/0{phonenumbers.national_significant_number(number)}"
    response = await client.get(url, headers={"User-Agent": BROWSER_UA}, follow_redirects=True)
    response.raise_for_status()
    return {"url": url, **parse_clever_dialer(response.text)}


async def collect(client, e164, active=False, scan=False):
    async def searches():
        # Websuchen nacheinander, um die Suchmaschinen nicht mit parallelen Anfragen zu reizen
        return [
            await run_source("Websuche (SearXNG)", web_search, client, e164),
            await run_source("Spam-Portale und Telefonbücher (Websuche)", spam_portals, client, e164),
        ]

    *direct, searched = await asyncio.gather(
        run_source("Rufnummernanalyse (libphonenumber)", analyze, e164),
        run_source("Bundesnetzagentur-Maßnahmenliste", bnetza.check, client, e164),
        run_source("Clever Dialer", clever_dialer, client, e164),
        searches(),
    )
    return [*direct, *searched]
