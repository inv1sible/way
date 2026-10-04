"""Rufnummern: lokale Auswertung mit libphonenumber und Websuche nach Erfahrungsberichten."""

import asyncio
import re

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from . import run_source, search

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


async def web_search(client, e164):
    number = phonenumbers.parse(e164)
    national = re.sub(r"\D", "", phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL))
    variants = {national, e164.lstrip("+")}
    batches = await asyncio.gather(*(search.searx(client, f'"{q}"') for q in (national, e164)))
    seen, hits = set(), []
    for hit in (h for batch in batches for h in batch):
        if hit["url"] not in seen and mentions_number(hit, variants):
            seen.add(hit["url"])
            hits.append(hit)
    return hits[:15]


async def collect(client, e164):
    return list(
        await asyncio.gather(
            run_source("Rufnummernanalyse (libphonenumber)", analyze, e164),
            run_source("Websuche (SearXNG)", web_search, client, e164),
        )
    )
