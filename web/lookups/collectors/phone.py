"""Rufnummern: lokale Auswertung mit libphonenumber und Websuche nach Erfahrungsberichten."""

import asyncio
import html
import re
from datetime import datetime, timezone as dt_timezone

import phonenumbers
from phonenumbers import Leniency, PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

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

    area_length = phonenumbers.length_of_geographical_area_code(number)
    area_code = f"0{nsn[:area_length]}" if number.country_code == 49 and area_length else None
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
        "nummerierung": {
            "landeskennung": f"+{number.country_code}",
            "ortsnetzkennzahl": area_code,
            "teilnehmernummer": nsn[area_length:] if area_code else None,
        },
        "hinweise": hints,
    }


DIGIT_SEPARATORS = re.compile(r"(?<=\d)[\s/().\-]+(?=\d)")
CONTACT_MARKERS = re.compile(r"\b(?:kontakt|contact|impressum|anschrift|telefonzentrale|zentrale)\b", re.I)
PAGE_DESCRIPTOR_MARKERS = re.compile(
    r"\b(?:kontakt|contact|impressum|anschrift|telefonzentrale|zentrale|presse|press|service|ansprechpartner)\b",
    re.I,
)
# Deutsche Nebenstellen haben in der Praxis häufig vier oder fünf Ziffern; sechs
# Ziffern kommen vor, sind aber deutlich seltener. Diese Begrenzung vermeidet,
# dass ein einzelnes Enddigit als vermeintliche Nebenstelle behandelt wird.
PREFERRED_EXTENSION_LENGTHS = (5, 4, 6)
MIN_STEM_SUBSCRIBER_DIGITS = 2
MAX_PUBLISHED_EXTENSION_DIGITS = 6


def mentions_number(hit, variants):
    """Suchmaschinen ignorieren Phrasensuche oft; nur Treffer behalten, die die Nummer wirklich enthalten."""
    text = DIGIT_SEPARATORS.sub("", " ".join(filter(None, (hit["titel"], hit["auszug"], hit["url"]))))
    # Keine Teiltreffer: Eine mögliche Zentralnummer darf nicht allein deshalb als Treffer gelten,
    # weil sie Präfix einer längeren Durchwahl im Ergebnis ist.
    return any(re.search(rf"(?<!\d){re.escape(value)}(?!\d)", text) for value in variants)


def _formats(e164):
    """Schreibweisen für die Suche: Suchmaschinen finden "069 90009123" oft, die reinen Ziffern
    "06990009123" dagegen kaum."""
    number = phonenumbers.parse(e164)
    national = phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL)
    international = phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL)
    digits = re.sub(r"\D", "", national)
    return national, international, digits, {digits, e164.lstrip("+")}


def stem_candidates(e164):
    """Erzeugt vorsichtige Stammnummern-Hypothesen für deutsche Festnetze.

    Die Ortsnetzkennzahl bleibt vollständig erhalten. Es werden nur plausible
    Durchwahllängen (vier, fünf oder ausnahmsweise sechs Ziffern) abgetrennt;
    im Teilnehmerteil der Stammnummer müssen mindestens zwei Ziffern bleiben.
    """
    number = phonenumbers.parse(e164)
    if number.country_code != 49 or phonenumbers.number_type(number) not in {
        PhoneNumberType.FIXED_LINE, PhoneNumberType.FIXED_LINE_OR_MOBILE,
    }:
        return []
    nsn = phonenumbers.national_significant_number(number)
    area_length = phonenumbers.length_of_geographical_area_code(number)
    subscriber = nsn[area_length:]
    if area_length <= 0 or len(subscriber) <= MIN_STEM_SUBSCRIBER_DIGITS:
        return []
    area_code = f"0{nsn[:area_length]}"
    candidates = []
    for extension_length in PREFERRED_EXTENSION_LENGTHS:
        kept = len(subscriber) - extension_length
        if kept < MIN_STEM_SUBSCRIBER_DIGITS:
            continue
        trunk = subscriber[:kept]
        candidates.append({
            "stammnummer": f"{area_code} {trunk}",
            "ziffern": area_code + trunk,
            "entfernte_endziffern": subscriber[kept:],
            "anzahl_entfernter_endziffern": extension_length,
        })
    return candidates


def central_candidates(e164):
    """Kompatibler Alias für ältere Aufrufer."""
    return stem_candidates(e164)


# Pause zwischen zwei Suchanfragen; schnelle Folgen lösen Sperren bei den Suchmaschinen aus.
SEARCH_PAUSE = 1.5
MAX_PHONE_SEARCHES = 3


class SearchBudget:
    """Gemeinsames, kleines SearXNG-Budget für eine Rufnummernanalyse.

    Alle Telefon-Teilrecherchen teilen Zähler und Pause. Das vermeidet kurze Serien von
    Suchmaschinenanfragen, obwohl die einzelnen Quellen nacheinander ausgeführt werden.
    """
    def __init__(self, maximum=MAX_PHONE_SEARCHES):
        self.maximum = maximum
        self.used = 0

    async def search(self, client, query, limit, meta):
        if self.used >= self.maximum:
            return None
        if self.used:
            await asyncio.sleep(SEARCH_PAUSE)
        self.used += 1
        return await search.searx(client, query, limit=limit, meta=meta)

    def state(self):
        return {"maximal": self.maximum, "verwendet": self.used, "verbleibend": self.maximum - self.used}


async def _search_all(client, queries, variants, limit, meta, budget=None):
    """Fragt nacheinander ab und behält nur Treffer, in denen die Nummer wirklich vorkommt.
    queries: Liste von (Suchbegriff, Seite, Bedingung); Bedingung erhält die bisherigen Treffer."""
    seen, hits, errors, asked = set(), [], [], 0
    for query, page, condition in queries:
        if condition and not condition(hits):
            continue
        if budget is None and asked:
            await asyncio.sleep(SEARCH_PAUSE)
        asked += 1
        try:
            if budget is None:
                batch = await search.searx(client, query, limit=20, pageno=page, meta=meta)
            else:
                # Bei budgetierter Recherche ist eine Suchseite bewusst eine einzelne, klar
                # begrenzte Abfrage. Wird das Budget aufgebraucht, ist das kein Suchfehler.
                batch = await budget.search(client, query, limit=20, meta=meta)
                if batch is None:
                    break
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


async def web_search(client, e164, budget=None):
    national, international, digits, variants = _formats(e164)
    meta = {}
    queries = [
        (f'"{national}"', 1, None),
        (f'"{international}"', 1, None),
        (f'"{national}"', 2, lambda hits: len(hits) >= 5),  # zweite Seite nur, wenn die erste ergiebig war
    ]
    # Die adaptive Telefonanalyse beginnt nur mit der nationalen Schreibweise. Die internationale
    # Variante und eine Folgeseite würden das gemeinsame Budget zu früh aufbrauchen.
    if budget is not None:
        # Manche Suchmaschinen indexieren Rufnummern nur als Ziffernfolge. Der unquotierte
        # Fallback läuft ausschließlich nach einer leeren Phrasensuche; die Ergebnisfilterung
        # verlangt weiterhin die vollständige Nummer und verhindert dadurch Teiltreffer.
        queries = [queries[0], (digits, 1, lambda hits: not hits)]
    hits = await _search_all(client, queries, variants, limit=30, meta=meta, budget=budget)
    result = {"treffer": hits, **_coverage(meta)}
    if budget is not None:
        result["abfragebudget"] = budget.state()
    return result


def _hit_text(hit):
    return " ".join(filter(None, (hit.get("titel"), hit.get("auszug"))))


def _published_numbers(hit):
    """Nur vollständig im Fundtext vorkommende deutsche Rufnummern, normalisiert für Vergleiche."""
    found = []
    for match in phonenumbers.PhoneNumberMatcher(_hit_text(hit), "DE", leniency=Leniency.POSSIBLE):
        number = match.number
        if number.country_code != 49:
            continue
        digits = "0" + phonenumbers.national_significant_number(number)
        item = {
            "ziffern": digits,
            "anzeige": match.raw_string,
            "fundstelle": match.raw_string,
        }
        if item not in found:
            found.append(item)
    return found


def _organisation_from_hit(hit):
    title = str(hit.get("titel") or "")
    parts = [part.strip(" -–—|:") for part in re.split(r"\s+-\s+|[|–—]", title) if part.strip(" -–—|:")]
    organisation_parts = [part for part in parts if not PAGE_DESCRIPTOR_MARKERS.search(part)]
    if organisation_parts:
        return max(organisation_parts, key=len)
    return max(parts, key=len) if parts else None


def _contact_page_signal(hit):
    return bool(CONTACT_MARKERS.search(f"{hit.get('url', '')} {_hit_text(hit)}"))


def _stem_evidence(e164, candidates, hits, observed_at):
    full_digits = _formats(e164)[2]
    evidence = []
    for hit in hits:
        for candidate in candidates:
            for published in _published_numbers(hit):
                # Nicht der gemeinsame Präfix, sondern eine ausdrücklich veröffentlichte
                # Kontakt- oder Zentralnummer auf derselben Seite ist das zusätzliche
                # Belegstück. Ihre Durchwahl darf nicht länger sein als die vermutete;
                # dadurch werden zufällig ähnliche, längere Nummernreihen verworfen.
                published_extension_length = len(published["ziffern"]) - len(candidate["ziffern"])
                candidate_extension_length = len(candidate["entfernte_endziffern"])
                if (published["ziffern"].startswith(candidate["ziffern"]) and
                        published["ziffern"] != full_digits and
                        1 <= published_extension_length <= min(
                            candidate_extension_length, MAX_PUBLISHED_EXTENSION_DIGITS
                        )):
                    evidence.append({
                        "organisation": _organisation_from_hit(hit),
                        "stammnummer": candidate["stammnummer"],
                        "veroeffentlichteNummer": published["anzeige"],
                        "moeglicheDurchwahl": candidate["entfernte_endziffern"],
                        "sourceUrl": hit["url"],
                        "fundstelle": hit.get("auszug") or hit.get("titel") or published["fundstelle"],
                        "abgerufenAm": observed_at,
                        "kontaktOderImpressumSignal": _contact_page_signal(hit),
                        "evidence": "Veröffentlichte Kontakt-/Zentralnummer teilt den Stamm; die konkrete Durchwahl ist nicht daraus abgeleitet.",
                    })
    return evidence


async def central_office_search(client, e164, budget=None, direct_hits=()):
    """Sucht eine begrenzte Menge schrittweise abgeleiteter Stammnummern in einer Anfrage."""
    candidates, meta, observed_at = stem_candidates(e164), {}, datetime.now(dt_timezone.utc).isoformat()
    if not candidates:
        return {"treffer": [], "evidenz": [],
                "hinweis": "Kein Stammnummernabgleich: keine geeignete deutsche Festnetznummer mit plausibler Durchwahllänge."}
    full_digits = _formats(e164)[2]
    if any(_contact_page_signal(hit) and any(number["ziffern"] == full_digits for number in _published_numbers(hit))
           for hit in direct_hits):
        return {"treffer": [], "evidenz": [],
                "hinweis": "Nicht abgefragt: die vollständige Nummer ist bereits auf einer Kontakt-/Impressumsseite belegt.",
                **_coverage(meta), **({"abfragebudget": budget.state()} if budget else {})}
    quoted = " OR ".join(f'"{candidate["stammnummer"]}"' for candidate in candidates)
    query = f"({quoted}) (Kontakt OR Impressum OR Telefon OR Zentrale)"
    try:
        hits = await (budget.search(client, query, limit=20, meta=meta) if budget else
                      search.searx(client, query, limit=20, meta=meta))
    except Exception as exc:
        raise RuntimeError(f"Stammnummernsuche fehlgeschlagen: {type(exc).__name__}") from None
    hits = hits or []
    result = {
        "treffer": hits[:20],
        "evidenz": _stem_evidence(e164, candidates, hits, observed_at),
        "hinweis": "Der Abgleich speichert keine abgeleiteten Suchbegriffe. Ein gemeinsames Präfix ohne veröffentlichte Kontakt-/Zentralnummer ist keine Zuordnung.",
        **_coverage(meta),
    }
    if budget is not None:
        result["abfragebudget"] = budget.state()
    return result


def stem_attribution(e164, direct_hits, stem_result):
    """Trennt belegte Stammnummern-Evidenz strikt von dem unbekannten Einzelanschluss."""
    observed_at = datetime.now(dt_timezone.utc).isoformat()
    full_digits = _formats(e164)[2]
    direct = []
    for hit in direct_hits or []:
        if not _contact_page_signal(hit):
            continue
        for published in _published_numbers(hit):
            if published["ziffern"] == full_digits:
                direct.append({
                    "organisation": _organisation_from_hit(hit), "sourceUrl": hit["url"],
                    "fundstelle": hit.get("auszug") or hit.get("titel"), "abgerufenAm": observed_at,
                    "veroeffentlichteNummer": published["anzeige"],
                })
    stem_evidence = [item for item in (stem_result or {}).get("evidenz", []) if item.get("kontaktOderImpressumSignal")]
    stem = stem_evidence[0] if stem_evidence else None
    return {
        "belegteOrganisationszuordnung": stem_evidence,
        "vermuteteStammnummer": ({key: stem[key] for key in ("stammnummer", "veroeffentlichteNummer", "organisation", "sourceUrl", "fundstelle", "abgerufenAm")}
                                 if stem else None),
        "moeglicheDurchwahl": stem.get("moeglicheDurchwahl") if stem else None,
        "belegterAnschlussinhaber": direct or None,
        "grenzen": [
            "Eine Stammnummernzuordnung belegt nicht, wem die konkrete Durchwahl gehört.",
            "Sie bestätigt nicht die Identität eines tatsächlichen Anrufers; Rufnummern können gefälscht sein.",
            "Ortsnetz-, Mobilfunk- und Providerblöcke sind keine Organisationsnachweise.",
        ],
    }


# Portale mit Nutzerbewertungen und Rückwärtssuche; gesucht wird über SearXNG, nicht per Scraping.
SPAM_PORTALS = (
    "tellows.de", "cleverdialer.de", "wemgehoert.de", "werruft.info", "anruferauskunft.de",
    "dasoertliche.de", "dastelefonbuch.de",
)


async def spam_portals(client, e164, budget=None):
    national, _, digits, variants = _formats(e164)
    sites = " OR ".join(f"site:{domain}" for domain in SPAM_PORTALS)
    # Ziffernfolge zusätzlich, weil Portale die Nummer oft so in der URL führen (tellows.de/num/0211…)
    queries = [(f'"{national}" ({sites})', 1, None), (f"{digits} ({sites})", 1, None)]
    if budget is not None:
        queries = queries[:1]
    hits = await _search_all(client, queries, variants, limit=20, meta={}, budget=budget)
    result = {domain: [] for domain in SPAM_PORTALS}
    for hit in hits:
        domain = next((d for d in SPAM_PORTALS if d in hit["url"]), None)
        if domain:
            result[domain].append(hit)
    output = {domain: found or "kein Treffer" for domain, found in result.items()}
    if budget is not None:
        output["abfragebudget"] = budget.state()
    return output


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


async def collect(client, e164, active=False, scan=False, as_of=None):
    async def searches():
        # Alle Teilrecherchen teilen ein Budget und laufen nacheinander: maximal drei Anfragen.
        budget = SearchBudget()
        direct = await run_source("Websuche (SearXNG)", web_search, client, e164, budget)
        direct_hits = (direct.get("data") or {}).get("treffer", []) if direct.get("ok") else []
        central = await run_source("Stammnummernabgleich (Websuche)", central_office_search,
                                   client, e164, budget, direct_hits)
        portals = await run_source("Spam-Portale und Telefonbücher (Websuche)", spam_portals, client, e164, budget)
        attribution = await run_source(
            "Stammnummern-Zuordnung", stem_attribution, e164, direct_hits,
            central.get("data") if central.get("ok") else {},
        )
        return [direct, central, attribution, portals]

    *direct, searched = await asyncio.gather(
        run_source("Rufnummernanalyse (libphonenumber)", analyze, e164),
        run_source("Bundesnetzagentur-Maßnahmenliste", bnetza.check, client, e164),
        run_source("Clever Dialer", clever_dialer, client, e164),
        searches(),
    )
    return [*direct, *searched]
