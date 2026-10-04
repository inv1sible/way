"""Maßnahmenliste der Bundesnetzagentur zu Rufnummernmissbrauch.

Die letzten sechs Monate stehen als HTML-Tabelle bereit, ältere Jahre als PDF. Beides wird zu
einem Index Rufnummer -> Einträge zusammengeführt und im Cache gehalten.
"""

import asyncio
import html
import io
import re

import phonenumbers
from django.core.cache import cache
from pypdf import PdfReader

BASE_URL = "https://www.bundesnetzagentur.de"
PAGE_URL = BASE_URL + "/DE/Vportal/TK/Aerger/Aktuelles/Ma%C3%9Fnahmen/artikel_RM.html"
PDF_YEARS = 3
CACHE_KEY = "bnetza:index:v1"
CACHE_SECONDS = 6 * 3600

ROW = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S)
CELL = re.compile(r"<td[^>]*>(.*?)</td>", re.S)
TAG = re.compile(r"<[^>]+>")
PDF_LINK = re.compile(r'href="([^"]*/Ma%C3%9Fnahmenliste(\d{4})[^"]*\.pdf[^"]*)"')
NUMBER = re.compile(r"(?<!\d)0\d{5,14}(?!\d)")
DATE = re.compile(r"\d{2}\.\d{2}\.\d{4}\b")


def _text(fragment):
    return " ".join(html.unescape(TAG.sub(" ", fragment)).split())


def parse_table(page):
    index = {}
    for row in ROW.findall(page):
        cells = [_text(c) for c in CELL.findall(row)]
        if len(cells) < 4:
            continue
        entry = {
            "quelle": "Maßnahmenliste (letzte 6 Monate)",
            "bescheid_vom": cells[0],
            "kategorie": cells[2],
            "massnahme": cells[3],
        }
        for number in NUMBER.findall(cells[1]):
            index.setdefault(number, []).append(entry)
    return index


def parse_pdf(data, year):
    """Die PDF-Tabellen verlieren beim Textexport ihre Spalten; je Treffer wird die Zeile und
    der zuletzt gesehene Eintragsbeginn (Zeile mit Bescheiddatum) gespeichert."""
    index = {}
    entry_start = None
    for page in PdfReader(io.BytesIO(data)).pages:
        for line in (page.extract_text() or "").splitlines():
            line = " ".join(line.split())
            if DATE.match(line):
                entry_start = line
            for number in NUMBER.findall(line):
                index.setdefault(number, []).append({
                    "quelle": f"Maßnahmenliste {year} (PDF)",
                    "zeile": line[:300],
                    "eintrag": entry_start[:300] if entry_start and entry_start != line else None,
                })
    return index


def _merge(target, source):
    for number, entries in source.items():
        target.setdefault(number, []).extend(entries)


async def build_index(client):
    response = await client.get(PAGE_URL, follow_redirects=True)
    response.raise_for_status()
    index = parse_table(response.text)
    links = sorted({(int(year), html.unescape(href)) for href, year in PDF_LINK.findall(response.text)}, reverse=True)
    for year, href in links[:PDF_YEARS]:
        pdf = await client.get(BASE_URL + href, follow_redirects=True, timeout=60)
        pdf.raise_for_status()
        _merge(index, await asyncio.to_thread(parse_pdf, pdf.content, year))
    return index


async def check(client, e164):
    number = phonenumbers.parse(e164)
    if number.country_code != 49:
        return {"hinweis": "Die Maßnahmenliste betrifft nur deutsche Rufnummern."}
    national = "0" + phonenumbers.national_significant_number(number)
    index = await cache.aget(CACHE_KEY)
    if index is None:
        index = await build_index(client)
        await cache.aset(CACHE_KEY, index, CACHE_SECONDS)
    hits = index.get(national, [])
    return {
        "rufnummer": national,
        "treffer": hits,
        "hinweis": None if hits else (
            "Nicht in der Maßnahmenliste gefunden (letzte 6 Monate und Jahreslisten der letzten "
            f"{PDF_YEARS} Jahre)."
        ),
    }
