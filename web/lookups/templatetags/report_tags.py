import json
import re

from django import template
from django.utils.safestring import mark_safe
from markdown_it import MarkdownIt

register = template.Library()

# html=False: HTML im KI-Text (z. B. aus Suchergebnissen übernommen) wird escaped statt gerendert.
_md = MarkdownIt("commonmark", {"html": False}).enable("table")
@register.filter
def markdown(text):
    return mark_safe(_md.render(text or ""))


@register.filter
def report_parts(text):
    """Zweisprachigen KI-Bericht teilen; ältere einsprachige Berichte bleiben unverändert sichtbar."""
    value = text or ""
    german = re.search(r"(?m)^# Deutsch\s*$", value)
    english = re.search(r"(?m)^# English\s*$", value)
    if not german or not english or german.start() >= english.start():
        return {"bilingual": False, "single": value}
    de_start = value.find("\n", german.end())
    en_start = value.find("\n", english.end())
    return {
        "bilingual": True,
        "de": value[de_start + 1:english.start()].strip() if de_start >= 0 else "",
        "en": value[en_start + 1:].strip() if en_start >= 0 else "",
    }


@register.filter
def pretty_json(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


# Nur Websuche-Quellen: andere Quellen (z. B. URLhaus) enthalten Schadsoftware-URLs, die nicht als
# klickbare Links erscheinen dürfen.
SEARCH_SOURCES = ("Websuche", "Stammnummernabgleich", "Spam-Portale", "Öffentliche Web-Referenzen")


@register.filter
def fundstellen(sources):
    """Alle Websuche-Treffer einer Analyse, ohne Duplikate, für die Anzeige als Linkliste."""
    seen, hits = set(), []
    for source in sources or []:
        if not source.get("ok") or not source["source"].startswith(SEARCH_SOURCES):
            continue
        data = source.get("data")
        groups = data.values() if isinstance(data, dict) else [data]
        if source["source"] == "Websuche (SearXNG)" and isinstance(data, dict):
            groups = [data.get("treffer", [])]
        elif source["source"] == "Öffentliche Web-Referenzen (SearXNG)" and isinstance(data, dict):
            groups = [data.get("references", [])]
        for group in groups:
            for hit in group if isinstance(group, list) else []:
                if not isinstance(hit, dict):
                    continue
                url = hit.get("url") or ""
                if url.startswith(("https://", "http://")) and url not in seen:
                    seen.add(url)
                    # E-Mail-Referenzen heißen aus Datenschutzgründen intern "fundstelle";
                    # die gemeinsame Anzeige verwendet ansonsten das ältere Feld "auszug".
                    hits.append({**hit, "auszug": hit.get("auszug") or hit.get("fundstelle"),
                                 "quelle": source["source"]})
    return hits


@register.filter
def returned_search_results(sources):
    """Begrenzte SearXNG-Ergebnisse, die nicht zwingend die vollständige Nummer im Auszug belegen."""
    seen, hits = set(), []
    for source in sources or []:
        if not source.get("ok") or source.get("source") != "Websuche (SearXNG)":
            continue
        for hit in (source.get("data") or {}).get("suchergebnisse", []):
            url = hit.get("url") or ""
            if url.startswith(("https://", "http://")) and url not in seen:
                seen.add(url)
                hits.append({**hit, "quelle": source["source"]})
    return hits


@register.filter
def email_search_links(sources):
    for source in sources or []:
        if source.get("ok") and source.get("source") == "Öffentliche Web-Referenzen (SearXNG)":
            return (source.get("data") or {}).get("suchlinks", [])
    return []


@register.filter
def email_search_responses(sources):
    """SearXNG results retained for review; they are not public-address references or report findings."""
    seen, results = set(), []
    for source in sources or []:
        if not source.get("ok") or source.get("source") != "Öffentliche Web-Referenzen (SearXNG)":
            continue
        for result in (source.get("data") or {}).get("suchergebnisse_zur_pruefung", []):
            url = result.get("url") or ""
            if url.startswith(("https://", "http://")) and url not in seen:
                seen.add(url)
                results.append(result)
    return results


@register.filter
def historical_dns(sources):
    """Normalized, timestamped historical DNS observations for the report and PDF."""
    seen, observations = set(), []
    for source in sources or []:
        if not source.get("ok"):
            continue
        name, data = source.get("source", ""), source.get("data") or {}
        if name == "VirusTotal (historische DNS-Auflösungen)":
            for item in data.get("aufloesungen", []) if isinstance(data, dict) else []:
                value, when = item.get("host_name"), item.get("beobachtet_am") or item.get("date")
                key = (name, value, when)
                if value and key not in seen:
                    seen.add(key)
                    observations.append({"wert": value, "zeit_von": when, "quelle": name})
        elif name.startswith("Passive DNS") and isinstance(data, dict):
            for group in ("zum_stichtag", "naechste_eintraege", "alle_adressen"):
                for item in data.get(group, []):
                    value = item.get("wert")
                    start, end = item.get("von_zeit") or item.get("von"), item.get("bis_zeit") or item.get("bis")
                    key = (name, value, start, end)
                    if value and key not in seen:
                        seen.add(key)
                        observations.append({"wert": value, "zeit_von": start, "zeit_bis": end,
                                             "typ": item.get("typ"), "quelle": name})
    return observations


def scan_data(sources):
    """Ergebnis des Portscans, falls vorhanden und erfolgreich."""
    for source in sources or []:
        if source.get("source", "").startswith("Portscan") and source.get("ok"):
            return source["data"]
    return None


def history_data(sources):
    """Verlauf aus früheren eigenen Analysen, falls vorhanden."""
    for source in sources or []:
        if source.get("source") == "Frühere eigene Analysen" and source.get("ok"):
            return source["data"]
    return None


@register.filter
def alphabetical_sources(sources):
    """Nur die Darstellung sortieren; die gespeicherte zeitliche Quellreihenfolge bleibt erhalten."""
    return sorted(sources or [], key=lambda source: str(source.get("source", "")).casefold())
