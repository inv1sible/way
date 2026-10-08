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
SEARCH_SOURCES = ("Websuche", "Stammnummernabgleich", "Spam-Portale")


@register.filter
def fundstellen(sources):
    """Alle Websuche-Treffer einer Analyse, ohne Duplikate, für die Anzeige als Linkliste."""
    seen, hits = set(), []
    for source in sources or []:
        if not source.get("ok") or not source["source"].startswith(SEARCH_SOURCES):
            continue
        data = source.get("data")
        for group in data.values() if isinstance(data, dict) else [data]:
            for hit in group if isinstance(group, list) else []:
                if not isinstance(hit, dict):
                    continue
                url = hit.get("url") or ""
                if url.startswith(("https://", "http://")) and url not in seen:
                    seen.add(url)
                    hits.append({**hit, "quelle": source["source"]})
    return hits


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
