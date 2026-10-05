import json

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
def pretty_json(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


# Nur Websuche-Quellen: andere Quellen (z. B. URLhaus) enthalten Schadsoftware-URLs, die nicht als
# klickbare Links erscheinen dürfen.
SEARCH_SOURCES = ("Websuche", "Spam-Portale")


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
