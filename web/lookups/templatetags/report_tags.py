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
