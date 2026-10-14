"""Kleine zweisprachige UI-Helfer ohne zusätzliche Übersetzungsdateien."""

from datetime import datetime, timezone as dt_timezone

from django import template
from django.utils import timezone
from django.utils.translation import get_language

from .report_tags import report_parts

register = template.Library()


def english():
    return (get_language() or "de").lower().startswith("en")


@register.simple_tag
def ui(german, english_text):
    return english_text if english() else german


@register.filter
def localized_report(text):
    parts = report_parts(text)
    if not parts["bilingual"]:
        return parts["single"]
    return parts["en" if english() else "de"]


@register.filter
def kind_label(value):
    labels = {
        "email": ("E-Mail-Adresse", "Email address"),
        "phone": ("Rufnummer", "Phone number"),
        "ip": ("IP-Adresse", "IP address"),
        "host": ("Hostname", "Hostname"),
    }
    pair = labels.get(value, (value, value))
    return pair[1] if english() else pair[0]


@register.filter
def status_label(value):
    labels = {
        "pending": ("Wartet", "Waiting"),
        "collecting": ("Quellen werden abgefragt", "Collecting sources"),
        "analyzing": ("KI schreibt den Bericht", "AI is writing the report"),
        "done": ("Fertig", "Complete"),
        "failed": ("Fehler", "Failed"),
    }
    pair = labels.get(value, (value, value))
    return pair[1] if english() else pair[0]


@register.filter
def risk_label(value):
    labels = {
        "niedrig": ("niedrig", "low"),
        "mittel": ("mittel", "medium"),
        "hoch": ("hoch", "high"),
        "unklar": ("unklar", "unclear"),
    }
    pair = labels.get(value, (value, value))
    return pair[1] if english() else pair[0]


@register.filter
def invitation_status(value):
    labels = {
        "offen": ("offen", "open"),
        "abgelaufen": ("abgelaufen", "expired"),
        "eingelöst": ("eingelöst", "redeemed"),
    }
    pair = labels.get(value, (value, value))
    return pair[1] if english() else pair[0]


@register.filter
def ui_datetime(value):
    if not value:
        return "–"
    local = timezone.localtime(value)
    return local.strftime("%Y-%m-%d %H:%M") if english() else local.strftime("%d.%m.%Y %H:%M")


@register.filter
def ui_date(value):
    if not value:
        return "–"
    return value.strftime("%Y-%m-%d") if english() else value.strftime("%d.%m.%Y")


@register.filter
def ui_timestamp(value):
    """Render API timestamps in the active UI language while preserving raw values in source data."""
    if not value:
        return "–"
    try:
        if isinstance(value, (int, float)):
            instant = datetime.fromtimestamp(value, dt_timezone.utc)
        else:
            text = str(value)
            if len(text) == 10:
                parsed = datetime.strptime(text, "%Y-%m-%d")
                return parsed.strftime("%Y-%m-%d") if english() else parsed.strftime("%d.%m.%Y")
            instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if timezone.is_naive(instant):
                instant = timezone.make_aware(instant, dt_timezone.utc)
        local = timezone.localtime(instant)
    except (TypeError, ValueError):
        return str(value)
    return local.strftime("%d %b %Y, %H:%M %Z") if english() else local.strftime("%d.%m.%Y, %H:%M %Z")
