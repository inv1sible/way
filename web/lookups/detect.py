"""Erkennt, ob eine Eingabe eine IP-Adresse, ein Hostname/URL oder eine Rufnummer ist."""

import ipaddress
import re
from urllib.parse import urlsplit

import phonenumbers
from django.conf import settings

PHONE_CHARS = re.compile(r"\+?[\d\s/()\-.]{3,30}")
HOSTNAME = re.compile(r"(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")


def _ip(text):
    try:
        addr = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    # IPv6-Zonen ("fe80::1%eth0") erlauben beliebige Zeichen und würden in die Quell-URLs gelangen.
    if getattr(addr, "scope_id", None):
        return None
    return str(addr)


def _hostname(text):
    try:
        host = urlsplit(text if "://" in text else f"//{text}").hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None


def detect(raw):
    """Gibt (kind, normalisierter Wert) zurück, kind ist "ip", "host" oder "phone".

    Raises ValueError bei unbekannter Eingabe.
    """
    text = raw.strip()
    if ip := _ip(text):
        return "ip", ip

    if host := _hostname(text):
        if ip := _ip(host):
            return "ip", ip
        if HOSTNAME.fullmatch(host):
            return "host", host

    if PHONE_CHARS.fullmatch(text):
        try:
            number = phonenumbers.parse(text, settings.OSINT_DEFAULT_REGION)
        except phonenumbers.NumberParseException:
            pass
        else:
            if phonenumbers.is_possible_number(number):
                return "phone", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)

    raise ValueError("Keine IP-Adresse, kein Hostname und keine gültige Rufnummer erkannt.")


# Muster für Kandidaten in geteiltem Freitext, in der Reihenfolge ihrer Prüfung.
CANDIDATES = [
    re.compile(r"https?://\S+"),
    re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    re.compile(r"\[?[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\]?"),
    re.compile(r"\+?\(?\d[\d\s/()\-.]{4,}\d"),
    re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE),
]


def extract(text):
    """Sucht in geteiltem Text (z. B. "Anruf von +49 211 …") den ersten analysierbaren Wert."""
    text = (text or "").strip()
    for candidate in (text, *(m.group(0) for p in CANDIDATES for m in p.finditer(text))):
        try:
            detect(candidate)
        except ValueError:
            continue
        return candidate.strip()
    return None
