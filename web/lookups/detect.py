"""Erkennt, ob eine Eingabe eine IP-Adresse, ein Hostname/URL oder eine Rufnummer ist."""

import ipaddress
import re
from urllib.parse import urlsplit

import phonenumbers
from django.conf import settings
from django.utils.translation import get_language

PHONE_CHARS = re.compile(r"\+?[\d\s/()\-.]{3,30}")
HOSTNAME = re.compile(r"(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")


def _message(german, english):
    return english if (get_language() or "de").startswith("en") else german


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

    raise ValueError(_message(
        "Keine IP-Adresse, kein Hostname und keine gültige Rufnummer erkannt.",
        "No IP address, hostname, or valid phone number was detected.",
    ))


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


def vcard_text(text):
    """Rufnummern aus einer Visitenkarte (vCard), wie sie Telefon- und Kontakte-Apps teilen."""
    if "BEGIN:VCARD" not in text.upper():
        return text[:2000]
    unfolded = re.sub(r"\r?\n[ \t]", "", text)
    numbers = [
        line.split(":", 1)[1].strip().removeprefix("tel:")
        for line in unfolded.splitlines()
        if re.match(r"(item\d+\.)?TEL[;:]", line, re.IGNORECASE) and ":" in line
    ]
    return " ".join(numbers)
