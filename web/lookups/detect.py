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
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


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
