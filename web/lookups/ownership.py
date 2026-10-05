"""Liste der eigenen Systeme: Nur für sie ist der Portscan erlaubt."""

import ipaddress

from django.core.exceptions import ValidationError

from .detect import HOSTNAME

MIN_PREFIX = {4: 22, 6: 56}  # größere Netze würden "alles scannen" erlauben


def parse(value):
    """Gibt ("net", normalisiertes Netz) oder ("host", Hostname) zurück."""
    text = str(value).strip().lower()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        network = None
    if network is not None:
        if getattr(network.network_address, "scope_id", None) or not network.is_global:
            raise ValidationError("Nur öffentliche Adressen können gescannt werden.")
        if network.prefixlen < MIN_PREFIX[network.version]:
            raise ValidationError(f"Das Netz ist zu groß (höchstens /{MIN_PREFIX[network.version]} erlaubt).")
        return "net", str(network)
    host = text.rstrip(".")
    if HOSTNAME.fullmatch(host):
        return "host", host
    raise ValidationError("Weder eine öffentliche IP-Adresse, ein Netz noch ein gültiger Hostname.")


def is_owned(kind, query):
    """Ob das Ziel einer Analyse als eigenes System eingetragen ist (Rufnummern nie)."""
    from .models import OwnedTarget

    values = list(OwnedTarget.objects.values_list("value", flat=True))
    if kind == "host":
        return query.strip().lower().rstrip(".") in values
    if kind != "ip":
        return False
    address = ipaddress.ip_address(query)
    for value in values:
        try:
            if address in ipaddress.ip_network(value):
                return True
        except ValueError:
            continue  # Hostname-Eintrag
    return False
