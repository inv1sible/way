"""Liste der eigenen Systeme: Nur für sie ist der Portscan erlaubt."""

import ipaddress
import re

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


def parse_asns(text):
    """Komma-getrennte AS-Nummern ("AS3320, 3209") als Menge von "AS<n>"."""
    result = set()
    for part in re.split(r"[,;\s]+", str(text or "").strip()):
        if not part:
            continue
        match = re.fullmatch(r"(?:as)?(\d{1,10})", part, re.IGNORECASE)
        if not match:
            raise ValidationError(f"„{part}“ ist keine AS-Nummer (Beispiel: AS3320).")
        result.add(f"AS{int(match.group(1))}")
    return result


def allowed_asns(kind, query):
    """Hinterlegte erwartete ASNs; None bedeutet, dass für dieses Ziel keine ASN-Schranke gesetzt ist."""
    from .models import OwnedTarget

    if kind == "host":
        entry = OwnedTarget.objects.filter(value=query.strip().lower().rstrip(".")).first()
    elif kind == "ip":
        address = ipaddress.ip_address(query)
        matches = []
        for candidate in OwnedTarget.objects.all():
            try:
                network = ipaddress.ip_network(candidate.value)
                if address in network:
                    matches.append((network.prefixlen, candidate))
            except ValueError:
                continue
        entry = max(matches, default=(None, None), key=lambda match: match[0])[1]
    else:
        return None
    try:
        allowed = parse_asns(entry.asn) if entry else set()
    except ValidationError:
        allowed = set()  # unlesbarer Eintrag: im Zweifel nicht scannen
    # Für Hostnamen ist ein ASN verpflichtend und ein fehlender Eintrag muss die Prüfung sperren.
    # Bei älteren IP-Einträgen ohne ASN bleibt das bisherige Verhalten erhalten.
    return allowed if kind == "host" or allowed else None


def expected_dns_name(kind, query):
    """Optionaler, explizit am IP-Asset gespeicherter DNS-Name für die aktive Bindungsprüfung."""
    if kind != "ip":
        return None
    from .models import OwnedTarget

    address = ipaddress.ip_address(query)
    matches = []
    for candidate in OwnedTarget.objects.exclude(dns_name=""):
        try:
            network = ipaddress.ip_network(candidate.value)
            if address in network:
                matches.append((network.prefixlen, candidate.dns_name))
        except ValueError:
            continue
    return max(matches, default=(None, None), key=lambda match: match[0])[1]


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
