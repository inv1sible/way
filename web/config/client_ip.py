import ipaddress

from django.conf import settings


def client_ip(request):
    """Client-IP für die Login-Sperre.

    X-Forwarded-For wird nur ausgewertet, wenn die Verbindung von einem vertrauenswürdigen
    Reverse Proxy kommt. Dann zählt der letzte Eintrag, denn den hat der Proxy selbst angehängt;
    weiter links stehende Einträge kann der Client fälschen.

    IPv6-Adressen werden auf ihr /64-Netz reduziert, weil ein einzelner Anschluss beliebig viele
    Adressen daraus nutzen und so die Sperre pro Adresse umgehen könnte.
    """
    remote = request.META.get("REMOTE_ADDR", "")
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    ip = forwarded.split(",")[-1].strip() if remote in settings.TRUSTED_PROXIES and forwarded else remote
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False).network_address)
    return str(addr)
