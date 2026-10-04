from django.conf import settings


def client_ip(request):
    """Client-IP für die Login-Sperre.

    X-Forwarded-For wird nur ausgewertet, wenn die Verbindung von einem vertrauenswürdigen
    Reverse Proxy kommt. Dann zählt der letzte Eintrag, denn den hat der Proxy selbst angehängt;
    weiter links stehende Einträge kann der Client fälschen.
    """
    remote = request.META.get("REMOTE_ADDR", "")
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if remote in settings.TRUSTED_PROXIES and forwarded:
        return forwarded.split(",")[-1].strip()
    return remote
