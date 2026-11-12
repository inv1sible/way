from django.conf import settings
from django.db import models


def default_active_ports():
    return [443, 8443]


class Lookup(models.Model):
    class Kind(models.TextChoices):
        EMAIL = "email", "E-Mail-Adresse"
        PHONE = "phone", "Rufnummer"
        IP = "ip", "IP-Adresse"
        HOST = "host", "Hostname"
        COMPARE = "compare", "Vergleich"

    class Status(models.TextChoices):
        PENDING = "pending", "Wartet"
        COLLECTING = "collecting", "Quellen werden abgefragt"
        ANALYZING = "analyzing", "KI schreibt den Bericht"
        DONE = "done", "Fertig"
        FAILED = "failed", "Fehler"

    class Risk(models.TextChoices):
        LOW = "niedrig", "niedrig"
        MEDIUM = "mittel", "mittel"
        HIGH = "hoch", "hoch"
        UNCLEAR = "unklar", "unklar"

    class ActiveProfile(models.TextChoices):
        FRITZBOX = "fritzbox", "FRITZ!Box"
        GENERIC_ROUTER = "generic-router", "Generischer Router"
        SPEEDPORT = "speedport", "Speedport"

    created_at = models.DateTimeField("erstellt", auto_now_add=True)
    finished_at = models.DateTimeField("abgeschlossen", null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    kind = models.CharField("Typ", max_length=10, choices=Kind.choices)
    query = models.CharField("Abfrage", max_length=255, db_index=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.PENDING)
    risk = models.CharField("Risiko", max_length=10, choices=Risk.choices, blank=True)
    model = models.CharField("KI-Modell", max_length=100, blank=True)
    sources = models.JSONField("Rohdaten", default=list, blank=True)
    report_md = models.TextField("Bericht", blank=True)
    error = models.TextField("Fehler", blank=True)
    note = models.CharField("Notiz", max_length=200, blank=True, default="")
    as_of = models.DateField(
        "Stand", null=True, blank=True,
        help_text="Rückblick: Historische Quellen (BGP, Passive DNS) für dieses Datum auswerten.",
    )
    port_scan = models.BooleanField(
        "Portscan", default=False,
        help_text="nmap-Portscan; nur für Ziele aus der Liste der eigenen Systeme.",
    )
    active_probe = models.BooleanField(
        "leicht aktiv", default=False,
        help_text="Berechtigung bestätigt; Ziel direkt für den FRITZ!Box-Fingerprint kontaktieren.",
    )
    active_ports = models.JSONField(
        "aktive Web-Ports", default=default_active_ports,
        help_text="Höchstens vier explizit freigegebene Ports; 80/8080 per HTTP, alle anderen per HTTPS.",
    )
    active_timeout = models.PositiveSmallIntegerField(
        "aktiver Timeout", default=8,
        help_text="Timeout je aktiver Anfrage in Sekunden (2 bis 20).",
    )
    active_profile = models.CharField(
        "aktives Profil", max_length=20, choices=ActiveProfile.choices, default=ActiveProfile.FRITZBOX,
        help_text="Ausdrücklich ausgewähltes, nicht destruktives aktives Prüfprofil.",
    )
    email_public_web = models.BooleanField(
        "Öffentliche E-Mail-Referenzen", default=False,
        help_text="Ausdrücklich bestätigte, begrenzte Suche nach der exakten E-Mail-Adresse in öffentlichen Web-Suchergebnissen.",
    )
    phone_public_web = models.BooleanField(
        "Öffentliche Rufnummern-Referenzen", default=False,
        help_text="Ausdrücklich bestätigte, begrenzte Suche nach der Rufnummer in öffentlichen Web-Suchergebnissen.",
    )
    local_only = models.BooleanField(
        "Nur lokal", default=False,
        help_text="IP-Analyse ausschließlich mit lokalen Daten (GeoIP-Datenbank, eigene frühere Analysen), ohne externe Anfragen.",
    )
    enrichment_of = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="+", editable=False,
        verbose_name="angereichert aus",
    )
    # Nur bei kind=compare: die verglichenen Analysen; ihre Ergebnisse werden angezeigt, nicht kopiert.
    compared = models.ManyToManyField(
        "self", symmetrical=False, blank=True, related_name="comparisons", verbose_name="verglichene Analysen",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Analyse"
        verbose_name_plural = "Analysen"

    def __str__(self):
        return f"{self.get_kind_display()} {self.query}"

    @property
    def is_running(self):
        return self.status in (self.Status.PENDING, self.Status.COLLECTING, self.Status.ANALYZING)
