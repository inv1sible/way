from django.conf import settings
from django.db import models


class Lookup(models.Model):
    class Kind(models.TextChoices):
        PHONE = "phone", "Rufnummer"
        IP = "ip", "IP-Adresse"
        HOST = "host", "Hostname"

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
        "leise aktiv", default=False,
        help_text="Ziel direkt kontaktieren (TLS-Zertifikat, Web-Kopfzeilen); erscheint im Log des Ziels.",
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


class OwnedTarget(models.Model):
    """Eigene Systeme: Nur für diese ist der Portscan erlaubt. Eintrag ist eine öffentliche
    IP-Adresse, ein kleines Netz (höchstens /22 bzw. /56) oder ein Hostname."""

    value = models.CharField(
        "Adresse oder Hostname", max_length=255, unique=True,
        help_text="z. B. 203.0.113.7, 203.0.113.0/24 oder meinserver.example.org. "
                  "Hostnamen gelten nur exakt (keine Subdomains).",
    )
    asn = models.CharField(
        "Erlaubte Netze (AS-Nummer)", max_length=100, blank=True,
        help_text="Bei Hostnamen erforderlich, z. B. AS3320 (Telekom). Ein Name beweist nicht, wem die Adresse "
                  "gehört, auf die er zeigt; gescannt wird nur, wenn alle seine Adressen in diesen Netzen liegen. "
                  "Die AS-Nummer steht im ASN-Block einer Analyse.",
    )
    note = models.CharField("Notiz", max_length=200, blank=True)
    created_at = models.DateTimeField("eingetragen", auto_now_add=True)

    class Meta:
        ordering = ["value"]
        verbose_name = "Eigenes System"
        verbose_name_plural = "Eigene Systeme"

    def __str__(self):
        return self.value

    def clean(self):
        from django.core.exceptions import ValidationError

        from .ownership import parse, parse_asns

        kind, self.value = parse(self.value)
        asns = parse_asns(self.asn)
        if kind == "host" and not asns:
            raise ValidationError({"asn": "Für Hostnamen ist die AS-Nummer des Netzes erforderlich."})
        self.asn = ", ".join(sorted(asns))

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)
