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
