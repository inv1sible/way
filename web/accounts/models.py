import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


class AllowedDomain(models.Model):
    domain = models.CharField(
        "Domain", max_length=253, unique=True,
        help_text="z. B. example.org. Subdomains müssen einzeln eingetragen werden. "
                  "Ist keine Domain eingetragen, ist jede Domain erlaubt.",
    )

    class Meta:
        ordering = ["domain"]
        verbose_name = "Erlaubte Domain"
        verbose_name_plural = "Erlaubte Domains"

    def __str__(self):
        return self.domain

    def save(self, *args, **kwargs):
        self.domain = self.domain.strip().lower().lstrip("@")
        super().save(*args, **kwargs)

    @classmethod
    def permits(cls, email):
        domains = set(cls.objects.values_list("domain", flat=True))
        return not domains or email.rsplit("@", 1)[-1].lower() in domains


class InvitationQuerySet(models.QuerySet):
    def usable(self):
        return self.filter(used_at__isnull=True, expires_at__gt=timezone.now())


class Invitation(models.Model):
    """Persönliche Einladung. Gespeichert wird nur der Hash des Tokens; der Link ist nach dem
    Erstellen einmal sichtbar."""

    email = models.EmailField("E-Mail")
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="+", verbose_name="erstellt von",
    )
    created_at = models.DateTimeField("erstellt", auto_now_add=True)
    expires_at = models.DateTimeField("gültig bis")
    used_at = models.DateTimeField("eingelöst", null=True, blank=True)
    confirmed_at = models.DateTimeField("E-Mail bestätigt", null=True, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="+", verbose_name="registrierter Nutzer",
    )

    objects = InvitationQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Einladung"
        verbose_name_plural = "Einladungen"

    def __str__(self):
        return self.email

    @classmethod
    def create_for(cls, email, created_by, days=None):
        token = secrets.token_urlsafe(32)
        invitation = cls.objects.create(
            email=email.lower(),
            token_hash=hash_token(token),
            created_by=created_by,
            expires_at=timezone.now() + timedelta(days=days or settings.INVITATION_DAYS),
        )
        return invitation, token

    @classmethod
    def from_token(cls, token):
        return cls.objects.usable().filter(token_hash=hash_token(token)).first()

    @property
    def status(self):
        if self.used_at:
            return "eingelöst"
        return "abgelaufen" if self.expires_at <= timezone.now() else "offen"
