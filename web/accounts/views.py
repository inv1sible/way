import logging

import segno
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_not_required
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db import transaction
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST

from .forms import InvitationForm, RegistrationForm
from .models import AllowedDomain, Invitation

log = logging.getLogger(__name__)
User = get_user_model()
CONFIRM_SALT = "accounts.email-confirm"


def _require_staff(request):
    if not request.user.is_staff:
        raise PermissionDenied


def _mail(subject, template, context, to):
    """Versendet eine Mail; Fehler werden geloggt und als False gemeldet statt die Seite abzubrechen."""
    try:
        send_mail(subject, render_to_string(template, context), None, [to])
    except Exception:
        log.exception("Mailversand an %s fehlgeschlagen", to)
        return False
    return True


def invitations(request):
    _require_staff(request)
    form = InvitationForm(request.POST or None)
    created = None
    if request.method == "POST" and form.is_valid():
        invitation, token = Invitation.create_for(form.cleaned_data["email"], request.user, form.cleaned_data["days"])
        url = request.build_absolute_uri(reverse("accounts:register", args=[token]))
        mailed = form.cleaned_data["send_mail"] and _mail(
            "Einladung zum OSINT-Agent",
            "accounts/email/invitation.txt",
            {"url": url, "invitation": invitation, "inviter": request.user},
            invitation.email,
        )
        created = {
            "invitation": invitation,
            "url": url,
            "qr": mark_safe(segno.make(url, error="m").svg_inline(scale=5, border=2)),
            "mailed": mailed,
            "mail_failed": form.cleaned_data["send_mail"] and not mailed,
        }
        form = InvitationForm()
    return render(request, "accounts/invitations.html", {
        "form": form,
        "created": created,
        "invitations": Invitation.objects.select_related("created_by", "user")[:100],
        "domains": AllowedDomain.objects.all(),
    })


@require_POST
def revoke(request, pk):
    _require_staff(request)
    Invitation.objects.usable().filter(pk=pk).update(expires_at=timezone.now())
    messages.info(request, "Einladung widerrufen.")
    return redirect("accounts:invitations")


@login_not_required
def register(request, token):
    invitation = Invitation.from_token(token)
    if invitation is None:
        return render(request, "accounts/invalid.html", {
            "title": "Einladung ungültig",
            "text": "Dieser Einladungslink ist ungültig, abgelaufen oder wurde bereits verwendet.",
        }, status=404)

    form = RegistrationForm(request.POST or None, email=invitation.email)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            locked = Invitation.objects.select_for_update().usable().filter(pk=invitation.pk).first()
            if locked is None:
                return redirect("accounts:register", token=token)
            user = User.objects.create_user(
                username=invitation.email, email=invitation.email,
                password=form.cleaned_data["password1"], is_active=False,
            )
            locked.used_at, locked.user = timezone.now(), user
            locked.save(update_fields=["used_at", "user"])
        confirm_url = request.build_absolute_uri(
            reverse("accounts:confirm", args=[signing.dumps(user.pk, salt=CONFIRM_SALT)])
        )
        mailed = _mail(
            "OSINT-Agent: E-Mail-Adresse bestätigen",
            "accounts/email/confirm.txt",
            {"url": confirm_url, "days": settings.EMAIL_CONFIRM_DAYS},
            user.email,
        )
        return render(request, "accounts/registered.html", {"email": user.email, "mailed": mailed})
    return render(request, "accounts/register.html", {"form": form, "invitation": invitation})


@login_not_required
def confirm(request, token):
    try:
        pk = signing.loads(token, salt=CONFIRM_SALT, max_age=settings.EMAIL_CONFIRM_DAYS * 24 * 3600)
    except signing.BadSignature:
        return render(request, "accounts/invalid.html", {
            "title": "Bestätigung fehlgeschlagen",
            "text": "Der Bestätigungslink ist ungültig oder abgelaufen. Bitte wende dich an einen Admin.",
        }, status=400)
    User.objects.filter(pk=pk, is_active=False).update(is_active=True)
    messages.success(request, "E-Mail-Adresse bestätigt. Du kannst dich jetzt anmelden.")
    return redirect("login")
