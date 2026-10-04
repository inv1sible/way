from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import AllowedDomain

User = get_user_model()
MAX_EMAIL_LENGTH = User._meta.get_field("username").max_length


def check_email(email):
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH:
        raise ValidationError(f"Die E-Mail-Adresse darf höchstens {MAX_EMAIL_LENGTH} Zeichen lang sein.")
    if not AllowedDomain.permits(email):
        raise ValidationError("Diese E-Mail-Domain ist nicht freigegeben.")
    if User.objects.filter(email__iexact=email).exists():
        raise ValidationError("Für diese E-Mail-Adresse gibt es bereits ein Konto.")
    return email


class InvitationForm(forms.Form):
    email = forms.EmailField(label="E-Mail-Adresse")
    days = forms.IntegerField(label="Gültig (Tage)", min_value=1, max_value=60, initial=settings.INVITATION_DAYS)
    send_mail = forms.BooleanField(label="Einladung zusätzlich per E-Mail senden", required=False, initial=True)

    def clean_email(self):
        return check_email(self.cleaned_data["email"])


class RegistrationForm(forms.Form):
    password1 = forms.CharField(label="Passwort", widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    password2 = forms.CharField(
        label="Passwort wiederholen", widget=forms.PasswordInput(attrs={"autocomplete": "new-password"})
    )

    def __init__(self, *args, email, **kwargs):
        super().__init__(*args, **kwargs)
        self.email = email

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password1")
        if password and password != cleaned.get("password2"):
            raise ValidationError("Die Passwörter stimmen nicht überein.")
        check_email(self.email)  # Domain-Freigabe kann seit der Einladung entzogen worden sein
        if password:
            validate_password(password, user=User(username=self.email, email=self.email))
        return cleaned
