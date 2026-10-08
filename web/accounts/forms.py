from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.translation import get_language

from .models import AllowedDomain

User = get_user_model()
MAX_EMAIL_LENGTH = User._meta.get_field("username").max_length


def text(german, english):
    return english if (get_language() or "de").startswith("en") else german


def check_email(email):
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH:
        raise ValidationError(text(
            f"Die E-Mail-Adresse darf höchstens {MAX_EMAIL_LENGTH} Zeichen lang sein.",
            f"The email address may contain at most {MAX_EMAIL_LENGTH} characters.",
        ))
    if not AllowedDomain.permits(email):
        raise ValidationError(text("Diese E-Mail-Domain ist nicht freigegeben.", "This email domain is not approved."))
    if User.objects.filter(email__iexact=email).exists():
        raise ValidationError(text(
            "Für diese E-Mail-Adresse gibt es bereits ein Konto.", "An account already exists for this email address."
        ))
    return email


class InvitationForm(forms.Form):
    email = forms.EmailField(label="E-Mail-Adresse")
    days = forms.IntegerField(label="Gültig (Tage)", min_value=1, max_value=60, initial=settings.INVITATION_DAYS)
    send_mail = forms.BooleanField(label="Einladung zusätzlich per E-Mail senden", required=False, initial=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].label = text("E-Mail-Adresse", "Email address")
        self.fields["days"].label = text("Gültig (Tage)", "Valid for (days)")
        self.fields["send_mail"].label = text(
            "Einladung zusätzlich per E-Mail senden", "Also send the invitation by email"
        )

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
        self.fields["password1"].label = text("Passwort", "Password")
        self.fields["password2"].label = text("Passwort wiederholen", "Repeat password")

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password1")
        if password and password != cleaned.get("password2"):
            raise ValidationError(text("Die Passwörter stimmen nicht überein.", "The passwords do not match."))
        check_email(self.email)  # Domain-Freigabe kann seit der Einladung entzogen worden sein
        if password:
            validate_password(password, user=User(username=self.email, email=self.email))
        return cleaned
