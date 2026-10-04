from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class EmailBackend(ModelBackend):
    """Anmeldung mit E-Mail-Adresse (Groß-/Kleinschreibung egal).

    Der Benutzername funktioniert weiterhin, z. B. für den beim ersten Start angelegten Admin.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or password is None:
            return None
        User = get_user_model()
        user = (
            User.objects.filter(email__iexact=username).order_by("pk").first()
            or User.objects.filter(username=username).first()
        )
        if user is None:
            User().set_password(password)  # gleiche Laufzeit wie bei existierenden Nutzern
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
