import re
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from lookups.models import Lookup

from .models import AllowedDomain, Invitation, hash_token

User = get_user_model()


def link_from(message):
    return re.search(r"https?://\S+", message.body).group(0)


class EmailLoginTests(TestCase):
    def setUp(self):
        User.objects.create_user("anna@example.org", email="anna@example.org", password="pw-sicher-123")

    def _login(self, username, password="pw-sicher-123"):
        return self.client.post(reverse("login"), {"username": username, "password": password})

    def test_login_with_email_ignores_case(self):
        self.assertRedirects(self._login("Anna@Example.ORG"), reverse("lookups:index"))

    def test_username_still_works_for_initial_admin(self):
        User.objects.create_user("admin", email="", password="pw-sicher-123")
        self.assertRedirects(self._login("admin"), reverse("lookups:index"))

    def test_inactive_user_cannot_login(self):
        User.objects.filter(email="anna@example.org").update(is_active=False)
        self.assertEqual(self._login("anna@example.org").status_code, 200)


class InvitationTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("chef@example.org", email="chef@example.org", password="x", is_staff=True)
        self.client.force_login(self.admin)

    def _invite(self, email, send_mail=True):
        data = {"email": email, "days": 7}
        if send_mail:
            data["send_mail"] = "on"
        return self.client.post(reverse("accounts:invitations"), data)

    def test_only_staff_can_invite(self):
        self.client.force_login(User.objects.create_user("normal@example.org", email="normal@example.org", password="x"))
        self.assertEqual(self.client.get(reverse("accounts:invitations")).status_code, 403)

    def test_invite_shows_link_and_qr_and_stores_only_hash(self):
        response = self._invite("Neu@Example.org")
        invitation = Invitation.objects.get()
        url = response.context["created"]["url"]
        token = url.rstrip("/").rsplit("/", 1)[-1]
        self.assertEqual(invitation.email, "neu@example.org")
        self.assertEqual(invitation.token_hash, hash_token(token))
        self.assertNotContains(response, invitation.token_hash)
        self.assertContains(response, "<svg")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(url, mail.outbox[0].body)

    def test_domain_whitelist(self):
        AllowedDomain.objects.create(domain="@Example.org")
        self.assertContains(self._invite("x@other.net"), "nicht freigegeben")
        self._invite("x@example.org")
        self.assertEqual(Invitation.objects.count(), 1)

    def test_existing_email_cannot_be_invited(self):
        self.assertContains(self._invite("CHEF@example.org"), "bereits ein Konto")

    def test_revoke(self):
        self._invite("neu@example.org", send_mail=False)
        invitation = Invitation.objects.get()
        self.client.post(reverse("accounts:revoke", args=[invitation.pk]))
        self.assertFalse(Invitation.objects.usable().exists())


class RegistrationTests(TestCase):
    def setUp(self):
        self.invitation, self.token = Invitation.create_for("neu@example.org", created_by=None)
        self.url = reverse("accounts:register", args=[self.token])

    def _register(self, password="ein-langes-passwort-42", repeat=None):
        return self.client.post(self.url, {"password1": password, "password2": repeat or password})

    def test_full_flow_register_confirm_login(self):
        response = self._register()
        self.assertContains(response, "Bestätigungsmail")
        user = User.objects.get(email="neu@example.org")
        self.assertFalse(user.is_active)

        # Einladung ist danach verbraucht
        self.assertEqual(self.client.get(self.url).status_code, 404)

        confirm = self.client.get(link_from(mail.outbox[0]))
        self.assertRedirects(confirm, reverse("login"))
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        login = self.client.post(reverse("login"), {"username": "neu@example.org", "password": "ein-langes-passwort-42"})
        self.assertRedirects(login, reverse("lookups:index"))

    def test_weak_or_mismatching_password_rejected(self):
        self.assertContains(self._register("123"), "zu kurz")
        self.assertContains(self._register("ein-langes-passwort-42", "anders-langes-passwort"), "stimmen nicht")
        self.assertFalse(User.objects.exists())

    def test_expired_or_unknown_invitation(self):
        Invitation.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.get(self.url).status_code, 404)
        self.assertEqual(self.client.get(reverse("accounts:register", args=["falsch"])).status_code, 404)

    def test_domain_removed_after_invitation(self):
        AllowedDomain.objects.create(domain="andere.org")
        self.assertContains(self._register(), "nicht freigegeben")
        self.assertFalse(User.objects.exists())

    def test_confirmation_link_works_only_once(self):
        # Ein Admin sperrt das Konto nach der Bestätigung; der alte Link darf es nicht reaktivieren.
        self._register()
        link = link_from(mail.outbox[0])
        self.client.get(link)
        User.objects.update(is_active=False)
        self.assertEqual(self.client.get(link).status_code, 400)
        self.assertFalse(User.objects.get().is_active)

    def test_tampered_confirmation_link(self):
        self._register()
        response = self.client.get(link_from(mail.outbox[0]).rstrip("/") + "x/")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.get().is_active)


class PasswordResetTests(TestCase):
    def test_reset_mail_contains_https_link(self):
        User.objects.create_user("anna@example.org", email="anna@example.org", password="x")
        self.client.post(reverse("password_reset"), {"email": "anna@example.org"}, HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(link_from(mail.outbox[0]).startswith("https://"))


class LookupVisibilityTests(TestCase):
    def setUp(self):
        self.anna = User.objects.create_user("anna@example.org", email="anna@example.org", password="x")
        self.ben = User.objects.create_user("ben@example.org", email="ben@example.org", password="x")
        self.lookup = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.anna, status="done")

    def test_users_see_only_their_own(self):
        self.client.force_login(self.ben)
        self.assertEqual(self.client.get(reverse("lookups:detail", args=[self.lookup.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("lookups:rerun", args=[self.lookup.pk])).status_code, 404)
        self.assertNotContains(self.client.get(reverse("lookups:index")), "8.8.8.8")

    def test_staff_index_with_lookup_without_owner(self):
        Lookup.objects.create(kind="ip", query="1.1.1.1", created_by=None)
        Invitation.create_for("x@example.org", created_by=None)
        self.client.force_login(User.objects.create_user("chef", password="x", is_staff=True))
        self.assertContains(self.client.get(reverse("lookups:index")), "1.1.1.1")
        self.assertContains(self.client.get(reverse("accounts:invitations")), "x@example.org")

    def test_owner_and_staff_see_it(self):
        self.client.force_login(self.anna)
        self.assertEqual(self.client.get(reverse("lookups:detail", args=[self.lookup.pk])).status_code, 200)
        self.client.force_login(User.objects.create_user("chef", password="x", is_staff=True))
        self.assertContains(self.client.get(reverse("lookups:index")), "8.8.8.8")
