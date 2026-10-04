import asyncio
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from . import llm
from .collectors import host, ip, phone
from .detect import detect
from .models import Lookup
from .templatetags.report_tags import markdown


@override_settings(OSINT_DEFAULT_REGION="DE")
class DetectTests(SimpleTestCase):
    def test_ipv4_and_ipv6(self):
        self.assertEqual(detect(" 8.8.8.8 "), ("ip", "8.8.8.8"))
        self.assertEqual(detect("[2001:DB8::1]"), ("ip", "2001:db8::1"))

    def test_phone_formats_normalize_to_e164(self):
        for raw in ("030 1234567", "0049 30 1234567", "+49 (30) 123-4567"):
            self.assertEqual(detect(raw), ("phone", "+49301234567"), raw)

    def test_hostnames_and_urls(self):
        self.assertEqual(detect("http://ABC123.MyFritz.net/"), ("host", "abc123.myfritz.net"))
        self.assertEqual(detect("example.com"), ("host", "example.com"))
        self.assertEqual(detect("https://203.0.113.7:8443/x"), ("ip", "203.0.113.7"))

    def test_garbage_is_rejected(self):
        for raw in ("hallo", "http://", "foo bar.com", ""):
            with self.assertRaises(ValueError):
                detect(raw)


class PhoneAnalyzeTests(SimpleTestCase):
    def test_berlin_landline(self):
        data = phone.analyze("+49301234567")
        self.assertEqual(data["ort_region"], "Berlin")
        self.assertEqual(data["typ"], "Festnetz")

    def test_premium_range_hint(self):
        self.assertIn("Premium", phone.analyze("+499001234567")["hinweise"][0])

    def test_search_hits_must_contain_number(self):
        variants = {"021112345678", "4921112345678"}
        hit = {"titel": "Wer ruft an?", "auszug": "Anruf von 0211 / 123-456 78 heute", "url": "https://x.example/"}
        unrelated = {"titel": "Schlüsseldienst Düsseldorf", "auszug": "Tel. 0211 999999", "url": "https://y.example/"}
        self.assertTrue(phone.mentions_number(hit, variants))
        self.assertFalse(phone.mentions_number(unrelated, variants))

    def test_ping_call_country_hint(self):
        self.assertIn("Ping-Anruf", phone.analyze("+21671123456")["hinweise"][0])


class IpTests(SimpleTestCase):
    def test_private_address_skips_external_sources(self):
        results = asyncio.run(ip.collect(client=None, ip="192.168.1.10"))
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["data"]["oeffentlich"])

    def test_cgnat_hint(self):
        self.assertIn("Carrier-Grade-NAT", ip.classify("100.64.3.4")["hinweis"])

    def test_rdap_contacts_are_flattened(self):
        entities = [{
            "roles": ["registrant"], "handle": "ORG-1",
            "vcardArray": ["vcard", [["fn", {}, "text", "Example GmbH"]]],
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]]}],
        }]
        contacts = ip._contacts(entities)
        self.assertEqual(contacts[0]["name"], "Example GmbH")
        self.assertEqual(contacts[1], {"rollen": ["abuse"], "name": None, "email": "abuse@example.net", "handle": None})


class HostTests(SimpleTestCase):
    def test_dyndns_hint_and_ip_analysis(self):
        fake = [(None, None, None, "", ("192.168.178.1", 0))]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            results = asyncio.run(host.collect(client=None, host="abc.myfritz.net"))
        dns = results[0]["data"]
        self.assertIn("FRITZ!Box", dns["hinweis"])
        self.assertEqual(dns["analysierte_adresse"], "192.168.178.1")
        self.assertEqual(results[1]["source"], "Adressklassifizierung")

    def test_unresolvable_host_is_reported(self):
        with mock.patch("socket.getaddrinfo", side_effect=OSError("Name or service not known")):
            results = asyncio.run(host.collect(client=None, host="gibtsnicht.example"))
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["ok"])


class ReportTests(SimpleTestCase):
    def test_extract_risk(self):
        self.assertEqual(llm.extract_risk("## Risikoeinschätzung\n**Risiko:** Hoch\nweil"), "hoch")
        self.assertEqual(llm.extract_risk("nichts"), "")

    def test_markdown_escapes_html(self):
        html = markdown("## Titel\n<script>alert(1)</script>")
        self.assertIn("<h2>Titel</h2>", html)
        self.assertNotIn("<script>", html)


class ViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("tester", password="pw-123456")

    def test_login_required(self):
        response = self.client.get(reverse("lookups:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_submit_creates_lookup_and_queues_task(self):
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {"q": "030 1234567"})
        lookup = Lookup.objects.get()
        self.assertRedirects(response, reverse("lookups:detail", args=[lookup.pk]))
        self.assertEqual((lookup.kind, lookup.query), ("phone", "+49301234567"))
        delay.assert_called_once_with(lookup.pk)

    def test_invalid_input_shows_error(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("lookups:index"), {"q": "quatsch"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Lookup.objects.exists())


PROXY = "10.9.9.9"


@override_settings(TRUSTED_PROXIES=[PROXY])
class LoginLockoutTests(TestCase):
    def setUp(self):
        get_user_model().objects.create_user("tester", password="pw-123456")

    def _login(self, password, ip="203.0.113.9", remote=PROXY):
        return self.client.post(
            reverse("login"), {"username": "tester", "password": password},
            REMOTE_ADDR=remote, HTTP_X_FORWARDED_FOR=ip,
        )

    def test_three_failures_lock_out_even_correct_password(self):
        for _ in range(3):
            self._login("falsch")
        response = self._login("pw-123456")
        self.assertEqual(response.status_code, 429)
        self.assertContains(response, "Zu viele Fehlversuche", status_code=429)

    def test_lockout_is_per_client_ip_behind_proxy(self):
        for _ in range(3):
            self._login("falsch", ip="203.0.113.9")
        self.assertRedirects(self._login("pw-123456", ip="198.51.100.4"), reverse("lookups:index"))

    def test_forged_forwarded_for_does_not_bypass_lockout(self):
        # Client schickt selbst wechselnde X-Forwarded-For-Werte, der Proxy hängt die echte IP an.
        for fake in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            self._login("falsch", ip=f"{fake}, 203.0.113.9")
        self.assertEqual(self._login("pw-123456", ip="4.4.4.4, 203.0.113.9").status_code, 429)

    def test_forwarded_for_ignored_without_trusted_proxy(self):
        for fake in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            self._login("falsch", ip=fake, remote="192.0.2.50")
        self.assertEqual(self._login("pw-123456", ip="4.4.4.4", remote="192.0.2.50").status_code, 429)

    def test_session_cookie_is_secure(self):
        response = self._login("pw-123456")
        self.assertTrue(response.cookies["sessionid"]["secure"])


class TaskTests(TestCase):
    def test_failed_llm_keeps_sources(self):
        from .tasks import run_lookup

        lookup = Lookup.objects.create(kind="ip", query="10.0.0.1")
        with mock.patch("lookups.tasks.llm.write_report", side_effect=RuntimeError("Ollama weg")):
            run_lookup(lookup.pk)
        lookup.refresh_from_db()
        self.assertEqual(lookup.status, Lookup.Status.FAILED)
        self.assertIn("Ollama weg", lookup.error)
        self.assertEqual(lookup.sources[0]["source"], "Adressklassifizierung")
