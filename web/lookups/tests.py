import asyncio
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from . import llm
from .collectors import bnetza, host, ip, phone, threatintel
from .detect import detect, extract
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

    def test_ipv6_zone_is_rejected(self):
        # Zonen-Angaben könnten sonst Query-Strings in die Quell-URLs einschleusen.
        for raw in ("2001:4860::8888%?key=x&a=", "[2001:4860::8888%25abc]", "fe80::1%eth0"):
            with self.assertRaises(ValueError):
                detect(raw)

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
        with mock.patch("socket.getaddrinfo", return_value=fake), mock.patch.object(threatintel, "jobs", return_value=[]):
            results = asyncio.run(host.collect(client=None, host="abc.myfritz.net"))
        dns = results[0]["data"]
        self.assertIn("FRITZ!Box", dns["hinweis"])
        self.assertEqual(dns["analysierte_adresse"], "192.168.178.1")
        self.assertEqual(results[1]["source"], "Adressklassifizierung")

    def test_unresolvable_host_is_reported(self):
        with mock.patch("socket.getaddrinfo", side_effect=OSError("Name or service not known")), \
                mock.patch.object(threatintel, "jobs", return_value=[]):
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

    def test_ipv6_addresses_of_one_connection_share_lockout(self):
        for suffix in ("1", "2", "3"):
            self._login("falsch", ip=f"2001:db8:1:2::{suffix}")
        self.assertEqual(self._login("pw-123456", ip="2001:db8:1:2:abcd::99").status_code, 429)

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


class ExtractTests(SimpleTestCase):
    def test_finds_value_in_shared_text(self):
        cases = {
            "Verpasster Anruf von +49 211 1234567 am 04.10.2026": "+49 211 1234567",
            "Login von 203.0.113.7 um 21:43:13": "203.0.113.7",
            "Schau mal https://way.example.org/pfad?x=1": "https://way.example.org/pfad?x=1",
            "030 1234567": "030 1234567",
        }
        for text, expected in cases.items():
            self.assertEqual(extract(text), expected, text)

    def test_vcard_numbers(self):
        from .detect import vcard_text
        vcf = "BEGIN:VCARD\nFN:X\nitem1.TEL;type=CELL:+49 211 1234567\nTEL;VALUE=uri:tel:+4930123456\nEND:VCARD"
        self.assertEqual(vcard_text(vcf), "+49 211 1234567 +4930123456")
        self.assertEqual(vcard_text("nur Text"), "nur Text")

    def test_nothing_found(self):
        self.assertIsNone(extract("Hallo, wie geht's?"))


class BnetzaTests(SimpleTestCase):
    PAGE = """<table><tbody>
      <tr class="odd"><td>01.10.2026</td><td>03012345678, 03087654321</td><td>Internet PopUp</td>
          <td>Abschaltung der Rufnummern zum 08.10.2026</td></tr>
      <tr><td>30.09.2026</td><td>017612345678</td><td>Spam-Messenger</td><td>Abschaltung</td></tr>
    </tbody></table>"""

    def test_parse_table_indexes_every_number(self):
        index = bnetza.parse_table(self.PAGE)
        self.assertEqual(set(index), {"03012345678", "03087654321", "017612345678"})
        self.assertEqual(index["03087654321"][0]["kategorie"], "Internet PopUp")

    def test_check_uses_national_format(self):
        index = bnetza.parse_table(self.PAGE)
        with mock.patch.object(bnetza.cache, "aget", mock.AsyncMock(return_value=index)):
            hit = asyncio.run(bnetza.check(None, "+4917612345678"))
            miss = asyncio.run(bnetza.check(None, "+49301234567"))
        self.assertEqual(hit["treffer"][0]["kategorie"], "Spam-Messenger")
        self.assertEqual(miss["treffer"], [])


class SpamPortalTests(SimpleTestCase):
    def test_only_hits_with_number_are_kept(self):
        async def fake_searx(client, query, limit=10):
            return [
                {"titel": "0211 1234567 - Bewertung", "url": "https://www.tellows.de/num/02111234567", "auszug": "Score 8"},
                {"titel": "Irgendwas", "url": "https://www.tellows.de/x", "auszug": "andere Nummer"},
            ]
        with mock.patch.object(phone.search, "searx", fake_searx):
            result = asyncio.run(phone.spam_portals(None, "+492111234567"))
        self.assertEqual(len(result["tellows.de"]), 1)


class ThreatIntelTests(SimpleTestCase):
    @override_settings(OSINT_VIRUSTOTAL_KEY="", OSINT_ABUSECH_KEY="", OSINT_CROWDSEC_KEY="")
    def test_only_keyless_sources_without_keys(self):
        self.assertEqual([j[0] for j in threatintel.jobs(None, "8.8.8.8", "ip")], ["AlienVault OTX"])

    @override_settings(OSINT_VIRUSTOTAL_KEY="k", OSINT_ABUSECH_KEY="k", OSINT_CROWDSEC_KEY="k")
    def test_crowdsec_only_for_ips(self):
        self.assertIn("CrowdSec CTI", [j[0] for j in threatintel.jobs(None, "8.8.8.8", "ip")])
        self.assertNotIn("CrowdSec CTI", [j[0] for j in threatintel.jobs(None, "example.com", "domain")])


class PwaTests(TestCase):
    def test_manifest_and_service_worker_without_login(self):
        manifest = self.client.get("/manifest.webmanifest")
        self.assertEqual(manifest.status_code, 200)
        data = manifest.json()
        self.assertEqual(data["short_name"], "Who Are You")
        self.assertEqual(data["share_target"]["action"], reverse("lookups:share"))
        self.assertEqual(data["share_target"]["method"], "POST")
        self.assertIn(".vcf", data["share_target"]["params"]["files"][0]["accept"])
        sw = self.client.get("/service-worker")
        self.assertEqual(sw["Content-Type"], "application/javascript")
        self.assertIn(r"/\r?\n[ \t]/g", sw.content.decode())  # Escapes müssen erhalten bleiben

    def test_share_prefills_form_without_starting_lookup(self):
        self.client.force_login(get_user_model().objects.create_user("t", password="pw-123456"))
        response = self.client.get(reverse("lookups:share"), {"text": "Anruf von 0211 1234567"})
        self.assertContains(response, 'value="0211 1234567"')
        self.assertFalse(Lookup.objects.exists())

    def test_share_post_with_vcard_without_csrf_token(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from django.test import Client
        client = Client(enforce_csrf_checks=True)
        client.force_login(get_user_model().objects.create_user("t", password="pw-123456"))
        vcf = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Unbekannt\r\nTEL;TYPE=CELL:+49 176 1234\r\n 5678\r\nEND:VCARD\r\n"
        response = client.post(reverse("lookups:share"), {"files": SimpleUploadedFile("k.vcf", vcf, "text/vcard")})
        self.assertContains(response, 'value="+49 176 12345678"')
        self.assertFalse(Lookup.objects.exists())

    def test_share_requires_login(self):
        response = self.client.get(reverse("lookups:share"), {"text": "8.8.8.8"})
        self.assertEqual(response.status_code, 302)


class PdfTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("anna", password="x")
        self.lookup = Lookup.objects.create(
            kind="phone", query="+4917612345678", created_by=self.user, status=Lookup.Status.DONE, risk="hoch",
            report_md="## Kurzfazit\nGelistet.\n\n![x](http://192.0.2.1/tracker.png) ![y](file:///etc/passwd)\n<script>x</script>",
            sources=[{"source": "Bundesnetzagentur-Maßnahmenliste", "ok": True, "data": {"treffer": [{"kategorie": "Spam"}]}},
                     {"source": "Websuche (SearXNG)", "ok": False, "error": "Timeout"}],
        )

    def test_owner_gets_pdf_download(self):
        self.client.force_login(self.user)
        from . import pdf
        with mock.patch.object(pdf, "block_external", wraps=pdf.block_external) as blocker:
            response = self.client.get(reverse("lookups:pdf", args=[self.lookup.pk]))
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertIn('filename="way-phone-+4917612345678-', response["Content-Disposition"])
        # Das Markdown-Bild ging an den Blocker statt ans Netz
        self.assertIn("http://192.0.2.1/tracker.png", [c.args[0] for c in blocker.call_args_list])

    def test_external_resources_are_blocked(self):
        from . import pdf
        fetcher = pdf.BlockingFetcher(allowed_protocols=())
        for url in ("http://192.0.2.1/tracker.png", "file:///etc/passwd", "data:text/plain,x"):
            with self.assertRaises(ValueError):
                fetcher.fetch(url)
        # file:-Links verwirft schon der Markdown-Renderer
        self.assertNotIn('src="file:', markdown("![y](file:///etc/passwd)"))

    def test_other_users_cannot_download(self):
        self.client.force_login(get_user_model().objects.create_user("ben", password="x"))
        self.assertEqual(self.client.get(reverse("lookups:pdf", args=[self.lookup.pk])).status_code, 404)

    def test_running_lookup_redirects(self):
        Lookup.objects.filter(pk=self.lookup.pk).update(status=Lookup.Status.ANALYZING)
        self.client.force_login(self.user)
        self.assertRedirects(
            self.client.get(reverse("lookups:pdf", args=[self.lookup.pk])),
            reverse("lookups:detail", args=[self.lookup.pk]), fetch_redirect_response=False,
        )


class InterruptedLookupTests(TestCase):
    def test_running_lookups_fail_on_worker_start(self):
        from .tasks import fail_interrupted_lookups
        running = Lookup.objects.create(kind="ip", query="1.1.1.1", status=Lookup.Status.ANALYZING)
        queued = Lookup.objects.create(kind="ip", query="8.8.8.8", status=Lookup.Status.PENDING)
        fail_interrupted_lookups()
        running.refresh_from_db(); queued.refresh_from_db()
        self.assertEqual(running.status, Lookup.Status.FAILED)
        self.assertEqual(queued.status, Lookup.Status.PENDING)  # steht noch in der Warteschlange
