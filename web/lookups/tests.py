import asyncio
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from . import llm
from .collectors import bnetza, censys, history, host, ip, phone, threatintel
from .collectors import tools as tools_client
from .detect import detect, extract
from .models import Lookup, OwnedTarget
from . import historie, ownership
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
        self.assertEqual(
            [r["source"] for r in results],
            ["DNS-Auflösung", "DNS-Einträge (dig)", "WHOIS Domain (lokal)", "Adressklassifizierung"],
        )

    def test_unresolvable_host_is_reported(self):
        with mock.patch("socket.getaddrinfo", side_effect=OSError("Name or service not known")), \
                mock.patch.object(threatintel, "jobs", return_value=[]):
            results = asyncio.run(host.collect(client=None, host="gibtsnicht.example"))
        self.assertFalse(results[0]["ok"])
        self.assertNotIn("Adressklassifizierung", [r["source"] for r in results])  # ohne Adresse keine IP-Analyse


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

    def test_delete_selected_own_finished_lookups(self):
        other = get_user_model().objects.create_user("other", password="pw-123456")
        done = Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=self.user, status="done")
        kept = Lookup.objects.create(kind="ip", query="203.0.113.8", created_by=self.user, status="done")
        running = Lookup.objects.create(kind="ip", query="203.0.113.9", created_by=self.user, status="collecting")
        foreign = Lookup.objects.create(kind="ip", query="203.0.113.10", created_by=other, status="done")
        self.client.force_login(self.user)
        response = self.client.post(reverse("lookups:delete"),
                                    {"ids": [done.pk, running.pk, foreign.pk, "x"]}, follow=True)
        self.assertRedirects(response, reverse("lookups:index"))
        self.assertEqual(set(Lookup.objects.values_list("pk", flat=True)), {kept.pk, running.pk, foreign.pk})
        self.assertContains(response, "1 Analyse gelöscht.")
        self.assertContains(response, "1 laufende Analyse(n) nicht gelöscht")

    def test_note_is_saved_and_shown_in_history(self):
        lookup = Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=self.user, status="done")
        self.client.force_login(self.user)
        response = self.client.post(reverse("lookups:note", args=[lookup.pk]), {"note": "  Anruf   vom Paketdienst "})
        self.assertRedirects(response, reverse("lookups:detail", args=[lookup.pk]))
        lookup.refresh_from_db()
        self.assertEqual(lookup.note, "Anruf vom Paketdienst")
        self.assertContains(self.client.get(reverse("lookups:index")), "(Anruf vom Paketdienst)")
        self.assertContains(self.client.get(reverse("lookups:index")), '<span class="count">(1)</span>', html=False)
        self.assertContains(self.client.get(reverse("lookups:detail", args=[lookup.pk])), "Notiz bearbeiten")

    def test_note_only_for_visible_lookups(self):
        other = get_user_model().objects.create_user("other", password="pw-123456")
        lookup = Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=other, status="done")
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(reverse("lookups:note", args=[lookup.pk]), {"note": "x"}).status_code, 404)
        lookup.refresh_from_db()
        self.assertEqual(lookup.note, "")

    def test_delete_requires_post(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("lookups:delete")).status_code, 405)


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
        async def fake_searx(client, query, limit=10, pageno=1, meta=None):
            return [
                {"titel": "0211 1234567 - Bewertung", "url": "https://www.tellows.de/num/02111234567", "auszug": "Score 8"},
                {"titel": "Irgendwas", "url": "https://www.tellows.de/x", "auszug": "andere Nummer"},
            ]
        with mock.patch.object(phone.search, "searx", fake_searx), mock.patch.object(phone, "SEARCH_PAUSE", 0):
            result = asyncio.run(phone.spam_portals(None, "+492111234567"))
        self.assertEqual(len(result["tellows.de"]), 1)
        self.assertEqual(result["cleverdialer.de"], "kein Treffer")


class WebSearchTests(SimpleTestCase):
    def test_formatted_queries_sequential_and_filtered(self):
        queries = []

        async def fake_searx(client, query, limit=10, pageno=1, meta=None):
            queries.append((query, pageno))
            meta.setdefault("ok", set()).add("bing")
            meta.setdefault("gestoert", {})["google"] = "access denied"
            return [
                {"titel": "Kita Beispielstraße", "url": "https://dekanat.example/kita", "auszug": "Tel. 069 90009123"},
                {"titel": "Werbung", "url": "https://spam.example/", "auszug": "nichts"},
            ]
        with mock.patch.object(phone.search, "searx", fake_searx), mock.patch.object(phone, "SEARCH_PAUSE", 0):
            result = asyncio.run(phone.web_search(None, "+496990009123"))
        self.assertEqual([h["url"] for h in result["treffer"]], ["https://dekanat.example/kita"])
        self.assertEqual(queries, [('"069 90009123"', 1), ('"+49 69 90009123"', 1)])  # Seite 2 nur bei >= 5 Treffern
        self.assertEqual(result["suchmaschinen_mit_ergebnissen"], ["bing"])
        self.assertEqual(result["gestoerte_suchmaschinen"], {"google": "access denied"})

    def test_all_queries_failing_is_an_error(self):
        async def broken(client, query, limit=10, pageno=1, meta=None):
            raise RuntimeError("down")
        with mock.patch.object(phone.search, "searx", broken), mock.patch.object(phone, "SEARCH_PAUSE", 0), \
                self.assertRaises(RuntimeError):
            asyncio.run(phone.web_search(None, "+496990009123"))

    def test_parse_clever_dialer(self):
        page = ("<title>06990009123 &#9989; Infos zur Telefonnummer aus Frankfurt am Main</title><body>"
                "<div>3,5 von 5 Sternen &bull; 12 Bewertungen</div><p>Anrufe letzte 30 Tage: 40</p>"
                "<p>Blockierte Anrufe letzte 30 Tage: 7</p></body>")
        self.assertEqual(phone.parse_clever_dialer(page), {
            "ort": "Frankfurt am Main", "sterne": 3.5, "bewertungen": 12,
            "anrufe_letzte_30_tage": 40, "blockiert_letzte_30_tage": 7,
        })

    def test_fundstellen_only_from_search_sources(self):
        from .templatetags.report_tags import fundstellen
        sources = [
            {"source": "Websuche (SearXNG)", "ok": True, "data": {"treffer": [{"titel": "A", "url": "https://a.example/"}],
                                                                  "suchmaschinen_mit_ergebnissen": ["bing"]}},
            {"source": "Spam-Portale und Telefonbücher (Websuche)", "ok": True,
             "data": {"tellows.de": [{"titel": "B", "url": "https://www.tellows.de/num/1"}], "werruft.info": "kein Treffer"}},
            {"source": "abuse.ch URLhaus", "ok": True, "data": {"urls": [{"url": "http://malware.example/x.exe"}]}},
            {"source": "Websuche (SearXNG)", "ok": True, "data": [{"titel": "js", "url": "javascript:alert(1)"}]},
        ]
        self.assertEqual([h["url"] for h in fundstellen(sources)], ["https://a.example/", "https://www.tellows.de/num/1"])


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


class LiveUpdateTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("anna", password="x")
        self.lookup = Lookup.objects.create(
            kind="ip", query="8.8.8.8", created_by=self.user, status=Lookup.Status.COLLECTING,
            sources=[{"source": "Reverse DNS", "ok": True, "data": {"ptr": "dns.google"}}],
        )
        self.url = reverse("lookups:status", args=[self.lookup.pk])

    def test_status_returns_fragments_and_sources(self):
        self.client.force_login(self.user)
        data = self.client.get(self.url).json()
        self.assertTrue(data["running"])
        self.assertEqual([s["key"] for s in data["sources"]], ["Reverse DNS"])
        self.assertIn("1 Quelle abgefragt", data["fragments"]["progress"]["html"])
        self.assertEqual(data["fragments"]["actions"]["html"].strip(), "")  # läuft noch: keine Buttons

    def test_unchanged_revision_skips_rendering(self):
        self.client.force_login(self.user)
        rev = self.client.get(self.url).json()["rev"]
        self.assertEqual(self.client.get(self.url, {"rev": rev}).json(), {"running": True, "rev": rev, "unchanged": True})

    def test_new_source_and_finish_change_revision(self):
        self.client.force_login(self.user)
        rev = self.client.get(self.url).json()["rev"]
        self.lookup.sources.append({"source": "RDAP", "ok": True, "data": {}})
        self.lookup.save()
        self.assertNotEqual(self.client.get(self.url, {"rev": rev}).json()["rev"], rev)
        Lookup.objects.filter(pk=self.lookup.pk).update(status="done", report_md="## Kurzfazit\nok")
        done = self.client.get(self.url).json()
        self.assertFalse(done["running"])
        self.assertIn("Kurzfazit", done["fragments"]["report"]["html"])
        self.assertIn("Als PDF", done["fragments"]["actions"]["html"])

    def test_other_user_and_anonymous_are_refused(self):
        self.assertEqual(self.client.get(self.url).status_code, 302)
        self.client.force_login(get_user_model().objects.create_user("ben", password="x"))
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_detail_page_polls_only_while_running(self):
        self.client.force_login(self.user)
        running = self.client.get(reverse("lookups:detail", args=[self.lookup.pk]))
        self.assertContains(running, 'data-running="1"')
        self.assertContains(running, "lookups/live.")
        Lookup.objects.filter(pk=self.lookup.pk).update(status="done")
        done = self.client.get(reverse("lookups:detail", args=[self.lookup.pk]))
        self.assertNotContains(done, 'data-running="1"')
        self.assertNotContains(done, "lookups/live.")


class ProgressTests(SimpleTestCase):
    def test_run_source_reports_each_result(self):
        from .collectors import _on_result, run_source
        got = []

        async def callback(result):
            got.append((result["source"], result["ok"]))

        async def go():
            _on_result.set(callback)
            await run_source("A", lambda: 1)
            await run_source("B", lambda: 1 / 0)

        asyncio.run(go())
        self.assertEqual(got, [("A", True), ("B", False)])


class IncrementalSaveTests(TransactionTestCase):
    def test_sources_are_stored_as_they_finish(self):
        from .tasks import run_lookup
        lookup = Lookup.objects.create(kind="ip", query="8.8.8.8")
        seen = []

        def stored():
            try:
                return len(Lookup.objects.get(pk=lookup.pk).sources)
            finally:
                connection.close()  # sonst blockiert die offene Verbindung das Aufräumen der Test-Datenbank

        async def fake_collect(kind, query, on_result=None, **kwargs):
            await on_result({"source": "A", "ok": True, "data": 1})
            seen.append(await asyncio.to_thread(stored))
            await on_result({"source": "B", "ok": True, "data": 2})
            seen.append(await asyncio.to_thread(stored))
            return [{"source": "A", "ok": True, "data": 1}, {"source": "B", "ok": True, "data": 2}]

        with mock.patch("lookups.tasks.collect", fake_collect), \
                mock.patch("lookups.tasks.llm.write_report", return_value="## Kurzfazit\nRisiko: niedrig"):
            run_lookup(lookup.pk)
        lookup.refresh_from_db()
        self.assertEqual(seen, [1, 2])
        self.assertEqual(lookup.status, Lookup.Status.DONE)
        self.assertEqual(len(lookup.sources), 2)



@override_settings(OSINT_TOOLS_URL="http://tools:8000", OSINT_TOOLS_TOKEN="geheim")
class ToolsClientTests(SimpleTestCase):
    def _client(self, handler):
        import httpx
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    def test_call_sends_token_and_params(self):
        import json
        seen = {}

        def handler(request):
            seen.update(auth=request.headers["Authorization"], body=json.loads(request.content), url=str(request.url))
            return __import__("httpx").Response(200, json={"ok": True, "data": {"asn": ["AS1"]}})

        async def go():
            async with self._client(handler) as client:
                return await tools_client.asn(client, "8.8.8.8")

        self.assertEqual(asyncio.run(go()), {"asn": ["AS1"]})
        self.assertEqual(seen["auth"], "Bearer geheim")
        self.assertEqual(seen["body"], {"tool": "asn", "ip": "8.8.8.8"})
        self.assertEqual(seen["url"], "http://tools:8000/run")

    def test_refusal_and_errors_become_runtime_errors(self):
        import httpx

        def handler(request):
            return httpx.Response(400, json={"ok": False, "error": "192.168.1.1 ist keine öffentliche Adresse"})

        async def go():
            async with self._client(handler) as client:
                await tools_client.tls(client, "192.168.1.1")

        with self.assertRaisesMessage(RuntimeError, "keine öffentliche Adresse"):
            asyncio.run(go())

    @override_settings(OSINT_TOOLS_TOKEN="")
    def test_missing_token_is_reported(self):
        async def go():
            await tools_client.whois(None, "8.8.8.8")

        with self.assertRaisesMessage(RuntimeError, "TOOLS_TOKEN"):
            asyncio.run(go())

    def test_job_lists_by_level(self):
        passive = [job[0] for job in tools_client.passive_ip_jobs(None, "8.8.8.8")]
        active = tools_client.active_ip_jobs(None, "8.8.8.8", "example.com")
        self.assertEqual(passive, ["WHOIS (lokal)", "ASN und Netzbetreiber (dig, Team Cymru)"])
        self.assertEqual([job[0] for job in active], [
            "TLS-Zertifikat (openssl, Port 443)", "Web-Kopfzeilen (curl, Port 443)", "Web-Kopfzeilen (curl, Port 80)"])
        self.assertTrue(all(job[4] == "example.com" for job in active))  # SNI wird durchgereicht

    def test_collectors_add_active_jobs_only_on_request(self):
        names = {}

        async def fake_run_source(name, fn, *args):
            names.setdefault("all", []).append(name)
            return {"source": name, "ok": True, "data": {}}

        for active in (False, True):
            names.clear()
            with mock.patch.object(ip, "run_source", fake_run_source):
                asyncio.run(ip.collect(None, "8.8.8.8", active=active))
            self.assertEqual(any("TLS-Zertifikat" in n for n in names["all"]), active, active)
            self.assertTrue(any(n.startswith("WHOIS") for n in names["all"]))


class ActiveProbeTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user("chef", password="x", is_staff=True)
        self.normal = get_user_model().objects.create_user("anna", password="x")

    def _submit(self, user, **extra):
        self.client.force_login(user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:index"), {"q": "8.8.8.8", **extra})
        return Lookup.objects.latest("pk")

    def test_staff_can_enable_active_probe(self):
        self.assertTrue(self._submit(self.staff, active="on").active_probe)
        self.assertFalse(self._submit(self.staff).active_probe)

    def test_normal_users_cannot_enable_it(self):
        self.assertFalse(self._submit(self.normal, active="on").active_probe)

    def test_checkbox_only_for_staff(self):
        self.client.force_login(self.staff)
        self.assertContains(self.client.get(reverse("lookups:index")), 'name="active"')
        self.client.force_login(self.normal)
        self.assertNotContains(self.client.get(reverse("lookups:index")), 'name="active"')

    def test_rerun_keeps_the_level_and_meta_shows_it(self):
        first = self._submit(self.staff, active="on")
        self.client.force_login(self.staff)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[first.pk]))
        again = Lookup.objects.latest("pk")
        self.assertNotEqual(again.pk, first.pk)
        self.assertTrue(again.active_probe)
        self.assertContains(self.client.get(reverse("lookups:detail", args=[again.pk])), "leise aktiv")

    def test_task_passes_level_to_collectors(self):
        from .tasks import run_lookup
        lookup = Lookup.objects.create(kind="ip", query="8.8.8.8", active_probe=True)
        seen = {}

        async def fake_collect(kind, query, on_result=None, **kwargs):
            seen.update(kwargs)
            return []

        with mock.patch("lookups.tasks.collect", fake_collect), \
                mock.patch("lookups.tasks.llm.write_report", return_value="Risiko: niedrig"):
            run_lookup(lookup.pk)
        self.assertTrue(seen["active"])
        self.assertFalse(seen["scan"])


class PromptBudgetTests(SimpleTestCase):
    def test_one_large_source_does_not_push_out_the_others(self):
        sources = [
            {"source": "WHOIS (lokal)", "ok": True, "data": {"x": "a" * 20000}},
            {"source": "TLS-Zertifikat (openssl, Port 443)", "ok": True, "data": {"inhaber": "CN = kita.example"}},
        ]
        prompt = llm.build_prompt("ip", "8.8.8.8", sources)
        self.assertIn("kita.example", prompt)
        self.assertIn("gekürzt", prompt)
        self.assertLess(len(prompt), 6000)



class OwnedTargetTests(TestCase):
    def test_parse_accepts_public_hosts_and_small_networks(self):
        self.assertEqual(ownership.parse(" 8.8.8.8 "), ("net", "8.8.8.8/32"))
        self.assertEqual(ownership.parse("8.8.8.0/24"), ("net", "8.8.8.0/24"))
        self.assertEqual(ownership.parse("Mein.Server.Example.ORG."), ("host", "mein.server.example.org"))

    def test_parse_rejects_private_huge_and_garbage(self):
        from django.core.exceptions import ValidationError
        for value in ("192.168.1.0/24", "10.0.0.5", "127.0.0.1", "8.0.0.0/8", "0.0.0.0/0", "::/0", "localhost", "a b", ""):
            with self.assertRaises(ValidationError, msg=value):
                ownership.parse(value)

    def test_is_owned(self):
        OwnedTarget.objects.create(value="8.8.8.0/24")
        OwnedTarget.objects.create(value="Mein.Example.org", asn="as64500")
        self.assertTrue(ownership.is_owned("ip", "8.8.8.8"))
        self.assertFalse(ownership.is_owned("ip", "8.8.9.8"))
        self.assertTrue(ownership.is_owned("host", "mein.example.org"))
        self.assertFalse(ownership.is_owned("host", "sub.mein.example.org"))  # keine Subdomains
        self.assertFalse(ownership.is_owned("phone", "+4930123456"))


class PortScanTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user("chef", password="x", is_staff=True)
        self.normal = get_user_model().objects.create_user("anna", password="x")
        OwnedTarget.objects.create(value="8.8.8.8")

    def _submit(self, user, q="8.8.8.8", **extra):
        self.client.force_login(user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            return self.client.post(reverse("lookups:index"), {"q": q, **extra})

    def test_staff_can_scan_own_system(self):
        self._submit(self.staff, scan="on")
        self.assertTrue(Lookup.objects.get().port_scan)

    def test_foreign_target_is_refused_without_creating_a_lookup(self):
        response = self._submit(self.staff, q="1.1.1.1", scan="on")
        self.assertContains(response, "nicht als eigenes System eingetragen", status_code=400)
        self.assertFalse(Lookup.objects.exists())

    def test_normal_users_cannot_scan_and_phones_never(self):
        self._submit(self.normal, scan="on")
        self.assertFalse(Lookup.objects.get().port_scan)
        Lookup.objects.all().delete()
        self._submit(self.staff, q="030 1234567", scan="on")
        self.assertFalse(Lookup.objects.get().port_scan)

    def test_form_offers_scan_only_to_staff(self):
        self.client.force_login(self.staff)
        self.assertContains(self.client.get(reverse("lookups:index")), 'name="scan"')
        self.client.force_login(self.normal)
        self.assertNotContains(self.client.get(reverse("lookups:index")), 'name="scan"')

    def test_task_rechecks_ownership_and_skips_scan(self):
        from .tasks import run_lookup
        lookup = Lookup.objects.create(kind="ip", query="1.1.1.1", port_scan=True)  # nicht in der Liste
        seen = {}

        async def fake_collect(kind, query, on_result=None, **kwargs):
            seen.update(kwargs)
            return []

        with mock.patch("lookups.tasks.collect", fake_collect), \
                mock.patch("lookups.tasks.llm.write_report", return_value="Risiko: niedrig"):
            run_lookup(lookup.pk)
        lookup.refresh_from_db()
        self.assertFalse(seen["scan"])
        self.assertIn("nicht (mehr) als eigenes System", lookup.sources[-1]["error"])

    def test_task_scans_owned_target(self):
        from .tasks import run_lookup
        lookup = Lookup.objects.create(kind="ip", query="8.8.8.8", port_scan=True)
        seen = {}

        async def fake_collect(kind, query, on_result=None, **kwargs):
            seen.update(kwargs)
            return []

        with mock.patch("lookups.tasks.collect", fake_collect), \
                mock.patch("lookups.tasks.llm.write_report", return_value="Risiko: niedrig"):
            run_lookup(lookup.pk)
        self.assertTrue(seen["scan"])

    def test_scan_job_only_when_requested_and_long_timeout(self):
        names = []

        async def fake_run_source(name, fn, *args):
            names.append(name)
            return {"source": name, "ok": True, "data": {}}

        for scan in (False, True):
            names.clear()
            with mock.patch.object(ip, "run_source", fake_run_source):
                asyncio.run(ip.collect(None, "8.8.8.8", scan=scan))
            self.assertEqual(any(n.startswith("Portscan") for n in names), scan)

    @override_settings(OSINT_TOOLS_URL="http://tools:8000", OSINT_TOOLS_TOKEN="t")
    def test_scan_call_waits_long_enough(self):
        import httpx
        seen = {}

        def handler(request):
            seen["timeout"] = request.extensions["timeout"]["read"]
            return httpx.Response(200, json={"ok": True, "data": {"offen": []}})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await tools_client.scan(client, "8.8.8.8")

        self.assertEqual(asyncio.run(go()), {"offen": []})
        self.assertEqual(seen["timeout"], 300)


class RiskFloorTests(SimpleTestCase):
    SCAN_MITTEL = [{"source": "Portscan (nmap, Top-1000-Ports)", "ok": True,
                    "data": {"auffaellig": [{"port": 22, "stufe": "mittel", "hinweis": "SSH"}]}}]
    SCAN_HOCH = [{"source": "Portscan (nmap, Top-1000-Ports)", "ok": True,
                  "data": {"auffaellig": [{"port": 22, "stufe": "mittel"}, {"port": 6379, "stufe": "hoch"}]}}]

    def test_low_risk_is_raised_and_text_adjusted(self):
        report, risk = llm.apply_risk_floor("## Risikoeinschätzung\nRisiko: niedrig\nAlles gut.", "niedrig", self.SCAN_HOCH)
        self.assertEqual(risk, "hoch")
        self.assertIn("Risiko: hoch (angehoben wegen offener Ports", report)
        self.assertNotIn("Risiko: niedrig", report)

    def test_higher_model_risk_is_kept(self):
        report, risk = llm.apply_risk_floor("Risiko: hoch\nx", "hoch", self.SCAN_MITTEL)
        self.assertEqual((report, risk), ("Risiko: hoch\nx", "hoch"))

    def test_without_scan_or_findings_nothing_changes(self):
        for sources in ([], [{"source": "Portscan (nmap, Top-1000-Ports)", "ok": True, "data": {"auffaellig": []}}],
                        [{"source": "Portscan (nmap, Top-1000-Ports)", "ok": False, "error": "x"}]):
            self.assertEqual(llm.apply_risk_floor("Risiko: niedrig", "niedrig", sources), ("Risiko: niedrig", "niedrig"))

    def test_missing_risk_line_gets_note_appended(self):
        report, risk = llm.apply_risk_floor("Bericht ohne Zeile", "", self.SCAN_MITTEL)
        self.assertEqual(risk, "mittel")
        self.assertTrue(report.endswith("siehe Portscan)"))


class ScanDisplayTests(TestCase):
    def test_detail_and_pdf_show_open_ports_and_flags(self):
        user = get_user_model().objects.create_user("anna", password="x")
        lookup = Lookup.objects.create(
            kind="ip", query="8.8.8.8", created_by=user, status=Lookup.Status.DONE, port_scan=True,
            sources=[{"source": "Portscan (nmap, Top-1000-Ports)", "ok": True, "data": {
                "profil": "Top-1000", "anzahl_offen": 2, "gefiltert": 0, "geschlossen": 998, "dauer_s": 31.4,
                "offen": [{"port": 22, "proto": "tcp", "dienst": "ssh", "produkt": "OpenSSH", "version": "8.4p1"},
                          {"port": 443, "proto": "tcp", "dienst": "https", "tunnel": "ssl"}],
                "auffaellig": [{"port": 22, "stufe": "mittel", "hinweis": "SSH aus dem Internet erreichbar"}],
            }}],
        )
        self.client.force_login(user)
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, "SSH aus dem Internet erreichbar")
        self.assertContains(page, "OpenSSH 8.4p1")
        self.assertContains(page, "· Portscan")
        pdf_response = self.client.get(reverse("lookups:pdf", args=[lookup.pk]))
        self.assertEqual(pdf_response["Content-Type"], "application/pdf")
        self.assertIn("scan", self.client.get(reverse("lookups:status", args=[lookup.pk])).json()["fragments"])



class HostScanScopeTests(SimpleTestCase):
    """Ein Hostname gehört dem Nutzer, die Adresse, auf die er zeigt, nicht unbedingt."""

    def _run(self, addresses, asn_by_address, allowed, scan=True):
        scanned, asn_calls = [], []

        async def fake_resolve(h):
            return {"hostname": h, "adressen": addresses}

        async def fake_ip_collect(client, address, active=False, sni=None, scan=False):
            if scan:
                scanned.append(address)
            return []

        async def fake_asn(client, address):
            asn_calls.append(address)
            return {"asn": asn_by_address[address]}

        async def go():
            with mock.patch.object(host, "resolve", fake_resolve), mock.patch.object(ip, "collect", fake_ip_collect), \
                    mock.patch.object(host.tools, "asn", fake_asn), \
                    mock.patch.object(host.tools, "dns", mock.AsyncMock(return_value={})), \
                    mock.patch.object(host.tools, "whois", mock.AsyncMock(return_value={})), \
                    mock.patch.object(host.threatintel, "jobs", return_value=[]):
                return await host.collect(None, "mein.example.org", scan=scan, scan_asns=allowed)

        results = asyncio.run(go())
        refusals = [r for r in results if r["source"] == host.SCAN_SOURCE]
        return scanned, refusals, asn_calls

    def test_address_in_allowed_network_is_scanned(self):
        scanned, refusals, _ = self._run(["91.1.2.3"], {"91.1.2.3": ["AS3320"]}, {"AS3320"})
        self.assertEqual((scanned, refusals), (["91.1.2.3"], []))

    def test_name_pointing_to_foreign_network_is_not_scanned(self):
        scanned, refusals, _ = self._run(["104.20.23.154"], {"104.20.23.154": ["AS13335"]}, {"AS3320"})
        self.assertEqual(scanned, [])
        self.assertIn("fremdes Netz", refusals[0]["error"])
        self.assertFalse(refusals[0]["ok"])

    def test_every_address_must_match_not_only_the_first(self):
        scanned, refusals, calls = self._run(
            ["91.1.2.3", "104.20.23.154"], {"91.1.2.3": ["AS3320"], "104.20.23.154": ["AS13335"]}, {"AS3320"})
        self.assertEqual(scanned, [])
        self.assertEqual(calls, ["91.1.2.3", "104.20.23.154"])
        self.assertIn("AS13335", refusals[0]["error"])

    def test_missing_network_entry_fails_closed(self):
        scanned, refusals, calls = self._run(["91.1.2.3"], {"91.1.2.3": ["AS3320"]}, set())
        self.assertEqual((scanned, calls), ([], []))
        self.assertIn("kein Netz", refusals[0]["error"])

    def test_failed_network_check_fails_closed(self):
        async def broken(client, address):
            raise RuntimeError("dig kaputt")

        async def go():
            return await host.scan_scope_problem(None, ["91.1.2.3"], {"AS3320"})

        with mock.patch.object(host.tools, "asn", broken):
            self.assertIn("fehlgeschlagen", asyncio.run(go()))

    def test_no_check_and_no_scan_without_request(self):
        scanned, refusals, calls = self._run(["104.20.23.154"], {}, set(), scan=False)
        self.assertEqual((scanned, refusals, calls), ([], [], []))


class OwnedAsnTests(TestCase):
    def test_parse_asns(self):
        self.assertEqual(ownership.parse_asns("AS3320, 3209;as3320"), {"AS3320", "AS3209"})
        self.assertEqual(ownership.parse_asns(""), set())
        from django.core.exceptions import ValidationError
        for bad in ("Telekom", "AS", "AS12x"):
            with self.assertRaises(ValidationError):
                ownership.parse_asns(bad)

    def test_hostname_entry_requires_asn_but_ip_entry_does_not(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            OwnedTarget.objects.create(value="mein.example.org")
        OwnedTarget.objects.create(value="8.8.8.8")
        entry = OwnedTarget.objects.create(value="Mein.Example.org", asn="3320, as3209")
        self.assertEqual(entry.asn, "AS3209, AS3320")

    def test_allowed_asns_lookup(self):
        OwnedTarget.objects.create(value="mein.example.org", asn="AS3320")
        self.assertEqual(ownership.allowed_asns("host", "Mein.Example.org."), {"AS3320"})
        self.assertEqual(ownership.allowed_asns("host", "anderer.example.org"), set())
        self.assertIsNone(ownership.allowed_asns("ip", "8.8.8.8"))

    def test_task_passes_allowed_networks_for_hosts(self):
        from .tasks import run_lookup
        OwnedTarget.objects.create(value="mein.example.org", asn="AS3320")
        lookup = Lookup.objects.create(kind="host", query="mein.example.org", port_scan=True)
        seen = {}

        async def fake_collect(kind, query, on_result=None, **kwargs):
            seen.update(kwargs)
            return []

        with mock.patch("lookups.tasks.collect", fake_collect), \
                mock.patch("lookups.tasks.llm.write_report", return_value="Risiko: niedrig"):
            run_lookup(lookup.pk)
        self.assertEqual((seen["scan"], seen["scan_asns"]), (True, {"AS3320"}))



CENSYS_SAMPLE = {"result": {"resource": {
    "ip": "203.0.113.5",
    "autonomous_system": {"asn": 64500, "name": "EXAMPLE-NET", "bgp_prefix": "203.0.113.0/24"},
    "location": {"country": "Germany", "city": "Berlin"},
    "dns": {"reverse_dns": {"names": ["host.example.net"]}},
    "service_count": 2,
    "services": [
        {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp", "software": [{"product": "nginx"}],
         "cert": {"names": ["example.org", "www.example.org"]}},
        {"port": 22, "protocol": "SSH", "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2"},
    ],
}}}
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM, OSINT_CENSYS_TOKEN="pat", OSINT_CENSYS_ORG_ID="org-1", OSINT_CENSYS_MONTHLY_LIMIT=2)
class CensysTests(SimpleTestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def _client(self, responses):
        import httpx
        calls = []

        def handler(request):
            calls.append(request)
            return responses.pop(0) if len(responses) > 1 else responses[0]

        return httpx.AsyncClient(transport=httpx.MockTransport(handler)), calls

    def _run(self, responses, ip="203.0.113.5"):
        client, calls = self._client(responses)

        async def go():
            async with client:
                return await censys.host(client, ip)

        return asyncio.run(go()), calls

    def test_summarize_extracts_services_and_network(self):
        summary = censys.summarize(CENSYS_SAMPLE)
        self.assertEqual((summary["as_nummer"], summary["land"], summary["reverse_dns"]), (64500, "Germany", ["host.example.net"]))
        self.assertEqual(summary["dienste"][0], {"port": 443, "protokoll": "HTTP", "transport": "tcp",
                                                 "software": ["nginx"], "zertifikat_namen": ["example.org", "www.example.org"]})
        self.assertIn("OpenSSH_9.2p1", summary["dienste"][1]["banner"])

    def test_unknown_format_is_visible_not_silent(self):
        summary = censys.summarize({"result": {"resource": {"neues_feld": 1}}})
        self.assertIn("ohne erkennbare", summary["hinweis"])
        self.assertEqual(summary["felder_der_antwort"], ["neues_feld"])

    def test_request_uses_bearer_token_org_and_accept_header(self):
        import httpx
        _, calls = self._run([httpx.Response(200, json=CENSYS_SAMPLE)])
        request = calls[0]
        self.assertEqual(str(request.url), "https://api.platform.censys.io/v3/global/asset/host/203.0.113.5")
        self.assertEqual(request.headers["Authorization"], "Bearer pat")
        self.assertEqual(request.headers["X-Organization-ID"], "org-1")
        self.assertIn("vnd.censys.api.v3.host", request.headers["Accept"])

    def test_second_lookup_comes_from_cache_without_spending_credits(self):
        import httpx
        client, calls = self._client([httpx.Response(200, json=CENSYS_SAMPLE)])

        async def go():
            async with client:
                return await censys.host(client, "203.0.113.5"), await censys.host(client, "203.0.113.5")

        first, second = asyncio.run(go())
        self.assertEqual(len(calls), 1)
        self.assertTrue(second["aus_zwischenspeicher"])
        self.assertNotIn("aus_zwischenspeicher", first)

    def test_monthly_cap_stops_further_calls(self):
        import httpx
        client, calls = self._client([httpx.Response(404)])

        async def go():
            async with client:
                for ip in ("203.0.113.5", "203.0.113.6"):
                    await censys.host(client, ip)
                await censys.host(client, "203.0.113.7")

        with self.assertRaisesMessage(RuntimeError, "Obergrenze von 2"):
            asyncio.run(go())
        self.assertEqual(len(calls), 2)

    def test_errors_are_translated(self):
        import httpx
        with self.assertRaisesMessage(RuntimeError, "lehnt den Zugang ab"):
            self._run([httpx.Response(403)])
        result, _ = self._run([httpx.Response(404)], ip="203.0.113.9")
        self.assertIn("keine Daten", result["hinweis"])

    def test_rate_limit_is_retried_once(self):
        import httpx
        with mock.patch.object(censys.asyncio, "sleep", mock.AsyncMock()):
            result, calls = self._run([httpx.Response(429), httpx.Response(200, json=CENSYS_SAMPLE)])
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["as_nummer"], 64500)

    @override_settings(OSINT_CENSYS_TOKEN="")
    def test_source_only_added_with_token(self):
        names = []

        async def fake_run_source(name, fn, *args):
            names.append(name)
            return {"source": name, "ok": True, "data": {}}

        with mock.patch.object(ip, "run_source", fake_run_source):
            asyncio.run(ip.collect(None, "8.8.8.8"))
        self.assertFalse(any("Censys" in n for n in names))
        with override_settings(OSINT_CENSYS_TOKEN="pat"), mock.patch.object(ip, "run_source", fake_run_source):
            asyncio.run(ip.collect(None, "8.8.8.8"))
        self.assertTrue(any("Censys" in n for n in names))



class HistorySourceTests(SimpleTestCase):
    DAY = __import__("datetime").date(2026, 6, 15)

    def test_routing_picks_prefixes_covering_the_day_most_specific_first(self):
        data = {"by_origin": [
            {"origin": "3320", "prefixes": [
                {"prefix": "91.0.0.0/10", "timelines": [{"starttime": "2026-05-01T00:00:00", "endtime": "2026-07-01T00:00:00"}]},
                {"prefix": "91.53.0.0/16", "timelines": [{"starttime": "2026-06-01T00:00:00", "endtime": "2026-06-30T00:00:00"}]}]},
            {"origin": "5089", "prefixes": [
                {"prefix": "91.0.0.0/8", "timelines": [{"starttime": "2022-12-30T00:00:00", "endtime": "2023-01-10T00:00:00"}]}]},
        ]}
        result = history.summarize_routing(data, self.DAY)
        self.assertEqual([e["praefix"] for e in result["angekuendigt_zum_stichtag"]], ["91.53.0.0/16", "91.0.0.0/10"])
        self.assertEqual(result["andere_ursprungs_as_im_zeitraum"][0]["as"], "AS5089")
        self.assertIsNone(result["hinweis"])

    def test_routing_without_announcement_says_so(self):
        result = history.summarize_routing({"by_origin": []}, self.DAY)
        self.assertEqual(result["angekuendigt_zum_stichtag"], [])
        self.assertIn("keine Ankündigung", result["hinweis"])

    def test_ripestat_request_is_limited_to_a_window_around_the_day(self):
        import httpx
        seen = {}

        def handler(request):
            seen.update(dict(request.url.params))
            return httpx.Response(200, json={"data": {"by_origin": []}})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await history.ripestat_routing(client, "198.51.100.190", self.DAY)

        asyncio.run(go())
        self.assertEqual((seen["resource"], seen["starttime"]), ("198.51.100.190", "2025-06-10"))
        self.assertTrue(seen["endtime"] <= __import__("datetime").date.today().isoformat())

    ROWS = [
        {"hostname": "a.example", "address": "1.2.3.4", "record_type": "A", "first": "2026-06-01T00:00:00", "last": "2026-06-20T00:00:00"},
        {"hostname": "a.example", "address": "1.2.3.5", "record_type": "A", "first": "2026-06-21T00:00:00", "last": "2026-07-02T00:00:00"},
        {"hostname": "b.example", "address": "1.2.3.4", "record_type": "A", "first": "2026-01-01T00:00:00", "last": "2026-02-01T00:00:00"},
    ]

    def test_passive_dns_for_host_gives_address_at_day_and_timeline(self):
        result = history.summarize_passive(self.ROWS[:2], self.DAY, "host")
        self.assertEqual([r["wert"] for r in result["zum_stichtag"]], ["1.2.3.4"])
        self.assertEqual([a["wert"] for a in result["alle_adressen"]], ["1.2.3.4", "1.2.3.5"])  # Wechsel sichtbar
        self.assertEqual(history.address_at(result), "1.2.3.4")

    def test_passive_dns_for_ip_lists_names_and_falls_back_to_nearest(self):
        result = history.summarize_passive(self.ROWS, self.DAY, "ip")
        self.assertEqual([r["wert"] for r in result["zum_stichtag"]], ["a.example"])
        later = history.summarize_passive(self.ROWS, __import__("datetime").date(2026, 4, 1), "ip")
        self.assertEqual(later["zum_stichtag"], [])
        self.assertIn("nächsten", later["hinweis"])
        self.assertTrue(later["naechste_eintraege"][0]["abstand_tage"] > 0)

    def test_passive_dns_empty_and_malformed_rows(self):
        self.assertIn("lückenhaft", history.summarize_passive([], self.DAY, "host")["hinweis"])
        self.assertEqual(history.summarize_passive([{"address": "1.2.3.4", "first": "kaputt"}], self.DAY, "host")["eintraege_gesamt"], 0)

    def test_host_with_stichtag_looks_up_routing_of_the_historic_address(self):
        called = []

        async def fake_passive(client, indicator, kind, day):
            return {"zum_stichtag": [{"wert": "91.1.2.3", "typ": "A"}]}

        async def fake_routing(client, address, day):
            called.append((address, day))
            return {"angekuendigt_zum_stichtag": []}

        async def fake_resolve(h):
            return {"hostname": h, "adressen": ["91.9.9.9"]}

        async def fake_ip_collect(client, address, **kwargs):
            return []

        async def go():
            with mock.patch.object(host.history, "otx_passive_dns", fake_passive), \
                    mock.patch.object(host.history, "ripestat_routing", fake_routing), \
                    mock.patch.object(host, "resolve", fake_resolve), mock.patch.object(ip, "collect", fake_ip_collect), \
                    mock.patch.object(host.tools, "dns", mock.AsyncMock(return_value={})), \
                    mock.patch.object(host.tools, "whois", mock.AsyncMock(return_value={})), \
                    mock.patch.object(host.threatintel, "jobs", return_value=[]):
                return await host.collect(None, "mein.example.org", as_of=self.DAY)

        results = asyncio.run(go())
        self.assertEqual(called, [("91.1.2.3", self.DAY)])  # nicht die heutige Adresse 91.9.9.9
        self.assertIn("RIPEstat Routing-Historie (Adresse zum Stichtag)", [r["source"] for r in results])

    def test_ip_collect_adds_history_sources_only_with_stichtag(self):
        names = []

        async def fake_run_source(name, fn, *args):
            names.append(name)
            return {"source": name, "ok": True, "data": {}}

        for as_of in (None, self.DAY):
            names.clear()
            with mock.patch.object(ip, "run_source", fake_run_source):
                asyncio.run(ip.collect(None, "8.8.8.8", as_of=as_of))
            self.assertEqual(any("RIPEstat" in n for n in names), as_of is not None)

    def test_prompt_mentions_the_stichtag(self):
        self.assertIn("Stichtag: 15.06.2026", llm.build_prompt("ip", "8.8.8.8", [], as_of=self.DAY))
        self.assertNotIn("Stichtag", llm.build_prompt("ip", "8.8.8.8", []))


class OwnHistoryTests(TestCase):
    def setUp(self):
        self.anna = get_user_model().objects.create_user("anna", password="x")
        self.ben = get_user_model().objects.create_user("ben", password="x")
        self.chef = get_user_model().objects.create_user("chef", password="x", is_staff=True)

    def _done(self, user, addresses, when):
        lookup = Lookup.objects.create(
            kind="host", query="fritz.example.net", created_by=user, status=Lookup.Status.DONE, risk="niedrig",
            sources=[{"source": "DNS-Auflösung", "ok": True, "data": {"adressen": addresses}}])
        Lookup.objects.filter(pk=lookup.pk).update(created_at=when)
        return lookup

    def _now_sources(self, addresses):
        return [{"source": "DNS-Auflösung", "ok": True, "data": {"adressen": addresses}}]

    def test_changed_address_is_reported(self):
        tz = __import__("django.utils.timezone", fromlist=["x"])
        now = tz.now()
        self._done(self.anna, ["91.0.0.1"], now - __import__("datetime").timedelta(days=3))
        self._done(self.anna, ["91.0.0.2"], now - __import__("datetime").timedelta(days=1))
        current = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.anna)
        result = historie.own_history(current, self._now_sources(["91.0.0.3"]))
        self.assertEqual(result["anzahl_frueherer_analysen"], 2)
        self.assertEqual(result["aenderungen_seit_letzter_analyse"], {"adressen": {"vorher": "91.0.0.2", "jetzt": "91.0.0.3"}})
        self.assertEqual(result["analysen"][1]["geaendert"], ["adressen"])
        self.assertNotIn("geaendert", result["analysen"][0])

    def test_missing_facts_are_not_reported_as_changes(self):
        """Lief in der früheren Analyse ein Portscan und jetzt nicht, ist das keine Änderung des Systems."""
        old = Lookup.objects.create(
            kind="host", query="fritz.example.net", created_by=self.anna, status=Lookup.Status.DONE,
            sources=[{"source": "DNS-Auflösung", "ok": True, "data": {"adressen": ["91.0.0.1"]}},
                     {"source": "Portscan (nmap, Top-1000-Ports)", "ok": True, "data": {"offen": [{"port": 22}]}}])
        current = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.anna)
        result = historie.own_history(current, self._now_sources(["91.0.0.1"]))
        self.assertEqual(result["aenderungen_seit_letzter_analyse"], {})
        self.assertEqual(old.pk, result["analysen"][0]["analyse"])

    def test_unchanged_has_no_changes_and_no_history_means_none(self):
        current = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.anna)
        self.assertIsNone(historie.own_history(current, self._now_sources(["91.0.0.1"])))
        self._done(self.anna, ["91.0.0.1"], __import__("django.utils.timezone", fromlist=["x"]).now())
        self.assertEqual(historie.own_history(current, self._now_sources(["91.0.0.1"]))["aenderungen_seit_letzter_analyse"], {})

    def test_history_contains_only_the_owners_own_analyses_even_for_staff(self):
        now = __import__("django.utils.timezone", fromlist=["x"]).now()
        self._done(self.anna, ["91.0.0.1"], now)
        self._done(self.chef, ["91.0.0.2"], now)
        by_ben = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.ben)
        by_chef = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.chef)
        by_anna = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.anna)
        self.assertIsNone(historie.own_history(by_ben, self._now_sources(["x"])))
        chef = historie.own_history(by_chef, self._now_sources(["x"]))
        self.assertEqual(chef["anzahl_frueherer_analysen"], 1)  # nur seine eigene, nicht die von anna
        self.assertEqual(chef["analysen"][0]["fakten"]["adressen"], "91.0.0.2")
        self.assertEqual(historie.own_history(by_anna, self._now_sources(["x"]))["analysen"][0]["fakten"]["adressen"], "91.0.0.1")

    def test_lookup_without_owner_gets_no_history(self):
        """Fail-closed: Ohne Eigentümer (z. B. gelöschter Nutzer) darf nicht der Verlauf aller erscheinen."""
        now = __import__("django.utils.timezone", fromlist=["x"]).now()
        self._done(self.anna, ["91.0.0.1"], now)
        ownerless = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=None)
        self.assertIsNone(historie.own_history(ownerless, self._now_sources(["x"])))

    def test_nearest_analysis_to_stichtag(self):
        import datetime
        now = __import__("django.utils.timezone", fromlist=["x"]).now()
        near = self._done(self.anna, ["91.0.0.1"], now - datetime.timedelta(days=10))
        self._done(self.anna, ["91.0.0.2"], now - datetime.timedelta(days=2))
        current = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.anna)
        stichtag = (now - datetime.timedelta(days=9)).date()
        result = historie.own_history(current, self._now_sources(["91.0.0.2"]), as_of=stichtag)
        self.assertEqual(result["naechste_zum_stichtag"]["analyse"], near.pk)
        self.assertEqual(result["naechste_zum_stichtag"]["abstand_tage"], 1)


class AsOfFormTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("anna", password="x")
        self.client.force_login(self.user)

    def _post(self, asof, q="8.8.8.8"):
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            return self.client.post(reverse("lookups:index"), {"q": q, "asof": asof})

    def test_form_has_a_date_field_limited_to_today(self):
        page = self.client.get(reverse("lookups:index"))
        self.assertContains(page, 'name="asof"')
        self.assertContains(page, f'max="{__import__("django.utils.timezone", fromlist=["x"]).localdate().isoformat()}"')

    def test_date_is_stored_shown_and_kept_on_rerun(self):
        self._post("2026-06-15")
        lookup = Lookup.objects.get()
        self.assertEqual(str(lookup.as_of), "2026-06-15")
        self.assertContains(self.client.get(reverse("lookups:detail", args=[lookup.pk])), "Stand 15.06.2026")
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[lookup.pk]))
        self.assertEqual(str(Lookup.objects.latest("pk").as_of), "2026-06-15")

    def test_empty_date_means_no_lookback(self):
        self._post("")
        self.assertIsNone(Lookup.objects.get().as_of)

    def test_invalid_and_future_dates_are_rejected(self):
        for value, message in (("morgen", "Ungültiges Datum"), ("2999-01-01", "Zukunft"), ("1999-12-31", "zu weit")):
            response = self._post(value)
            self.assertContains(response, message, status_code=400)
        self.assertFalse(Lookup.objects.exists())

    def test_task_passes_stichtag_and_attaches_history(self):
        import datetime
        from .tasks import run_lookup
        Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.user, status="done",
                              sources=[{"source": "DNS-Auflösung", "ok": True, "data": {"adressen": ["91.0.0.1"]}}])
        lookup = Lookup.objects.create(kind="host", query="fritz.example.net", created_by=self.user,
                                       as_of=datetime.date(2026, 6, 15))
        seen = {}

        async def fake_collect(kind, query, on_result=None, **kwargs):
            seen.update(kwargs)
            return [{"source": "DNS-Auflösung", "ok": True, "data": {"adressen": ["91.0.0.9"]}}]

        with mock.patch("lookups.tasks.collect", fake_collect), \
                mock.patch("lookups.tasks.llm.write_report", return_value="Risiko: niedrig") as write:
            run_lookup(lookup.pk)
        lookup.refresh_from_db()
        self.assertEqual(seen["as_of"], datetime.date(2026, 6, 15))
        self.assertEqual(write.call_args.kwargs["as_of"], datetime.date(2026, 6, 15))
        self.assertEqual(lookup.sources[-1]["source"], "Frühere eigene Analysen")
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, "Verlauf dieser Abfrage")
        self.assertContains(page, "91.0.0.9")


class OtxPassiveRequestTests(SimpleTestCase):
    def test_request_disables_compression_and_keep_alive(self):
        import httpx
        seen = {}

        def handler(request):
            seen.update(request.headers)
            return httpx.Response(200, json={"passive_dns": []})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await history.otx_passive_dns(client, "8.8.8.8", "ip", __import__("datetime").date(2026, 6, 15))

        asyncio.run(go())
        self.assertEqual((seen["accept-encoding"], seen["connection"]), ("identity", "close"))


    def test_one_timeout_is_retried_but_not_two(self):
        import httpx
        calls = []

        def flaky(request):
            calls.append(1)
            if len(calls) == 1:
                raise httpx.ReadTimeout("hängt", request=request)
            return httpx.Response(200, json={"passive_dns": []})

        def dead(request):
            raise httpx.ReadTimeout("hängt", request=request)

        async def go(handler):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await history.otx_passive_dns(client, "8.8.8.8", "ip", __import__("datetime").date(2026, 6, 15))

        self.assertEqual(asyncio.run(go(flaky))["eintraege_gesamt"], 0)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(httpx.TimeoutException):
            asyncio.run(go(dead))


class OtxReputationRequestTests(SimpleTestCase):
    def test_reputation_lookup_retries_one_timeout_without_compression(self):
        import httpx
        calls = []

        def flaky(request):
            calls.append(request.headers["accept-encoding"])
            if len(calls) == 1:
                raise httpx.ReadTimeout("hängt", request=request)
            return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}, "reputation": 0})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(flaky)) as client:
                return await threatintel.otx(client, "8.8.8.8", "ip")

        self.assertEqual(asyncio.run(go())["pulse_anzahl"], 0)
        self.assertEqual(calls, ["identity", "identity"])


class CopyButtonTests(TestCase):
    def test_every_source_and_the_whole_list_have_copy_buttons(self):
        user = get_user_model().objects.create_user("anna", password="x")
        lookup = Lookup.objects.create(
            kind="ip", query="8.8.8.8", created_by=user, status=Lookup.Status.DONE,
            sources=[{"source": "Reverse DNS", "ok": True, "data": {"ptr": "dns.google"}},
                     {"source": "RDAP", "ok": False, "error": "Timeout"}])
        self.client.force_login(user)
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, "data-copy-all")
        self.assertContains(page, "data-copy-source", count=2)
        self.assertContains(page, '<pre class="raw">')
        self.assertContains(page, 'class="error raw"')  # auch Fehlermeldungen lassen sich kopieren
        # beim Nachladen während der Recherche enthalten die Teile ebenfalls den Button
        status = self.client.get(reverse("lookups:status", args=[lookup.pk])).json()
        self.assertTrue(all("data-copy-source" in source["html"] for source in status["sources"]))
