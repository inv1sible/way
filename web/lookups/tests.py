import asyncio
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone, translation

from . import llm
from .collectors import bnetza, censys, email, fritzbox, geoip, history, host, ip, ipinfo, netlas, phone, router, shodan, speedport, threatintel
from .collectors import tools as tools_client
from .detect import detect, extract
from .models import Lookup
from . import geo, historie
from .templatetags.report_tags import fundstellen, markdown, report_parts


@override_settings(OSINT_DEFAULT_REGION="DE")
class DetectTests(SimpleTestCase):
    def test_email_normalizes_case(self):
        self.assertEqual(detect("  User.Name+tag@Example.ORG "), ("email", "user.name+tag@example.org"))
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


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
                   OSINT_HIBP_KEY="a" * 32, OSINT_GOOGLE_CSE_API_KEY="", OSINT_GOOGLE_CSE_ID="")
class EmailExposureTests(SimpleTestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_hibp_returns_breach_metadata_without_pastes(self):
        import httpx
        observed = {}

        def handler(request):
            observed.update({"url": str(request.url), "headers": dict(request.headers)})
            return httpx.Response(200, json=[{"Name": "Example", "Title": "Example breach", "Domain": "example.org",
                                              "BreachDate": "2025-01-01", "DataClasses": ["Email addresses"],
                                              "Description": "must not be kept"}])

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await email.hibp(client, "person@example.org")

        result = asyncio.run(go())
        self.assertEqual(result["breaches"][0]["Name"], "Example")
        self.assertNotIn("Description", result["breaches"][0])
        self.assertIn("breachedaccount/person%40example.org", observed["url"])
        self.assertNotIn("paste", observed["url"])
        self.assertEqual(observed["headers"]["hibp-api-key"], "a" * 32)

    def test_hibp_404_is_normal_negative_result(self):
        import httpx

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404))) as client:
                return await email.hibp(client, "person@example.org")

        self.assertEqual(asyncio.run(go())["breaches"], [])

    def test_google_cse_uses_provider_exact_terms_and_limits_results(self):
        import httpx
        observed = {}

        def handler(request):
            observed.update(dict(request.url.params))
            return httpx.Response(200, json={"items": [
                {"title": "Exact result", "link": "https://example.org/contact", "snippet": "Contact"},
                {"title": "Public profile", "link": "https://github.com/example/contact", "snippet": "Contact"},
            ]})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                with override_settings(OSINT_GOOGLE_CSE_API_KEY="test-key", OSINT_GOOGLE_CSE_ID="test-cx"):
                    return await email.google_exact_search(client, "person@example.org")

        result = asyncio.run(go())
        self.assertEqual(observed["q"], "person@example.org")
        self.assertEqual(observed["exactTerms"], "person@example.org")
        self.assertEqual(observed["cx"], "test-cx")
        self.assertEqual([item["url"] for item in result["references"]],
                         ["https://example.org/contact", "https://github.com/example/contact"])
        self.assertTrue(result["references"][0]["exact_phrase_required"])
        self.assertNotIn("test-key", str(result))

    @override_settings(OSINT_HIBP_KEY="")
    def test_missing_key_is_capability_status(self):
        result = asyncio.run(email.collect(None, "person@example.org"))
        self.assertFalse(result[-1]["ok"])
        self.assertIn("Nicht konfiguriert", result[-1]["error"])

    def test_public_web_keeps_exact_public_search_references_only(self):
        queries = []

        async def fake_searx(client, query, limit=10, pageno=1, meta=None, language="de"):
            meta.update({"ok": {"bing"}, "gestoert": {"qwant": "CAPTCHA"}})
            queries.append((query, language))
            return [
                {"url": "https://example.org/contact", "titel": "Contact", "auszug": "person@example.org"},
                {"url": "https://linkedin.com/in/person", "titel": "person@example.org", "auszug": ""},
                {"url": "https://example.net", "titel": "Unrelated", "auszug": "No address here"},
            ]

        with mock.patch.object(email.search, "searx", fake_searx):
            result = asyncio.run(email.public_web_search(None, "person@example.org"))
        self.assertEqual(queries, [('"person@example.org"', "all")])
        self.assertEqual(result["references"], [
            {"url": "https://example.org/contact", "titel": "Contact", "fundstelle": "person@example.org"},
            {"url": "https://linkedin.com/in/person", "titel": "person@example.org", "fundstelle": None},
        ])
        self.assertEqual([item["url"] for item in result["suchergebnisse_zur_pruefung"]], [
            "https://example.org/contact", "https://linkedin.com/in/person", "https://example.net",
        ])
        self.assertEqual(result["suchmaschinen_mit_ergebnissen"], ["bing"])
        self.assertEqual(result["suchmaschinen"], ["bing", "qwant"])
        self.assertNotIn("grenzen", result)
        from urllib.parse import parse_qs, urlsplit
        for link in result["suchlinks"]:
            self.assertEqual(parse_qs(urlsplit(link["url"]).query)["q"], ['"person@example.org"'])

    def test_complete_email_survives_http_encoding_and_results_keep_engine_attribution(self):
        import httpx
        requests = []
        address = "person+tag@example.org"
        query = f'"{address}"'

        def handler(request):
            requests.append(dict(request.url.params))
            return httpx.Response(200, json={"query": query, "results": [
                {"title": "Contact", "url": "https://github.com/example/contact", "content": address,
                 "engines": ["google cse", "bing"]},
                {"title": "Other person", "url": "https://example.net", "content": "person", "engines": ["bing"]},
            ]})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await email.public_web_search(client, address)

        result = asyncio.run(go())
        self.assertEqual(requests[0]["q"], query)
        self.assertEqual(requests[0]["language"], "all")
        self.assertEqual(requests[0]["categories"], "general")
        self.assertEqual(result["searxng_empfangene_suchanfrage"], query)
        self.assertEqual(result["suchergebnisse_zur_pruefung"][0]["suchmaschinen"], ["bing", "google cse"])
        self.assertEqual(len(result["suchergebnisse_zur_pruefung"]), 2)
        self.assertEqual([ref["url"] for ref in result["references"]], ["https://github.com/example/contact"])

    def test_public_web_source_runs_only_when_explicitly_requested(self):
        async def fake_run_source(name, fn, *args):
            return {"source": name, "ok": True, "data": {}}

        with override_settings(OSINT_HIBP_KEY=""), mock.patch.object(email, "run_source", fake_run_source):
            disabled = asyncio.run(email.collect(None, "person@example.org"))
            enabled = asyncio.run(email.collect(None, "person@example.org", public_web=True))
        self.assertFalse(any(item["source"] == email.PUBLIC_WEB_SOURCE for item in disabled))
        self.assertTrue(any(item["source"] == email.PUBLIC_WEB_SOURCE for item in enabled))
        self.assertFalse(any(item["source"] == "E-Mail-Prüfgrenze" for item in enabled))


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}, OSINT_VIRUSTOTAL_KEY="vt-key")
class VirusTotalResolutionTests(SimpleTestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_resolution_history_is_bounded_cached_and_labelled(self):
        import httpx
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(200, json={"data": [
                {"attributes": {"host_name": "old.example.org", "date": 1}},
                {"attributes": {"host_name": "", "date": 2}},
            ]})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await threatintel.virustotal_resolutions(client, "203.0.113.5"), await threatintel.virustotal_resolutions(client, "203.0.113.5")

        first, second = asyncio.run(go())
        self.assertEqual(first["aufloesungen"], [{"host_name": "old.example.org", "beobachtet_am": "1970-01-01T00:00:01Z"}])
        self.assertIn("keine Zuordnung", first["hinweis"])
        self.assertTrue(second["aus_zwischenspeicher"])
        self.assertEqual(len(calls), 1)


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

    def test_central_number_candidates_are_explicit_hypotheses(self):
        candidates = phone.central_candidates("+49301234567")
        self.assertTrue(candidates)
        self.assertTrue(all(candidate["anzahl_entfernter_endziffern"] in {4, 5, 6} for candidate in candidates))
        self.assertTrue(all(len(candidate["ziffern"]) >= 2 for candidate in candidates))


class StemNumberTests(SimpleTestCase):
    TEST_NUMBER = "+49301234567"
    TEST_LONG_NUMBER = "+493012345678"

    def test_published_central_number_documents_stem_but_not_specific_extension(self):
        hit = {
            "titel": "Impressum | Beispielorganisation",
            "url": "https://example.invalid/impressum",
            "auszug": "Beispielorganisation. Telefon: 030 12-0.",
        }

        async def fake_searx(client, query, limit=10, pageno=1, meta=None):
            return [hit]

        with mock.patch.object(phone.search, "searx", fake_searx):
            stem = asyncio.run(phone.central_office_search(None, self.TEST_NUMBER))
        self.assertIn("030 12", [candidate["stammnummer"] for candidate in phone.stem_candidates(self.TEST_NUMBER)])
        self.assertNotIn("kandidaten", stem)
        self.assertEqual(stem["evidenz"][0]["veroeffentlichteNummer"], "030 12-0")
        result = phone.stem_attribution(self.TEST_NUMBER, [], stem)
        self.assertEqual(result["vermuteteStammnummer"]["organisation"], "Beispielorganisation")
        self.assertEqual(result["moeglicheDurchwahl"], "34567")
        self.assertIsNone(result["belegterAnschlussinhaber"])

    def test_stem_candidates_use_plausible_extension_lengths(self):
        candidates = phone.stem_candidates(self.TEST_LONG_NUMBER)
        by_extension = {candidate["entfernte_endziffern"]: candidate for candidate in candidates}
        self.assertEqual(by_extension["45678"]["stammnummer"], "030 123")
        self.assertEqual(set(item["anzahl_entfernter_endziffern"] for item in candidates), {4, 5, 6})

    def test_five_digit_extension_and_two_digit_stem_are_matched(self):
        hit = {
            "titel": "Beispielorganisation - Kontakt",
            "url": "https://example.invalid/kontakt",
            "auszug": "So erreichen Sie die Beispielorganisation. Telefon: 030/12-13083.",
        }

        async def fake_searx(client, query, limit=10, pageno=1, meta=None):
            return [hit]

        with mock.patch.object(phone.search, "searx", fake_searx):
            stem = asyncio.run(phone.central_office_search(None, self.TEST_NUMBER))
        self.assertEqual(phone.stem_candidates(self.TEST_NUMBER)[0]["stammnummer"], "030 12")
        self.assertEqual(phone.stem_candidates(self.TEST_NUMBER)[0]["entfernte_endziffern"], "34567")
        result = phone.stem_attribution(self.TEST_NUMBER, [], stem)
        self.assertEqual(result["vermuteteStammnummer"]["organisation"], "Beispielorganisation")
        self.assertEqual(result["moeglicheDurchwahl"], "34567")

    def test_longer_published_extension_does_not_create_a_false_match(self):
        longer_extension_hit = {
            "titel": "Andere Beispielorganisation - Kontakt",
            "url": "https://other.example.invalid/kontakt",
            "auszug": "Impressum der anderen Beispielorganisation. Telefon 030 123 999999",
        }

        async def fake_searx(client, query, limit=10, pageno=1, meta=None):
            return [longer_extension_hit]

        with mock.patch.object(phone.search, "searx", fake_searx):
            stem = asyncio.run(phone.central_office_search(None, self.TEST_NUMBER))
        self.assertEqual(stem["evidenz"], [])

    def test_mobile_numbers_get_no_organization_stem_hypotheses(self):
        self.assertEqual(phone.stem_candidates("+491701234567"), [])

    def test_competing_prefix_without_contact_evidence_is_not_an_assignment(self):
        stem = {"evidenz": [{
            "organisation": "Unklare Seite", "stammnummer": "030 12", "veroeffentlichteNummer": "030 12-0",
            "moeglicheDurchwahl": "34567", "sourceUrl": "https://example.invalid/info", "fundstelle": "030 12-0",
            "abgerufenAm": "2026-10-08T00:00:00+00:00", "kontaktOderImpressumSignal": False,
        }]}
        result = phone.stem_attribution(self.TEST_NUMBER, [], stem)
        self.assertEqual(result["belegteOrganisationszuordnung"], [])
        self.assertIsNone(result["vermuteteStammnummer"])

    def test_no_source_evidence_means_no_assignment(self):
        result = phone.stem_attribution(self.TEST_NUMBER, [], {"evidenz": []})
        self.assertEqual(result["belegteOrganisationszuordnung"], [])
        self.assertIsNone(result["belegterAnschlussinhaber"])


class IpTests(SimpleTestCase):
    def test_private_address_skips_external_sources(self):
        results = asyncio.run(ip.collect(client=None, ip="192.168.1.10"))
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0]["data"]["oeffentlich"])
        self.assertEqual(results[1]["source"], fritzbox.SOURCE)
        self.assertFalse(results[1]["data"]["target"]["publiclyRoutable"])

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

@override_settings(OSINT_IPINFO_TOKEN="secret-token")
class IpinfoTests(SimpleTestCase):
    SAMPLE = {
        "ip": "2001:4860:4860::8888",
        "asn": "AS15169",
        "as_name": "Example Network LLC",
        "as_domain": "example.net",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
        "unexpected_paid_field": "must not leak into stored results",
    }

    def _run(self, response, address="2001:4860:4860::8888"):
        import httpx
        calls = []

        def handler(request):
            calls.append(request)
            return response

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await ipinfo.lookup(client, address)

        return asyncio.run(go()), calls

    def test_lite_request_uses_bearer_token_and_supports_ipv6(self):
        import httpx
        result, calls = self._run(httpx.Response(200, json=self.SAMPLE))
        request = calls[0]
        self.assertEqual(str(request.url), "https://api.ipinfo.io/lite/2001:4860:4860::8888")
        self.assertEqual(request.headers["Authorization"], "Bearer secret-token")
        self.assertNotIn("secret-token", str(request.url))
        self.assertEqual(result["asn"], "AS15169")
        self.assertNotIn("unexpected_paid_field", result)
        self.assertEqual(result["source_url"], "https://ipinfo.io/")

    def test_rejects_auth_errors_and_a_response_for_another_address(self):
        import httpx
        with self.assertRaisesMessage(RuntimeError, "rejected the access token"):
            self._run(httpx.Response(401, json={}))
        wrong = {**self.SAMPLE, "ip": "2001:4860:4860::8844"}
        with self.assertRaisesMessage(RuntimeError, "does not match"):
            self._run(httpx.Response(200, json=wrong))

    @override_settings(OSINT_IPINFO_TOKEN="")
    def test_source_is_only_added_when_a_token_is_configured(self):
        names = []

        async def fake_run_source(name, fn, *args):
            names.append(name)
            return {"source": name, "ok": True, "data": {}}

        with mock.patch.object(ip, "run_source", fake_run_source):
            asyncio.run(ip.collect(None, "8.8.8.8"))
        self.assertNotIn(ipinfo.SOURCE, names)
        names.clear()
        with override_settings(OSINT_IPINFO_TOKEN="secret-token"), mock.patch.object(ip, "run_source", fake_run_source):
            asyncio.run(ip.collect(None, "8.8.8.8"))
        self.assertIn(ipinfo.SOURCE, names)

    def test_history_compares_ipinfo_network_context_only_when_both_runs_have_it(self):
        def source(asn, name, country):
            return [{"source": ipinfo.SOURCE, "ok": True,
                     "data": {"asn": asn, "as_name": name, "country_code": country}}]

        self.assertEqual(historie.compare(
            source("AS64500", "Old Network", "DE"),
            source("AS64501", "New Network", "NL"),
        ), [
            ("ipinfo_as_name", "Old Network", "New Network"),
            ("ipinfo_asn", "AS64500", "AS64501"),
            ("ipinfo_country", "DE", "NL"),
        ])
        self.assertEqual(historie.compare([], source("AS64501", "New Network", "NL")), [])


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
            ["DNS-Auflösung", "DNS-Einträge (dig)", "WHOIS Domain (lokal)", "Adressklassifizierung",
             "FRITZ!Box Fingerprint"],
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
        self.assertEqual(llm.extract_risk("## Risk assessment\nRisk: medium\nbecause"), "mittel")
        self.assertEqual(llm.extract_risk("nichts"), "")

    def test_prompt_requires_equivalent_german_and_english_reports(self):
        self.assertIn("# Deutsch", llm.SYSTEM_PROMPT)
        self.assertIn("# English", llm.SYSTEM_PROMPT)
        self.assertIn("Identification and attribution", llm.SYSTEM_PROMPT)
        self.assertNotIn("## Risk assessment", llm.SYSTEM_PROMPT)

    def test_positive_web_findings_are_added_to_both_report_languages(self):
        report = "# Deutsch\n## Kurzfazit\nFund.\n\n# English\n## Executive summary\nFinding."
        sources = [{"source": "Websuche (SearXNG)", "ok": True, "data": {"treffer": [{
            "titel": "Organisation", "url": "https://example.org/contact", "auszug": "Kontaktangabe",
        }]}}]
        output = llm.append_web_findings(report, sources)
        self.assertIn("## Belegte Web-Fundstellen", output)
        self.assertIn("## Documented web findings", output)
        self.assertEqual(output.count("https://example.org/contact"), 2)
        self.assertIn("[Organisation](https://example.org/contact)", output)

    def test_returned_phone_search_results_are_added_to_both_report_languages(self):
        report = "# Deutsch\n## Kurzfazit\nFund.\n\n# English\n## Executive summary\nFinding."
        sources = [{"source": "Websuche (SearXNG)", "ok": True, "data": {"treffer": [], "suchergebnisse": [{
            "titel": "Suchtreffer", "url": "https://example.org/result", "auszug": "Ergebnistext",
        }]}}]
        output = llm.append_web_findings(report, sources)
        self.assertIn("## Weitere SearXNG-Suchergebnisse", output)
        self.assertIn("## Additional SearXNG search results", output)
        self.assertEqual(output.count("https://example.org/result"), 2)

    def test_unverified_returned_phone_results_do_not_enter_the_ai_prompt(self):
        prompt = llm.build_prompt("phone", "+49301234567", [{
            "source": "Websuche (SearXNG)", "ok": True,
            "data": {"treffer": [], "suchergebnisse": [{"url": "https://example.org/result"}]},
        }])
        self.assertNotIn("example.org/result", prompt)

    def test_email_review_results_do_not_enter_the_ai_prompt(self):
        prompt = llm.build_prompt("email", "person@example.org", [{
            "source": "Öffentliche Web-Referenzen (SearXNG)", "ok": True,
            "data": {"references": [], "suchergebnisse_zur_pruefung": [{"url": "https://example.org/result"}]},
        }])
        self.assertNotIn("example.org/result", prompt)

    def test_historical_dns_is_available_for_report_and_pdf(self):
        from .templatetags.report_tags import historical_dns
        observations = historical_dns([
            {"source": "VirusTotal (historische DNS-Auflösungen)", "ok": True,
             "data": {"aufloesungen": [{"host_name": "old.example.net", "beobachtet_am": "2026-10-10T12:00:00Z"}]}},
            {"source": "Passive DNS (OTX, Namen auf dieser IP)", "ok": True,
             "data": {"zum_stichtag": [{"wert": "past.example.net", "typ": "A",
                                            "von_zeit": "2026-10-01T00:00:00Z", "bis_zeit": "2026-10-02T00:00:00Z"}]}},
        ])
        self.assertEqual(observations, [
            {"wert": "old.example.net", "zeit_von": "2026-10-10T12:00:00Z", "quelle": "VirusTotal (historische DNS-Auflösungen)"},
            {"wert": "past.example.net", "zeit_von": "2026-10-01T00:00:00Z", "zeit_bis": "2026-10-02T00:00:00Z", "typ": "A", "quelle": "Passive DNS (OTX, Namen auf dieser IP)"},
        ])

    def test_historical_timestamp_is_human_readable(self):
        from .templatetags.ui_tags import ui_timestamp
        self.assertRegex(ui_timestamp("2026-10-10T12:34:56Z"), r"^10\.10\.2026, \d{2}:34 \w+$")

    def test_markdown_escapes_html(self):
        html = markdown("## Titel\n<script>alert(1)</script>")
        self.assertIn("<h2>Titel</h2>", html)
        self.assertNotIn("<script>", html)

    def test_bilingual_report_is_split_for_language_switch(self):
        report = ("# Deutsch\n## Kurzfazit\nDeutscher Text.\n\n"
                  "# English\n## Executive summary\nEnglish text.")
        parts = report_parts(report)
        self.assertTrue(parts["bilingual"])
        self.assertIn("Deutscher Text", parts["de"])
        self.assertIn("English text", parts["en"])
        self.assertNotIn("# English", parts["de"])

    def test_legacy_report_remains_visible_without_switch(self):
        report = "## Kurzfazit\nNur Deutsch."
        self.assertEqual(report_parts(report), {"bilingual": False, "single": report})

    def test_negative_fritz_fingerprint_is_excluded_from_report_prompt(self):
        negative = {
            "source": "FRITZ!Box Fingerprint", "ok": True,
            "data": {"classification": {"likelyFritzBox": False, "confidence": "none"}},
        }
        positive = {
            "source": "FRITZ!Box Fingerprint", "ok": True,
            "data": {"classification": {"likelyFritzBox": True, "confidence": "high"}},
        }
        self.assertNotIn("FRITZ!Box Fingerprint", llm.build_prompt("ip", "8.8.8.8", [negative]))
        self.assertIn("FRITZ!Box Fingerprint", llm.build_prompt("ip", "8.8.8.8", [positive]))


class ViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("tester", password="pw-123456")

    def test_login_required(self):
        response = self.client.get(reverse("lookups:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_staff_navigation_uses_burger_menu_and_sign_out_icon(self):
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:index"))
        self.assertContains(page, '<details class="admin-menu">', html=False)
        self.assertContains(page, reverse("accounts:invitations"))
        self.assertContains(page, reverse("admin:index"))
        self.assertContains(page, 'aria-label="Abmelden"', html=False)
        self.assertNotContains(page, '<button class="link">Abmelden</button>', html=False)

    def test_submit_creates_lookup_and_queues_task(self):
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {"q": "030 1234567"})
        lookup = Lookup.objects.get()
        self.assertRedirects(response, reverse("lookups:detail", args=[lookup.pk]))
        self.assertEqual((lookup.kind, lookup.query), ("phone", "+49301234567"))
        delay.assert_called_once_with(lookup.pk)

    def test_email_creates_lookup_without_authorization_checkbox(self):
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {"q": "person@example.org"})
        lookup = Lookup.objects.get()
        self.assertRedirects(response, reverse("lookups:detail", args=[lookup.pk]))
        delay.assert_called_once_with(lookup.pk)

    def test_email_normalizes_before_creating_lookup(self):
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {"q": "Person@Example.ORG"})
        lookup = Lookup.objects.get()
        self.assertRedirects(response, reverse("lookups:detail", args=[lookup.pk]))
        self.assertEqual((lookup.kind, lookup.query), ("email", "person@example.org"))
        delay.assert_called_once_with(lookup.pk)

    def test_email_can_enable_public_web_references(self):
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:index"), {
                "q": "person@example.org", "email_public_web": "on",
            })
        self.assertTrue(Lookup.objects.get().email_public_web)

    def test_email_rerun_can_select_new_source_without_authorization_checkbox(self):
        original = Lookup.objects.create(kind="email", query="person@example.org", created_by=self.user)
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:rerun", args=[original.pk]), {
                "email_public_web": "on",
            })
        rerun = Lookup.objects.latest("pk")
        self.assertRedirects(response, reverse("lookups:detail", args=[rerun.pk]))
        self.assertTrue(rerun.email_public_web)

    def test_email_detail_offers_rerun_options(self):
        lookup = Lookup.objects.create(kind="email", query="person@example.org", created_by=self.user, status=Lookup.Status.DONE)
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, 'id="rerun-pop"', html=False)
        self.assertContains(page, 'name="email_public_web"', html=False)
        self.assertNotContains(page, 'name="email_authorized"', html=False)
        self.assertContains(page, '← Back', html=False)

    def test_phone_detail_offers_the_passive_rerun_dialog(self):
        lookup = Lookup.objects.create(kind="phone", query="+49301234567", created_by=self.user, status=Lookup.Status.DONE)
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, 'id="rerun-pop"', html=False)
        self.assertContains(page, "Rufnummer erneut analysieren")
        self.assertContains(page, 'name="phone_public_web"', html=False)
        self.assertNotContains(page, 'name="phone_authorized"', html=False)
        self.assertNotContains(page, 'name="active"', html=False)

    def test_phone_public_web_is_stored_without_authorization_checkbox(self):
        self.client.force_login(self.user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:index"), {
                "q": "030 1234567", "phone_public_web": "on",
            })
        self.assertTrue(Lookup.objects.latest("pk").phone_public_web)

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

    def test_history_list_groups_runs_of_the_same_query(self):
        for query in ("203.0.113.7", "203.0.113.8", "203.0.113.7"):
            Lookup.objects.create(kind="ip", query=query, created_by=self.user, status="done")
        newest = Lookup.objects.filter(query="203.0.113.7").first()
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:index"))
        self.assertEqual([l.pk for l in page.context["lookups"]][0], newest.pk)
        self.assertEqual(page.context["total"], 2)
        self.assertContains(page, "2×")
        runs = ",".join(str(pk) for pk in Lookup.objects.filter(query="203.0.113.7").values_list("pk", flat=True))
        self.client.post(reverse("lookups:delete"), {"ids": [runs]})
        self.assertEqual(list(Lookup.objects.values_list("query", flat=True)), ["203.0.113.8"])

    def test_detail_lists_only_existing_runs_of_the_same_owner(self):
        other = get_user_model().objects.create_user("other", password="pw-123456")
        old = Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=self.user, status="done")
        gone = Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=self.user, status="done")
        Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=other, status="done")
        current = Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=self.user, status="done")
        gone.delete()
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:detail", args=[current.pk]))
        self.assertEqual([run.pk for run in page.context["runs"]], [old.pk])
        self.assertContains(page, reverse("lookups:detail", args=[old.pk]))
        self.assertContains(page, "erste Analyse")

    def test_each_earlier_run_shows_its_changes_against_the_one_before(self):
        def run(score, risk):
            return Lookup.objects.create(kind="ip", query="203.0.113.7", created_by=self.user, status="done", risk=risk,
                                         sources=[{"source": "AbuseIPDB", "ok": True,
                                                   "data": {"abuseConfidenceScore": score, "totalReports": 0}}])
        run(0, "niedrig")
        second = run(40, "mittel")
        current = run(40, "mittel")
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:detail", args=[current.pk]))
        changes = {r.pk: r.changes for r in page.context["runs"]}
        self.assertEqual(changes[second.pk], [("abuseipdb_score", "0", "40")])
        self.assertContains(page, "1 Änderung")
        self.assertContains(page, "Öffnen")

    def test_history_list_sorts_runs_of_the_same_minute_alphabetically(self):
        from django.utils import timezone
        minute = timezone.now().replace(second=0, microsecond=0) - __import__("datetime").timedelta(minutes=10)
        for query, second in (("b.example.org", 1), ("a.example.org", 2), ("c.example.org", 3)):
            lookup = Lookup.objects.create(kind="host", query=query, created_by=self.user, status="done")
            Lookup.objects.filter(pk=lookup.pk).update(created_at=minute.replace(second=second))
        Lookup.objects.create(kind="host", query="z.example.org", created_by=self.user, status="done")
        lookup = Lookup.objects.create(kind="host", query="y.example.org", created_by=self.user, status="done")
        Lookup.objects.filter(pk=lookup.pk).update(created_at=minute - __import__("datetime").timedelta(minutes=5))
        self.client.force_login(self.user)
        page = self.client.get(reverse("lookups:index"))
        queries = [l.query for l in page.context["lookups"]]
        self.assertEqual(queries[-4:], ["a.example.org", "b.example.org", "c.example.org", "y.example.org"])

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
        self.assertEqual([h["url"] for h in result["suchergebnisse"]],
                         ["https://dekanat.example/kita", "https://spam.example/"])
        self.assertEqual(queries, [('"069 90009123"', 1), ('"+49 69 90009123"', 1)])  # Seite 2 nur bei >= 5 Treffern
        self.assertEqual(result["suchmaschinen_mit_ergebnissen"], ["bing"])
        self.assertEqual(result["gestoerte_suchmaschinen"], {"google": "access denied"})
        self.assertNotIn("abfragevarianten", result)

    def test_all_queries_failing_is_an_error(self):
        async def broken(client, query, limit=10, pageno=1, meta=None):
            raise RuntimeError("down")
        with mock.patch.object(phone.search, "searx", broken), mock.patch.object(phone, "SEARCH_PAUSE", 0), \
                self.assertRaises(RuntimeError):
            asyncio.run(phone.web_search(None, "+496990009123"))

    def test_adaptive_phone_research_shares_a_three_query_budget(self):
        queries = []

        async def fake_searx(client, query, limit=10, pageno=1, meta=None):
            queries.append(query)
            return []

        async def go():
            budget = phone.SearchBudget()
            direct = await phone.web_search(None, "+49301234567", budget)
            await phone.central_office_search(None, "+49301234567", budget, direct["treffer"])
            await phone.spam_portals(None, "+49301234567", budget)
            return budget

        with mock.patch.object(phone.search, "searx", fake_searx), mock.patch.object(phone, "SEARCH_PAUSE", 0):
            budget = asyncio.run(go())
        self.assertEqual((budget.used, len(queries)), (3, 3))
        self.assertEqual(queries[1], "0301234567")

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

    def test_public_email_references_are_shown_as_web_findings(self):
        sources = [{"source": "Öffentliche Web-Referenzen (SearXNG)", "ok": True,
                    "data": {"references": [{"url": "https://example.org/contact", "titel": "Contact",
                                                "fundstelle": "person@example.org"}],
                             "suchergebnisse_zur_pruefung": [{"url": "https://example.org/review"}]}}]
        self.assertEqual(fundstellen(sources), [{"url": "https://example.org/contact", "titel": "Contact",
                                                  "fundstelle": "person@example.org", "auszug": "person@example.org",
                                                  "quelle": "Öffentliche Web-Referenzen (SearXNG)"}])
        from .templatetags.report_tags import email_search_responses
        self.assertEqual(email_search_responses(sources), [{"url": "https://example.org/review"}])


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
        self.assertContains(response, ">0211 1234567</textarea>")
        self.assertFalse(Lookup.objects.exists())

    def test_share_post_with_vcard_without_csrf_token(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from django.test import Client
        client = Client(enforce_csrf_checks=True)
        client.force_login(get_user_model().objects.create_user("t", password="pw-123456"))
        vcf = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Unbekannt\r\nTEL;TYPE=CELL:+49 176 1234\r\n 5678\r\nEND:VCARD\r\n"
        response = client.post(reverse("lookups:share"), {"files": SimpleUploadedFile("k.vcf", vcf, "text/vcard")})
        self.assertContains(response, ">+49 176 12345678</textarea>")
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

    def test_pdf_uses_requested_global_language(self):
        self.client.force_login(self.user)
        from . import pdf
        with mock.patch.object(pdf, "render", side_effect=lambda *_, **__: translation.get_language().encode()) as render:
            response = self.client.get(f"{reverse('lookups:pdf', args=[self.lookup.pk])}?language=en")
        self.assertEqual(response.content, b"en")
        self.assertEqual(response["Content-Language"], "en")
        self.assertIn("-en-", response["Content-Disposition"])
        render.assert_called_once()

    def test_pdf_hides_negative_fritz_fingerprint(self):
        from django.template.loader import render_to_string
        self.lookup.sources.append({
            "source": "FRITZ!Box Fingerprint", "ok": True,
            "data": {"classification": {"likelyFritzBox": False, "confidence": "none"}},
        })
        with translation.override("de"):
            html = render_to_string("lookups/report_pdf.html", {
                "lookup": self.lookup, "generated_at": self.lookup.created_at, "scan": None, "history": None,
            })
        self.assertNotIn("FRITZ!Box Fingerprint", html)

    def test_pdf_lists_sources_alphabetically(self):
        from django.template.loader import render_to_string
        self.lookup.sources = [
            {"source": "Zulu provider", "ok": True, "data": {}},
            {"source": "Alpha provider", "ok": True, "data": {}},
        ]
        html = render_to_string("lookups/report_pdf.html", {
            "lookup": self.lookup, "generated_at": self.lookup.created_at, "scan": None, "history": None,
        })
        self.assertLess(html.index("Alpha provider"), html.index("Zulu provider"))

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

    def test_status_sorts_provider_display_alphabetically(self):
        self.lookup.sources.extend([
            {"source": "Zulu provider", "ok": True, "data": {}},
            {"source": "Alpha provider", "ok": True, "data": {}},
        ])
        self.lookup.save(update_fields=["sources"])
        self.client.force_login(self.user)
        keys = [source["key"] for source in self.client.get(self.url).json()["sources"]]
        self.assertEqual(keys, ["Alpha provider", "Reverse DNS", "Zulu provider"])

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
        self.assertIn("Als PDF herunterladen", done["fragments"]["actions"]["html"])

    def test_bilingual_report_uses_global_language(self):
        report = ("# Deutsch\n## Kurzfazit\nDeutscher Text.\n\n"
                  "# English\n## Executive summary\nEnglish text.")
        Lookup.objects.filter(pk=self.lookup.pk).update(status="done", report_md=report)
        self.client.force_login(self.user)
        html = self.client.get(self.url).json()["fragments"]["report"]["html"]
        self.assertIn('lang="de"', html)
        self.assertIn("Deutscher Text", html)
        self.assertNotIn("English text", html)
        self.client.cookies["django_language"] = "en"
        english = self.client.get(self.url).json()["fragments"]["report"]["html"]
        self.assertIn('lang="en"', english)
        self.assertIn("English text", english)
        self.assertNotIn("Deutscher Text", english)

    def test_passive_hostname_has_no_separate_report_box(self):
        self.lookup.kind = "host"
        self.lookup.query = "router.example.org"
        self.lookup.save(update_fields=["kind", "query"])
        self.client.force_login(self.user)
        german = self.client.get(self.url).json()["fragments"]["report"]["html"]
        self.assertNotIn("DNS-Zielbindung", german)
        self.client.cookies["django_language"] = "en"
        english = self.client.get(self.url).json()["fragments"]["report"]["html"]
        self.assertNotIn("DNS target binding", english)

    def test_ip_has_no_dynamic_address_report_box(self):
        self.client.force_login(self.user)
        german = self.client.get(self.url).json()["fragments"]["report"]["html"]
        self.assertNotIn("Dynamische IP-Adresse", german)
        self.client.cookies["django_language"] = "en"
        english = self.client.get(self.url).json()["fragments"]["report"]["html"]
        self.assertNotIn("Dynamic IP address", english)

    def test_negative_fritz_fingerprint_remains_raw_data_only(self):
        data = {
            "target": {"resolvedAddress": "8.8.8.8", "addressFamily": "IPv4"},
            "authorization": {"activeChecksConfirmed": False, "activeChecksPerformed": False},
            "classification": {"likelyFritzBox": False, "confidence": "low", "reasons": ["AVM-Merkmal aus DNS"]},
            "summary": "Ein einzelnes Indiz.",
            "device": {"model": None, "hardwareId": None, "fritzOsVersion": None,
                       "rawFirmwareVersion": None, "revision": None},
            "warnings": [],
        }
        self.lookup.sources.append({"source": "FRITZ!Box Fingerprint", "ok": True, "data": data})
        self.lookup.save(update_fields=["sources"])
        self.client.force_login(self.user)
        response = self.client.get(self.url).json()
        self.assertNotIn("fritz", response["fragments"])
        source = next(item for item in response["sources"] if item["key"] == "FRITZ!Box Fingerprint")
        self.assertIn('id="source-fritzbox-fingerprint"', source["html"])

    def test_global_language_switch_is_visible_on_every_page(self):
        self.client.force_login(self.user)
        german = self.client.get(reverse("lookups:index"))
        self.assertContains(german, 'name="language" value="en"')
        self.client.post(reverse("set_language"), {"language": "en", "next": reverse("lookups:index")})
        english = self.client.get(reverse("lookups:index"))
        self.assertContains(english, "Analyze")
        self.assertContains(english, "History")

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
        names = []

        async def fake_run_source(name, fn, *args):
            names.append(name)
            return {"source": name, "ok": True, "data": {}}

        for active in (False, True):
            names.clear()
            with mock.patch.object(ip, "run_source", fake_run_source), \
                    mock.patch.object(fritzbox.tools, "fritzbox", mock.AsyncMock(return_value={})) as direct:
                asyncio.run(ip.collect(None, "8.8.8.8", active=active))
            self.assertEqual(direct.await_count, int(active))
            self.assertTrue(any(n.startswith("WHOIS") for n in names))


class ActiveProbeTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user("chef", password="x", is_staff=True)
        self.normal = get_user_model().objects.create_user("anna", password="x")

    def _submit(self, user, q="8.8.8.8", **extra):
        self.client.force_login(user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:index"), {"q": q, **extra})
        return Lookup.objects.latest("pk")

    def test_staff_can_enable_active_probe(self):
        self.assertTrue(self._submit(self.staff, active="on").active_probe)
        self.assertFalse(self._submit(self.staff).active_probe)

    def test_ports_and_timeout_are_validated_and_stored(self):
        lookup = self._submit(self.staff, active="on", active_ports="9443, 443, 9443", active_timeout="12")
        self.assertEqual(lookup.active_ports, [9443, 443])
        self.assertEqual(lookup.active_timeout, 12)

    def test_invalid_active_options_do_not_create_lookup(self):
        self.client.force_login(self.staff)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {
                "q": "8.8.8.8", "active": "on", "active_ports": "1,2,3,4,5", "active_timeout": "8",
            })
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "1 bis 4", status_code=400)
        self.assertFalse(Lookup.objects.exists())

    def test_private_active_target_is_rejected(self):
        self.client.force_login(self.staff)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {"q": "192.168.1.1", "active": "on"})
        self.assertContains(response, "öffentlich routbar", status_code=400)
        self.assertFalse(Lookup.objects.exists())

    def test_active_probe_needs_no_prior_registration(self):
        lookup = self._submit(self.staff, q="1.1.1.1", active="on")
        self.assertEqual((lookup.query, lookup.active_probe), ("1.1.1.1", True))

    def test_rerun_with_active_options_is_staff_only(self):
        first = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.normal, status=Lookup.Status.DONE)
        self.client.force_login(self.normal)
        response = self.client.post(reverse("lookups:rerun", args=[first.pk]), {
            "active": "on", "authorization": "confirmed"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Lookup.objects.count(), 1)

    def test_enrichment_is_staff_only(self):
        parent = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.normal, status=Lookup.Status.DONE)
        self.client.force_login(self.normal)
        self.assertNotContains(self.client.get(reverse("lookups:detail", args=[parent.pk])), "enrich-pop")
        response = self.client.post(reverse("lookups:enrich", args=[parent.pk]), {"authorization": "confirmed"})
        self.assertEqual(response.status_code, 403)

    def test_normal_users_cannot_enable_it(self):
        self.assertFalse(self._submit(self.normal, active="on").active_probe)

    def test_checkbox_only_for_staff(self):
        self.client.force_login(self.staff)
        self.assertContains(self.client.get(reverse("lookups:index")), 'name="active"')
        self.client.force_login(self.normal)
        self.assertNotContains(self.client.get(reverse("lookups:index")), 'name="active"')

    def test_rerun_requires_a_fresh_active_selection_and_confirmation(self):
        first = self._submit(self.staff, active="on")
        self.client.force_login(self.staff)
        blocked = self.client.post(reverse("lookups:rerun", args=[first.pk]), {"active": "on"}, follow=True)
        self.assertContains(blocked, "Berechtigung", status_code=200)
        self.assertEqual(Lookup.objects.count(), 1)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[first.pk]), {
                "active": "on", "authorization": "confirmed", "profile": "speedport",
                "active_ports": "80, 443", "active_timeout": "12",
            })
        again = Lookup.objects.latest("pk")
        self.assertNotEqual(again.pk, first.pk)
        self.assertTrue(again.active_probe)
        self.assertEqual(again.active_profile, Lookup.ActiveProfile.SPEEDPORT)
        self.assertEqual(again.active_ports, [80, 443])
        self.assertEqual(again.active_timeout, 12)
        self.assertContains(self.client.get(reverse("lookups:detail", args=[again.pk])), "leicht aktiv")

    def test_rerun_without_active_options_is_passive(self):
        first = self._submit(self.staff, active="on")
        self.client.force_login(self.staff)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[first.pk]), {"asof": ""})
        self.assertFalse(Lookup.objects.latest("pk").active_probe)

    def test_network_detail_offers_rerun_options(self):
        lookup = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.staff, status=Lookup.Status.DONE)
        self.client.force_login(self.staff)
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, 'id="rerun-pop"', html=False)
        self.assertContains(page, 'name="active"', html=False)
        self.assertContains(page, 'name="scan"', html=False)
        self.assertContains(page, 'name="asof"', html=False)

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
        self.assertEqual(seen["active_ports"], [443, 8443])
        self.assertEqual(seen["active_timeout"], 8)

    def test_enrichment_requires_confirmation_and_creates_a_separate_generic_run(self):
        parent = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.staff, status=Lookup.Status.DONE)
        self.client.force_login(self.staff)
        response = self.client.post(reverse("lookups:enrich", args=[parent.pk]), {"profile": "generic-router"})
        self.assertRedirects(response, reverse("lookups:detail", args=[parent.pk]))
        self.assertEqual(Lookup.objects.count(), 1)
        with mock.patch("lookups.views.run_lookup.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:enrich", args=[parent.pk]), {
                "profile": "generic-router", "authorization": "confirmed", "active_ports": "443", "active_timeout": "9",
            })
        enriched = Lookup.objects.latest("pk")
        self.assertRedirects(response, reverse("lookups:detail", args=[enriched.pk]))
        self.assertEqual((enriched.enrichment_of, enriched.active_profile, enriched.active_ports, enriched.active_timeout),
                         (parent, Lookup.ActiveProfile.GENERIC_ROUTER, [443], 9))
        delay.assert_called_once_with(enriched.pk)

    def test_fritz_enrichment_default_ports_and_detail_control(self):
        parent = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.staff, status=Lookup.Status.DONE)
        self.client.force_login(self.staff)
        self.assertContains(self.client.get(reverse("lookups:detail", args=[parent.pk])), "enrich-pop")
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:enrich", args=[parent.pk]), {
                "profile": "fritzbox", "authorization": "confirmed",
            })
        enriched = Lookup.objects.latest("pk")
        self.assertEqual((enriched.active_profile, enriched.active_ports), (Lookup.ActiveProfile.FRITZBOX, [443, 8443]))

    def test_speedport_enrichment_has_explicit_profile_and_defaults(self):
        parent = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.staff, status=Lookup.Status.DONE)
        self.client.force_login(self.staff)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:enrich", args=[parent.pk]), {
                "profile": "speedport", "authorization": "confirmed",
            })
        enriched = Lookup.objects.latest("pk")
        self.assertEqual((enriched.active_profile, enriched.active_ports), (Lookup.ActiveProfile.SPEEDPORT, [80, 443]))

class FritzBoxFingerprintTests(SimpleTestCase):
    def test_port_timeout_and_address_validation(self):
        self.assertEqual(fritzbox.parse_ports("443, 8443 443"), [443, 8443])
        self.assertEqual(fritzbox.parse_ports(""), [443, 8443])
        self.assertEqual(fritzbox.parse_timeout(""), 8)
        for bad in ("", "localhost", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1",
                    "192.0.2.1", "224.0.0.1", "::1", "fe80::1", "fd00::1", "2001:db8::1"):
            self.assertFalse(fritzbox.public_address(bad), bad)
        self.assertTrue(fritzbox.public_address("8.8.8.8"))
        self.assertTrue(fritzbox.public_address("2001:4860:4860::8888"))

    def test_all_dns_answers_must_be_public(self):
        self.assertIsNone(fritzbox.validate_resolved_addresses(["8.8.8.8", "2001:4860:4860::8888"]))
        self.assertIn("nicht öffentlich", fritzbox.validate_resolved_addresses(["8.8.8.8", "127.0.0.1"]))
        self.assertIn("keine", fritzbox.validate_resolved_addresses([]))


class RouterFingerprintTests(SimpleTestCase):
    @override_settings(OSINT_TOOLS_TOKEN="test-token", OSINT_TOOLS_URL="http://tools.test")
    def test_speedport_keeps_service_and_transport_timeouts_separate(self):
        captured = {}

        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {"ok": True, "data": {"services": []}}

        class Client:
            async def post(self, url, **kwargs):
                captured["url"] = url
                captured.update(kwargs)
                return Response()

        asyncio.run(tools_client.speedport(Client(), "8.8.8.8", ports=[80, 443], timeout=8))
        self.assertEqual(captured["json"]["timeout"], 8)
        self.assertEqual(captured["timeout"], 100)

    def test_generic_router_marker_is_a_direct_but_vendor_neutral_result(self):
        direct = {
            "services": [{"port": 443, "reachable": True}],
            "observations": [{"evidence": "Router-/Gateway-Merkmal in HTTP-Metadaten auf Port 443"}],
            "requestPolicy": "sequenziell",
        }
        result = router.build("router.example", "8.8.8.8", direct=direct)
        self.assertEqual((result["classification"]["likelyRouter"], result["classification"]["confidence"]),
                         (True, "low"))
        self.assertEqual(result["device"], {"vendor": None, "model": None, "firmwareVersion": None})

    def test_generic_profile_does_not_call_the_fritz_adapter(self):
        async def fake_run_source(name, fn, *args):
            if name != router.SOURCE:
                return {"source": name, "ok": True, "data": {}}
            data = fn(*args)
            if hasattr(data, "__await__"):
                data = await data
            return {"source": name, "ok": True, "data": data}

        with mock.patch.object(ip, "run_source", fake_run_source), \
                mock.patch.object(fritzbox.tools, "fritzbox", mock.AsyncMock()) as fritz_direct, \
                mock.patch.object(router.tools, "router", mock.AsyncMock(return_value={"services": []})) as generic_direct:
            results = asyncio.run(ip.collect(None, "8.8.8.8", active=True, active_profile="generic-router", active_ports=[443]))
        fritz_direct.assert_not_awaited()
        generic_direct.assert_awaited_once()
        self.assertIn(router.SOURCE, [item["source"] for item in results])

    def test_speedport_status_directly_backs_model_and_firmware(self):
        direct = {"speedport": {"plausible": True, "device": {
            "vendor": "Telekom", "model": "Speedport Smart 4", "rawFirmwareVersion": "010139.5.0.001.0",
        }}}
        result = speedport.build("router.example", "8.8.8.8", direct=direct)
        self.assertEqual((result["classification"]["likelySpeedport"], result["classification"]["confidence"]),
                         (True, "high"))
        self.assertEqual(result["device"]["rawFirmwareVersion"], "010139.5.0.001.0")

    def test_speedport_profile_does_not_call_other_router_adapters(self):
        async def fake_run_source(name, fn, *args):
            if name != speedport.SOURCE:
                return {"source": name, "ok": True, "data": {}}
            data = fn(*args)
            if hasattr(data, "__await__"):
                data = await data
            return {"source": name, "ok": True, "data": data}

        with mock.patch.object(ip, "run_source", fake_run_source), \
                mock.patch.object(fritzbox.tools, "fritzbox", mock.AsyncMock()) as fritz_direct, \
                mock.patch.object(router.tools, "router", mock.AsyncMock()) as generic_direct, \
                mock.patch.object(speedport.tools, "speedport", mock.AsyncMock(return_value={"services": []})) as speedport_direct:
            results = asyncio.run(ip.collect(None, "8.8.8.8", active=True, active_profile="speedport", active_ports=[443]))
        fritz_direct.assert_not_awaited()
        generic_direct.assert_not_awaited()
        speedport_direct.assert_awaited_once()
        self.assertIn(speedport.SOURCE, [item["source"] for item in results])

    def test_confidence_rules(self):
        none = fritzbox.build("example.com", "8.8.8.8", [])
        self.assertEqual((none["classification"]["likelyFritzBox"], none["classification"]["confidence"]),
                         (False, "none"))
        low = fritzbox.build("router.myfritz.net", "8.8.8.8", [])
        self.assertEqual((low["classification"]["likelyFritzBox"], low["classification"]["confidence"]),
                         (False, "low"))
        sources = [
            {"source": "Reverse DNS", "ok": True, "data": {"ptr": "x.myfritz.net"}},
            {"source": "Shodan InternetDB", "ok": True, "data": {"hostnames": ["FRITZ!Box"]}},
        ]
        medium = fritzbox.build("example.com", "8.8.8.8", sources)
        self.assertEqual((medium["classification"]["likelyFritzBox"], medium["classification"]["confidence"]),
                         (True, "medium"))
        direct = {"boxinfo": {"plausible": True, "serialRedacted": True, "device": {
            "model": "FRITZ!Box 7590", "hardwareId": "226", "fritzOsVersion": "7.59",
            "rawFirmwareVersion": "226.07.59", "revision": "1", "oem": "avm", "language": "de",
            "labBuild": None,
        }}}
        high = fritzbox.build("example.com", "8.8.8.8", [], active_confirmed=True, direct=direct)
        self.assertEqual(high["classification"]["confidence"], "high")
        self.assertEqual(high["device"]["rawFirmwareVersion"], "226.07.59")

    def test_serial_is_absent_from_structured_and_summary_output(self):
        direct = {"boxinfo": {"plausible": True, "serialRedacted": True, "device": {
            "model": "FRITZ!Box 7590", "hardwareId": "226", "fritzOsVersion": None,
            "rawFirmwareVersion": None, "revision": None, "oem": "avm", "language": None,
            "labBuild": None,
        }}}
        result = fritzbox.build("example.com", "8.8.8.8", [], direct=direct)
        import json
        serialized = json.dumps(result)
        self.assertNotIn("serial", serialized.lower())
        self.assertNotIn("SERIAL-MUST-NEVER-LEAK", serialized)


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

    def test_prompt_prioritizes_historical_dns_and_excludes_failed_sources(self):
        sources = [
            {"source": "WHOIS (lokal)", "ok": True, "data": {"text": "x" * 20_000}},
            {"source": "VirusTotal (historische DNS-Auflösungen)", "ok": True,
             "data": {"aufloesungen": [{"host_name": "router.example.net", "date": 1}]}},
            {"source": "Censys", "ok": False, "error": "Rate limit reached"},
        ]
        prompt = llm.build_prompt("ip", "8.8.8.8", sources)
        self.assertIn("router.example.net", prompt)
        self.assertNotIn("Rate limit reached", prompt)




class PortScanTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user("chef", password="x", is_staff=True)
        self.normal = get_user_model().objects.create_user("anna", password="x")

    def _submit(self, user, q="8.8.8.8", **extra):
        self.client.force_login(user)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            return self.client.post(reverse("lookups:index"), {"q": q, **extra})

    def test_staff_can_scan_own_system(self):
        self._submit(self.staff, scan="on")
        self.assertTrue(Lookup.objects.get().port_scan)

    def test_any_target_can_be_scanned_without_registration(self):
        self._submit(self.staff, q="1.1.1.1", scan="on")
        self.assertTrue(Lookup.objects.get(query="1.1.1.1").port_scan)

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

    def test_task_passes_scan_to_collectors(self):
        from .tasks import run_lookup
        lookup = Lookup.objects.create(kind="ip", query="1.1.1.1", port_scan=True)
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

    def test_risk_floor_updates_both_languages(self):
        bilingual = ("# Deutsch\n## Risikoeinschätzung\nRisiko: niedrig\nDeutsch.\n\n"
                     "# English\n## Risk assessment\nRisk: low\nEnglish.")
        report, risk = llm.apply_risk_floor(bilingual, "niedrig", self.SCAN_HOCH)
        self.assertEqual(risk, "hoch")
        self.assertIn("Risiko: hoch", report)
        self.assertIn("Risk: high", report)
        self.assertNotIn("Risk: low", report)

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






class HostActiveTests(SimpleTestCase):
    def _run(self, addresses, **options):
        calls = []

        async def fake_resolve(hostname):
            return {"hostname": hostname, "adressen": addresses}

        async def fake_ip_collect(client, address, **kwargs):
            calls.append((address, kwargs))
            return []

        async def go():
            with mock.patch.object(host, "resolve", fake_resolve), mock.patch.object(ip, "collect", fake_ip_collect), \
                    mock.patch.object(host.tools, "dns", mock.AsyncMock(return_value={})), \
                    mock.patch.object(host.tools, "whois", mock.AsyncMock(return_value={})), \
                    mock.patch.object(host.threatintel, "jobs", return_value=[]):
                return await host.collect(None, "router.example.org", **options)

        asyncio.run(go())
        return calls

    def test_public_hostname_is_checked_and_scanned_as_requested(self):
        calls = self._run(["91.1.2.3"], active=True, scan=True, active_ports=[443])
        self.assertEqual(calls[0][0], "91.1.2.3")
        self.assertIsNone(calls[0][1]["active_blocked"])
        self.assertTrue(calls[0][1]["scan"])

    def test_hostname_pointing_to_a_private_address_blocks_active_checks(self):
        calls = self._run(["91.1.2.3", "192.168.1.5"], active=True)
        self.assertTrue(calls[0][1]["active_blocked"])


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


@override_settings(CACHES=LOCMEM, OSINT_NETLAS_KEY="netlas-key", OSINT_NETLAS_MONTHLY_LIMIT=2)
class NetlasTests(SimpleTestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_summary_retains_only_bounded_public_context(self):
        summary = netlas.summarize({"ip": "203.0.113.5", "ptr": ["host.example"], "ports": [443],
                                    "geo": {"country": "Germany", "city": "Berlin"},
                                    "privacy": {"vpn": False, "proxy": True, "tor": False},
                                    "whois": {"registrant": "must not be retained"}})
        self.assertEqual(summary["ports"], [443])
        self.assertNotIn("whois", summary)

    def test_request_uses_public_indices_and_cache(self):
        import httpx
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(200, json={"ip": "203.0.113.5", "ports": [443]})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await netlas.host(client, "203.0.113.5"), await netlas.host(client, "203.0.113.5")

        first, second = asyncio.run(go())
        self.assertEqual(first["ports"], [443])
        self.assertTrue(second["aus_zwischenspeicher"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].headers["Authorization"], "Bearer netlas-key")
        self.assertEqual(calls[0].url.params["public_indices_only"], "true")


@override_settings(CACHES=LOCMEM, OSINT_SHODAN_KEY="shodan-key", OSINT_SHODAN_MONTHLY_LIMIT=2)
class ShodanHostTests(SimpleTestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_summary_limits_banner_and_keeps_timestamp(self):
        summary = shodan.summarize({"ip_str": "203.0.113.5", "hostnames": ["host.example"], "ports": [443],
                                    "last_update": "2026-10-10T10:00:00.000000", "data": [
                                        {"port": 443, "transport": "tcp", "product": "nginx", "timestamp": "2026-10-10T10:00:00.000000", "data": "x" * 500}
                                    ]})
        self.assertEqual(len(summary["dienste"][0]["banner"]), 160)
        self.assertEqual(summary["letzte_aktualisierung"], "2026-10-10T10:00:00.000000")

    def test_request_is_cached_and_key_is_not_in_source_result(self):
        import httpx
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(200, json={"ip_str": "203.0.113.5", "ports": [443]})

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await shodan.host(client, "203.0.113.5"), await shodan.host(client, "203.0.113.5")

        first, second = asyncio.run(go())
        self.assertEqual(first["ports"], [443])
        self.assertTrue(second["aus_zwischenspeicher"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].url.params["key"], "shodan-key")



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
        self.assertEqual(result["zum_stichtag"][0]["von_zeit"], "2026-06-01T00:00:00")
        self.assertEqual(result["zum_stichtag"][0]["bis_zeit"], "2026-06-20T00:00:00")
        self.assertEqual([a["wert"] for a in result["alle_adressen"]], ["1.2.3.4", "1.2.3.5"])  # Wechsel sichtbar
        self.assertEqual(result["alle_adressen"][0]["von_zeit"], "2026-06-01T00:00:00")
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

    def test_reputation_changes_are_reported(self):
        def rep(score, malicious):
            return [{"source": "AbuseIPDB", "ok": True, "data": {"abuseConfidenceScore": score, "totalReports": 0}},
                    {"source": "VirusTotal", "ok": True, "data": {"last_analysis_stats": {"malicious": malicious, "suspicious": 0}}},
                    {"source": "CrowdSec CTI", "ok": False, "error": "x"}]
        Lookup.objects.create(kind="ip", query="91.0.0.1", created_by=self.anna, status=Lookup.Status.DONE,
                              sources=rep(0, 0))
        current = Lookup.objects.create(kind="ip", query="91.0.0.1", created_by=self.anna)
        result = historie.own_history(current, rep(0, 3))
        self.assertEqual(result["aenderungen_seit_letzter_analyse"],
                         {"virustotal_boesartig": {"vorher": "0", "jetzt": "3"}})

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
        # Ortsdatum wie in historie.py: mit UTC schlug der Test nachts zwischen 0 und 2 Uhr fehl
        stichtag = __import__("django.utils.timezone", fromlist=["x"]).localtime(now - datetime.timedelta(days=9)).date()
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

    def test_note_is_kept_on_rerun_and_a_new_analysis_of_the_same_target(self):
        prior = Lookup.objects.create(kind="ip", query="8.8.8.8", created_by=self.user, note="Eigener Anschluss")
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[prior.pk]))
        self.assertEqual(Lookup.objects.latest("pk").note, "Eigener Anschluss")
        self._post("")
        self.assertEqual(Lookup.objects.latest("pk").note, "Eigener Anschluss")

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
        self.assertContains(page, "Weitere Analysen dieser Abfrage (1)")
        self.assertContains(page, "adressen</b>: 91.0.0.1 → 91.0.0.9")


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
    def test_every_source_and_the_whole_list_have_copy_and_toggle_buttons(self):
        user = get_user_model().objects.create_user("anna", password="x")
        lookup = Lookup.objects.create(
            kind="ip", query="8.8.8.8", created_by=user, status=Lookup.Status.DONE,
            sources=[{"source": "Reverse DNS", "ok": True, "data": {"ptr": "dns.google"}},
                     {"source": "RDAP", "ok": False, "error": "Timeout"}])
        self.client.force_login(user)
        page = self.client.get(reverse("lookups:detail", args=[lookup.pk]))
        self.assertContains(page, "data-copy-all")
        self.assertContains(page, "data-toggle-sources")
        self.assertContains(page, "data-copy-source", count=2)
        self.assertContains(page, '<pre class="raw">')
        self.assertContains(page, 'class="error raw"')  # auch Fehlermeldungen lassen sich kopieren
        # beim Nachladen während der Recherche enthalten die Teile ebenfalls den Button
        status = self.client.get(reverse("lookups:status", args=[lookup.pk])).json()
        self.assertTrue(all("data-copy-source" in source["html"] for source in status["sources"]))


class FakeMmdb:
    def __init__(self, record, prefix):
        self.record, self.prefix = record, prefix

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_with_prefix_len(self, ip):
        return self.record, self.prefix

    def metadata(self):
        return mock.Mock(build_epoch=1793491200)  # 2026-11-01


class GeoipTests(SimpleTestCase):
    CITY = {"country": {"iso_code": "DE", "names": {"de": "Deutschland", "en": "Germany"}},
            "subdivisions": [{"names": {"en": "Hesse"}}], "city": {"names": {"en": "Frankfurt am Main"}},
            "location": {"latitude": 50.1, "longitude": 8.7}}
    ASN = {"autonomous_system_number": 64500, "autonomous_system_organization": "Example Net GmbH"}

    def _lookup(self, files, readers):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder, override_settings(OSINT_GEOIP_DIR=folder):
            for name in files:
                Path(folder, name).write_bytes(b"")
            with mock.patch("lookups.collectors.geoip.maxminddb.open_database", side_effect=readers):
                return geoip.lookup("203.0.113.7")

    def test_reads_city_and_asn_with_attribution(self):
        result = self._lookup(["dbip-city-lite.mmdb", "dbip-asn-lite.mmdb"],
                              [FakeMmdb(self.CITY, 24), FakeMmdb(self.ASN, 20)])
        self.assertEqual(result["land"], "Deutschland")
        self.assertEqual(result["ort"], "Frankfurt am Main")
        self.assertEqual(result["asn"], "AS64500")
        self.assertEqual(result["netz_asn"], "203.0.112.0/20")
        self.assertIn("DB-IP", result["datenbanken"][0]["lizenz"])
        self.assertEqual(result["datenbanken"][0]["stand"], "2026-11-01")

    def test_prefers_geolite2_when_present(self):
        result = self._lookup(["GeoLite2-City.mmdb", "dbip-city-lite.mmdb"], [FakeMmdb(self.CITY, 24)])
        self.assertEqual(result["datenbanken"][0]["datei"], "GeoLite2-City.mmdb")
        self.assertIn("MaxMind", result["datenbanken"][0]["lizenz"])

    def test_missing_database_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "update_geoip"):
            self._lookup([], [])


class LocalOnlyTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user("chef", password="x", is_staff=True)

    def _submit(self, q="8.8.8.8", **extra):
        self.client.force_login(self.staff)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            return self.client.post(reverse("lookups:index"), {"q": q, "local_only": "on", **extra})

    def test_collect_makes_no_external_request(self):
        geo = {"land": "Deutschland"}
        with mock.patch("lookups.collectors.ip.geoip.lookup", return_value=geo), \
                mock.patch("socket.gethostbyaddr", side_effect=AssertionError("DNS")), \
                mock.patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS")):
            results = asyncio.run(ip.collect(client=None, ip="8.8.8.8", local_only=True, as_of="2026-01-01"))
        self.assertEqual([r["source"] for r in results], ["Adressklassifizierung", geoip.SOURCE])
        self.assertEqual(results[1]["data"], geo)

    def test_private_address_gets_only_the_classification(self):
        results = asyncio.run(ip.collect(client=None, ip="192.168.1.10", local_only=True))
        self.assertEqual([r["source"] for r in results], ["Adressklassifizierung"])

    def test_checkbox_is_stored_and_shown(self):
        self._submit()
        lookup = Lookup.objects.get()
        self.assertTrue(lookup.local_only)
        self.assertContains(self.client.get(reverse("lookups:detail", args=[lookup.pk])), "nur lokal")
        self.assertContains(self.client.get(reverse("lookups:index")), 'name="local_only"')

    def test_refused_for_hostnames_and_with_active_options(self):
        self.assertContains(self._submit(q="example.com"), "nur für IP-Adressen", status_code=400)
        self.assertContains(self._submit(active="on"), "schließt aktive", status_code=400)
        self.assertContains(self._submit(scan="on"), "schließt aktive", status_code=400)
        self.assertFalse(Lookup.objects.exists())

    def test_rerun_keeps_choice_only_when_selected_again(self):
        self._submit()
        first = Lookup.objects.get()
        Lookup.objects.filter(pk=first.pk).update(status=Lookup.Status.DONE)
        page = self.client.get(reverse("lookups:detail", args=[first.pk]))
        self.assertContains(page, 'name="local_only" value="on" checked', html=False)
        with mock.patch("lookups.views.run_lookup.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[first.pk]), {"local_only": "on"})
            self.client.post(reverse("lookups:rerun", args=[first.pk]), {})
        self.assertEqual(list(Lookup.objects.order_by("pk").values_list("local_only", flat=True)), [True, True, False])

    def test_task_passes_local_only_to_collectors(self):
        from .tasks import run_lookup
        lookup = Lookup.objects.create(kind="ip", query="8.8.8.8", local_only=True)
        seen = {}

        async def fake_collect(kind, query, on_result=None, **kwargs):
            seen.update(kwargs)
            return []

        with mock.patch("lookups.tasks.collect", fake_collect), mock.patch("lookups.tasks.llm.write_report", return_value=""):
            run_lookup(lookup.pk)
        self.assertTrue(seen["local_only"])


def _png(color="#cccccc", size=(256, 256)):
    import io
    from PIL import Image
    out = io.BytesIO()
    Image.new("RGB", size, color).save(out, "PNG")
    return out.getvalue()


class GeoTests(SimpleTestCase):
    SOURCES = [
        {"source": "Lokale GeoIP-Datenbank", "ok": True,
         "data": {"koordinaten": [50.11, 8.68], "ort": "Frankfurt", "land": "Deutschland", "genauigkeit_km": 20}},
        {"source": "ip-api.com (Geo/ASN)", "ok": True,
         "data": {"lat": 52.52, "lon": 13.40, "city": "Berlin", "country": "Deutschland"}},
        {"source": "Shodan Host API (Internet-Scan-Daten)", "ok": True, "data": {"koordinaten": [51.0, 10.0], "land": "Germany"}},
        {"source": "Netlas (Internet-Scan-Daten)", "ok": True, "data": {"koordinaten": [0, 0], "stadt": "Nowhere"}},
        {"source": "Censys (Internet-Scan-Daten)", "ok": False, "error": "x"},
    ]

    def test_points_carry_source_and_reported_or_estimated_accuracy(self):
        points = geo.locations(self.SOURCES)
        self.assertEqual([p["quelle"] for p in points],
                         ["Lokale GeoIP-Datenbank", "ip-api.com (Geo/ASN)", "Shodan Host API (Internet-Scan-Daten)"])
        self.assertEqual((points[0]["genauigkeit_km"], points[0]["geschaetzt"]), (20, False))
        self.assertEqual((points[1]["genauigkeit_km"], points[1]["geschaetzt"], points[1]["stufe"]), (25, True, "stadt"))
        self.assertEqual((points[2]["genauigkeit_km"], points[2]["stufe"]), (500, "land"))
        self.assertIn("mlat=52.52000", points[1]["osm"])

    def test_summary_reports_the_largest_distance(self):
        self.assertAlmostEqual(geo.summary(self.SOURCES)["max_abstand_km"], 424, delta=5)  # Frankfurt–Berlin
        self.assertIsNone(geo.summary([{"source": "Reverse DNS", "ok": True, "data": {"ptr": "x"}}]))

    def test_static_map_draws_over_osm_tiles(self):
        from PIL import Image
        import io
        with mock.patch("lookups.geo._tile", return_value=_png()) as tile:
            image = geo.static_map(geo.locations(self.SOURCES))
        self.assertTrue(tile.called)
        self.assertEqual(Image.open(io.BytesIO(image)).size, (900, 440))

    def test_static_map_is_skipped_when_tiles_fail(self):
        with mock.patch("lookups.geo._tile", side_effect=RuntimeError("offline")):
            self.assertIsNone(geo.static_map(geo.locations(self.SOURCES)))

    def test_collectors_expose_coordinates(self):
        self.assertEqual(shodan.summarize({"ip_str": "203.0.113.5", "latitude": 50.1, "longitude": 8.6,
                                           "city": "Frankfurt"})["koordinaten"], [50.1, 8.6])
        self.assertEqual(netlas.summarize({"ip": "203.0.113.5", "geo": {"location": {"lat": 1.5, "long": 2.5}}})
                         ["koordinaten"], [1.5, 2.5])
        resource = {"result": {"resource": {"ip": "203.0.113.5", "autonomous_system": {"asn": 1},
                                            "location": {"city": "X", "coordinates": {"latitude": 3.5, "longitude": 4.5}}}}}
        self.assertEqual(censys.summarize(resource)["koordinaten"], [3.5, 4.5])

    def test_prompt_contains_computed_locations_first(self):
        prompt = llm.build_prompt("ip", "203.0.113.5", self.SOURCES)
        data = prompt.split("Rohdaten je Quelle (JSON):\n", 1)[1]
        self.assertTrue(data.startswith('[{"source":"Standortabschätzung (berechnet)"'))
        self.assertIn('"max_abstand_km"', data)


class GeoViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("anna", password="x")
        self.lookup = Lookup.objects.create(kind="ip", query="203.0.113.5", created_by=self.user, status=Lookup.Status.DONE,
                                            report_md="# Deutsch\n## Kurzfazit\nx", sources=GeoTests.SOURCES)
        self.client.force_login(self.user)

    def test_detail_shows_map_and_legend(self):
        page = self.client.get(reverse("lookups:detail", args=[self.lookup.pk]))
        self.assertContains(page, 'class="geo-map"')
        self.assertContains(page, "vendor/leaflet/leaflet.")
        self.assertContains(page, "geschätzt")
        self.assertContains(page, "von der Quelle gemeldet")

    def test_pdf_embeds_map_image_and_legend(self):
        from . import pdf
        with mock.patch("lookups.geo._tile", return_value=_png()), \
                mock.patch("lookups.pdf.HTML") as html:
            pdf.render(self.lookup, None)
        fetcher = html.call_args.kwargs["url_fetcher"]
        self.assertIn('src="way-asset:map.png"', html.call_args.kwargs["string"])
        self.assertTrue(fetcher.fetch("way-asset:map.png").url)
        with self.assertRaises(ValueError):
            fetcher.fetch("way-asset:other.png")

    def test_local_only_pdf_keeps_osm_basemap(self):
        # Kartenkacheln verraten nur einen Kartenausschnitt, nicht die Adresse: auch bei „Nur lokal“ erlaubt.
        from . import pdf
        Lookup.objects.filter(pk=self.lookup.pk).update(local_only=True)
        self.lookup.refresh_from_db()
        with mock.patch("lookups.geo._tile", return_value=_png()) as tile, \
                mock.patch("lookups.pdf.HTML") as html:
            pdf.render(self.lookup, None)
        self.assertTrue(tile.called)
        self.assertIn('src="way-asset:map.png"', html.call_args.kwargs["string"])

    def test_pdf_renders_with_map(self):
        with mock.patch("lookups.geo._tile", return_value=_png()):
            response = self.client.get(reverse("lookups:pdf", args=[self.lookup.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content.startswith(b"%PDF"))


class MultiTargetTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("multi", password="x")
        self.client.force_login(self.user)

    def _submit(self, q, **extra):
        with mock.patch("lookups.views.run_lookup.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:index"), {"q": q, **extra})
        return response, delay

    def test_detect_many_splits_lines_commas_and_spaces_but_keeps_phone_numbers(self):
        from .detect import detect_many
        self.assertEqual(detect_many("+49 30 1234567"), [("phone", "+49301234567")])
        self.assertEqual(detect_many("203.0.113.5\n198.51.100.7, example.com; 203.0.113.5"),
                         [("ip", "203.0.113.5"), ("ip", "198.51.100.7"), ("host", "example.com")])
        self.assertEqual(detect_many("203.0.113.5\nexample.com"), [("ip", "203.0.113.5"), ("host", "example.com")])
        self.assertEqual(detect_many("203.0.113.5 198.51.100.7"), [("ip", "203.0.113.5"), ("ip", "198.51.100.7")])
        self.assertEqual(detect_many("+49 30 1234567\n203.0.113.5"), [("phone", "+49301234567"), ("ip", "203.0.113.5")])
        with self.assertRaisesMessage(ValueError, "„kein ziel“"):
            detect_many("203.0.113.5, kein ziel")
        with self.assertRaisesMessage(ValueError, "Höchstens 10"):
            detect_many(", ".join(f"203.0.113.{n}" for n in range(1, 12)))

    def test_several_targets_start_one_analysis_each(self):
        response, delay = self._submit("203.0.113.5\nexample.com", local_only="")
        self.assertRedirects(response, reverse("lookups:index"))
        self.assertEqual(sorted(Lookup.objects.values_list("kind", "query")), [("host", "example.com"), ("ip", "203.0.113.5")])
        self.assertEqual(delay.call_count, 2)

    def test_local_only_and_active_options_are_checked_for_every_target(self):
        response, _ = self._submit("203.0.113.5, example.com", local_only="on")
        self.assertContains(response, "nur für IP-Adressen", status_code=400)
        response, _ = self._submit("203.0.113.5, 198.51.100.7", active="on")
        self.assertContains(response, "einzelnes Ziel", status_code=400)
        self.assertFalse(Lookup.objects.exists())
        self._submit("203.0.113.5, 198.51.100.7", local_only="on")
        self.assertEqual(list(Lookup.objects.values_list("local_only", flat=True)), [True, True])

    def test_index_offers_multiline_input_and_comparison(self):
        Lookup.objects.create(kind="ip", query="203.0.113.5", created_by=self.user, status=Lookup.Status.DONE)
        page = self.client.get(reverse("lookups:index"))
        self.assertContains(page, '<textarea name="q"')
        self.assertContains(page, "data-pick-compare")
        self.assertContains(page, reverse("lookups:compare"))


class CompareTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("vergleich", password="x")
        self.client.force_login(self.user)
        done = Lookup.Status.DONE
        self.older = Lookup.objects.create(kind="ip", query="203.0.113.5", created_by=self.user, status=done,
                                           report_md="# Deutsch\n## Kurzfazit\nFrankfurt-Netz\n# English\n## Executive summary\nx",
                                           sources=GeoTests.SOURCES[:1])
        self.newer = Lookup.objects.create(kind="ip", query="198.51.100.7", created_by=self.user, status=done,
                                           report_md="Berlin-Netz", sources=GeoTests.SOURCES[1:2])
        Lookup.objects.filter(pk=self.older.pk).update(created_at=timezone.now() - timedelta(days=1))
        self.older.refresh_from_db()

    def _compare(self, *lookups):
        with mock.patch("lookups.views.run_compare.delay") as delay, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("lookups:compare"), {"ids": [f"{l.pk},999" for l in lookups]})
        return response, delay

    def test_selected_analyses_become_a_comparison(self):
        response, delay = self._compare(self.newer, self.older)
        comparison = Lookup.objects.get(kind="compare")
        self.assertRedirects(response, reverse("lookups:detail", args=[comparison.pk]))
        self.assertEqual(comparison.query, "Vergleich: 203.0.113.5, 198.51.100.7")
        self.assertEqual(set(comparison.compared.all()), {self.older, self.newer})
        delay.assert_called_once_with(comparison.pk)

    def test_needs_two_visible_completed_analyses(self):
        other = get_user_model().objects.create_user("fremd", password="x")
        foreign = Lookup.objects.create(kind="ip", query="192.0.2.1", created_by=other, status=Lookup.Status.DONE)
        running = Lookup.objects.create(kind="ip", query="192.0.2.2", created_by=self.user)
        for pair in ((self.older,), (self.older, foreign), (self.older, running)):
            self._compare(*pair)
        self.assertFalse(Lookup.objects.filter(kind="compare").exists())

    def test_task_writes_the_report_from_stored_results_only(self):
        from . import tasks
        comparison = Lookup.objects.create(kind="compare", query="Vergleich", created_by=self.user)
        comparison.compared.set([self.newer, self.older])
        with mock.patch("lookups.llm._chat", return_value="# Deutsch\nlaut [#1]") as chat, \
                mock.patch("lookups.collectors.collect", side_effect=AssertionError("Abfrage")):
            tasks.run_compare(comparison.pk)
        comparison.refresh_from_db()
        self.assertEqual(comparison.status, Lookup.Status.DONE)
        prompt = chat.call_args.args[1]
        self.assertLess(prompt.index(f"#{self.older.pk}"), prompt.index(f'"#{self.newer.pk}"'))
        self.assertIn("Frankfurt-Netz", prompt)
        self.assertNotIn("Executive summary", prompt)
        self.assertIn('"abstaende"', prompt)

    def test_detail_shows_report_links_map_and_members_by_date(self):
        comparison = Lookup.objects.create(kind="compare", query="Vergleich", created_by=self.user, status=Lookup.Status.DONE,
                                           report_md=f"# Deutsch\n## Kurzfazit\nPasst [ #{self.older.pk}, #{self.newer.pk} ].")
        comparison.compared.set([self.newer, self.older])
        page = self.client.get(reverse("lookups:detail", args=[comparison.pk]))
        html = page.content.decode()
        self.assertIn(f'href="{reverse("lookups:detail", args=[self.older.pk])}"', html)
        self.assertIn('class="geo-map"', html)
        self.assertLess(html.index(f'id="a{self.older.pk}"'), html.index(f'id="a{self.newer.pk}"'))
        self.assertIn("Rohdaten", html)
        self.assertIn("Lokale GeoIP-Datenbank", html)
        status = self.client.get(reverse("lookups:status", args=[comparison.pk])).json()
        self.assertIn("report", status["fragments"])

    def test_pdf_contains_comparison_map_and_raw_data_of_each_member(self):
        from . import pdf
        comparison = Lookup.objects.create(kind="compare", query="Vergleich", created_by=self.user, status=Lookup.Status.DONE,
                                           report_md=f"Passt [#{self.older.pk}].")
        comparison.compared.set([self.newer, self.older])
        with mock.patch("lookups.geo._tile", return_value=_png()), mock.patch("lookups.pdf.HTML") as html:
            pdf.render(comparison, None, members=[self.older, self.newer])
        text = html.call_args.kwargs["string"]
        self.assertIn('src="way-asset:map.png"', text)
        self.assertIn(f'href="#a{self.older.pk}"', text)
        self.assertIn("ip-api.com (Geo/ASN)", text)
        self.assertIn("Frankfurt-Netz", text)
        with mock.patch("lookups.geo._tile", return_value=_png()):
            response = self.client.get(reverse("lookups:pdf", args=[comparison.pk]))
        self.assertTrue(response.content.startswith(b"%PDF"))

    def test_rerun_compares_the_same_analyses_again(self):
        comparison = Lookup.objects.create(kind="compare", query="Vergleich", created_by=self.user, status=Lookup.Status.DONE)
        comparison.compared.set([self.newer, self.older])
        with mock.patch("lookups.views.run_compare.delay"), self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("lookups:rerun", args=[comparison.pk]))
        again = Lookup.objects.filter(kind="compare").exclude(pk=comparison.pk).get()
        self.assertEqual(set(again.compared.all()), {self.older, self.newer})

    def test_comparison_places_and_distances(self):
        places = geo.comparison([self.older, self.newer])
        self.assertEqual([p["analyse"] for p in places["punkte"]], [self.older.pk, self.newer.pk])
        self.assertEqual(places["abstaende"][0]["km"], round(geo.distance_km(*places["punkte"])))
        self.assertGreater(places["max_abstand_km"], 400)

    def test_members_are_filtered_by_visibility_when_shown(self):
        other = get_user_model().objects.create_user("fremd2", password="x")
        foreign = Lookup.objects.create(kind="ip", query="192.0.2.9", created_by=other, status=Lookup.Status.DONE,
                                        report_md="Geheim-Bericht")
        comparison = Lookup.objects.create(kind="compare", query="Vergleich", created_by=self.user, status=Lookup.Status.DONE)
        comparison.compared.set([self.older, foreign])
        page = self.client.get(reverse("lookups:detail", args=[comparison.pk]))
        self.assertNotContains(page, "Geheim-Bericht")
        self.assertContains(page, f'id="a{self.older.pk}"')
