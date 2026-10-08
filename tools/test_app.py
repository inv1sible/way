import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

os.environ["TOOLS_TOKEN"] = "test-token"

import app  # noqa: E402

CERT_PEM = None
VALID_BOXINFO = b"""<?xml version="1.0" encoding="utf-8"?>
<j:BoxInfo xmlns:j="http://jason.avm.de/updatecheck/">
  <j:Name>FRITZ!Box 7590 AX</j:Name>
  <j:HW>259</j:HW>
  <j:Version>259.08.02-123456</j:Version>
  <j:Revision>123456</j:Revision>
  <j:OEM>avm</j:OEM>
  <j:Lang>de</j:Lang>
  <j:Annex>B</j:Annex>
  <j:Lab>Labor</j:Lab>
  <j:Serial>SERIAL-MUST-NEVER-LEAK</j:Serial>
</j:BoxInfo>"""
MISSING_BOXINFO_FIELDS = b"""<?xml version="1.0"?>
<BoxInfo><Name>Test Router</Name><HW>123</HW></BoxInfo>"""
INVALID_BOXINFO_DOCUMENTS = (
    b'<?xml version="1.0"?><BoxInfo><Name>FRITZ!Box 7590</BoxInfo>',
    b"<!doctype html><html><head><title>Router login</title></head><body>Login</body></html>",
    b'''<?xml version="1.0"?>
<!DOCTYPE BoxInfo [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<BoxInfo><Name>&secret;</Name><HW>259</HW></BoxInfo>''',
)


def make_cert():
    global CERT_PEM
    if CERT_PEM is None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", f"{tmp}/k", "-out", f"{tmp}/c", "-days", "30", "-subj", "/CN=test.example/O=Test AG",
                 "-addext", "subjectAltName=DNS:test.example,DNS:www.test.example,IP:203.0.113.5"],
                check=True, capture_output=True,
            )
            CERT_PEM = Path(f"{tmp}/c").read_text()
    return CERT_PEM


class TargetChecks(unittest.TestCase):
    def test_internal_addresses_are_refused(self):
        for value in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.17.0.2", "169.254.169.254", "100.64.0.1",
                      "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1",
                      "fe80::1%eth0"):
            with self.assertRaises(app.Refused, msg=value):
                app.classify(value)

    def test_public_addresses_and_hostnames_pass(self):
        self.assertEqual(app.classify("8.8.8.8")[0], "ip")
        self.assertEqual(app.classify("2001:4860:4860::8888")[0], "ip")
        self.assertEqual(app.classify("Example.COM."), ("host", "example.com"))

    def test_invalid_hostnames_are_refused(self):
        for value in ("db", "localhost", "-x.example.com", "a b.example.com", "x;ls.example.com", "", "1.2.3", "a.b/../c.com"):
            with self.assertRaises(app.Refused, msg=value):
                app.classify(value)

    def test_ports_are_limited(self):
        self.assertEqual(app.port_of({"port": "443"}, app.TLS_PORTS, 443), 443)
        for port in (22, 6379, "abc", None.__class__):
            with self.assertRaises(app.Refused):
                app.port_of({"port": port}, app.TLS_PORTS, 443)

    def test_fritz_ports_and_timeout_are_strictly_limited(self):
        self.assertEqual(app.fritz_ports({}), [443, 8443])
        self.assertEqual(app.fritz_ports({"ports": [443, "9443", 443]}), [443, 9443])
        self.assertEqual(app.fritz_timeout({}), 8)
        for ports in ([], [1, 2, 3, 4, 5], [0], [65536], [True], "443"):
            with self.assertRaises(app.Refused, msg=ports):
                app.fritz_ports({"ports": ports})
        for timeout in (1, 21, "x", True):
            with self.assertRaises(app.Refused, msg=timeout):
                app.fritz_timeout({"timeout": timeout})

    def test_private_ip_is_refused_by_every_tool(self):
        for name, params in (("tls", {"ip": "192.168.1.1"}), ("web", {"ip": "127.0.0.1"}), ("asn", {"ip": "10.0.0.1"}),
                             ("whois", {"target": "172.16.0.1"}), ("scan", {"ip": "192.168.1.139"})):
            with self.assertRaises(app.Refused, msg=name):
                app.TOOLS[name](params)


class Parsers(unittest.TestCase):
    def test_cymru_names(self):
        self.assertEqual(app.cymru_name(app.parse_ip("1.2.3.4")), "4.3.2.1.origin.asn.cymru.com")
        v6 = app.cymru_name(app.parse_ip("2001:db8::1"))
        self.assertTrue(v6.startswith("1.0.0.0.") and v6.endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com"), v6)

    def test_parse_nmap(self):
        xml = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="203.0.113.5"/>
          <ports><extraports state="filtered" count="996"/>
            <port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" tunnel="ssl"/></port>
            <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="protocol 2.0"/></port>
            <port protocol="tcp" portid="3306"><state state="closed"/><service name="mysql"/></port>
            <port protocol="tcp" portid="23"><state state="closed"/></port>
          </ports></host><runstats><finished elapsed="31.42"/></runstats></nmaprun>"""
        result = app.parse_nmap(xml)
        self.assertEqual([p["port"] for p in result["offen"]], [22, 443])
        self.assertEqual(result["offen"][0], {"port": 22, "proto": "tcp", "dienst": "ssh", "produkt": "OpenSSH",
                                              "version": "9.2p1", "zusatz": "protocol 2.0"})
        self.assertEqual((result["anzahl_offen"], result["gefiltert"], result["geschlossen"]), (2, 996, 2))
        self.assertEqual(result["dauer_s"], 31.42)
        self.assertEqual([(f["port"], f["stufe"]) for f in result["auffaellig"]], [(22, "mittel")])  # 443 ist normal

    def test_flag_ports_levels(self):
        flagged = app.flag_ports([{"port": p} for p in (80, 443, 3389, 5901, 8443, 6379)])
        self.assertEqual({f["port"]: f["stufe"] for f in flagged}, {3389: "hoch", 5901: "hoch", 8443: "mittel", 6379: "hoch"})

    def test_parse_dig_joins_split_txt_and_drops_empty(self):
        out = '"v=spf1 include:a.example " "~all"\n""\n;; Kommentar\n"v=DMARC1;p=none"\n'
        self.assertEqual(app.parse_dig(out), ["v=spf1 include:a.example ~all", "v=DMARC1;p=none"])

    def test_parse_whois(self):
        text = """% This is the RIPE Database
inetnum:        185.220.101.0 - 185.220.101.255
netname:        ARTIKEL10
descr:          Artikel10 e.V.
descr:          Berlin
country:        DE
abuse-mailbox:  abuse@artikel10.org
remarks:        wird ignoriert
mnt-by:         ignoriert
"""
        fields = app.parse_whois(text)
        self.assertEqual(fields["netname"], "ARTIKEL10")
        self.assertEqual(fields["descr"], ["Artikel10 e.V.", "Berlin"])
        self.assertNotIn("remarks", fields)

    def test_parse_headers_uses_last_block(self):
        text = "HTTP/1.1 100 Continue\r\n\r\nHTTP/2 301\r\nServer: nginx\r\nLocation: https://x.example/\r\nSet-Cookie: sid=abc; Path=/\r\n\r\n"
        status, headers, cookies = app.parse_headers(text)
        self.assertEqual((status, headers["server"], cookies), (301, "nginx", ["sid"]))

    def test_describe_cert(self):
        cert = app.describe_cert(make_cert())
        self.assertIn("test.example", cert["inhaber"])
        self.assertTrue(cert["selbstsigniert"])
        self.assertEqual(cert["alternative_namen"], ["test.example", "www.test.example", "203.0.113.5"])
        self.assertFalse(cert["abgelaufen"])
        self.assertTrue(28 <= cert["tage_bis_ablauf"] <= 30)


class FritzBoxParserTests(unittest.TestCase):
    def test_valid_boxinfo_and_version_fields(self):
        result = app.parse_boxinfo(VALID_BOXINFO)
        self.assertTrue(result["plausible"])
        self.assertEqual(result["device"], {
            "model": "FRITZ!Box 7590 AX",
            "hardwareId": "259",
            "fritzOsVersion": "8.02",
            "rawFirmwareVersion": "259.08.02-123456",
            "revision": "123456",
            "oem": "avm",
            "language": "de",
            "annex": "B",
            "labBuild": "Labor",
        })
        self.assertTrue(result["serialRedacted"])
        self.assertNotIn("SERIAL-MUST-NEVER-LEAK", json.dumps(result))

    def test_missing_fields_are_null_and_model_is_not_invented(self):
        result = app.parse_boxinfo(MISSING_BOXINFO_FIELDS)
        self.assertIsNone(result["device"]["model"])
        self.assertIsNone(result["device"]["fritzOsVersion"])
        self.assertIsNone(result["device"]["revision"])

    def test_malformed_login_and_xxe_are_rejected(self):
        for document in INVALID_BOXINFO_DOCUMENTS:
            with self.assertRaises(ValueError):
                app.parse_boxinfo(document)

    def test_oversized_response_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "zu groß"):
            app.parse_boxinfo(b"<BoxInfo>" + b"x" * 65_537 + b"</BoxInfo>")

    def test_version_is_only_derived_for_unambiguous_formats(self):
        self.assertEqual(app.derive_fritz_os("154.07.57"), "7.57")
        self.assertEqual(app.derive_fritz_os("259.08.02-123456"), "8.02")
        self.assertEqual(app.derive_fritz_os("7.57"), "7.57")
        for value in ("", "154.7", "Linux 5.15", "154.07.57 extra"):
            self.assertIsNone(app.derive_fritz_os(value))

    def test_speedport_status_is_allowlisted_and_does_not_leak_other_fields(self):
        payload = json.dumps({
            "device_name": "Speedport_Smart_4_Typ_A", "firmware_version": "010139.5.0.001.0",
            "serial_number": "SERIAL-MUST-NEVER-LEAK", "connected_devices": ["private-device"],
        }).encode()
        result = app.parse_speedport_status(payload)
        self.assertTrue(result["plausible"])
        self.assertEqual(result["device"], {
            "vendor": "Telekom", "model": "Speedport Smart 4 Typ A", "rawFirmwareVersion": "010139.5.0.001.0",
        })
        serialized = json.dumps(result)
        self.assertNotIn("SERIAL-MUST-NEVER-LEAK", serialized)
        self.assertNotIn("private-device", serialized)

    def test_speedport_status_rejects_invalid_json_and_does_not_guess_model(self):
        with self.assertRaises(ValueError):
            app.parse_speedport_status(b"<html>login</html>")
        result = app.parse_speedport_status(b'{"model_name":"Home Gateway","firmware_version":"1.2"}')
        self.assertFalse(result["plausible"])
        self.assertIsNone(result["device"]["model"])


class FritzBoxToolTests(unittest.TestCase):
    def _fetch(self, status=404, body=b"", content_type="text/plain", oversized=False):
        return {
            "url": "https://router.example:443/jason_boxinfo.xml",
            "status": status,
            "headers": {"content-type": content_type},
            "cookieNames": [],
            "body": body,
            "oversized": oversized,
        }

    def test_401_403_404_are_normal_negative_results(self):
        for status in (401, 403, 404):
            with self.subTest(status=status), \
                    mock.patch.object(app, "_curl_fetch", return_value=self._fetch(status=status)), \
                    mock.patch.object(app, "probe_tls", side_effect=RuntimeError("kein TLS")):
                result = app.tool_fritzbox({"ip": "8.8.8.8", "ports": [443]})
                self.assertIsNone(result["boxinfo"])
                endpoint = result["services"][0]["endpoints"][1]
                self.assertEqual((endpoint["status"], endpoint["result"]), (status, "negative"))

    def test_timeout_is_a_normal_negative_result(self):
        with mock.patch.object(app, "_curl_fetch", side_effect=RuntimeError("Zeitüberschreitung nach 8 s")), \
                mock.patch.object(app, "probe_tls", side_effect=RuntimeError("kein TLS")):
            result = app.tool_fritzbox({"ip": "8.8.8.8", "ports": [443]})
        self.assertIsNone(result["boxinfo"])
        self.assertEqual(len(result["services"][0]["endpoints"]), 2)
        self.assertTrue(all(e["result"] == "negative" for e in result["services"][0]["endpoints"]))

    def test_valid_boxinfo_is_parsed_without_serial_in_output_or_logs(self):
        calls = []

        def fetch(addr, sni, port, scheme, path, timeout):
            calls.append((str(addr), sni, port, scheme, path, timeout))
            if path == "/":
                return self._fetch(200, b"<html><title>FRITZ!Box</title></html>", "text/html")
            return self._fetch(200, VALID_BOXINFO, "application/xml")

        cert = {"inhaber": "CN=router.example", "aussteller": "CN=router.example", "alternative_namen": [],
                "vertrauenswuerdig": False, "gueltig_ab": None, "gueltig_bis": None}
        with mock.patch.object(app, "_curl_fetch", side_effect=fetch), mock.patch.object(app, "probe_tls", return_value=cert), \
                mock.patch("builtins.print") as printed:
            result = app.tool_fritzbox({"ip": "8.8.8.8", "sni": "router.example", "ports": [443], "timeout": 8})
        serialized = json.dumps(result)
        self.assertNotIn("SERIAL-MUST-NEVER-LEAK", serialized)
        self.assertNotIn("SERIAL-MUST-NEVER-LEAK", repr(printed.call_args_list))
        self.assertEqual(result["boxinfo"]["device"]["model"], "FRITZ!Box 7590 AX")
        self.assertEqual([call[4] for call in calls], ["/", "/jason_boxinfo.xml"])
        self.assertIn("nicht vertrauenswürdig", result["warnings"][0])

    def test_oversized_xml_is_not_parsed(self):
        responses = [self._fetch(200, b"<html></html>", "text/html"),
                     self._fetch(200, b"<BoxInfo/>", "application/xml", oversized=True)]
        with mock.patch.object(app, "_curl_fetch", side_effect=responses), \
                mock.patch.object(app, "probe_tls", side_effect=RuntimeError("kein TLS")), \
                mock.patch.object(app, "parse_boxinfo") as parser:
            result = app.tool_fritzbox({"ip": "8.8.8.8", "ports": [443]})
        parser.assert_not_called()
        self.assertIsNone(result["boxinfo"])

    def test_ipv6_url_is_bracketed_and_hostname_is_pinned(self):
        seen = []

        def fake_run(cmd, timeout, input_text=None):
            seen.append(cmd)
            header = Path(cmd[cmd.index("-D") + 1])
            body = Path(cmd[cmd.index("-o") + 1])
            header.write_text("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n")
            body.write_bytes(b"")
            return "", "", 0

        with mock.patch.object(app, "run", side_effect=fake_run):
            fetched = app._curl_fetch(app.parse_ip("2001:4860:4860::8888"), "router.example", 9443,
                                      "https", "/jason_boxinfo.xml", 8)
        command = seen[0]
        self.assertIn("router.example:9443:[2001:4860:4860::8888]", command)
        self.assertEqual(command[command.index("--max-redirs") + 1], "0")
        self.assertEqual(command[-1], "https://router.example:9443/jason_boxinfo.xml")
        self.assertEqual(fetched["status"], 404)

    def test_generic_router_profile_only_requests_the_root(self):
        fetched = self._fetch(200, b"<html><title>Speedport Router</title></html>", "text/html")
        with mock.patch.object(app, "_curl_fetch", return_value=fetched) as fetch, \
                mock.patch.object(app, "probe_tls", side_effect=RuntimeError("kein TLS")):
            result = app.tool_router({"ip": "8.8.8.8", "profile": "generic"})
        self.assertEqual(result["ports"], [443])
        self.assertEqual([call.args[4] for call in fetch.call_args_list], ["/"])
        self.assertIn("Router-/Gateway", result["observations"][0]["evidence"])
        self.assertIn("höchstens zwei HTTP-Anfragen", result["requestPolicy"])

    def test_speedport_profile_only_requests_root_and_public_status(self):
        def fetch(addr, sni, port, scheme, path, timeout):
            body = b"<html><title>Speedport</title></html>" if path == "/" else (
                b'{"device_name":"Speedport_Smart_4","firmware_version":"010139.5.0.001.0"}'
            )
            return self._fetch(200, body, "text/html" if path == "/" else "application/json")

        with mock.patch.object(app, "_curl_fetch", side_effect=fetch) as mocked, \
                mock.patch.object(app, "probe_tls", side_effect=RuntimeError("kein TLS")):
            result = app.tool_router({"ip": "8.8.8.8", "profile": "speedport", "ports": [443]})
        self.assertEqual([call.args[4] for call in mocked.call_args_list], ["/", "/data/Status.json"])
        self.assertEqual(result["speedport"]["device"]["model"], "Speedport Smart 4")
        self.assertIn("keine Redirects, Anmeldung", result["requestPolicy"])


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def post(self, payload, token="test-token"):
        request = urllib.request.Request(
            f"{self.base}/run", data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {token}"} if token else {}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_health_needs_no_token(self):
        with urllib.request.urlopen(f"{self.base}/health") as response:
            self.assertEqual(response.status, 200)

    def test_token_is_required(self):
        self.assertEqual(self.post({"tool": "dns", "target": "example.com"}, token=None)[0], 401)
        self.assertEqual(self.post({"tool": "dns", "target": "example.com"}, token="falsch")[0], 401)

    def test_unknown_tool_and_garbage(self):
        self.assertEqual(self.post({"tool": "rm"})[0], 400)
        self.assertEqual(self.post({"nope": 1})[0], 400)

    def test_internal_target_is_refused_with_400(self):
        status, body = self.post({"tool": "tls", "ip": "192.168.1.1"})
        self.assertEqual(status, 400)
        self.assertTrue(body["refused"])

    def test_dig_runs_for_real_when_dns_is_available(self):
        status, body = self.post({"tool": "asn", "ip": "8.8.8.8"})
        if status == 502:
            self.skipTest("kein DNS-Zugriff in dieser Umgebung: " + body["error"])
        self.assertEqual(status, 200)
        self.assertIn("AS15169", body["data"]["asn"])


if __name__ == "__main__":
    unittest.main()
