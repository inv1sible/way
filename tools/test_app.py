import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

os.environ["TOOLS_TOKEN"] = "test-token"

import app  # noqa: E402

CERT_PEM = None


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
            CERT_PEM = open(f"{tmp}/c").read()
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
