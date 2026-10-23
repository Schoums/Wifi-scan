"""Tests du scanner : python -m unittest test_wifi_scan"""

import json
import os
import socket
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

import wifi_scan as ws


class ParsingTests(unittest.TestCase):
    def test_proc_net_arp(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0\n"
            "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
        )
        self.assertEqual(ws.parse_arp(text), {"192.168.1.1": "aa:bb:cc:dd:ee:01"})

    def test_macos_arp(self):
        text = ("? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n"
                "? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]\n")
        self.assertEqual(ws.parse_arp(text), {"192.168.1.1": "0a:0b:0c:0d:0e:0f"})

    def test_windows_arp(self):
        text = ("Interface : 192.168.1.20 --- 0x5\n"
                "  Adresse Internet      Adresse physique      Type\n"
                "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamique\n"
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     statique\n")
        self.assertEqual(ws.parse_arp(text), {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})

    def test_linux_route(self):
        text = ("Iface\tDestination\tGateway \tFlags\n"
                "wlan0\t00000000\t0101A8C0\t0003\n"
                "wlan0\t0001A8C0\t00000000\t0001\n")
        self.assertEqual(ws.parse_linux_route(text), "192.168.1.1")

    def test_gateway_french_and_macos(self):
        self.assertEqual(ws.parse_gateway(
            "   Passerelle par d\x82faut. . . . . . . . . : 192.168.1.254\n"), "192.168.1.254")
        self.assertEqual(ws.parse_gateway("   gateway: 10.0.0.1\n"), "10.0.0.1")

    def test_netmask(self):
        self.assertEqual(ws.parse_netmask(
            "\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255", "192.168.1.20"),
            "255.255.255.0")
        win = ("   Adresse IPv4. . . . . . . . . . . . . .: 192.168.1.20\n"
               "   Masque de sous-r\x82seau. . . . . . . . . : 255.255.254.0\n")
        self.assertEqual(ws.parse_netmask(win, "192.168.1.20"), "255.255.254.0")

    def test_dns(self):
        self.assertEqual(ws.parse_resolv_conf("# x\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n"),
                         ["192.168.1.1", "1.1.1.1"])
        win = ("   Serveurs DNS. . . . . . . . . . . . . : 192.168.1.1\n"
               "                                       8.8.8.8\n"
               "   NetBIOS sur Tcpip. . . . . . . . . . . : Activ\x82\n")
        self.assertEqual(ws.parse_windows_dns(win), ["192.168.1.1", "8.8.8.8"])

    def test_mac_helpers(self):
        self.assertTrue(ws.is_random_mac("da:a1:19:00:00:01"))
        self.assertFalse(ws.is_random_mac("00:1a:2b:3c:4d:5e"))
        self.assertIsNone(ws.normalize_mac("ff-ff-ff-ff-ff-ff"))


class AnalysisTests(unittest.TestCase):
    def dev(self, ip, ports=(), known=True):
        return {"ip": ip, "mac": None, "name": "", "ports": list(ports), "known": known}

    def test_findings(self):
        devices = [self.dev("192.168.1.1", [80, 23, 7547]),
                   self.dev("192.168.1.50", [5555], known=False)]
        f = ws.analyse(devices, "192.168.1.1", ["192.168.1.1", "45.33.1.2"])
        titles = [x["title"] for x in f]
        self.assertEqual(f[0]["level"], "danger")
        self.assertIn("Telnet ouvert sur la box (port 23)", titles)
        self.assertTrue(any("ADB" in t for t in titles))
        self.assertTrue(any("inconnu" in t for t in titles))
        self.assertTrue(any("45.33.1.2" in t for t in titles))
        self.assertFalse(any("80" in t for t in titles))

    def test_dns_classification(self):
        self.assertEqual(ws.classify_dns("192.168.1.1")[0], "ok")
        self.assertEqual(ws.classify_dns("1.1.1.1")[0], "ok")
        self.assertEqual(ws.classify_dns("45.33.1.2")[0], "warn")


class LiveTests(unittest.TestCase):
    def test_tcp_state(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        self.assertEqual(ws.tcp_state("127.0.0.1", port), "open")
        srv.close()
        self.assertEqual(ws.tcp_state("127.0.0.1", port), "closed")


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.known = mock.patch.object(ws, "KNOWN_FILE", os.path.join(self.tmp.name, "k.json"))
        self.known.start()
        report = {"network": "192.168.1.0/24", "me": "192.168.1.20", "gateway": "192.168.1.1",
                  "dns": [], "findings": [], "port_names": {}, "duration": 1, "date": "",
                  "devices": [
                      {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "name": "box", "ports": [],
                       "is_gateway": True, "is_me": False, "random_mac": False,
                       "known": False, "label": ""}]}
        self.scan = mock.patch.object(ws, "scan", return_value=report)
        self.scan.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ws.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.scan.stop()
        self.known.stop()
        self.tmp.cleanup()

    def post(self, path, body, header=True):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), method="POST",
                                     headers={"X-Scanner": "1"} if header else {})
        with urllib.request.urlopen(req) as r:
            return json.load(r)

    def test_page(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn(b"Lancer le scan", r.read())

    def test_scan_and_mark_known(self):
        r = self.post("/api/scan", {})
        self.assertFalse(r["devices"][0]["known"])
        r = self.post("/api/known", {"key": "aa:bb:cc:dd:ee:01", "action": "add", "name": "Box"})
        self.assertTrue(r["devices"][0]["known"])
        self.assertEqual(r["devices"][0]["label"], "Box")
        self.assertEqual(ws.load_known()["aa:bb:cc:dd:ee:01"]["name"], "Box")
        r = self.post("/api/known", {"key": "aa:bb:cc:dd:ee:01", "action": "forget"})
        self.assertFalse(r["devices"][0]["known"])

    def test_rejects_without_header(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.post("/api/scan", {}, header=False)
        self.assertEqual(cm.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
