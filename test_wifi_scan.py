"""Tests du scanner : python -m unittest test_wifi_scan"""

import ipaddress
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.parse import parse_qs, urlparse

import wifi_scan as ws

# Réponses au format de l'API locale de la Bbox (valeurs inventées).
BBOX_DEVICE = [{"device": {"modelname": "F@st5688b", "uptime": 172800,
                           "main": {"version": "24.0.12", "date": "2024-06-27T11:15:05Z"}}}]
BBOX_HOSTS = [{"hosts": {"list": [
    {"hostname": "Bouygtel4K-272", "macaddress": "00:11:22:33:44:55", "ipaddress": "192.168.1.148",
     "link": "Ethernet", "active": 1, "guest": 0, "firstseen": "2024-01-02T10:00:00+0100", "lastseen": 0},
    {"hostname": "Mac", "macaddress": "3C:22:FB:00:00:01", "ipaddress": "192.168.1.20",
     "link": "Wifi 5", "active": 1, "guest": 0, "firstseen": "2024-01-02T10:00:00+0100", "lastseen": 0},
    {"hostname": "iPhone-004", "macaddress": "DA:A1:19:00:00:04", "ipaddress": "192.168.1.30",
     "link": "Wifi 2.4", "active": 1, "guest": 0, "firstseen": "2024-01-02T10:00:00+0100", "lastseen": 0},
    {"hostname": "Michel", "macaddress": "AA:BB:CC:00:00:64", "ipaddress": "192.168.1.64",
     "link": "Wifi 2.4", "active": 1, "guest": 0, "firstseen": "2024-01-02T10:00:00+0100", "lastseen": 0},
    {"hostname": "android-x", "macaddress": "02:00:00:00:00:99", "ipaddress": "192.168.1.99",
     "link": "Wifi 2.4", "active": 0, "guest": 0, "firstseen": "2026-10-20T10:00:00+0200",
     "lastseen": 7200},
]}}]
BBOX_WIRELESS = [{"wireless": {
    "radio": {"24": {"enable": 1, "state": 1, "standard": "11n", "channel": 0, "current_channel": 11,
                     "current_bandwidth": 20},
              "5": {"enable": 1, "state": 1, "standard": "11ac", "channel": 0, "current_channel": 0,
                    "current_bandwidth": 80},
              "guest": {"enable": 0}},
    "ssid": {"24": {"id": "Bbox-MICHEL", "enable": 1, "bssid": "AA:00:00:00:00:4B",
                    "wps": {"enable": 1}, "security": {"protocol": "WPA2", "isdefault": 0,
                                                        "passphrase": "SECRET-PASS"}},
             "5": {"id": "Bbox-MICHEL", "enable": 1, "bssid": "AA:00:00:00:00:4D",
                   "wps": {"enable": 1}, "security": {"protocol": "WPA2", "isdefault": 0,
                                                       "passphrase": "SECRET-PASS"}},
             "guest": {"id": "Bbox-Invite", "enable": 0, "security": {"protocol": "WPA2"}},
             "compatibility": {"id": "Bbox-Legacy", "enable": 0, "security": {"protocol": "WPA+WPA2"}}}}}]
BBOX_SERVICES = [{"services": {"firewall": {"enable": 1}, "upnp": {"igd": {"enable": 1}},
                               "remote": {"admin": {"enable": 0, "port": 4443}}}}]
BBOX_ALERTS = [{"alerts": {"list": [
    {"ident": "ALERT_WAN_API_LOCKED", "param": "10.0.0.198;10;40;", "count": 8,
     "last_date": "2026-10-22T14:20:26+0200", "level": "warning"}]}}]


class FakeBbox(BaseHTTPRequestHandler):
    """Imite l'API locale : tout exige le cookie BBOX_ID et le btoken."""
    logins = 0
    data = {"device": BBOX_DEVICE, "hosts": BBOX_HOSTS, "wireless": BBOX_WIRELESS,
            "services": BBOX_SERVICES, "alerts": BBOX_ALERTS}

    def log_message(self, *a):
        pass

    def reply(self, code, body, cookie=None):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", f"BBOX_ID={cookie}; Path=/; HttpOnly")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path == "/api/v1/login":
            FakeBbox.logins += 1
            form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if form.get("password") == ["bon-mot-de-passe"]:
                return self.reply(200, {}, cookie="session42")
            return self.reply(401, {"exception": {"code": "401"}})
        self.reply(404, {})

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path[len("/api/v1/"):]
        logged = "BBOX_ID=session42" in (self.headers.get("Cookie") or "")
        if path == "device/token":
            if not logged:
                return self.reply(401, {})
            return self.reply(200, [{"device": {"token": "tok", "expires": "2099-01-01T00:00:00Z"}}])
        if not logged or parse_qs(url.query).get("btoken") != ["tok"]:
            return self.reply(401, {"exception": {"code": "401"}})
        if path in self.data:
            return self.reply(200, self.data[path])
        self.reply(404, {})


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


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
                "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamique\n"
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     statique\n")
        self.assertEqual(ws.parse_arp(text), {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})

    def test_linux_route(self):
        text = ("Iface\tDestination\tGateway \tFlags\n"
                "wlan0\t00000000\t0101A8C0\t0003\n")
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
        self.assertEqual(ws.parse_resolv_conf("nameserver 192.168.1.1\nnameserver 1.1.1.1\n"),
                         ["192.168.1.1", "1.1.1.1"])
        win = ("   Serveurs DNS. . . . . . . . . . . . . : 192.168.1.1\n"
               "                                       8.8.8.8\n"
               "   NetBIOS sur Tcpip. . . . . . . . . . . : Activ\x82\n")
        self.assertEqual(ws.parse_windows_dns(win), ["192.168.1.1", "8.8.8.8"])

    def test_mac_helpers(self):
        self.assertTrue(ws.is_random_mac("da:a1:19:00:00:01"))
        self.assertFalse(ws.is_random_mac("00:1a:2b:3c:4d:5e"))
        self.assertIsNone(ws.normalize_mac("ff-ff-ff-ff-ff-ff"))


def mdns_answer(qname, target):
    """Réponse mDNS « legacy unicast » : question + PTR compressé."""
    rdata = ws.dns_name(target)
    return (struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0) + ws.dns_name(qname)
            + struct.pack(">HH", 12, 1) + b"\xc0\x0c"
            + struct.pack(">HHIH", 12, 1, 10, len(rdata)) + rdata)


class DiscoveryTests(unittest.TestCase):
    def test_mdns_reverse_name(self):
        pkt = mdns_answer(ws.reverse_name("192.168.1.20"), "Mac-de-Michel.local")
        ptrs = ws.parse_dns_ptrs(pkt)
        self.assertEqual(ptrs, [("20.1.168.192.in-addr.arpa", "Mac-de-Michel.local")])
        self.assertEqual(ws.friendly_mdns_name(ptrs), "Mac-de-Michel")

    def test_mdns_service_instance(self):
        ptrs = ws.parse_dns_ptrs(mdns_answer("_companion-link._tcp.local",
                                             "iPhone de Michel._companion-link._tcp.local"))
        self.assertEqual(ws.friendly_mdns_name(ptrs), "iPhone de Michel")

    def test_mdns_garbage(self):
        self.assertEqual(ws.parse_dns_ptrs(b"\x00\x01garbage"), [])

    def test_mdns_probe_live(self):
        """Un faux répondeur Bonjour sur 127.0.0.1:5353."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            srv.bind(("127.0.0.1", 5353))
        except OSError:
            self.skipTest("port 5353 indisponible")

        def respond():
            data, addr = srv.recvfrom(2048)
            srv.sendto(mdns_answer(ws.reverse_name("127.0.0.1"), "Mac.local"), addr)
        t = threading.Thread(target=respond, daemon=True)
        t.start()
        try:
            with mock.patch.object(ws, "MDNS_SERVICES", []):
                self.assertEqual(ws.mdns_probe(["127.0.0.1"], wait=1.0), {"127.0.0.1": "Mac"})
        finally:
            srv.close()

    def test_nbstat(self):
        entry = b"BUREAU-PC".ljust(15) + b"\x00" + struct.pack(">H", 0x0400)
        group = b"WORKGROUP".ljust(15) + b"\x00" + struct.pack(">H", 0x8400)
        pkt = b"\x00" * 56 + bytes([2]) + group + entry
        self.assertEqual(ws.parse_nbstat(pkt), "BUREAU-PC")
        self.assertEqual(ws.parse_nbstat(b"court"), "")

    def test_tcp_state(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        self.assertEqual(ws.tcp_state("127.0.0.1", port), "open")
        srv.close()
        self.assertEqual(ws.tcp_state("127.0.0.1", port), "closed")


class BboxTests(unittest.TestCase):
    def setUp(self):
        FakeBbox.logins = 0
        self.server, self.base = serve(FakeBbox)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def info(self, password):
        return ws.bbox_info(None, password, bases=["http://127.0.0.1:9/api/v1",  # injoignable
                                                   self.base + "/api/v1"])

    def test_full_read_with_password(self):
        info = self.info("bon-mot-de-passe")
        self.assertTrue(info["authenticated"])
        self.assertEqual(FakeBbox.logins, 1)
        self.assertEqual(info["device"]["firmware"], "24.0.12")
        self.assertEqual([h["name"] for h in info["hosts"] if h["active"]],
                         ["Bouygtel4K-272", "Mac", "iPhone-004", "Michel"])
        self.assertEqual(info["hosts"][1]["link"], "Wi-Fi 5 GHz")
        self.assertEqual(info["hosts"][1]["mac"], "3c:22:fb:00:00:01")
        w = info["wireless"]
        self.assertTrue(w["unified"])
        self.assertTrue(w["bands"]["24"]["wps"])
        self.assertEqual(w["bands"]["24"]["channel"], 11)
        self.assertEqual(w["bands"]["5"]["channel"], 0)
        self.assertNotIn("SECRET-PASS", json.dumps(info))  # jamais le mot de passe Wi-Fi
        self.assertTrue(info["services"]["upnp"])
        self.assertEqual(info["alerts"][0]["count"], 8)

    def test_wrong_password_tries_once(self):
        info = self.info("faux")
        self.assertFalse(info["authenticated"])
        self.assertEqual(FakeBbox.logins, 1)  # sinon la box se verrouille
        self.assertIn("refusé", info["error"])

    def test_without_password(self):
        info = self.info(None)
        self.assertTrue(info["need_password"])
        self.assertEqual(FakeBbox.logins, 0)
        self.assertEqual(info["error"], "")

    def test_no_bbox(self):
        self.assertIsNone(ws.bbox_info(None, None, bases=["http://127.0.0.1:9/api/v1"]))


class WifiTests(unittest.TestCase):
    def net(self, ssid, ch, sig, bssid="11:22:33:44:55:66", sec="WPA2"):
        return {"ssid": ssid, "bssid": bssid, "channel": ch, "band": ws.band_of(ch),
                "signal": sig, "security": sec}

    def test_freq(self):
        self.assertEqual(ws.freq_to_channel(2462), (11, "24"))
        self.assertEqual(ws.freq_to_channel(5180), (36, "5"))

    def test_termux(self):
        text = json.dumps([{"bssid": "aa:bb:cc:dd:ee:ff", "frequency_mhz": 2437, "rssi": -60,
                            "ssid": "Voisin"}])
        self.assertEqual(ws.parse_termux_scan(text)[0]["channel"], 6)
        self.assertEqual(ws.parse_termux_scan('{"API_ERROR": "Location"}'), [])

    def test_nmcli(self):
        nets = ws.parse_nmcli("Voisin:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:70:WPA2\n")
        self.assertEqual(nets[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual((nets[0]["channel"], nets[0]["signal"]), (6, -65))

    def test_netsh_french(self):
        text = ("SSID 1 : Voisin\n    Type de réseau          : Infrastructure\n"
                "    Authentification        : WPA2 - Personnel\n"
                "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
                "         Signal             : 80%\n         Canal              : 44\n")
        n = ws.parse_netsh(text)[0]
        self.assertEqual((n["channel"], n["band"], n["signal"]), (44, "5", -60))

    def test_system_profiler(self):
        text = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [{
            "spairport_current_network_information": {"_name": "Maison",
                                                      "spairport_network_channel": "11 (2GHz, 20MHz)"},
            "spairport_airport_other_local_wireless_networks": [
                {"_name": "Voisin", "spairport_network_channel": "6 (2GHz, 20MHz)",
                 "spairport_signal_noise": "-58 dBm / -93 dBm"}]}]}]})
        nets, cur = ws.parse_system_profiler(text)
        self.assertEqual(cur, "Maison")
        self.assertEqual([(n["ssid"], n["channel"], n["signal"]) for n in nets],
                         [("Maison", 11, -80), ("Voisin", 6, -58)])

    def test_channel_advice(self):
        nets = [self.net("A", 11, -50), self.net("B", 11, -55), self.net("C", 10, -60),
                self.net("D", 1, -50), self.net("E", 36, -60), self.net("F", 40, -70),
                self.net("Bbox-MICHEL", 11, -40, bssid="aa:00:00:00:00:4b")]
        bands = {"24": {"enabled": True, "channel": 11}, "5": {"enabled": True, "channel": 36}}
        adv = ws.channel_advice(nets, {"Bbox-MICHEL"}, {"aa:00:00:00:00:4b"}, bands)
        self.assertEqual(adv["24"]["best"], 6)
        self.assertIn("6", adv["24"]["advice"])
        self.assertEqual(adv["24"]["neighbors"], 4)  # notre propre réseau est exclu
        self.assertEqual(adv["5"]["best"], "52-64")

    def test_channel_advice_keeps_good_channel(self):
        adv = ws.channel_advice([self.net("A", 1, -80)], set(), set(),
                                {"24": {"enabled": True, "channel": 6}})
        self.assertIn("rien à changer", adv["24"]["advice"])

    def test_5ghz_inactive(self):
        adv = ws.channel_advice([], set(), set(), {"5": {"enabled": True, "channel": 0}})
        self.assertIn("inactive", adv["5"]["advice"])

    def test_evil_twin(self):
        own = {"aa:00:00:00:00:4b"}
        nets = [self.net("Bbox-MICHEL", 11, -40, bssid="aa:00:00:00:00:4b"),
                self.net("Bbox-MICHEL", 6, -70, bssid="66:66:66:66:66:66")]
        f = ws.twin_findings(nets, {"Bbox-MICHEL"}, own, True)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["level"], "warn")
        f = ws.twin_findings([self.net("Bbox-MICHEL", 6, -70, sec="--")], {"Bbox-MICHEL"}, set(), True)
        self.assertEqual(f[0]["level"], "danger")


class ScanTests(unittest.TestCase):
    """Scan complet simulé : le cas de Michel (Mac et iPhone ne répondent pas)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patches = {
            "KNOWN_FILE": os.path.join(self.tmp.name, "k.json"),
            "local_ip": lambda: "192.168.1.64",
            "network_for": lambda ip: ipaddress.ip_network("192.168.1.0/24"),
            "default_gateway": lambda: None,  # Android ne la donne pas
            "dns_servers": lambda: [],
            "is_alive": lambda ip: ip in ("192.168.1.148", "192.168.1.254"),
            "mdns_probe": lambda ips: {},
            "netbios_probe": lambda ips: {},
            "ssdp_probe": lambda: {"192.168.1.148": "Linux UPnP/1.0 Bouygues"},
            "arp_table": lambda: {},
            "open_ports": lambda ip: [53, 80, 443] if ip == "192.168.1.254" else [],
            "hostname": lambda ip: {"192.168.1.254": "bbox.lan"}.get(ip, ""),
            "own_mac": lambda: None,
            "wifi_environment": lambda: {"neighbors": [
                {"ssid": "Voisin", "bssid": "11:22:33:44:55:66", "channel": 11, "band": "24",
                 "signal": -50, "security": "WPA2"}], "current_ssid": "Bbox-MICHEL", "note": ""},
            "bbox_info": lambda gw, pw: {
                "base": "http://192.168.1.254/api/v1", "authenticated": True, "need_password": False,
                "error": "", "device": ws.extract_bbox_device(BBOX_DEVICE),
                "hosts": ws.extract_bbox_hosts(BBOX_HOSTS), "wireless": ws.extract_bbox_wireless(BBOX_WIRELESS),
                "services": ws.extract_bbox_services(BBOX_SERVICES),
                "alerts": ws.extract_bbox_alerts(BBOX_ALERTS)},
            "guess_gateway": lambda base, devs: "192.168.1.254",
        }
        self.patchers = [mock.patch.object(ws, k, v) for k, v in patches.items()]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in self.patchers:
            p.stop()
        self.tmp.cleanup()

    def test_scan(self):
        r = ws.scan()
        by_ip = {d["ip"]: d for d in r["devices"]}
        self.assertEqual(sorted(by_ip), ["192.168.1.148", "192.168.1.20", "192.168.1.254",
                                         "192.168.1.30", "192.168.1.64"])
        self.assertEqual(by_ip["192.168.1.20"]["name"], "Mac")
        self.assertEqual(by_ip["192.168.1.20"]["seen_by"], "box")
        self.assertEqual(by_ip["192.168.1.30"]["link"], "Wi-Fi 2,4 GHz")
        self.assertTrue(by_ip["192.168.1.254"]["is_gateway"] and by_ip["192.168.1.254"]["known"])
        self.assertTrue(by_ip["192.168.1.64"]["known"])
        self.assertEqual([h["name"] for h in r["history"]], ["android-x"])
        titles = " | ".join(f["title"] for f in r["findings"])
        self.assertIn("WPS activé", titles)
        self.assertIn("depuis Internet", titles)
        self.assertIn("Appareil inconnu passé récemment", titles)
        self.assertIn("Bande 5 GHz inactive", titles)
        self.assertEqual(r["findings"][0]["level"], "danger")
        self.assertEqual(r["wifi"]["advice"]["24"]["best"], 1)
        self.assertIn("inactive", r["wifi"]["bands_advice"])
        json.dumps(r)  # le rapport doit être sérialisable pour la page web


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.known = mock.patch.object(ws, "KNOWN_FILE", os.path.join(self.tmp.name, "k.json"))
        self.known.start()

        def fake_scan(bbox_password=None, **kw):
            self.password = bbox_password
            return ws.apply_known({
                "network": "192.168.1.0/24", "me": "192.168.1.20", "gateway": "192.168.1.254",
                "termux": False, "dns": [], "port_names": {}, "duration": 1, "date": "", "bbox": None,
                "wifi": {"neighbors": [], "note": "", "advice": None, "bands_advice": "", "own_ssids": []},
                "wifi_findings": [],
                "devices": [{"ip": "192.168.1.31", "mac": "aa:bb:cc:dd:ee:01", "name": "tel",
                             "ports": [], "is_gateway": False, "is_me": False, "random_mac": False,
                             "link": "", "seen_by": "scan", "upnp": ""}],
                "history": [{"ip": "192.168.1.99", "mac": "02:00:00:00:00:99", "name": "old",
                             "is_me": False, "is_gateway": False, "new_days": 100, "first_seen": "",
                             "last_seen_hours": 5, "link": ""}]})
        self.scan = mock.patch.object(ws, "scan", side_effect=fake_scan)
        self.scan.start()
        self.server, self.base = serve(ws.Handler)

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
            page = r.read()
        self.assertIn(b"Lancer le scan", page)
        self.assertIn("Mot de passe d'administration".encode(), page)

    def test_scan_and_mark_known(self):
        r = self.post("/api/scan", {"bbox_password": "pw"})
        self.assertEqual(self.password, "pw")
        self.assertFalse(r["devices"][0]["known"])
        self.assertTrue(any("inconnu" in f["title"] for f in r["findings"]))
        r = self.post("/api/known", {"key": "aa:bb:cc:dd:ee:01", "action": "add", "name": "Box TV"})
        self.assertTrue(r["devices"][0]["known"])
        self.assertEqual(r["devices"][0]["label"], "Box TV")
        r = self.post("/api/known", {"key": "02:00:00:00:00:99", "action": "add", "name": "Ancien"})
        self.assertTrue(r["history"][0]["known"])
        r = self.post("/api/known", {"key": "aa:bb:cc:dd:ee:01", "action": "forget"})
        self.assertFalse(r["devices"][0]["known"])

    def test_empty_password_is_none(self):
        self.post("/api/scan", {"bbox_password": ""})
        self.assertIsNone(self.password)

    def test_rejects_without_header(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.post("/api/scan", {}, header=False)
        self.assertEqual(cm.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
