#!/usr/bin/env python3
"""Scanner de réseau Wi-Fi domestique.

Liste les appareils connectés au réseau local, repère les services
sensibles ouverts, vérifie les serveurs DNS, lit les réglages et
l'historique d'une Bbox (Bouygues Telecom) et conseille les canaux Wi-Fi.

Aucune dépendance : Python 3.8+ suffit (Windows, macOS, Linux, Android
avec Termux).

    python wifi_scan.py            # scan en mode texte
    python wifi_scan.py --web      # interface dans le navigateur
"""

import argparse
import getpass
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from shutil import which
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

SYSTEM = platform.system()
HERE = os.path.dirname(os.path.abspath(__file__))
KNOWN_FILE = os.path.join(HERE, "known_devices.json")
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")

# Ports essayés pour savoir si un appareil est présent (une connexion
# refusée prouve aussi que l'appareil existe).
DISCOVERY_PORTS = [80, 443, 22, 445, 139, 53, 62078, 7000, 8080, 8008,
                   8009, 554, 5000, 3689, 49152]

# Services dont la présence mérite une alerte : port -> (nom, niveau, explication)
RISKY_PORTS = {
    23: ("Telnet", "danger",
         "Accès à distance non chiffré, cible n°1 des botnets (Mirai…)."),
    2323: ("Telnet (port alternatif)", "danger",
           "Variante de Telnet souvent ouverte par des objets piratés."),
    5555: ("Débogage Android (ADB)", "danger",
           "Permet de prendre le contrôle d'un appareil Android ou d'une box TV."),
    4444: ("Port de porte dérobée", "danger",
           "Port classique des outils de prise de contrôle à distance."),
    1080: ("Proxy SOCKS", "danger",
           "Un appareil qui sert de proxy peut avoir été enrôlé dans un botnet."),
    7547: ("TR-069 (gestion à distance du fournisseur)", "warn",
           "Sert au fournisseur d'accès ; vulnérable sur certaines box anciennes."),
    3389: ("Bureau à distance Windows (RDP)", "warn",
           "Prise de contrôle à distance d'un PC : à fermer si vous ne l'utilisez pas."),
    5900: ("VNC (partage d'écran)", "warn",
           "Partage d'écran souvent mal protégé."),
    21: ("FTP", "warn",
         "Transfert de fichiers non chiffré."),
    8291: ("Winbox (MikroTik)", "warn",
           "Administration de routeur MikroTik, souvent attaquée."),
    445: ("Partage de fichiers Windows (SMB)", "info",
          "Normal sur un PC ou un NAS ; ne doit pas être joignable depuis Internet."),
}
# Autres services simplement affichés.
INFO_PORTS = {22: "SSH", 53: "DNS", 80: "Web (HTTP)", 443: "Web (HTTPS)",
              8080: "Web (HTTP alt.)", 139: "NetBIOS", 554: "Caméra (RTSP)",
              631: "Imprimante (IPP)", 9100: "Imprimante", 62078: "iPhone/iPad"}
SCAN_PORTS = sorted(set(RISKY_PORTS) | set(INFO_PORTS))

# Résolveurs publics connus et sans danger.
KNOWN_DNS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "80.67.169.12": "FDN", "80.67.169.40": "FDN",
}

IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
MAC_RE = r"[0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5}"


# --------------------------------------------------------------------------
# Utilitaires
# --------------------------------------------------------------------------

def run(cmd, timeout=10):
    """Lance une commande et renvoie sa sortie texte ('' en cas d'échec)."""
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return out.stdout.decode(errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def normalize_mac(mac):
    """'a:b:c:d:e:f' ou 'AA-BB-…' -> 'aa:bb:cc:dd:ee:ff'."""
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) != 6:
        return None
    mac = ":".join(p.zfill(2).lower() for p in parts)
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def is_random_mac(mac):
    """Adresse MAC « privée » (téléphones récents) : bit localement administré."""
    return bool(mac) and int(mac.split(":")[0], 16) & 0x02 != 0


# --------------------------------------------------------------------------
# Informations sur le réseau local
# --------------------------------------------------------------------------

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # aucun paquet n'est envoyé
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def linux_netmask(ip):
    """Masque de l'interface portant `ip` (Linux, via ioctl)."""
    import fcntl
    for _, name in socket.if_nameindex():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            req = struct.pack("256s", name.encode()[:15])
            addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])
            if addr == ip:
                return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, req)[20:24])
        except OSError:
            continue
        finally:
            s.close()
    return None


def parse_netmask(text, ip):
    """Cherche le masque associé à `ip` dans une sortie ifconfig/ipconfig."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if ip not in line:
            continue
        m = re.search(r"netmask (0x[0-9a-fA-F]{8}|" + IP_RE + ")", line)
        if m:
            v = m.group(1)
            return socket.inet_ntoa(struct.pack(">I", int(v, 16))) if v.startswith("0x") else v
        for nxt in lines[i + 1:i + 3]:  # ipconfig : le masque suit l'adresse
            m = re.search(r":\s*(255\.(?:\d{1,3}\.){2}\d{1,3})", nxt)
            if m:
                return m.group(1)
    return None


def network_for(ip):
    mask = None
    try:
        if SYSTEM == "Linux":
            mask = linux_netmask(ip)
        elif SYSTEM == "Darwin":
            mask = parse_netmask(run(["ifconfig"]), ip)
        elif SYSTEM == "Windows":
            mask = parse_netmask(run(["ipconfig"]), ip)
    except Exception:
        mask = None
    net = ipaddress.ip_network(f"{ip}/{mask or '255.255.255.0'}", strict=False)
    if net.prefixlen < 22:  # trop grand : on se limite au /24 de l'ordinateur
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return net


def parse_linux_route(text):
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000" and f[2] != "00000000":
            return socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    return None


def parse_gateway(text):
    """Passerelle dans la sortie de `route -n get default` ou `ipconfig`."""
    for line in text.splitlines():
        if re.search(r"gateway|passerelle|puerta|gateway predefinito", line, re.I):
            m = re.search(IP_RE, line)
            if m:
                return m.group(0)
    return None


def default_gateway():
    if SYSTEM == "Linux":
        try:
            with open("/proc/net/route") as f:
                return parse_linux_route(f.read())
        except OSError:
            return None
    if SYSTEM == "Darwin":
        return parse_gateway(run(["route", "-n", "get", "default"]))
    if SYSTEM == "Windows":
        return parse_gateway(run(["ipconfig"]))
    return None


def parse_resolv_conf(text):
    return re.findall(r"^\s*nameserver\s+(" + IP_RE + r")", text, re.M)


def parse_windows_dns(text):
    servers, in_dns = [], False
    for line in text.splitlines():
        if re.search(r"DNS", line) and ":" in line and re.search(r"serv", line, re.I):
            in_dns = True
            servers += re.findall(IP_RE, line.split(":", 1)[1])
        elif in_dns and re.fullmatch(r"\s*" + IP_RE + r"\s*", line):
            servers.append(line.strip())
        else:
            in_dns = False
    return servers


def dns_servers():
    found = []
    if SYSTEM == "Windows":
        found = parse_windows_dns(run(["ipconfig", "/all"]))
    elif SYSTEM == "Darwin":
        found = re.findall(r"nameserver\[\d+\]\s*:\s*(" + IP_RE + ")", run(["scutil", "--dns"]))
    else:
        for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
            try:
                with open(path) as f:
                    found = [s for s in parse_resolv_conf(f.read())
                             if not s.startswith("127.")]
            except OSError:
                continue
            if found:
                break
    return list(dict.fromkeys(found))  # sans doublons, ordre conservé


# --------------------------------------------------------------------------
# Découverte des appareils
# --------------------------------------------------------------------------

def parse_arp(text):
    """Renvoie {ip: mac} depuis /proc/net/arp, `arp -a` ou `ip neigh`."""
    table = {}
    for line in text.splitlines():
        ip = re.search(r"\b" + IP_RE + r"\b", line)
        mac = re.search(r"(?<![0-9A-Fa-f:-])" + MAC_RE + r"(?![0-9A-Fa-f:-])", line)
        if ip and mac:
            if line.split()[2:3] == ["0x0"]:
                continue  # entrée incomplète de /proc/net/arp
            m = normalize_mac(mac.group(0))
            if m:
                table[ip.group(0)] = m
    return table


def arp_table():
    if SYSTEM == "Linux":
        try:
            with open("/proc/net/arp") as f:
                return parse_arp(f.read())
        except OSError:
            pass
    return parse_arp(run(["arp", "-a"]))


def ping(ip):
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    elif SYSTEM == "Darwin":
        cmd = ["ping", "-c", "1", "-W", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    out = run(cmd, timeout=3)
    return "ttl=" in out.lower()


def tcp_state(ip, port, timeout=0.5):
    """'open', 'closed' (refusé : l'appareil existe) ou None (pas de réponse)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
    except OSError:
        return None
    finally:
        s.close()
    if code == 0:
        return "open"
    if code in (111, 61, 10061):  # ECONNREFUSED Linux / macOS / Windows
        return "closed"
    return None


def is_alive(ip):
    if ping(ip):
        return True
    return any(tcp_state(ip, p, 0.4) for p in DISCOVERY_PORTS)


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def open_ports(ip):
    with ThreadPoolExecutor(max_workers=len(SCAN_PORTS)) as ex:
        states = list(ex.map(lambda p: tcp_state(ip, p, 0.8), SCAN_PORTS))
    return [p for p, st in zip(SCAN_PORTS, states) if st == "open"]


def own_mac():
    import uuid
    node = uuid.getnode()
    if node >> 40 & 0x01:  # uuid a inventé une adresse au hasard
        return None
    return ":".join(f"{node >> s & 0xff:02x}" for s in range(40, -8, -8))


# --------------------------------------------------------------------------
# Découverte par UDP : Bonjour (mDNS), NetBIOS et UPnP (SSDP)
#
# Les Mac et iPhone dont le pare-feu ignore ping et TCP répondent souvent
# encore à Bonjour ; les PC Windows à NetBIOS ; box TV et imprimantes à UPnP.
# --------------------------------------------------------------------------

MDNS_SERVICES = ["_services._dns-sd._udp.local", "_companion-link._tcp.local",
                 "_apple-mobdev2._tcp.local", "_airplay._tcp.local",
                 "_raop._tcp.local", "_device-info._tcp.local",
                 "_googlecast._tcp.local", "_hap._tcp.local",
                 "_smb._tcp.local", "_ipp._tcp.local", "_spotify-connect._tcp.local"]


def dns_name(name):
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def dns_query(name, qtype=12, qid=0, unicast=True):
    """Requête DNS/mDNS (type 12 = PTR). `unicast` demande une réponse directe."""
    header = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack(">HH", qtype, 0x8001 if unicast else 1)


def read_name(data, off, depth=0):
    """Lit un nom DNS (avec compression) ; renvoie (nom, position suivante)."""
    labels, jumped, end = [], False, off
    while depth < 20:
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off, jumped, depth = ((n & 0x3F) << 8) | data[off + 1], True, depth + 1
            continue
        labels.append(data[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def parse_dns_ptrs(data):
    """Renvoie la liste (nom, cible) des enregistrements PTR d'une réponse."""
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            off = read_name(data, off)[1] + 4
        ptrs = []
        for _ in range(an + ns + ar):
            name, off = read_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                ptrs.append((name, read_name(data, off)[0]))
            off += rdlen
        return ptrs
    except (IndexError, struct.error):
        return []


def reverse_name(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def friendly_mdns_name(ptrs):
    """Nom lisible tiré d'une réponse Bonjour ('Mac.local', 'iPhone de Michel')."""
    for name, target in ptrs:
        if name.endswith(".in-addr.arpa"):
            return target[:-6] if target.endswith(".local") else target
    for name, target in ptrs:
        if "._" in target and not target.startswith("_"):
            return target.split("._")[0]
    return ""


def udp_collect(sock, deadline, handle):
    while True:
        left = deadline - time.time()
        if left <= 0:
            return
        sock.settimeout(left)
        try:
            data, (ip, _) = sock.recvfrom(9000)
        except socket.timeout:
            return
        except OSError:
            continue
        handle(ip, data)


def mdns_probe(ips, wait=2.5):
    """{ip: nom} des appareils qui répondent à Bonjour."""
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        for ip in ips:
            try:
                sock.sendto(dns_query(reverse_name(ip)), (ip, 5353))
            except OSError:
                pass
        for svc in MDNS_SERVICES:
            try:
                sock.sendto(dns_query(svc), ("224.0.0.251", 5353))
            except OSError:
                pass

        def handle(ip, data):
            name = friendly_mdns_name(parse_dns_ptrs(data))
            if name or ip not in found:
                found[ip] = name or found.get(ip, "")
        udp_collect(sock, time.time() + wait, handle)
    finally:
        sock.close()
    return found


NBSTAT_QUERY = (struct.pack(">HHHHHH", 0x4242, 0, 1, 0, 0, 0)
                + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1))


def parse_nbstat(data):
    """Nom d'ordinateur dans une réponse NetBIOS « node status »."""
    try:
        count = data[56]
        for i in range(count):
            entry = data[57 + 18 * i:57 + 18 * (i + 1)]
            name, suffix, flags = entry[:15], entry[15], struct.unpack(">H", entry[16:18])[0]
            if suffix == 0 and not flags & 0x8000:
                return name.decode("latin-1").strip()
    except (IndexError, struct.error):
        pass
    return ""


def netbios_probe(ips, wait=2.0):
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        for ip in ips:
            try:
                sock.sendto(NBSTAT_QUERY, (ip, 137))
            except OSError:
                pass
        udp_collect(sock, time.time() + wait, lambda ip, d: found.__setitem__(ip, parse_nbstat(d)))
    finally:
        sock.close()
    return found


def ssdp_probe(wait=3.0):
    """{ip: description} des appareils UPnP (box TV, imprimantes, TV…)."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        for _ in range(2):
            try:
                sock.sendto(msg, ("239.255.255.250", 1900))
            except OSError:
                pass

        def handle(ip, data):
            m = re.search(rb"^server:\s*(.+?)\r?$", data, re.I | re.M)
            if m or ip not in found:
                found[ip] = m.group(1).decode("utf-8", "replace").strip() if m else ""
        udp_collect(sock, time.time() + wait, handle)
    finally:
        sock.close()
    return found


# --------------------------------------------------------------------------
# Bbox (Bouygues Telecom) : API locale de la box
# --------------------------------------------------------------------------

class BboxError(Exception):
    pass


class BboxAuthError(BboxError):
    pass


class Bbox:
    """Client minimal de l'API locale de la Bbox (lecture seule)."""

    def __init__(self, gateway=None, password=None, timeout=5, bases=None):
        self.bases = bases or ["https://mabbox.bytel.fr/api/v1",
                               f"http://{gateway or '192.168.1.254'}/api/v1"]
        self.password = password
        self.timeout = timeout
        self.base = self.cookie = self.token = None
        self.login_failed = False

    def _request(self, base, path, method="GET", data=None):
        url = f"{base}/{path}"
        if self.token and path not in ("login", "device/token"):
            url += "?btoken=" + quote(self.token)
        req = Request(url, data=urlencode(data).encode() if data else None, method=method,
                      headers={"Accept": "application/json"})
        if self.cookie:
            req.add_header("Cookie", "BBOX_ID=" + self.cookie)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                status, raw, headers = resp.status, resp.read(), resp.headers
        except HTTPError as e:
            status, raw, headers = e.code, e.read(), e.headers
        except (URLError, OSError, ValueError) as e:
            raise BboxError(f"box injoignable ({e})")
        for cookie in headers.get_all("Set-Cookie") or []:
            m = re.match(r"\s*BBOX_ID=([^;]+)", cookie)
            if m:
                self.cookie = m.group(1)
        try:
            payload = json.loads(raw.decode("utf-8", "replace")) if raw else None
        except ValueError:
            payload = None
        return status, payload

    def connect(self):
        """Cherche une Bbox qui répond ; True si trouvée."""
        for base in self.bases:
            try:
                status, payload = self._request(base, "device")
            except BboxError:
                continue
            if (status == 200 and isinstance(payload, list)) or status in (401, 403):
                self.base = base
                return True
        return False

    def login(self):
        if not self.password:
            raise BboxAuthError("mot de passe d'administration nécessaire")
        if self.login_failed:
            raise BboxAuthError("mot de passe refusé")
        status, _ = self._request(self.base, "login", "POST",
                                  {"password": self.password, "remember": 1})
        if status == 429:
            self.login_failed = True
            raise BboxAuthError("box verrouillée après trop d'essais : attendez quelques minutes")
        if status not in (200, 204) or not self.cookie:
            self.login_failed = True
            raise BboxAuthError("mot de passe refusé par la box")
        status, payload = self._request(self.base, "device/token")
        try:
            self.token = payload[0]["device"]["token"]
        except (TypeError, LookupError):
            self.login_failed = True
            raise BboxAuthError("la box n'a pas fourni de jeton")

    def get(self, path):
        status, payload = self._request(self.base, path)
        if status in (401, 403) and not self.token:
            self.login()
            status, payload = self._request(self.base, path)
        if status in (401, 403):
            raise BboxAuthError("accès refusé")
        if status != 200 or payload is None:
            raise BboxError(f"réponse inattendue ({status})")
        return payload


def bbox_section(payload, key):
    """Les réponses de la Bbox ont la forme [{"clé": {...}}]."""
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return payload[0].get(key) or {}
    if isinstance(payload, dict):
        return payload.get(key) or {}
    return {}


def parse_bbox_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
    except (TypeError, ValueError):
        return None


def extract_bbox_device(payload):
    d = bbox_section(payload, "device")
    main = d.get("main") or {}
    return {"model": d.get("modelname", ""), "firmware": main.get("version", ""),
            "firmware_date": (main.get("date") or "")[:10],
            "uptime_days": round((d.get("uptime") or 0) / 86400, 1)}


def extract_bbox_hosts(payload, now=None):
    now = now or datetime.now(timezone.utc)
    hosts = []
    for h in (bbox_section(payload, "hosts").get("list") or []):
        first = parse_bbox_date(h.get("firstseen"))
        link = h.get("link") or ""
        hosts.append({
            "ip": h.get("ipaddress") or "",
            "mac": normalize_mac(h.get("macaddress") or ""),
            "name": h.get("hostname") or "",
            "active": bool(h.get("active")),
            "link": {"Wifi 2.4": "Wi-Fi 2,4 GHz", "Wifi 5": "Wi-Fi 5 GHz"}.get(link, link),
            "guest": bool(h.get("guest")),
            "first_seen": first.strftime("%d/%m/%Y") if first else "",
            "new_days": (now - first).days if first else None,
            "last_seen_hours": round(h["lastseen"] / 3600) if isinstance(h.get("lastseen"), int)
            and not h.get("active") else None,
        })
    return hosts


def extract_bbox_wireless(payload):
    """Réglages Wi-Fi utiles (jamais le mot de passe)."""
    w = bbox_section(payload, "wireless")
    radio, ssid = w.get("radio") or {}, w.get("ssid") or {}
    bands = {}
    for band in ("24", "5"):
        r, s = radio.get(band) or {}, ssid.get(band) or {}
        sec = s.get("security") or {}
        bands[band] = {
            "enabled": bool(r.get("enable")) and bool(s.get("enable", 1)) and r.get("state", 1) != 0,
            "standard": r.get("standard", ""),
            "channel": r.get("current_channel") or r.get("channel") or 0,
            "auto": r.get("channel") == 0,
            "bandwidth": r.get("current_bandwidth") or r.get("htbw") or 0,
            "ssid": s.get("id", ""), "bssid": normalize_mac(s.get("bssid") or ""),
            "wps": bool((s.get("wps") or {}).get("enable")),
            "protocol": sec.get("protocol", ""), "default_password": bool(sec.get("isdefault")),
        }
    extra = {}
    for name in ("guest", "compatibility"):
        s = ssid.get(name) or {}
        sec = s.get("security") or {}
        extra[name] = {"enabled": bool(s.get("enable")) and bool((radio.get(name) or {}).get("enable", 1)),
                       "ssid": s.get("id", ""), "protocol": sec.get("protocol", ""),
                       "default_password": bool(sec.get("isdefault"))}
    unified = bool(bands["24"]["ssid"]) and bands["24"]["ssid"] == bands["5"]["ssid"]
    return {"bands": bands, "unified": unified, **extra}


def extract_bbox_services(payload):
    s = bbox_section(payload, "services")
    admin = ((s.get("remote") or {}).get("admin")) or {}
    return {"remote_admin": bool(admin.get("enable")), "remote_port": admin.get("port"),
            "upnp": bool(((s.get("upnp") or {}).get("igd") or {}).get("enable")),
            "firewall": bool((s.get("firewall") or {}).get("enable", 1))}


def extract_bbox_alerts(payload):
    alerts = []
    for a in (bbox_section(payload, "alerts").get("list") or []):
        last = parse_bbox_date(a.get("last_date"))
        alerts.append({"ident": a.get("ident", ""), "param": a.get("param", ""),
                       "count": a.get("count", 1), "level": a.get("level", ""),
                       "last": last.strftime("%d/%m/%Y %H:%M") if last else ""})
    return alerts


def bbox_info(gateway, password=None, bases=None):
    """Lit la Bbox ; None si le réseau n'a pas de Bbox."""
    box = Bbox(gateway, password, bases=bases)
    if not box.connect():
        return None
    info = {"base": box.base, "authenticated": False, "need_password": False, "error": "",
            "device": {}, "hosts": [], "wireless": None, "services": None, "alerts": None}
    parts = [("device", "device", extract_bbox_device), ("hosts", "hosts", extract_bbox_hosts),
             ("wireless", "wireless", extract_bbox_wireless),
             ("services", "services", extract_bbox_services),
             ("alerts", "alerts", extract_bbox_alerts)]
    for key, path, extract in parts:
        try:
            info[key] = extract(box.get(path))
        except BboxAuthError as e:
            info["need_password"] = True
            if box.login_failed:  # on n'insiste pas : la box se verrouillerait
                info["error"] = str(e)
                break
        except BboxError:
            continue
    info["authenticated"] = box.token is not None
    if info["authenticated"] and not info["error"]:
        info["need_password"] = False
    return info


# --------------------------------------------------------------------------
# Réseaux Wi-Fi voisins et conseils de canaux
# --------------------------------------------------------------------------

def freq_to_channel(freq):
    freq = int(freq)
    if freq == 2484:
        return 14, "24"
    if 2400 < freq < 2500:
        return (freq - 2407) // 5, "24"
    if 5000 < freq < 5900:
        return (freq - 5000) // 5, "5"
    if 5925 < freq < 7125:
        return (freq - 5950) // 5, "6"
    return 0, ""


def band_of(channel):
    return "24" if 0 < channel <= 14 else "5"


def parse_termux_scan(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    nets = []
    for n in data:
        if not isinstance(n, dict) or "frequency_mhz" not in n:
            continue
        ch, band = freq_to_channel(n["frequency_mhz"])
        nets.append({"ssid": n.get("ssid") or "", "bssid": normalize_mac(n.get("bssid") or ""),
                     "channel": ch, "band": band, "signal": int(n.get("rssi", -90)),
                     "security": n.get("capabilities", "")})
    return nets


def parse_nmcli(text):
    nets = []
    for line in text.splitlines():
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) < 5 or not f[2].isdigit():
            continue
        ch = int(f[2])
        sig = int(f[3]) if f[3].isdigit() else 0
        nets.append({"ssid": f[0], "bssid": normalize_mac(f[1]), "channel": ch,
                     "band": band_of(ch), "signal": sig // 2 - 100, "security": f[4]})
    return nets


def parse_netsh(text):
    nets, ssid, sec, cur = [], "", "", None
    for line in text.splitlines():
        m = re.match(r"^SSID \d+\s*:\s*(.*)$", line.strip())
        if m:
            ssid, sec = m.group(1).strip(), ""
            continue
        m = re.match(r"^\s*Auth\w*\s*:\s*(.+)$", line)
        if m:
            sec = m.group(1).strip()
            continue
        m = re.match(r"^\s*BSSID \d+\s*:\s*(\S+)", line)
        if m:
            cur = {"ssid": ssid, "bssid": normalize_mac(m.group(1)), "channel": 0,
                   "band": "", "signal": -90, "security": sec}
            nets.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^\s*Signal\s*:\s*(\d+)\s*%", line)
        if m:
            cur["signal"] = int(m.group(1)) // 2 - 100
        m = re.match(r"^\s*(?:Channel|Canal)\s*:\s*(\d+)", line)
        if m:
            cur["channel"] = int(m.group(1))
            cur["band"] = band_of(cur["channel"])
    return [n for n in nets if n["channel"]]


def parse_system_profiler(text):
    """Réseaux voisins et réseau actuel depuis `system_profiler -json` (macOS)."""
    nets, current = [], ""
    try:
        data = json.loads(text)["SPAirPortDataType"][0]["spairport_airport_interfaces"]
    except (ValueError, LookupError, TypeError):
        return nets, current
    for iface in data:
        cur = iface.get("spairport_current_network_information") or {}
        current = current or cur.get("_name", "")
        for n in [cur] + (iface.get("spairport_airport_other_local_wireless_networks") or []):
            m = re.match(r"\s*(\d+)", str(n.get("spairport_network_channel", "")))
            if not n or not m:
                continue
            ch = int(m.group(1))
            sig = re.match(r"\s*(-\d+)", str(n.get("spairport_signal_noise", "")))
            nets.append({"ssid": n.get("_name", ""), "bssid": None, "channel": ch,
                         "band": band_of(ch), "signal": int(sig.group(1)) if sig else -80,
                         "security": n.get("spairport_security_mode", "")})
    return nets, current


def wifi_environment():
    """Réseaux visibles depuis cet appareil et nom du réseau actuel."""
    env = {"neighbors": [], "current_ssid": "", "note": ""}
    if IS_TERMUX or which("termux-wifi-scaninfo"):
        if not which("termux-wifi-scaninfo"):
            env["note"] = ("Pour analyser les canaux sur Android : installez l'app Termux:API "
                           "(F-Droid) puis tapez « pkg install termux-api ».")
            return env
        env["neighbors"] = parse_termux_scan(run(["termux-wifi-scaninfo"], timeout=20))
        try:
            env["current_ssid"] = json.loads(run(["termux-wifi-connectioninfo"], timeout=10)).get("ssid", "")
        except (ValueError, AttributeError):
            pass
        if not env["neighbors"]:
            env["note"] = ("Android n'a renvoyé aucun réseau : autorisez la localisation pour "
                           "Termux:API et activez la localisation du téléphone.")
    elif SYSTEM == "Linux" and which("nmcli"):
        env["neighbors"] = parse_nmcli(run(["nmcli", "-t", "-e", "yes", "-f",
                                            "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"], 20))
        for line in run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"]).splitlines():
            if line.startswith("yes:"):
                env["current_ssid"] = line[4:]
    elif SYSTEM == "Windows":
        env["neighbors"] = parse_netsh(run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", run(["netsh", "wlan", "show", "interfaces"]), re.M)
        env["current_ssid"] = m.group(1).strip() if m else ""
    elif SYSTEM == "Darwin":
        env["neighbors"], env["current_ssid"] = parse_system_profiler(
            run(["system_profiler", "SPAirPortDataType", "-json"], timeout=30))
    if not env["neighbors"] and not env["note"]:
        env["note"] = "Impossible de lister les réseaux Wi-Fi voisins sur cet appareil."
    return env


def interference(n):
    """Poids d'un réseau voisin selon sa puissance (-45 dBm ≈ 6, -90 dBm ≈ 1)."""
    return max(1.0, min(6.0, (n["signal"] + 95) / 8))


BLOCKS_5 = [("36-48", 36, 48, False), ("52-64", 52, 64, True), ("100-112", 100, 112, True),
            ("116-128", 116, 128, True), ("132-144", 132, 144, True)]


def channel_advice(neighbors, own_ssids, own_bssids, bands=None):
    """Conseils de canal pour 2,4 et 5 GHz."""
    bands = bands or {}
    own_prefixes = {b[:14] for b in own_bssids if b}
    others = [n for n in neighbors if n["ssid"] not in own_ssids
              and (n["bssid"] or "")[:14] not in own_prefixes]

    def own_channel(band):
        ch = (bands.get(band) or {}).get("channel")
        if ch:
            return ch
        mine = [n for n in neighbors if n["band"] == band and n["ssid"] in own_ssids]
        return max(mine, key=lambda n: n["signal"])["channel"] if mine else None

    res = {}
    n24 = [n for n in others if n["band"] == "24"]
    scores = {c: round(sum(interference(n) * (1 if n["channel"] == c else 0.6)
                           for n in n24 if abs(n["channel"] - c) < 5), 1) for c in (1, 6, 11)}
    cur = own_channel("24")
    best = min(scores, key=lambda c: (scores[c], c != cur))
    if not n24:
        text = "Aucun réseau voisin détecté en 2,4 GHz : le canal importe peu."
    elif cur is None:
        text = f"Le canal le moins encombré est le {best}."
    elif cur not in (1, 6, 11):
        text = (f"Le canal {cur} chevauche ses voisins : choisissez plutôt le {best} "
                "(seuls 1, 6 et 11 ne se chevauchent pas).")
    elif best != cur and scores[best] + 1 < scores[cur] * 0.6:
        text = f"Le canal {best} est nettement moins encombré que le {cur} : vous pouvez le choisir."
    else:
        text = f"Le canal {cur} est un bon choix, rien à changer."
    res["24"] = {"current": cur, "best": best, "scores": scores, "neighbors": len(n24), "advice": text}

    n5 = [n for n in others if n["band"] == "5"]
    bscores = {name: round(sum(interference(n) for n in n5 if lo <= n["channel"] <= hi), 1)
               for name, lo, hi, _ in BLOCKS_5}
    cur5 = own_channel("5")
    cur_block = next((name for name, lo, hi, _ in BLOCKS_5 if cur5 and lo <= cur5 <= hi), None)
    best5 = min(BLOCKS_5, key=lambda b: (bscores[b[0]] + (1 if b[3] else 0), b[0] != cur_block))[0]
    b5 = bands.get("5") or {}
    if b5 and (not b5.get("enabled") or not b5.get("channel")):
        text = ("La bande 5 GHz semble inactive (canal 0) : vos appareils sont alors tous "
                "en 2,4 GHz, plus lente. Vérifiez qu'elle est bien activée dans la box.")
    elif not n5:
        text = "Aucun réseau voisin détecté en 5 GHz : le réglage automatique convient."
    elif cur_block and bscores[cur_block] <= bscores[best5] + 1:
        text = f"Le canal {cur5} (bloc {cur_block}) est peu encombré, rien à changer."
    else:
        text = (f"Le bloc de canaux {best5} est le moins encombré"
                + (" (canaux DFS : la box peut en changer brièvement en cas de radar)"
                   if best5 != "36-48" else "") + ".")
    res["5"] = {"current": cur5, "best": best5, "scores": bscores, "neighbors": len(n5), "advice": text}
    return res


def is_open_security(sec):
    sec = (sec or "").strip().lower()
    return sec in ("", "--", "none", "open", "ouvert", "ouverte") or "wep" in sec


def twin_findings(neighbors, own_ssids, own_bssids, own_security_known):
    """Repère un faux point d'accès qui imite le nom de votre Wi-Fi."""
    findings = []
    prefixes = {b[:14] for b in own_bssids if b}
    for n in neighbors:
        if n["ssid"] not in own_ssids or not n["ssid"]:
            continue
        foreign = bool(prefixes) and n["bssid"] and n["bssid"][:14] not in prefixes
        if own_security_known and n["security"] and is_open_security(n["security"]):
            findings.append({"level": "danger", "ip": "", "title": f"Réseau « {n['ssid']} » ouvert ou en WEP",
                             "detail": "Un réseau portant votre nom n'est pas protégé : possible faux "
                                       "point d'accès. Ne vous y connectez pas."})
        elif foreign:
            findings.append({"level": "warn", "ip": "",
                             "title": f"Un autre émetteur diffuse le nom « {n['ssid']} » (canal {n['channel']})",
                             "detail": "Normal si vous avez un répéteur Wi-Fi. Sinon, c'est peut-être "
                                       "un faux point d'accès qui cherche à intercepter vos connexions."})
    return findings


# --------------------------------------------------------------------------
# Appareils connus
# --------------------------------------------------------------------------

def device_key(dev):
    return dev["mac"] or "ip:" + dev["ip"]


def load_known():
    try:
        with open(KNOWN_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_known(known):
    tmp = KNOWN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(known, f, indent=2, ensure_ascii=False)
    os.replace(tmp, KNOWN_FILE)




# --------------------------------------------------------------------------
# Scan complet
# --------------------------------------------------------------------------

def classify_dns(server):
    addr = ipaddress.ip_address(server)
    if addr.is_private:
        return "ok", "Adresse locale (en général la box)"
    if server in KNOWN_DNS:
        return "ok", "Résolveur public connu (" + KNOWN_DNS[server] + ")"
    return "warn", ("Serveur public inconnu : normal si c'est celui de votre "
                    "fournisseur d'accès, suspect sinon")


def bands_advice(wireless):
    text = ("Gardez le Wi-Fi unifié (un seul nom) : la box place chaque appareil sur la "
            "meilleure bande. Séparez les bandes seulement si un appareil (caméra, prise "
            "connectée, imprimante, vieil ordinateur) n'arrive pas à se connecter ou décroche "
            "souvent : connectez-le alors au réseau 2,4 GHz.")
    b5 = ((wireless or {}).get("bands") or {}).get("5") or {}
    if wireless and (not b5.get("enabled") or not b5.get("channel")):
        text = ("Votre bande 5 GHz semble inactive : séparer les bandes n'y changera rien tant "
                "qu'elle n'est pas réactivée. " + text)
    return text


ALERT_TEXT = {"LAN": "depuis un appareil de la maison", "WAN": "depuis Internet"}


def analyse(r):
    """Construit la liste des points d'attention à partir du rapport."""
    findings = []

    def add(level, title, detail, ip=""):
        findings.append({"level": level, "ip": ip, "title": title, "detail": detail})

    for d in r["devices"]:
        who = d["label"] or d["name"] or d["ip"]
        if not d["known"]:
            via = f" ({d['link']})" if d.get("link") else ""
            add("warn", f"Appareil inconnu : {who}{via}",
                "Vérifiez de quoi il s'agit, puis cliquez sur « Je le connais ».", d["ip"])
        for p in d["ports"]:
            if p in RISKY_PORTS:
                name, level, why = RISKY_PORTS[p]
                place = "la box" if d["is_gateway"] else who
                add(level, f"{name} ouvert sur {place} (port {p})", why, d["ip"])
    for h in r.get("history") or []:
        if not h["known"] and h["new_days"] is not None and h["new_days"] <= 30:
            add("warn", f"Appareil inconnu passé récemment : {h['name'] or h['mac']}",
                f"Vu pour la première fois le {h['first_seen']}, déconnecté depuis. "
                "Si vous ne le reconnaissez pas, changez le mot de passe Wi-Fi.")
    if r["gateway"] and not any(d["is_gateway"] for d in r["devices"]):
        add("info", "La box n'a pas répondu au scan",
            "Rien d'anormal en soi, certaines box ne répondent pas.", r["gateway"])

    box = r.get("bbox")
    if box:
        w = box.get("wireless")
        if w:
            wps = [b for b in ("24", "5") if w["bands"][b]["wps"]]
            if wps:
                add("warn", "WPS activé sur la box",
                    "Le WPS permet de se connecter sans mot de passe (bouton ou code PIN) et "
                    "fait l'objet d'attaques. Désactivez « Appairage WPS autorisé » dans les "
                    "réglages Wi-Fi de la box.")
            for b, label in (("24", "2,4 GHz"), ("5", "5 GHz")):
                band = w["bands"][b]
                proto = (band["protocol"] or "").upper()
                if not band["enabled"] or not proto:
                    continue
                if "WPA2" not in proto and "WPA3" not in proto:
                    add("danger", f"Chiffrement faible en {label} ({band['protocol']})",
                        "Choisissez WPA2 ou WPA2/WPA3 dans les réglages Wi-Fi de la box.")
                elif proto.startswith("WPA+") or proto.startswith("WPA/"):
                    add("warn", f"Mode de sécurité mixte en {label} ({band['protocol']})",
                        "Le vieux WPA reste accepté : passez en WPA2 ou WPA2/WPA3.")
            if any(w["bands"][b]["default_password"] and w["bands"][b]["enabled"] for b in ("24", "5")):
                add("warn", "Mot de passe Wi-Fi d'origine",
                    "C'est celui de l'étiquette de la box : toute personne qui l'a vue peut se "
                    "connecter. Choisissez un mot de passe personnel.")
            if w["compatibility"]["enabled"]:
                add("warn", "Réseau « compatibilité » activé",
                    "Ce second réseau accepte d'anciens chiffrements moins sûrs. Désactivez-le "
                    "si vous n'en avez pas besoin.")
            if w["guest"]["enabled"]:
                add("info", f"Réseau invité activé ({w['guest']['ssid']})",
                    "Pensez à le couper quand vos invités sont partis.")
            b5 = w["bands"]["5"]
            if not b5["enabled"] or not b5["channel"]:
                add("info", "Bande 5 GHz inactive", "Voir les conseils sur les canaux plus bas.")
        s = box.get("services")
        if s:
            if s["remote_admin"]:
                add("warn", "Administration de la box depuis Internet activée"
                    + (f" (port {s['remote_port']})" if s.get("remote_port") else ""),
                    "Désactivez l'accès à distance si vous ne l'utilisez pas.")
            if s["upnp"]:
                add("info", "UPnP activé sur la box",
                    "Les appareils peuvent ouvrir des ports vers Internet tout seuls. Pratique "
                    "pour les consoles, mais un appareil piraté peut aussi s'en servir.")
            if not s["firewall"]:
                add("danger", "Pare-feu de la box désactivé", "Réactivez-le dans les réglages.")
        for a in box.get("alerts") or []:
            ident = a["ident"]
            if "LOCKED" in ident or "LOGIN" in ident or "AUTH" in ident:
                where = "WAN" if "WAN" in ident else "LAN"
                ip = (a["param"] or "").split(";")[0]
                add("danger" if where == "WAN" else "warn",
                    f"Tentatives de connexion à la box {ALERT_TEXT[where]} ({a['count']} fois)",
                    f"Dernière le {a['last']}" + (f", depuis {ip}" if ip else "") + ". "
                    "Si ce n'est pas vous ni une de vos applis, changez le mot de passe "
                    "d'administration de la box.")
            else:
                add("info", f"Alerte de la box : {ident}", f"Dernière le {a['last']}.")
        if box.get("error"):
            add("warn", "Connexion à la box impossible : " + box["error"],
                "Vérifiez le mot de passe d'administration (celui de mabbox.bytel.fr).")
        elif box.get("need_password") and not box.get("authenticated"):
            add("info", "Analyse de la box incomplète",
                "Entrez le mot de passe d'administration de la Bbox pour voir tous les "
                "appareils (même ceux qui ne répondent pas), l'historique et les réglages.")

    findings += r.get("wifi_findings") or []
    for s in r["dns"]:
        if s["status"] != "ok":
            add(s["status"], f"Serveur DNS {s['server']}", s["detail"], s["server"])
    order = {"danger": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order[f["level"]])
    return findings


def guess_gateway(base, devices):
    """Adresse de la box quand le système ne la donne pas (Android)."""
    if base:
        host = re.match(r"https?://([^/]+)", base).group(1)
        try:
            ip = socket.gethostbyname(host)
            if ipaddress.ip_address(ip).is_private:
                return ip
        except OSError:
            pass
    for d in devices:
        if d["ip"].endswith((".1", ".254")) and 53 in d["ports"]:
            return d["ip"]
    return None


def apply_known(r):
    """Statut connu/inconnu et noms donnés par l'utilisateur."""
    known = load_known()
    for d in r["devices"] + r.get("history", []):
        entry = known.get(device_key(d))
        d["key"] = device_key(d)
        if d.get("is_me"):
            d["known"], d["label"] = True, "Cet appareil"
        elif d.get("is_gateway"):
            d["known"], d["label"] = True, (entry or {}).get("name") or "Votre box"
        else:
            d["known"], d["label"] = bool(entry), (entry or {}).get("name", "")
    r["findings"] = analyse(r)
    return r


def scan(progress=None, bbox_password=None, wifi=True):
    def step(msg):
        if progress:
            progress(msg)

    started = time.time()
    me = local_ip()
    if not me:
        raise RuntimeError("Pas de connexion réseau détectée.")
    net = network_for(me)
    gateway = default_gateway()
    dns = dns_servers()
    hosts = [str(h) for h in net.hosts() if str(h) != me]

    step(f"Recherche des appareils sur {net} …")
    with ThreadPoolExecutor(max_workers=8) as ex:
        f_box = ex.submit(bbox_info, gateway, bbox_password)
        f_wifi = ex.submit(wifi_environment) if wifi else None
        f_mdns = ex.submit(mdns_probe, hosts)
        f_nb = ex.submit(netbios_probe, hosts)
        f_ssdp = ex.submit(ssdp_probe)
        with ThreadPoolExecutor(max_workers=128) as pool:
            alive = {ip for ip, ok in zip(hosts, pool.map(is_alive, hosts)) if ok}
        box, mdns, nbns, ssdp = f_box.result(), f_mdns.result(), f_nb.result(), f_ssdp.result()
        env = f_wifi.result() if f_wifi else {"neighbors": [], "current_ssid": "", "note": ""}

    in_net = lambda ip: bool(ip) and ipaddress.ip_address(ip) in net
    arp = arp_table()
    box_hosts = {h["ip"]: h for h in (box or {}).get("hosts", []) if h["active"] and in_net(h["ip"])}
    scanned = alive | {ip for ip in list(mdns) + list(nbns) + list(ssdp) + list(arp) if in_net(ip)}
    scanned.add(me)
    ips = sorted(scanned | set(box_hosts), key=ipaddress.ip_address)

    step(f"{len(ips)} appareil(s) trouvé(s), vérification des services …")
    with ThreadPoolExecutor(max_workers=16) as ex:
        ports = list(ex.map(open_ports, ips))
        rdns = list(ex.map(hostname, ips))

    devices = []
    for ip, p, rname in zip(ips, ports, rdns):
        bh = box_hosts.get(ip, {})
        mac = (own_mac() if ip == me else None) or arp.get(ip) or bh.get("mac")
        name = bh.get("name") or mdns.get(ip) or nbns.get(ip) or rname
        seen = ("scan+box" if ip in scanned and bh else "box" if bh else "scan")
        devices.append({"ip": ip, "mac": mac, "name": name, "ports": p,
                        "is_gateway": False, "is_me": ip == me, "random_mac": is_random_mac(mac),
                        "link": bh.get("link", ""), "seen_by": seen, "upnp": ssdp.get(ip, "")})
    gateway = gateway or guess_gateway((box or {}).get("base"), devices)
    for d in devices:
        d["is_gateway"] = d["ip"] == gateway

    history = [dict(h, is_me=False, is_gateway=False) for h in (box or {}).get("hosts", [])
               if not h["active"]]

    wireless = (box or {}).get("wireless")
    own_ssids = {s for s in [env["current_ssid"]] + [b["ssid"] for b in (wireless or {}).get("bands", {}).values()] if s}
    own_bssids = {b["bssid"] for b in (wireless or {}).get("bands", {}).values() if b["bssid"]}
    advice = channel_advice(env["neighbors"], own_ssids, own_bssids,
                            (wireless or {}).get("bands")) if env["neighbors"] or wireless else None

    report = {
        "network": str(net), "me": me, "gateway": gateway, "termux": IS_TERMUX,
        "dns": [{"server": s, "status": classify_dns(s)[0], "detail": classify_dns(s)[1]}
                for s in dns],
        "devices": devices, "history": history, "bbox": box,
        "wifi": {"neighbors": sorted(env["neighbors"], key=lambda n: -n["signal"]),
                 "note": env["note"], "advice": advice, "bands_advice": bands_advice(wireless),
                 "own_ssids": sorted(own_ssids)},
        "wifi_findings": twin_findings(env["neighbors"], own_ssids, own_bssids, True),
        "port_names": {p: (RISKY_PORTS[p][0] if p in RISKY_PORTS else INFO_PORTS[p])
                       for p in SCAN_PORTS},
        "duration": round(time.time() - started, 1),
        "date": time.strftime("%d/%m/%Y %H:%M"),
    }
    return apply_known(report)


# --------------------------------------------------------------------------
# Mode texte
# --------------------------------------------------------------------------

def print_report(r):
    icons = {"danger": "[DANGER]", "warn": "[ATTENTION]", "info": "[INFO]"}
    print(f"\nRéseau {r['network']} — box : {r['gateway'] or '?'} — scan en {r['duration']} s\n")
    print(f"{'IP':<16}{'MAC':<19}{'Nom':<28}{'Connexion':<16}Ports ouverts")
    for d in r["devices"]:
        name = (d["label"] or d["name"] or "?")[:26]
        status = "" if d["known"] else "  <- inconnu"
        print(f"{d['ip']:<16}{d['mac'] or '?':<19}{name:<28}{d['link'] or '-':<16}"
              f"{', '.join(map(str, d['ports'])) or '-'}{status}")
    if r["history"]:
        print("\nDéjà connectés à la box (absents maintenant) :")
        for h in r["history"]:
            ago = f"il y a {h['last_seen_hours']} h" if h["last_seen_hours"] is not None else ""
            print(f"  {h['label'] or h['name'] or '?':<28}{h['mac'] or '?':<19}{h['link']:<16}{ago}"
                  + ("" if h["known"] else "  <- inconnu"))
    w = r["wifi"]
    if w["advice"]:
        print("\nCanaux Wi-Fi :")
        print("  2,4 GHz : " + w["advice"]["24"]["advice"])
        print("  5 GHz   : " + w["advice"]["5"]["advice"])
    if w["note"]:
        print("  " + w["note"])
    print("  Séparer 2,4 et 5 GHz ? " + w["bands_advice"])
    print("\nServeurs DNS : " + (", ".join(s["server"] for s in r["dns"]) or "non lisibles"))
    print()
    if not r["findings"]:
        print("Rien de suspect détecté (ce qui ne garantit pas que le réseau est sain).")
    for f in r["findings"]:
        print(f"{icons[f['level']]:<12} {f['title']}\n{'':12} {f['detail']}")


# --------------------------------------------------------------------------
# Interface web
# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scanner Wi-Fi</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#667085;--line:#e4e7ec;
--accent:#2563eb;--danger:#c0262d;--warn:#b54708;--ok:#067647;--info:#475467}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1b2027;--text:#e8eaed;
--muted:#98a2b3;--line:#2c333d;--accent:#5b8def;--danger:#f97066;--warn:#fdb022;--ok:#47cd89;--info:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:20px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}h3{font-size:14px;margin:12px 0 4px}
.muted{color:var(--muted)}.small{font-size:13px}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:16px;margin-top:14px}
button{font:inherit;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;
background:var(--accent);color:#fff}button.ghost{background:transparent;color:var(--accent);
border:1px solid var(--line);padding:4px 10px;font-size:13px}button:disabled{opacity:.5;cursor:wait}
input{font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);
color:var(--text);width:100%;max-width:340px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
.f{border-left:4px solid var(--info);padding:4px 12px;margin:10px 0}
.f.danger{border-color:var(--danger)}.f.warn{border-color:var(--warn)}
.f b{display:block}.tag{font-size:12px;border-radius:99px;padding:1px 8px;border:1px solid var(--line);white-space:nowrap;display:inline-block}
.tag.ok{color:var(--ok)}.tag.warn{color:var(--warn)}.tag.danger{color:var(--danger)}
.dev{display:flex;gap:10px;justify-content:space-between;align-items:flex-start;padding:10px 0;border-top:1px solid var(--line)}
.dev:first-of-type{border-top:0}.dev .main{min-width:0;flex:1}.dev code{font-size:12px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 14px}
.bar{height:8px;border-radius:4px;background:var(--accent);opacity:.7;min-width:2px}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:500}
details summary{cursor:pointer;color:var(--accent)}
</style></head><body><main>
<div class="top"><div><h1>Scanner Wi-Fi</h1>
<div class="muted" id="sub">Vérifie les appareils connectés, la box et les canaux Wi-Fi.</div></div>
<button id="go">Lancer le scan</button></div>
<div class="card small"><label for="pw"><b>Mot de passe d'administration de la Bbox</b> (facultatif)</label><br>
<span class="muted">Celui de mabbox.bytel.fr. Il permet de voir tous les appareils, l'historique et les réglages.
Utilisé seulement pour ce scan, jamais enregistré. Attention : plusieurs erreurs bloquent la box quelques minutes.</span><br>
<input id="pw" type="password" autocomplete="off" placeholder="Laisser vide si vous n'avez pas de Bbox"></div>
<div id="out"></div>
<div class="card muted small">Le scan ne voit que les appareils connectés en ce moment (et, avec une Bbox,
ceux qu'elle a gardés en mémoire). « Rien de suspect » ne garantit pas que le réseau est sain.</div>
</main><script>
const $=s=>document.querySelector(s), out=$("#out");
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const api=(url,body)=>fetch(url,{method:"POST",headers:{"Content-Type":"application/json","X-Scanner":"1"},
  body:JSON.stringify(body||{})}).then(r=>r.ok?r.json():r.json().then(e=>Promise.reject(e.error)));
const LV={danger:"Danger",warn:"Attention",info:"Info"};
const STD={"11ax":"Wi-Fi 6","11be":"Wi-Fi 7","11ac":"Wi-Fi 5","11n":"Wi-Fi 4"};
const yes=(v,good)=>v===good?'<span class="tag ok">'+(v?"oui":"non")+'</span>':'<span class="tag warn">'+(v?"oui":"non")+'</span>';
function btn(d){return d.is_me||d.is_gateway?"":d.known?`<button class="ghost" data-k="${esc(d.key)}" data-a="forget">Oublier</button>`
  :`<button class="ghost" data-k="${esc(d.key)}" data-a="add">Je le connais</button>`}
function devRow(d,r){
  const ports=(d.ports||[]).map(p=>`<span class="tag">${p} ${esc(r.port_names[p]||"")}</span>`).join(" ");
  const st=d.known?'<span class="tag ok">connu</span>':'<span class="tag warn">inconnu</span>';
  const title=esc(d.label||d.name||"Appareil sans nom");
  const sub=[d.label&&d.name&&esc(d.name),d.ip&&`<code>${esc(d.ip)}</code>`,d.mac&&`<code>${esc(d.mac)}</code>`].filter(Boolean).join(" · ");
  const extra=[d.link&&`<span class="tag">${esc(d.link)}</span>`,
    d.seen_by=="box"&&'<span class="tag" title="Ne répond pas au scan, mais la box le voit connecté">vu par la box</span>',
    d.random_mac&&!d.is_gateway&&'<span class="tag" title="Adresse MAC privée, typique des téléphones">MAC privée</span>',
    d.last_seen_hours!=null&&`<span class="muted small">absent depuis ${d.last_seen_hours} h</span>`,
    d.first_seen&&`<span class="muted small">1re connexion ${esc(d.first_seen)}</span>`].filter(Boolean).join(" ");
  return `<div class="dev"><div class="main">${st} <b>${title}</b><div class="small muted">${sub}</div>
    <div>${extra}</div>${ports?`<div class="small">Services ouverts : ${ports}</div>`:""}</div><div>${btn(d)}</div></div>`}
function boxCard(b){
  if(!b) return "";
  const w=b.wireless, dv=b.device||{};
  let h=`<div class="card"><h2>Votre Bbox</h2>`;
  if(dv.model) h+=`<div class="kv small"><span class="muted">Modèle</span><span>${esc(dv.model)}</span>
    <span class="muted">Logiciel</span><span>${esc(dv.firmware)} (${esc(dv.firmware_date)})</span>
    <span class="muted">Allumée depuis</span><span>${dv.uptime_days} jours</span></div>`;
  if(w){
    h+=`<p class="small">Wi-Fi ${w.unified?"unifié (un seul nom pour 2,4 et 5 GHz)":"séparé en deux réseaux"}</p>`;
    for(const [k,l] of [["24","2,4 GHz"],["5","5 GHz"]]){const x=w.bands[k];
      h+=`<h3>${l} ${x.enabled?"":'<span class="tag warn">inactive</span>'}</h3><div class="kv small">
      <span class="muted">Nom</span><span>${esc(x.ssid)}</span>
      <span class="muted">Canal</span><span>${x.channel||0} ${x.auto?"(automatique)":""}${x.bandwidth?" · "+x.bandwidth+" MHz":""}</span>
      <span class="muted">Norme</span><span>${esc(STD[x.standard]||x.standard)}</span>
      <span class="muted">Sécurité</span><span>${esc(x.protocol)}</span>
      <span class="muted">WPS</span><span>${yes(x.wps,false)}</span></div>`}
  } else if(b.need_password) h+=`<p class="muted small">Entrez le mot de passe d'administration en haut de la page pour lire les réglages.</p>`;
  if(b.services) h+=`<h3>Services</h3><div class="kv small"><span class="muted">Accès à distance</span><span>${yes(b.services.remote_admin,false)}</span>
    <span class="muted">UPnP</span><span>${b.services.upnp?"activé":"désactivé"}</span>
    <span class="muted">Pare-feu</span><span>${yes(b.services.firewall,true)}</span></div>`;
  return h+"</div>"}
function wifiCard(w){
  let h=`<div class="card"><h2>Canaux Wi-Fi</h2>`;
  if(w.advice){for(const [k,l] of [["24","2,4 GHz"],["5","5 GHz"]]){const a=w.advice[k];
    const max=Math.max(1,...Object.values(a.scores));
    h+=`<h3>${l}${a.current?" · canal actuel "+a.current:""}</h3><p class="small">${esc(a.advice)}</p>
    <table class="small"><tr><th>${k=="24"?"Canal":"Canaux"}</th><th style="width:60%">Encombrement</th></tr>`+
    Object.entries(a.scores).map(([c,s])=>`<tr><td>${c}${c==a.best?' <span class="tag ok">conseillé</span>':""}</td>
      <td><div class="bar" style="width:${Math.round(s/max*100)}%"></div></td></tr>`).join("")+`</table>
    <p class="muted small">${a.neighbors} réseau(x) voisin(s) sur cette bande.</p>`}}
  if(w.note) h+=`<p class="muted small">${esc(w.note)}</p>`;
  h+=`<h3>Faut-il séparer 2,4 et 5 GHz ?</h3><p class="small">${esc(w.bands_advice)}</p>`;
  if(w.neighbors.length) h+=`<details><summary class="small">Réseaux voisins (${w.neighbors.length})</summary><table class="small">
    <tr><th>Nom</th><th>Canal</th><th>Signal</th></tr>`+w.neighbors.map(n=>`<tr><td>${esc(n.ssid||"(caché)")}${w.own_ssids.includes(n.ssid)?' <span class="tag ok">vous</span>':""}</td>
    <td>${n.channel}</td><td>${n.signal} dBm</td></tr>`).join("")+`</table></details>`;
  return h+"</div>"}
function render(r){
  $("#sub").textContent=`Réseau ${r.network} · box ${r.gateway||"?"} · ${r.date} · ${r.duration} s`;
  const f=r.findings.length?r.findings.map(x=>`<div class="f ${x.level}"><b>${LV[x.level]} — ${esc(x.title)}</b>
    <span class="muted small">${esc(x.detail)}</span></div>`).join(""):`<p>Rien de suspect détecté.</p>`;
  const dns=r.dns.map(s=>`<div><span class="tag ${s.status}">${s.status=="ok"?"ok":"à vérifier"}</span>
    <code>${esc(s.server)}</code> <span class="muted small">${esc(s.detail)}</span></div>`).join("")
    ||`<span class="muted small">${r.termux?"Android ne permet pas de les lire depuis Termux.":"Non trouvés."}</span>`;
  out.innerHTML=`<div class="card"><h2>Points d'attention</h2>${f}</div>
   <div class="card"><h2>Connectés maintenant (${r.devices.length})</h2>${r.devices.map(d=>devRow(d,r)).join("")}</div>
   ${r.history.length?`<div class="card"><h2>Déjà connectés à la box (${r.history.length})</h2>
     <p class="muted small">Appareils absents maintenant mais gardés en mémoire par la box.</p>${r.history.map(d=>devRow(d,r)).join("")}</div>`:""}
   ${boxCard(r.bbox)}${wifiCard(r.wifi)}<div class="card"><h2>Serveurs DNS</h2>${dns}</div>`;
}
$("#go").onclick=()=>{
  $("#go").disabled=true;$("#go").textContent="Scan en cours…";
  out.innerHTML='<div class="card muted">Scan en cours, cela prend en général 15 à 60 secondes…</div>';
  api("/api/scan",{bbox_password:$("#pw").value}).then(render).catch(e=>out.innerHTML=`<div class="card f danger">Erreur : ${esc(e)}</div>`)
   .finally(()=>{$("#go").disabled=false;$("#go").textContent="Relancer le scan"});
};
out.onclick=e=>{
  const b=e.target.closest("button[data-k]");if(!b)return;
  let name="";
  if(b.dataset.a=="add"){name=prompt("Nom de cet appareil (ex : téléphone de Michel) :");if(name===null)return;}
  api("/api/known",{key:b.dataset.k,action:b.dataset.a,name}).then(render);
};
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    last_report = None
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self.send(200, PAGE.encode(), "text/html; charset=utf-8")
        else:
            self.send(404, {"error": "introuvable"})

    def do_POST(self):
        # L'en-tête personnalisé empêche un autre site de piloter le scanner.
        if self.headers.get("X-Scanner") != "1":
            return self.send(403, {"error": "requête refusée"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.send(400, {"error": "requête invalide"})

        if self.path == "/api/scan":
            if not Handler.lock.acquire(blocking=False):
                return self.send(409, {"error": "un scan est déjà en cours"})
            try:
                Handler.last_report = scan(bbox_password=str(body.get("bbox_password") or "") or None)
            except Exception as e:
                return self.send(500, {"error": str(e)})
            finally:
                Handler.lock.release()
            return self.send(200, Handler.last_report)

        if self.path == "/api/known":
            report = Handler.last_report
            key = str(body.get("key", ""))
            dev = next((d for d in report["devices"] + report["history"] if d["key"] == key),
                       None) if report else None
            if not dev:
                return self.send(400, {"error": "appareil introuvable, relancez le scan"})
            known = load_known()
            if body.get("action") == "add":
                known[key] = {"name": str(body.get("name", ""))[:80], "ip": dev["ip"],
                              "added": time.strftime("%Y-%m-%d")}
            else:
                known.pop(key, None)
            save_known(known)
            return self.send(200, apply_known(report))

        self.send(404, {"error": "introuvable"})


def serve(port, open_browser=True):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Interface ouverte sur {url}  (Ctrl+C pour arrêter)")
    if IS_TERMUX:
        print("Ouvrez cette adresse dans Chrome, et laissez Termux tourner en arrière-plan.")
    if open_browser and not IS_TERMUX:
        threading.Timer(0.5, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt.")
    finally:
        server.server_close()


def main(argv=None):
    p = argparse.ArgumentParser(description="Scanner de réseau Wi-Fi domestique.")
    p.add_argument("--web", action="store_true", help="ouvrir l'interface dans le navigateur")
    p.add_argument("--port", type=int, default=8765, help="port de l'interface web (8765)")
    p.add_argument("--no-browser", action="store_true", help="ne pas ouvrir le navigateur")
    p.add_argument("--json", action="store_true", help="afficher le résultat en JSON")
    p.add_argument("--bbox", action="store_true",
                   help="demander le mot de passe d'administration de la Bbox")
    p.add_argument("--no-wifi", action="store_true", help="ne pas analyser les réseaux voisins")
    args = p.parse_args(argv)

    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except AttributeError:
            pass

    if args.web:
        return serve(args.port, not args.no_browser)
    password = os.environ.get("BBOX_PASSWORD") or (
        getpass.getpass("Mot de passe d'administration de la Bbox : ") if args.bbox else None)
    report = scan(progress=None if args.json else print, bbox_password=password,
                  wifi=not args.no_wifi)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
