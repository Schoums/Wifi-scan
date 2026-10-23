#!/usr/bin/env python3
"""Scanner de réseau Wi-Fi domestique.

Liste les appareils connectés au réseau local, repère les services
sensibles ouverts et vérifie les serveurs DNS utilisés.

Aucune dépendance : Python 3.8+ suffit (Windows, macOS, Linux).

    python wifi_scan.py            # scan en mode texte
    python wifi_scan.py --web      # interface dans le navigateur
"""

import argparse
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SYSTEM = platform.system()
HERE = os.path.dirname(os.path.abspath(__file__))
KNOWN_FILE = os.path.join(HERE, "known_devices.json")

# Ports essayés pour savoir si un appareil est présent (une connexion
# refusée prouve aussi que l'appareil existe).
DISCOVERY_PORTS = [80, 443, 22, 445, 139, 53, 62078, 8080, 554, 5353]

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


def analyse(devices, gateway, dns):
    """Construit la liste des points d'attention."""
    findings = []
    for d in devices:
        who = d["name"] or d["ip"]
        if not d["known"]:
            findings.append({"level": "warn", "ip": d["ip"],
                             "title": f"Appareil inconnu : {who}",
                             "detail": "Vérifiez de quoi il s'agit, puis cliquez sur « Je le connais »."})
        for p in d["ports"]:
            if p in RISKY_PORTS:
                name, level, why = RISKY_PORTS[p]
                place = "la box" if d["ip"] == gateway else who
                findings.append({"level": level, "ip": d["ip"],
                                 "title": f"{name} ouvert sur {place} (port {p})",
                                 "detail": why})
    if gateway and not any(d["ip"] == gateway for d in devices):
        findings.append({"level": "info", "ip": gateway,
                         "title": "La box n'a pas répondu au scan",
                         "detail": "Rien d'anormal en soi, certaines box ne répondent pas."})
    for server in dns:
        level, why = classify_dns(server)
        if level != "ok":
            findings.append({"level": level, "ip": server,
                             "title": f"Serveur DNS {server}", "detail": why})
    order = {"danger": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order[f["level"]])
    return findings


def scan(progress=None):
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

    step(f"Recherche des appareils sur {net} …")
    hosts = [str(h) for h in net.hosts() if str(h) != me]
    with ThreadPoolExecutor(max_workers=128) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(is_alive, hosts)) if ok}
    arp = arp_table()
    alive |= {ip for ip in arp if ipaddress.ip_address(ip) in net}
    alive.add(me)
    ips = sorted(alive, key=lambda ip: ipaddress.ip_address(ip))

    step(f"{len(ips)} appareil(s) trouvé(s), vérification des services …")
    with ThreadPoolExecutor(max_workers=16) as ex:
        ports = list(ex.map(open_ports, ips))
        names = list(ex.map(hostname, ips))

    known = load_known()
    devices = []
    for ip, p, name in zip(ips, ports, names):
        mac = own_mac() if ip == me else arp.get(ip)
        dev = {"ip": ip, "mac": mac, "name": name, "ports": p,
               "is_gateway": ip == gateway, "is_me": ip == me,
               "random_mac": is_random_mac(mac)}
        entry = known.get(device_key(dev))
        dev["known"] = bool(entry) or dev["is_me"]
        dev["label"] = entry.get("name", "") if entry else ("Cet ordinateur" if dev["is_me"] else "")
        devices.append(dev)

    return {
        "network": str(net), "me": me, "gateway": gateway,
        "dns": [{"server": s, "status": classify_dns(s)[0], "detail": classify_dns(s)[1]}
                for s in dns],
        "devices": devices,
        "findings": analyse(devices, gateway, dns),
        "port_names": {p: (RISKY_PORTS[p][0] if p in RISKY_PORTS else INFO_PORTS[p])
                       for p in SCAN_PORTS},
        "duration": round(time.time() - started, 1),
        "date": time.strftime("%d/%m/%Y %H:%M"),
    }


# --------------------------------------------------------------------------
# Mode texte
# --------------------------------------------------------------------------

def print_report(r):
    icons = {"danger": "[DANGER]", "warn": "[ATTENTION]", "info": "[INFO]"}
    print(f"\nRéseau {r['network']} — box : {r['gateway'] or '?'} — scan en {r['duration']} s\n")
    print(f"{'IP':<16}{'MAC':<19}{'Nom':<28}Ports ouverts")
    for d in r["devices"]:
        tag = " (box)" if d["is_gateway"] else ""
        name = (d["label"] or d["name"] or "?")[:26] + tag
        status = "" if d["known"] else "  <- inconnu"
        print(f"{d['ip']:<16}{d['mac'] or '?':<19}{name:<28}"
              f"{', '.join(map(str, d['ports'])) or '-'}{status}")
    print("\nServeurs DNS : " + (", ".join(s["server"] for s in r["dns"]) or "?"))
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
main{max-width:1000px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:16px;margin-top:16px}
button{font:inherit;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;
background:var(--accent);color:#fff}button.ghost{background:transparent;color:var(--accent);
border:1px solid var(--line);padding:4px 10px}button:disabled{opacity:.5;cursor:wait}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.f{border-left:4px solid var(--info);padding:6px 12px;margin:8px 0}
.f.danger{border-color:var(--danger)}.f.warn{border-color:var(--warn)}
.f b{display:block}.tag{font-size:12px;border-radius:99px;padding:1px 8px;border:1px solid var(--line);white-space:nowrap}
.tag.ok{color:var(--ok)}.tag.warn{color:var(--warn)}.tag.danger{color:var(--danger)}
.table{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}code{font-size:13px}
.port{display:inline-block;margin:0 4px 4px 0}
</style></head><body><main>
<div class="top"><div><h1>Scanner Wi-Fi</h1>
<div class="muted" id="sub">Vérifie les appareils connectés à votre réseau.</div></div>
<button id="go">Lancer le scan</button></div>
<div id="out"></div>
<div class="card muted" style="font-size:13px">Le scan ne voit que les appareils connectés
en ce moment. « Rien de suspect » ne garantit pas que le réseau est sain.</div>
</main><script>
const $=s=>document.querySelector(s), out=$("#out");
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const api=(url,body)=>fetch(url,{method:"POST",headers:{"Content-Type":"application/json","X-Scanner":"1"},
  body:JSON.stringify(body||{})}).then(r=>r.ok?r.json():r.json().then(e=>Promise.reject(e.error)));
const LV={danger:"Danger",warn:"Attention",info:"Info"};
let last=null;
function render(r){
  last=r;
  $("#sub").textContent=`Réseau ${r.network} · box ${r.gateway||"?"} · ${r.date} · ${r.duration} s`;
  const f=r.findings.length?r.findings.map(x=>`<div class="f ${x.level}"><b>${LV[x.level]} — ${esc(x.title)}</b>
    <span class="muted">${esc(x.detail)}</span></div>`).join(""):
    `<p>Rien de suspect détecté.</p>`;
  const rows=r.devices.map(d=>{
    const ports=d.ports.map(p=>`<span class="port tag">${p} ${esc(r.port_names[p]||"")}</span>`).join("")||"<span class=muted>—</span>";
    const who=[d.label&&`<b>${esc(d.label)}</b>`,d.name&&esc(d.name),d.is_gateway&&"<span class=tag>box</span>"].filter(Boolean).join("<br>")||"<span class=muted>?</span>";
    const mac=d.mac?`<code>${esc(d.mac)}</code>${d.random_mac&&!d.is_gateway?'<br><span class="muted" style="font-size:12px">adresse privée (téléphone ?)</span>':""}`:"<span class=muted>?</span>";
    const st=d.known?'<span class="tag ok">connu</span>':'<span class="tag warn">inconnu</span>';
    const act=d.is_me?"":d.known?`<button class="ghost" data-k="${esc(d.key)}" data-a="forget">Oublier</button>`
      :`<button class="ghost" data-k="${esc(d.key)}" data-a="add">Je le connais</button>`;
    return `<tr><td>${st}</td><td><code>${esc(d.ip)}</code></td><td>${mac}</td><td>${who}</td><td>${ports}</td><td>${act}</td></tr>`}).join("");
  const dns=r.dns.map(s=>`<div><span class="tag ${s.status}">${s.status=="ok"?"ok":"à vérifier"}</span>
    <code>${esc(s.server)}</code> <span class="muted">${esc(s.detail)}</span></div>`).join("")||"<span class=muted>Non trouvés</span>";
  out.innerHTML=`<div class="card"><h2>Points d'attention</h2>${f}</div>
   <div class="card"><h2>Appareils (${r.devices.length})</h2><div class="table"><table>
   <tr><th>Statut</th><th>IP</th><th>Adresse MAC</th><th>Nom</th><th>Services ouverts</th><th></th></tr>${rows}</table></div></div>
   <div class="card"><h2>Serveurs DNS</h2>${dns}</div>`;
}
$("#go").onclick=()=>{
  $("#go").disabled=true;$("#go").textContent="Scan en cours…";
  out.innerHTML='<div class="card muted">Scan en cours, cela prend en général 10 à 60 secondes…</div>';
  api("/api/scan").then(render).catch(e=>out.innerHTML=`<div class="card f danger">Erreur : ${esc(e)}</div>`)
   .finally(()=>{$("#go").disabled=false;$("#go").textContent="Relancer le scan"});
};
out.onclick=e=>{
  const b=e.target.closest("button[data-k]");if(!b)return;
  let name="";
  if(b.dataset.a=="add"){name=prompt("Nom de cet appareil (ex : téléphone de Michel) :");if(name===null)return;}
  api("/api/known",{key:b.dataset.k,action:b.dataset.a,name}).then(render);
};
</script></body></html>"""


def with_keys(report):
    for d in report["devices"]:
        d["key"] = device_key(d)
    return report


def refresh_known(report):
    """Recalcule le statut connu/inconnu après une modification."""
    known = load_known()
    for d in report["devices"]:
        entry = known.get(device_key(d))
        d["known"] = bool(entry) or d["is_me"]
        if not d["is_me"]:
            d["label"] = entry.get("name", "") if entry else ""
    dns = [s["server"] for s in report["dns"]]
    report["findings"] = analyse(report["devices"], report["gateway"], dns)
    return with_keys(report)


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
                Handler.last_report = with_keys(scan())
            except Exception as e:
                return self.send(500, {"error": str(e)})
            finally:
                Handler.lock.release()
            return self.send(200, Handler.last_report)

        if self.path == "/api/known":
            report = Handler.last_report
            key = str(body.get("key", ""))
            dev = next((d for d in report["devices"] if d["key"] == key), None) if report else None
            if not dev:
                return self.send(400, {"error": "appareil introuvable, relancez le scan"})
            known = load_known()
            if body.get("action") == "add":
                known[key] = {"name": str(body.get("name", ""))[:80], "ip": dev["ip"],
                              "added": time.strftime("%Y-%m-%d")}
            else:
                known.pop(key, None)
            save_known(known)
            return self.send(200, refresh_known(report))

        self.send(404, {"error": "introuvable"})


def serve(port, open_browser=True):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Interface ouverte sur {url}  (Ctrl+C pour arrêter)")
    if open_browser:
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
    args = p.parse_args(argv)

    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except AttributeError:
            pass

    if args.web:
        return serve(args.port, not args.no_browser)
    report = scan(progress=None if args.json else print)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
