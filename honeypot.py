"""
honeypot.py — active deception layer for the ZeroDay-Edge node.

The node opens decoy network services (Telnet, FTP, a router-style web admin
page) on ports no legitimate device on this LAN has any reason to touch.
Detection is therefore trivial and almost free of false positives: ANY
connection to a decoy is hostile reconnaissance or a login attempt. Unlike the
statistical detectors this needs no traffic baseline and fires on the very
first packet, so a scanner is caught — and can be blocked — before it has
probed a handful of real ports.

For every visitor it also records what the attacker tried (usernames /
passwords, HTTP request line + User-Agent), which feeds the incident brief
and the campaign kill-chain.

Safety: decoys never execute anything or touch the filesystem; they only speak
a few lines of protocol, cap input at a few KB, time out quickly, and are
limited to a bounded number of concurrent connections.

Config:  EDGE_HONEYPOT=0 disables.
         EDGE_HONEYPOT_PORTS="23:telnet,21:ftp,8080:http"  (default shown)
"""

import logging
import os
import socket
import threading
import time
from datetime import datetime
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)

DEFAULT_PORTS = "23:telnet,21:ftp,8080:http"
_MAX_BYTES = 4096
_CONN_TIMEOUT = 8.0
_MAX_CONCURRENT = 40
_EVENT_COOLDOWN_S = 3.0      # per (ip, port, kind), so a hammering scanner can't flood the DB

_LOGIN_PAGE = (
    b"<html><head><title>Router Administration</title></head><body style='font-family:sans-serif'>"
    b"<h3>Wireless Router - Administration Login</h3>"
    b"<form method='POST' action='/login'>User: <input name='username'><br>"
    b"Password: <input type='password' name='password'><br><input type='submit' value='Login'></form>"
    b"</body></html>"
)


def parse_ports(spec: str) -> list[tuple[int, str]]:
    out = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        port, _, svc = item.partition(":")
        try:
            out.append((int(port), (svc or "tcp").lower()))
        except ValueError:
            logger.warning("honeypot: ignoring bad port spec %r", item)
    return out


class Honeypot:
    def __init__(self, on_event, ports: str | None = None, bind: str = "0.0.0.0", ignore_ips=()):
        """
        on_event(event: dict) is called for every hostile interaction:
            {src_ip, port, service, kind: 'probe'|'credentials', credentials: [(u,p)...],
             detail: str, timestamp}
        """
        self._on_event = on_event
        self._ports = parse_ports(ports or os.environ.get("EDGE_HONEYPOT_PORTS", DEFAULT_PORTS))
        self._bind = bind
        self._ignore = set(ignore_ips)
        self._slots = threading.BoundedSemaphore(_MAX_CONCURRENT)
        self._last: dict = {}
        self._lock = threading.Lock()
        self.listening: list[int] = []
        self.hits = 0
        self.credential_captures = 0
        self.last_hit: dict | None = None

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self):
        for port, service in self._ports:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self._bind, port))
                srv.listen(32)
            except OSError as e:
                logger.warning("honeypot: cannot listen on %d (%s): %s", port, service, e)
                continue
            self.listening.append(port)
            threading.Thread(target=self._accept_loop, args=(srv, port, service),
                             daemon=True, name=f"honeypot-{port}").start()
        if self.listening:
            logger.info("Honeypot: decoy services listening on ports %s", self.listening)
        else:
            logger.warning("Honeypot: no decoy ports could be opened")

    def status(self) -> dict:
        return {"listening_ports": self.listening, "hits": self.hits,
                "credential_captures": self.credential_captures, "last_hit": self.last_hit}

    # ── plumbing ─────────────────────────────────────────────────────────

    def _accept_loop(self, srv: socket.socket, port: int, service: str):
        while True:
            try:
                conn, (ip, _) = srv.accept()
            except OSError:
                time.sleep(0.5)
                continue
            if ip in self._ignore or ip.startswith("127."):
                conn.close()
                continue
            if not self._slots.acquire(blocking=False):   # saturated: drop, don't spawn
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, ip, port, service), daemon=True).start()

    def _serve(self, conn: socket.socket, ip: str, port: int, service: str):
        try:
            conn.settimeout(_CONN_TIMEOUT)
            self._emit(ip, port, service, "probe", [], f"connection to decoy {service} service")
            handler = {"telnet": self._telnet, "ftp": self._ftp, "http": self._http}.get(service, self._banner)
            creds: list = []     # handlers append AS they capture, so a peer that hangs up
            detail = ""          # mid-conversation can't make us lose what it already typed
            try:
                detail = handler(conn, creds) or ""
            except Exception as e:                      # a hostile peer must never crash us
                logger.debug("honeypot session error from %s: %s", ip, e)
            if creds or detail:
                self._emit(ip, port, service, "credentials" if creds else "probe", creds, detail)
        except Exception as e:
            logger.debug("honeypot session error from %s: %s", ip, e)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._slots.release()

    def _emit(self, ip, port, service, kind, creds, detail):
        key = (ip, port, kind)
        now = time.time()
        with self._lock:
            if now - self._last.get(key, 0.0) < _EVENT_COOLDOWN_S and not creds:
                return
            self._last[key] = now
            if len(self._last) > 2000:
                self._last = {k: t for k, t in self._last.items() if now - t < 60}
            self.hits += 1
            if creds:
                self.credential_captures += 1
            event = {"src_ip": ip, "port": port, "service": service, "kind": kind,
                     "credentials": creds, "detail": detail,
                     "timestamp": datetime.utcnow().isoformat()}
            self.last_hit = {"src_ip": ip, "port": port, "service": service, "kind": kind,
                             "timestamp": event["timestamp"]}
        try:
            self._on_event(event)
        except Exception as e:
            logger.error("honeypot callback failed: %s", e)

    # ── decoy protocols ──────────────────────────────────────────────────

    @staticmethod
    def _readline(conn: socket.socket) -> str:
        buf = b""
        while len(buf) < 256 and not buf.endswith(b"\n"):
            chunk = conn.recv(64)
            if not chunk:
                break
            buf += chunk
        # strip telnet IAC negotiation bytes + line endings
        return bytes(b for b in buf if 32 <= b < 127).decode("ascii", "replace").strip()

    def _telnet(self, conn, creds):
        conn.sendall(b"\r\nUbuntu 20.04.6 LTS\r\n")
        for _ in range(3):
            conn.sendall(b"router login: ")
            user = self._readline(conn)
            if not user:
                break
            conn.sendall(b"Password: ")
            pw = self._readline(conn)
            creds.append((user, pw))
            conn.sendall(b"\r\nLogin incorrect\r\n")
        return ""

    def _ftp(self, conn, creds):
        user = ""
        conn.sendall(b"220 ProFTPD 1.3.5e Server (Debian) ready.\r\n")
        for _ in range(8):
            line = self._readline(conn)
            if not line:
                break
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            if cmd == "USER":
                user = arg
                conn.sendall(b"331 Password required for " + arg.encode("ascii", "replace")[:40] + b"\r\n")
            elif cmd == "PASS":
                creds.append((user, arg))
                conn.sendall(b"530 Login incorrect.\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"530 Please login with USER and PASS.\r\n")
        return ""

    def _http(self, conn, creds):
        data = b""
        while len(data) < _MAX_BYTES:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep and (b"content-length" not in head.lower() or len(body) >= 1):
                break
        text = data.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0][:120]
        ua = next((l.split(":", 1)[1].strip() for l in text.split("\r\n") if l.lower().startswith("user-agent:")), "")
        if first.upper().startswith("POST"):
            body = text.partition("\r\n\r\n")[2]
            form = parse_qs(body)
            u = (form.get("username") or form.get("user") or [""])[0]
            p = (form.get("password") or form.get("pass") or [""])[0]
            if u or p:
                creds.append((u[:64], p[:64]))
        detail = f"{first} | UA: {ua[:80]}"
        conn.sendall(b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.55\r\nContent-Type: text/html\r\n"
                     b"Content-Length: " + str(len(_LOGIN_PAGE)).encode() + b"\r\nConnection: close\r\n\r\n" + _LOGIN_PAGE)
        return detail

    def _banner(self, conn, creds):
        conn.sendall(b"\r\n")
        data = conn.recv(256)
        return f"sent {len(data)} bytes" if data else ""
