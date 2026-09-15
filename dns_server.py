#!/usr/bin/env python3
"""
dnsfilter — Pure Python DNS filtering server.
Listens on UDP/TCP port 53, checks queries against SQLite blocklist,
forwards allowed queries to upstream resolvers (Google / Cloudflare DoT).
"""

import socket
import struct
import threading
import sqlite3
import ssl
import logging
import re
import os
import signal
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LISTEN_HOST   = "0.0.0.0"
LISTEN_PORT   = 53
DB_PATH       = "/etc/dnsfilter/blocklist.db"
LOG_PATH      = "/var/log/dnsfilter/dns.log"
UPSTREAM_DNS  = [
    ("8.8.8.8",           853, "dns.google"),
    ("1.1.1.1",           853, "cloudflare-dns.com"),
]
SINKHOLE_IP   = "0.0.0.0"   # IP returned for blocked A queries
BUFFER_SIZE   = 4096
UPSTREAM_TIMEOUT = 5

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("dnsfilter")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            domain  TEXT NOT NULL,
            type    TEXT NOT NULL DEFAULT 'exact',  -- exact | wildcard | regex
            source  TEXT DEFAULT 'manual',
            added   TEXT DEFAULT (datetime('now')),
            enabled INTEGER DEFAULT 1
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_domain ON blocklist(domain, type);

        CREATE TABLE IF NOT EXISTS allowlist (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            domain  TEXT NOT NULL UNIQUE,
            added   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS query_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT DEFAULT (datetime('now')),
            client_ip TEXT,
            domain    TEXT,
            qtype     TEXT,
            action    TEXT,   -- ALLOWED | BLOCKED | SINKHLED
            upstream  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_log_ts ON query_log(ts);

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        INSERT OR IGNORE INTO settings VALUES ('sinkhole_ip', '0.0.0.0');
        INSERT OR IGNORE INTO settings VALUES ('log_queries', '1');
        INSERT OR IGNORE INTO settings VALUES ('upstream_strategy', 'failover');
    """)
    conn.commit()
    conn.close()
    log.info("Database initialised at %s", DB_PATH)

# ---------------------------------------------------------------------------
# Blocklist engine
# ---------------------------------------------------------------------------
_blocklist_cache = {}
_cache_lock = threading.Lock()
_cache_loaded = 0

def _load_cache():
    global _blocklist_cache, _cache_loaded
    conn = get_db()
    rows = conn.execute(
        "SELECT domain, type FROM blocklist WHERE enabled=1"
    ).fetchall()
    conn.close()
    exact = set()
    wildcards = []
    regexps = []
    for r in rows:
        t = r["type"]
        d = r["domain"].lower().strip(".")
        if t == "exact":
            exact.add(d)
        elif t == "wildcard":
            wildcards.append(d.lstrip("*."))
        elif t == "regex":
            try:
                regexps.append(re.compile(d))
            except re.error:
                pass
    with _cache_lock:
        _blocklist_cache = {"exact": exact, "wildcards": wildcards, "regex": regexps}
        _cache_loaded = time.time()

def reload_cache():
    _load_cache()
    log.info("Blocklist cache reloaded (%d exact entries)", len(_blocklist_cache.get("exact", [])))

def is_blocked(domain: str) -> bool:
    domain = domain.lower().strip(".")
    # Check allowlist first
    conn = get_db()
    row = conn.execute(
        "SELECT 1 FROM allowlist WHERE ?=domain", (domain,)
    ).fetchone()
    conn.close()
    if row:
        return False
    # Reload cache every 60 s
    if time.time() - _cache_loaded > 60:
        _load_cache()
    with _cache_lock:
        cache = _blocklist_cache
    if domain in cache.get("exact", set()):
        return True
    for wc in cache.get("wildcards", []):
        if domain == wc or domain.endswith("." + wc):
            return True
    for rx in cache.get("regex", []):
        if rx.search(domain):
            return True
    return False

def log_query(client_ip, domain, qtype, action, upstream=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO query_log(client_ip,domain,qtype,action,upstream) VALUES(?,?,?,?,?)",
        (client_ip, domain, qtype, action, upstream)
    )
    # Keep only last 50 000 rows
    conn.execute(
        "DELETE FROM query_log WHERE id NOT IN (SELECT id FROM query_log ORDER BY id DESC LIMIT 50000)"
    )
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# DNS wire-format helpers
# ---------------------------------------------------------------------------
def parse_dns_name(data: bytes, offset: int):
    """Return (name_str, new_offset) handling pointer compression."""
    labels = []
    visited = set()
    while True:
        if offset in visited:
            raise ValueError("DNS name loop")
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:          # pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            name_part, _ = parse_dns_name(data, ptr)
            labels.append(name_part)
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset

def build_nxdomain(query: bytes) -> bytes:
    """Build an NXDOMAIN response from the original query."""
    header = bytearray(query[:12])
    # QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    header[2] = 0x81
    header[3] = 0x83
    # Zero all count fields except QDCOUNT
    header[6] = 0; header[7] = 0  # ANCOUNT
    header[8] = 0; header[9] = 0  # NSCOUNT
    header[10] = 0; header[11] = 0 # ARCOUNT
    return bytes(header) + query[12:]

def build_sinkhole_a(query: bytes, ip: str) -> bytes:
    """Return a spoofed A record pointing to sinkhole_ip."""
    header = bytearray(query[:12])
    header[2] = 0x81; header[3] = 0x80  # QR=1, RA=1, RCODE=0
    header[6] = 0; header[7] = 1        # ANCOUNT=1
    header[8] = 0; header[9] = 0
    header[10] = 0; header[11] = 0
    # Answer: pointer to question name (0xC00C), TYPE A, CLASS IN, TTL 60, RDLENGTH 4
    ip_parts = bytes(int(x) for x in ip.split("."))
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_parts
    return bytes(header) + query[12:] + answer

def extract_query_info(data: bytes):
    """Return (domain, qtype_str) from a DNS query packet."""
    if len(data) < 12:
        return None, None
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount == 0:
        return None, None
    try:
        domain, offset = parse_dns_name(data, 12)
        qtype_int = struct.unpack("!H", data[offset:offset + 2])[0]
    except Exception:
        return None, None
    qtypes = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT",
              2: "NS", 6: "SOA", 33: "SRV", 255: "ANY"}
    return domain, qtypes.get(qtype_int, str(qtype_int))

# ---------------------------------------------------------------------------
# Upstream forwarding over DoT (DNS-over-TLS)
# ---------------------------------------------------------------------------
def forward_dot(query: bytes, host: str, port: int, sni: str) -> bytes | None:
    """Forward query to upstream using DNS-over-TLS (RFC 7858)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=UPSTREAM_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                # RFC 7858: 2-byte length prefix
                msg = struct.pack("!H", len(query)) + query
                tls.sendall(msg)
                # Read response length
                rlen_data = b""
                while len(rlen_data) < 2:
                    chunk = tls.recv(2 - len(rlen_data))
                    if not chunk:
                        return None
                    rlen_data += chunk
                rlen = struct.unpack("!H", rlen_data)[0]
                resp = b""
                while len(resp) < rlen:
                    chunk = tls.recv(rlen - len(resp))
                    if not chunk:
                        return None
                    resp += chunk
                return resp
    except Exception as e:
        log.debug("DoT upstream %s:%d failed: %s", host, port, e)
        return None

def forward_query(query: bytes) -> tuple[bytes | None, str]:
    """Try upstreams in order, return (response, upstream_label)."""
    for host, port, sni in UPSTREAM_DNS:
        resp = forward_dot(query, host, port, sni)
        if resp:
            return resp, f"{host}:{port}"
    # Fallback: plain UDP to first upstream
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(UPSTREAM_TIMEOUT)
            s.sendto(query, (UPSTREAM_DNS[0][0], 53))
            data, _ = s.recvfrom(BUFFER_SIZE)
            return data, f"{UPSTREAM_DNS[0][0]}:53(udp-fallback)"
    except Exception as e:
        log.warning("All upstreams failed: %s", e)
        return None, "none"

# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
def handle_query(data: bytes, client_addr: tuple, send_fn):
    domain, qtype = extract_query_info(data)
    if not domain:
        return

    client_ip = client_addr[0]

    if is_blocked(domain):
        log.info("BLOCKED  %-50s [%s] from %s", domain, qtype, client_ip)
        log_query(client_ip, domain, qtype, "BLOCKED")
        response = build_nxdomain(data)
        send_fn(response)
        return

    response, upstream = forward_query(data)
    if response:
        log.info("ALLOWED  %-50s [%s] via %s", domain, qtype, upstream)
        log_query(client_ip, domain, qtype, "ALLOWED", upstream)
        send_fn(response)
    else:
        log.warning("SERVFAIL %-50s [%s]", domain, qtype)
        log_query(client_ip, domain, qtype, "SERVFAIL")
        # Return SERVFAIL
        hdr = bytearray(data[:12])
        hdr[2] = 0x81; hdr[3] = 0x82
        send_fn(bytes(hdr) + data[12:])

# ---------------------------------------------------------------------------
# UDP server
# ---------------------------------------------------------------------------
class UDPServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="udp-server")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind((LISTEN_HOST, LISTEN_PORT))
        log.info("UDP listener on %s:%d", LISTEN_HOST, LISTEN_PORT)

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                def send(resp, a=addr):
                    self.sock.sendto(resp, a)
                threading.Thread(target=handle_query, args=(data, addr, send),
                                 daemon=True).start()
            except Exception as e:
                log.error("UDP recv error: %s", e)

# ---------------------------------------------------------------------------
# TCP server
# ---------------------------------------------------------------------------
class TCPServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="tcp-server")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((LISTEN_HOST, LISTEN_PORT))
        self.sock.listen(64)
        log.info("TCP listener on %s:%d", LISTEN_HOST, LISTEN_PORT)

    def run(self):
        while True:
            try:
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr),
                                 daemon=True).start()
            except Exception as e:
                log.error("TCP accept error: %s", e)

    def _handle_conn(self, conn, addr):
        try:
            with conn:
                # Read 2-byte length prefix
                raw_len = conn.recv(2)
                if len(raw_len) < 2:
                    return
                msg_len = struct.unpack("!H", raw_len)[0]
                data = b""
                while len(data) < msg_len:
                    chunk = conn.recv(msg_len - len(data))
                    if not chunk:
                        return
                    data += chunk
                def send(resp):
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
                handle_query(data, addr, send)
        except Exception as e:
            log.debug("TCP conn error from %s: %s", addr, e)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    log.info("dnsfilter DNS server starting")
    init_db()
    reload_cache()

    udp = UDPServer()
    tcp = TCPServer()
    udp.start()
    tcp.start()

    def on_signal(signum, _):
        log.info("Signal %d received, reloading blocklist", signum)
        reload_cache()

    signal.signal(signal.SIGUSR1, on_signal)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    log.info("dnsfilter ready — send SIGUSR1 to reload blocklist")
    try:
        while True:
            time.sleep(30)
            # Periodic cache warm — also catches DB updates from the UI
            reload_cache()
    except KeyboardInterrupt:
        log.info("Shutting down")

if __name__ == "__main__":
    main()
