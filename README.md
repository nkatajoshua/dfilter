# DNSFilter

A self-contained, pure-Python DNS filtering system for Ubuntu Server. No Pi-hole, no dnsmasq, no Unbound — just three files and one command.

Intercepts all DNS traffic on your network, checks queries against a blocklist, and forwards allowed queries to upstream resolvers over DNS-over-TLS. Ships with a web admin UI for managing rules and viewing live query logs.

---

## What it closes

| Bypass vector | How it is blocked |
|---|---|
| Plain DNS (UDP/TCP 53) | iptables PREROUTING redirects all port-53 traffic to our server, regardless of destination IP |
| DNS-over-HTTPS (DoH) | 17 known provider IPs blocked on TCP:443 + all UDP:443 (QUIC/HTTP3) |
| DNS-over-TLS from clients (DoT) | FORWARD REJECT on TCP/UDP:853 — only our server uses DoT outbound |
| VPN tunnels | OpenVPN, WireGuard, IPSec, IKEv2, PPTP, L2TP, GRE, ESP all blocked in FORWARD |
| Tor | Port 9001/9030 blocked + up to 500 live guard node IPs fetched and blocked at install time |
| Hardcoded-IP bypass | Default FORWARD policy set to DROP — only HTTP/HTTPS/ICMP/DNS forwarded |
| IPv6 | Every rule mirrored to ip6tables |
| Unknown DoH providers | Clients cannot resolve DoH hostnames — DNS query to find them is intercepted first |
| Admin UI access | Login page with SHA-256 password auth, 8-hour sessions, change-password endpoint |

---

## Architecture

```
Clients (any device on the network)
        │  port 53 (UDP/TCP)
        ▼
iptables PREROUTING  ──────────────────────────────────────────────
        │  redirects all port-53 to 127.0.0.1:53
        ▼
dns_server.py  (Python, systemd: dnsfilter-dns)
        │
        ├── Blocklist engine (SQLite)
        │     exact match · wildcard · regex · allowlist override
        │
        ├── BLOCKED  →  NXDOMAIN returned to client
        │
        └── ALLOWED  →  forward over DNS-over-TLS
                          8.8.8.8:853 (dns.google)
                          1.1.1.1:853 (cloudflare-dns.com)
                          plain UDP fallback if DoT fails

web_ui.py  (Flask, systemd: dnsfilter-ui, port 8080)
        │
        ├── /login          password-protected login page
        ├── /               admin dashboard
        ├── /api/blocklist  add · remove · search rules
        ├── /api/allowlist  allowlist management
        ├── /api/logs       live query log (50 000 row rolling window)
        ├── /api/import     import hosts-format lists from URL
        └── /api/settings   sinkhole IP · log toggle · password change

Shared state:  /etc/dnsfilter/blocklist.db  (SQLite)
               /etc/dnsfilter/admin_pass.hash
               /etc/dnsfilter/doh_hosts.txt
               /etc/dnsfilter/tor_guards.txt
```

---

## Requirements

- Ubuntu Server 20.04, 22.04, or 24.04 (amd64 or arm64)
- Root access (`sudo`)
- The VM/host must sit in the traffic path — either as the network gateway or with the router's DNS pointing to it
- Python 3.8+ (pre-installed on all supported Ubuntu versions)
- Outbound TCP:853 to `8.8.8.8` and `1.1.1.1` (for DNS-over-TLS to upstream)

---

## Installation

### Option 1 — Git clone (recommended)

```bash
git clone https://github.com/<your-username>/dnsfilter.git
cd dnsfilter
sudo bash install.sh
```

### Option 2 — One-liner (no git required)

```bash
sudo bash -c "
  cd /tmp &&
  curl -sSL https://raw.githubusercontent.com/<your-username>/dnsfilter/main/dns_server.py -o dns_server.py &&
  curl -sSL https://raw.githubusercontent.com/<your-username>/dnsfilter/main/web_ui.py     -o web_ui.py     &&
  curl -sSL https://raw.githubusercontent.com/<your-username>/dnsfilter/main/install.sh    -o install.sh    &&
  bash install.sh
"
```

The installer will:

1. Detect your main network interface and IP
2. Generate a random admin password (printed once at the end — save it)
3. Install Python 3 venv + Flask, and Squid (for future HTTPS inspection)
4. Deploy `dns_server.py` and `web_ui.py` to `/opt/dnsfilter/`
5. Initialise the SQLite database at `/etc/dnsfilter/blocklist.db`
6. Configure iptables and ip6tables (DNS intercept, DoH block, VPN block, Tor block, default-deny FORWARD)
7. Fetch live Tor guard node IPs from the Tor Project API
8. Register and start two systemd services (`dnsfilter-dns`, `dnsfilter-ui`)
9. Install two nightly crons (DoH IP refresh at 03:00, Tor guard refresh at 04:00)
10. Run a live DNS resolution test to verify the stack is working

Total install time: ~60–90 seconds on a fresh VM.

---

## Post-install setup

### 1. Point your router's DNS at the VM

Log into your router admin panel and set the **primary DNS server** to the VM's IP address. Leave the secondary DNS blank or set it to the same IP — if you leave it as `8.8.8.8`, clients will fall back to unfiltered DNS when your VM is unreachable.

### 2. Open the admin UI

```
http://<VM-IP>:8080
```

Username: `admin`  
Password: printed at the end of the install output

### 3. Import a blocklist

In the admin UI → **Import** tab, click one of the quick-add buttons:

- **StevenBlack unified** — ads + malware (400 000+ domains)
- **OISD big** — comprehensive multi-category list
- Or paste any URL to a hosts-format or plain domain list

Then go to **Dashboard** to confirm queries are flowing and being filtered.

---

## Directory layout (on the server)

```
/opt/dnsfilter/
├── dns_server.py        # DNS server (installed from repo)
├── web_ui.py            # Admin UI (installed from repo)
├── venv/                # Python virtualenv (created by installer)
├── refresh_doh.sh       # Nightly DoH IP refresh script
└── refresh_tor.sh       # Nightly Tor guard IP refresh script

/etc/dnsfilter/
├── blocklist.db         # SQLite — blocklist, allowlist, query log, settings
├── admin_pass.hash      # SHA-256 hash of admin password (chmod 600)
├── doh_hosts.txt        # Resolved DoH provider IPs
└── tor_guards.txt       # Tor guard node IPs

/var/log/dnsfilter/
├── dns.log              # DNS server log (stdout + stderr)
├── ui.log               # Web UI log
├── doh_refresh.log      # Nightly DoH refresh output
└── tor_refresh.log      # Nightly Tor refresh output

/etc/systemd/system/
├── dnsfilter-dns.service
└── dnsfilter-ui.service

/etc/cron.d/
├── dnsfilter-doh        # 03:00 daily — re-resolve DoH provider IPs
└── dnsfilter-tor        # 04:00 daily — refresh Tor guard node list
```

---

## Service management

```bash
# Status
sudo systemctl status dnsfilter-dns
sudo systemctl status dnsfilter-ui

# Logs (live tail)
sudo journalctl -u dnsfilter-dns -f
sudo journalctl -u dnsfilter-ui -f

# Restart
sudo systemctl restart dnsfilter-dns
sudo systemctl restart dnsfilter-ui

# Reload blocklist without restarting (picks up DB changes made outside the UI)
sudo kill -USR1 $(cat /run/dnsfilter-dns.pid)

# Manually refresh DoH IP blocks
sudo /opt/dnsfilter/refresh_doh.sh

# Manually refresh Tor guard IP blocks
sudo /opt/dnsfilter/refresh_tor.sh
```

---

## Blocklist management (CLI)

You can manage rules directly via sqlite3 without going through the UI:

```bash
# Open the database
sudo sqlite3 /etc/dnsfilter/blocklist.db

# Add a domain (exact match)
INSERT INTO blocklist(domain, type, source) VALUES('ads.example.com', 'exact', 'manual');

# Add a wildcard (blocks ads.example.com, tracker.ads.example.com, etc.)
INSERT INTO blocklist(domain, type, source) VALUES('ads.example.com', 'wildcard', 'manual');

# Add a regex rule
INSERT INTO blocklist(domain, type, source) VALUES('.*\.ads\..*', 'regex', 'manual');

# Add to allowlist (overrides blocklist)
INSERT INTO allowlist(domain) VALUES('safe.example.com');

# Count blocked rules
SELECT COUNT(*) FROM blocklist WHERE enabled=1;

# View recent queries
SELECT ts, client_ip, domain, action FROM query_log ORDER BY id DESC LIMIT 20;
```

After any direct DB change, signal the DNS server to reload:

```bash
sudo kill -USR1 $(cat /run/dnsfilter-dns.pid)
```

---

## Changing the admin password

**Via the UI:** Settings tab → Change password section.

**Via CLI:**

```bash
# Generate and set a new password
NEW_PASS="your-new-password"
python3 -c "import hashlib; print(hashlib.sha256('${NEW_PASS}'.encode()).hexdigest())" \
  | sudo tee /etc/dnsfilter/admin_pass.hash > /dev/null
sudo chmod 600 /etc/dnsfilter/admin_pass.hash
echo "Password updated"
```

---

## Adding custom iptables FORWARD rules

The default FORWARD policy is DROP — only HTTP (80), HTTPS (443), ICMP, and DNS pass through. If clients need to reach other ports (e.g. SSH to a remote server, custom application ports), add explicit ACCEPT rules:

```bash
# Allow clients to reach SSH on any host
sudo iptables  -I FORWARD -p tcp --dport 22 -m comment --comment "custom-ssh" -j ACCEPT
sudo ip6tables -I FORWARD -p tcp --dport 22 -m comment --comment "custom-ssh" -j ACCEPT

# Allow a specific subnet through unrestricted
sudo iptables  -I FORWARD -s 192.168.1.0/24 -m comment --comment "custom-subnet" -j ACCEPT

# Save so rules survive reboot
sudo netfilter-persistent save
```

---

## Uninstall

```bash
sudo bash install.sh --uninstall
```

This stops and removes both services, flushes all dnsfilter iptables/ip6tables rules (IPv4 + IPv6), resets the FORWARD policy to ACCEPT, removes cron jobs, and deletes `/opt/dnsfilter/` and `/var/log/dnsfilter/`.

Your config and database at `/etc/dnsfilter/` are kept so you can reinstall without losing your blocklist. To remove those too:

```bash
sudo rm -rf /etc/dnsfilter/
```

---

## Known limitations

| Limitation | Notes |
|---|---|
| Self-hosted / private DoH | If a client has a DoH server IP hardcoded (not resolved via DNS), it can reach it on port 443 — we can't distinguish DoH HTTPS from regular HTTPS without SSL inspection |
| VPN over port 443 | Some commercial VPNs (e.g. ExpressVPN, NordVPN Obfuscated) tunnel over HTTPS port 443. Indistinguishable from regular HTTPS without deep packet inspection |
| Pluggable Tor transports | Obfs4 and meek bridges route over port 443 and look like HTTPS traffic |
| DNS-over-HTTPS in apps | Mobile apps with hardcoded DoH (some versions of YouTube, Chrome on Android) will fail silently and may show connectivity errors rather than falling back to plain DNS |

---

## Tested on

- Ubuntu Server 22.04 LTS (amd64)
- Ubuntu Server 24.04 LTS (amd64)
- Ubuntu Server 22.04 LTS (arm64 / Raspberry Pi)

---

## License

MIT
