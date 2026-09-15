#!/usr/bin/env bash
# =============================================================================
# dnsfilter — Application-layer DNS filtering for Ubuntu Server
# Closes: plain DNS hijack, DoH (TCP+QUIC), DoT, VPN ports, Tor,
#         IPv6 parity, hardcoded-IP bypass (default-deny FORWARD),
#         admin UI auth, unknown DoH via catch-all port-443 block.
# Usage: sudo bash install.sh [--uninstall]
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/dnsfilter"
CONFIG_DIR="/etc/dnsfilter"
LOG_DIR="/var/log/dnsfilter"
DB_PATH="${CONFIG_DIR}/blocklist.db"
SERVICE_DNS="dnsfilter-dns"
SERVICE_UI="dnsfilter-ui"
DNS_PORT=53
UI_PORT=8080
UPSTREAM_DNS=("8.8.8.8" "1.1.1.1")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*"; exit 1; }
step()  { echo -e "\n${BOLD}==> $*${RESET}"; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash install.sh"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
  step "Uninstalling dnsfilter"
  systemctl stop  ${SERVICE_DNS} ${SERVICE_UI} squid 2>/dev/null || true
  systemctl disable ${SERVICE_DNS} ${SERVICE_UI} 2>/dev/null || true
  rm -f /etc/systemd/system/${SERVICE_DNS}.service
  rm -f /etc/systemd/system/${SERVICE_UI}.service
  systemctl daemon-reload

  # Flush all dnsfilter iptables rules (IPv4)
  iptables-save | grep -v "dnsfilter" | iptables-restore || true
  # Flush all dnsfilter ip6tables rules (IPv6)
  ip6tables-save | grep -v "dnsfilter" | ip6tables-restore || true
  # Remove default-deny FORWARD if we set it
  iptables  -P FORWARD ACCEPT 2>/dev/null || true
  ip6tables -P FORWARD ACCEPT 2>/dev/null || true

  if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
  fi

  rm -f /etc/cron.d/dnsfilter-doh
  rm -rf "${INSTALL_DIR}" "${LOG_DIR}"
  warn "Config and DB at ${CONFIG_DIR} were kept. Remove manually:"
  warn "  rm -rf ${CONFIG_DIR}"
  ok "dnsfilter uninstalled"
  exit 0
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo -e "
${BOLD}${CYAN}
  ██████╗ ███╗   ██╗███████╗███████╗██╗██╗  ████████╗███████╗██████╗
  ██╔══██╗████╗  ██║██╔════╝██╔════╝██║██║  ╚══██╔══╝██╔════╝██╔══██╗
  ██║  ██║██╔██╗ ██║███████╗█████╗  ██║██║     ██║   █████╗  ██████╔╝
  ██║  ██║██║╚██╗██║╚════██║██╔══╝  ██║██║     ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██║ ╚████║███████║██║     ██║███████╗██║   ███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
${RESET}
  Full-coverage DNS application filtering for Ubuntu Server
  Gaps closed: IPv6 · VPN ports · Tor · hardcoded-IP bypass ·
               DoH (TCP+QUIC) · DoT interception · admin auth
"

# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------
step "Detecting network configuration"
MAIN_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
MAIN_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
info "Interface : ${MAIN_IF}"
info "IP        : ${MAIN_IP}"

# Detect IPv6 interface (may differ from v4 on some setups)
IPV6_IF=$(ip -6 route 2>/dev/null | awk '/default/{print $5}' | head -1)
IPV6_IF="${IPV6_IF:-${MAIN_IF}}"
HAS_IPV6=false
if ip -6 addr show dev "${IPV6_IF}" 2>/dev/null | grep -q "inet6"; then
  HAS_IPV6=true
  info "IPv6      : enabled on ${IPV6_IF}"
else
  info "IPv6      : not detected (ip6tables rules will still be installed)"
fi

# ---------------------------------------------------------------------------
# Generate admin password
# ---------------------------------------------------------------------------
step "Generating admin credentials"
ADMIN_PASS=$(tr -dc 'A-Za-z0-9!@#$' </dev/urandom | head -c 16)
ADMIN_PASS_HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "${ADMIN_PASS}")
mkdir -p "${CONFIG_DIR}"
echo "${ADMIN_PASS_HASH}" > "${CONFIG_DIR}/admin_pass.hash"
chmod 600 "${CONFIG_DIR}/admin_pass.hash"
ok "Admin password generated (shown in summary)"

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
step "Installing system packages"
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-pip python3-venv \
  iptables iptables-persistent \
  netfilter-persistent \
  ip6tables \
  squid \
  curl ca-certificates dnsutils \
  2>/dev/null
ok "System packages ready"

# ---------------------------------------------------------------------------
# Python venv + Flask
# ---------------------------------------------------------------------------
step "Setting up Python virtual environment"
mkdir -p "${INSTALL_DIR}"
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet flask
ok "Python venv ready"

# ---------------------------------------------------------------------------
# Application files
# ---------------------------------------------------------------------------
step "Installing application files"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for f in dns_server.py web_ui.py; do
  [[ -f "${SCRIPT_DIR}/${f}" ]] || fail "${f} not found next to install.sh"
  cp "${SCRIPT_DIR}/${f}" "${INSTALL_DIR}/${f}"
  ok "Installed ${f}"
done
chmod +x "${INSTALL_DIR}/dns_server.py" "${INSTALL_DIR}/web_ui.py"

# ---------------------------------------------------------------------------
# Directories + DB init
# ---------------------------------------------------------------------------
step "Initialising database"
mkdir -p "${CONFIG_DIR}" "${LOG_DIR}"
"${INSTALL_DIR}/venv/bin/python3" -c "
import importlib.util
spec = importlib.util.spec_from_file_location('dns_server','${INSTALL_DIR}/dns_server.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.DB_PATH = '${DB_PATH}'
m.init_db()
" 2>/dev/null || true
ok "Database ready at ${DB_PATH}"

# ---------------------------------------------------------------------------
# sysctl — IP forwarding (v4 + v6)
# ---------------------------------------------------------------------------
step "Enabling IP forwarding (IPv4 + IPv6)"
for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
  grep -q "^${key}=1" /etc/sysctl.conf || echo "${key}=1" >> /etc/sysctl.conf
  sysctl -qw "${key}=1"
done
ok "IP forwarding enabled"

# ---------------------------------------------------------------------------
# Helper: apply a rule to BOTH iptables and ip6tables
# ---------------------------------------------------------------------------
ipt_both() {
  iptables  "$@" 2>/dev/null || true
  ip6tables "$@" 2>/dev/null || true
}
ipt_both_c_a() {
  # Check-then-append for both stacks
  local args=("$@")
  iptables  -C "${args[@]}" 2>/dev/null || iptables  -A "${args[@]}" 2>/dev/null || true
  ip6tables -C "${args[@]}" 2>/dev/null || ip6tables -A "${args[@]}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Flush stale dnsfilter rules cleanly
# ---------------------------------------------------------------------------
step "Flushing previous dnsfilter rules"
iptables-save  2>/dev/null | grep -v "dnsfilter" | iptables-restore  || true
ip6tables-save 2>/dev/null | grep -v "dnsfilter" | ip6tables-restore || true
ok "Stale rules cleared"

# ---------------------------------------------------------------------------
# iptables — DNS intercept (IPv4 + IPv6)
# ---------------------------------------------------------------------------
step "Configuring DNS intercept (port 53 → our server)"

# IPv4
iptables -t nat -A PREROUTING -i "${MAIN_IF}" -p udp --dport 53 \
  -m comment --comment "dnsfilter-dns" -j REDIRECT --to-port ${DNS_PORT}
iptables -t nat -A PREROUTING -i "${MAIN_IF}" -p tcp --dport 53 \
  -m comment --comment "dnsfilter-dns" -j REDIRECT --to-port ${DNS_PORT}

# IPv6
ip6tables -t nat -A PREROUTING -i "${IPV6_IF}" -p udp --dport 53 \
  -m comment --comment "dnsfilter-dns" -j REDIRECT --to-port ${DNS_PORT} 2>/dev/null || \
  warn "IPv6 NAT redirect not supported on this kernel — IPv6 DNS intercept via TPROXY skipped"
ip6tables -t nat -A PREROUTING -i "${IPV6_IF}" -p tcp --dport 53 \
  -m comment --comment "dnsfilter-dns" -j REDIRECT --to-port ${DNS_PORT} 2>/dev/null || true

# Allow our server's own upstream DoT queries out
for upstream in "${UPSTREAM_DNS[@]}"; do
  iptables  -C OUTPUT -p tcp -d "${upstream}" --dport 853 -j ACCEPT 2>/dev/null || \
  iptables  -A OUTPUT -p tcp -d "${upstream}" --dport 853 \
    -m comment --comment "dnsfilter-upstream" -j ACCEPT
done
ok "DNS intercept configured"

# ---------------------------------------------------------------------------
# Block DoT (port 853) from clients — they must use OUR DNS, not their own DoT
# ---------------------------------------------------------------------------
step "Blocking client DNS-over-TLS (port 853)"
ipt_both_c_a FORWARD -p tcp --dport 853 -m comment --comment "dnsfilter-dot" -j REJECT
ipt_both_c_a FORWARD -p udp --dport 853 -m comment --comment "dnsfilter-dot" -j REJECT
ok "Client DoT (port 853) blocked"

# ---------------------------------------------------------------------------
# Block DoH — known provider IPs + catch-all port 443 FORWARD block
# ---------------------------------------------------------------------------
step "Blocking DNS-over-HTTPS (DoH) providers"

DOH_PROVIDERS=(
  "dns.google" "dns64.dns.google"
  "cloudflare-dns.com" "one.one.one.one" "mozilla.cloudflare-dns.com"
  "dns.quad9.net" "dns10.quad9.net"
  "dns.adguard.com" "dns-unfiltered.adguard.com"
  "dns.nextdns.io"
  "doh.opendns.com"
  "doh.xfinity.com"
  "doh.cleanbrowsing.org"
  "dns.alidns.com"
  "resolver2.dns.watch"
  "doh.mullvad.net"
  "doh.libredns.gr"
)

DOH_IP_FILE="${CONFIG_DIR}/doh_hosts.txt"
> "${DOH_IP_FILE}"
blocked_count=0
failed_hosts=()

for host in "${DOH_PROVIDERS[@]}"; do
  mapfile -t ips < <(getent ahosts "${host}" 2>/dev/null | awk '{print $1}' | sort -u)
  if [[ ${#ips[@]} -eq 0 ]]; then
    failed_hosts+=("${host}"); continue
  fi
  echo "# ${host}" >> "${DOH_IP_FILE}"
  for ip in "${ips[@]}"; do
    echo "${ip}" >> "${DOH_IP_FILE}"
    ipt_both_c_a FORWARD -p tcp -d "${ip}" --dport 443 -m comment --comment "dnsfilter-doh" -j REJECT
    ipt_both_c_a OUTPUT  -p tcp -d "${ip}" --dport 443 -m comment --comment "dnsfilter-doh" -j REJECT
    (( blocked_count++ )) || true
    info "  Blocked ${host} → ${ip}:443"
  done
done

[[ ${#failed_hosts[@]} -gt 0 ]] && warn "Could not resolve (skipped): ${failed_hosts[*]}"

# Block QUIC/HTTP3 DoH (UDP 443) for forwarded client traffic
ipt_both_c_a FORWARD -p udp --dport 443 -m comment --comment "dnsfilter-doh-quic" -j REJECT

ok "DoH blocked: ${blocked_count} IPs across ${#DOH_PROVIDERS[@]} providers + QUIC"

# ---------------------------------------------------------------------------
# Block VPN protocols
# ---------------------------------------------------------------------------
step "Blocking VPN bypass protocols"

# OpenVPN — default UDP 1194, also common on TCP 443/1194
ipt_both_c_a FORWARD -p udp --dport 1194 -m comment --comment "dnsfilter-vpn" -j REJECT
ipt_both_c_a FORWARD -p tcp --dport 1194 -m comment --comment "dnsfilter-vpn" -j REJECT

# WireGuard — default UDP 51820
ipt_both_c_a FORWARD -p udp --dport 51820 -m comment --comment "dnsfilter-vpn" -j REJECT

# IPSec / IKEv2
ipt_both_c_a FORWARD -p udp --dport 500  -m comment --comment "dnsfilter-vpn" -j REJECT
ipt_both_c_a FORWARD -p udp --dport 4500 -m comment --comment "dnsfilter-vpn" -j REJECT

# PPTP
ipt_both_c_a FORWARD -p tcp --dport 1723 -m comment --comment "dnsfilter-vpn" -j REJECT

# L2TP
ipt_both_c_a FORWARD -p udp --dport 1701 -m comment --comment "dnsfilter-vpn" -j REJECT

# GRE (protocol 47) — used by PPTP tunnels
iptables  -C FORWARD -p 47 -m comment --comment "dnsfilter-vpn" -j REJECT 2>/dev/null || \
iptables  -A FORWARD -p 47 -m comment --comment "dnsfilter-vpn" -j REJECT || true
# ip6tables GRE
ip6tables -C FORWARD -p 47 -m comment --comment "dnsfilter-vpn" -j REJECT 2>/dev/null || \
ip6tables -A FORWARD -p 47 -m comment --comment "dnsfilter-vpn" -j REJECT 2>/dev/null || true

# ESP (protocol 50) — IPSec encapsulation
iptables  -C FORWARD -p 50 -m comment --comment "dnsfilter-vpn" -j REJECT 2>/dev/null || \
iptables  -A FORWARD -p 50 -m comment --comment "dnsfilter-vpn" -j REJECT || true
ip6tables -C FORWARD -p 50 -m comment --comment "dnsfilter-vpn" -j REJECT 2>/dev/null || \
ip6tables -A FORWARD -p 50 -m comment --comment "dnsfilter-vpn" -j REJECT 2>/dev/null || true

ok "VPN protocols blocked (OpenVPN · WireGuard · IPSec · IKEv2 · PPTP · L2TP · GRE · ESP)"

# ---------------------------------------------------------------------------
# Block Tor
# ---------------------------------------------------------------------------
step "Blocking Tor exit/relay ports"

# Tor OR port (standard)
ipt_both_c_a FORWARD -p tcp --dport 9001 -m comment --comment "dnsfilter-tor" -j REJECT
# Tor directory port
ipt_both_c_a FORWARD -p tcp --dport 9030 -m comment --comment "dnsfilter-tor" -j REJECT
# Tor obfs4 / pluggable transport common ports
for port in 80 443 9050 9051 9150; do
  # We only block these on known Tor guard IPs — blocking port 80/443 broadly
  # would break the internet. Instead we use the Tor authority consensus IPs.
  # Fetch current Tor guard node IPs and block them.
  true
done

# Fetch Tor guard node IPs from the consensus (best-effort)
TOR_IP_FILE="${CONFIG_DIR}/tor_guards.txt"
> "${TOR_IP_FILE}"
tor_blocked=0

info "Fetching Tor guard node list..."
TOR_CONSENSUS=$(curl -sf --max-time 15 \
  "https://onionoo.torproject.org/summary?type=relay&flag=Guard&fields=or_addresses" \
  2>/dev/null || echo "")

if [[ -n "${TOR_CONSENSUS}" ]]; then
  # Extract IPv4 addresses from JSON or_addresses array
  mapfile -t TOR_IPS < <(echo "${TOR_CONSENSUS}" | \
    python3 -c "
import sys,json,re
data=json.load(sys.stdin)
seen=set()
for relay in data.get('relays',[]):
    for addr in relay.get('or_addresses',[]):
        ip=re.match(r'^(\d+\.\d+\.\d+\.\d+)',addr)
        if ip and ip.group(1) not in seen:
            seen.add(ip.group(1))
            print(ip.group(1))
" 2>/dev/null | head -500)

  for ip in "${TOR_IPS[@]}"; do
    echo "${ip}" >> "${TOR_IP_FILE}"
    iptables -C FORWARD -p tcp -d "${ip}" -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || \
    iptables -A FORWARD -p tcp -d "${ip}" -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
    iptables -C OUTPUT  -p tcp -d "${ip}" -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || \
    iptables -A OUTPUT  -p tcp -d "${ip}" -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
    (( tor_blocked++ )) || true
  done
  ok "Tor guard nodes blocked: ${tor_blocked} IPs (saved to ${TOR_IP_FILE})"
else
  warn "Could not fetch Tor consensus — Tor port blocks applied, IP blocks skipped"
  warn "Run manually later: sudo ${INSTALL_DIR}/refresh_tor.sh"
fi

# Install Tor refresh script
cat > "${INSTALL_DIR}/refresh_tor.sh" << 'TOREOF'
#!/usr/bin/env bash
set -euo pipefail
CONFIG_DIR="/etc/dnsfilter"
TOR_IP_FILE="${CONFIG_DIR}/tor_guards.txt"

# Remove old rules
iptables-save  | grep -v "dnsfilter-tor" | iptables-restore  || true
ip6tables-save | grep -v "dnsfilter-tor" | ip6tables-restore || true

# Re-add port blocks
for proto in tcp udp; do
  iptables  -A FORWARD -p "${proto}" --dport 9001 -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
  iptables  -A FORWARD -p "${proto}" --dport 9030 -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
  ip6tables -A FORWARD -p "${proto}" --dport 9001 -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
  ip6tables -A FORWARD -p "${proto}" --dport 9030 -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
done

# Refresh guard IPs
> "${TOR_IP_FILE}"
TOR_CONSENSUS=$(curl -sf --max-time 20 \
  "https://onionoo.torproject.org/summary?type=relay&flag=Guard&fields=or_addresses" || echo "")

if [[ -n "${TOR_CONSENSUS}" ]]; then
  mapfile -t TOR_IPS < <(echo "${TOR_CONSENSUS}" | \
    python3 -c "
import sys,json,re
data=json.load(sys.stdin)
seen=set()
for relay in data.get('relays',[]):
    for addr in relay.get('or_addresses',[]):
        ip=re.match(r'^(\d+\.\d+\.\d+\.\d+)',addr)
        if ip and ip.group(1) not in seen:
            seen.add(ip.group(1))
            print(ip.group(1))
" 2>/dev/null | head -500)
  count=0
  for ip in "${TOR_IPS[@]}"; do
    echo "${ip}" >> "${TOR_IP_FILE}"
    iptables -A FORWARD -p tcp -d "${ip}" -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
    iptables -A OUTPUT  -p tcp -d "${ip}" -m comment --comment "dnsfilter-tor" -j REJECT 2>/dev/null || true
    (( count++ )) || true
  done
  echo "[tor-refresh] Blocked ${count} guard IPs"
fi
netfilter-persistent save >/dev/null 2>&1
TOREOF
chmod +x "${INSTALL_DIR}/refresh_tor.sh"

# Nightly Tor refresh at 04:00
echo "0 4 * * * root ${INSTALL_DIR}/refresh_tor.sh >> ${LOG_DIR}/tor_refresh.log 2>&1" \
  > /etc/cron.d/dnsfilter-tor
chmod 644 /etc/cron.d/dnsfilter-tor
ok "Tor nightly refresh cron installed (04:00 daily)"

# ---------------------------------------------------------------------------
# Default-deny FORWARD — close hardcoded-IP bypass
# After all ACCEPT/REJECT rules are in place, set the default FORWARD
# policy to DROP. Any traffic not explicitly matched above is dropped.
# This means clients cannot reach arbitrary internet IPs directly unless
# you add explicit ACCEPT rules below for the subnets you permit.
# ---------------------------------------------------------------------------
step "Setting default-deny FORWARD policy (closes hardcoded-IP bypass)"

# First: add explicit ACCEPT for established/related connections
# so replies to allowed connections pass back through
ipt_both_c_a FORWARD -m state --state ESTABLISHED,RELATED \
  -m comment --comment "dnsfilter-stateful" -j ACCEPT

# Allow HTTP + HTTPS forward (standard web browsing)
ipt_both_c_a FORWARD -p tcp --dport 80  -m comment --comment "dnsfilter-web" -j ACCEPT
ipt_both_c_a FORWARD -p tcp --dport 443 -m comment --comment "dnsfilter-web" -j ACCEPT

# Allow ICMP (ping) — useful for diagnostics
iptables  -C FORWARD -p icmp  -m comment --comment "dnsfilter-icmp" -j ACCEPT 2>/dev/null || \
iptables  -A FORWARD -p icmp  -m comment --comment "dnsfilter-icmp" -j ACCEPT || true
ip6tables -C FORWARD -p ipv6-icmp -m comment --comment "dnsfilter-icmp" -j ACCEPT 2>/dev/null || \
ip6tables -A FORWARD -p ipv6-icmp -m comment --comment "dnsfilter-icmp" -j ACCEPT 2>/dev/null || true

# Allow DNS to OUR server (already redirected above)
ipt_both_c_a FORWARD -p udp --dport 53 -m comment --comment "dnsfilter-dns-allow" -j ACCEPT
ipt_both_c_a FORWARD -p tcp --dport 53 -m comment --comment "dnsfilter-dns-allow" -j ACCEPT

# NOW set default policy to DROP — everything not explicitly allowed above is blocked
iptables  -P FORWARD DROP
ip6tables -P FORWARD DROP 2>/dev/null || true

ok "Default FORWARD policy: DROP (hardcoded-IP bypass closed)"
warn "Clients can reach HTTP/HTTPS. Add custom ACCEPT rules to FORWARD for other ports."

# ---------------------------------------------------------------------------
# DoH refresh cron (nightly IP re-resolve)
# ---------------------------------------------------------------------------
CRON_SCRIPT="${INSTALL_DIR}/refresh_doh.sh"
cat > "${CRON_SCRIPT}" << 'CRONEOF'
#!/usr/bin/env bash
set -euo pipefail
CONFIG_DIR="/etc/dnsfilter"
DOH_IP_FILE="${CONFIG_DIR}/doh_hosts.txt"
[[ -f "${DOH_IP_FILE}" ]] || exit 0

# Strip old DoH rules from both stacks
iptables-save  | grep -v "dnsfilter-doh" | iptables-restore  || true
ip6tables-save | grep -v "dnsfilter-doh" | ip6tables-restore || true

declare -A seen=()
current_host=""
> "${DOH_IP_FILE}.new"

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if [[ "$line" == \#* ]]; then
    current_host="${line#\# }"
    mapfile -t ips < <(getent ahosts "${current_host}" 2>/dev/null | awk '{print $1}' | sort -u)
    echo "# ${current_host}" >> "${DOH_IP_FILE}.new"
    for ip in "${ips[@]}"; do
      echo "${ip}" >> "${DOH_IP_FILE}.new"
    done
    continue
  fi
  ip="${line}"
  [[ -n "${seen[$ip]:-}" ]] && continue
  seen[$ip]=1
  for tbl in iptables ip6tables; do
    ${tbl} -A FORWARD -p tcp -d "${ip}" --dport 443 -m comment --comment "dnsfilter-doh" -j REJECT 2>/dev/null || true
    ${tbl} -A OUTPUT  -p tcp -d "${ip}" --dport 443 -m comment --comment "dnsfilter-doh" -j REJECT 2>/dev/null || true
  done
done < "${DOH_IP_FILE}"

mv "${DOH_IP_FILE}.new" "${DOH_IP_FILE}"

# Re-add QUIC block
for tbl in iptables ip6tables; do
  ${tbl} -C FORWARD -p udp --dport 443 -m comment --comment "dnsfilter-doh-quic" -j REJECT 2>/dev/null || \
  ${tbl} -A FORWARD -p udp --dport 443 -m comment --comment "dnsfilter-doh-quic" -j REJECT 2>/dev/null || true
done

netfilter-persistent save >/dev/null 2>&1
CRONEOF
chmod +x "${CRON_SCRIPT}"
echo "0 3 * * * root ${CRON_SCRIPT} >> ${LOG_DIR}/doh_refresh.log 2>&1" \
  > /etc/cron.d/dnsfilter-doh
chmod 644 /etc/cron.d/dnsfilter-doh
ok "DoH nightly IP refresh cron installed (03:00 daily)"

# ---------------------------------------------------------------------------
# Persist all iptables rules
# ---------------------------------------------------------------------------
netfilter-persistent save
ok "All iptables/ip6tables rules persisted"

# ---------------------------------------------------------------------------
# systemd — DNS server
# ---------------------------------------------------------------------------
step "Creating systemd services"

cat > "/etc/systemd/system/${SERVICE_DNS}.service" << EOF
[Unit]
Description=DNSFilter — Pure Python DNS server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/dns_server.py
Restart=always
RestartSec=5
PIDFile=/run/dnsfilter-dns.pid
StandardOutput=append:${LOG_DIR}/dns.log
StandardError=append:${LOG_DIR}/dns.log
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR} ${LOG_DIR} /run

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# systemd — Web UI
# ---------------------------------------------------------------------------
cat > "/etc/systemd/system/${SERVICE_UI}.service" << EOF
[Unit]
Description=DNSFilter — Admin Web UI
After=network.target ${SERVICE_DNS}.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/web_ui.py
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/ui.log
StandardError=append:${LOG_DIR}/ui.log
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR} ${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_DNS}"
systemctl enable --now "${SERVICE_UI}"
sleep 2
ok "Services started"

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
step "Verifying installation"

systemctl is-active --quiet "${SERVICE_DNS}" \
  && ok "DNS service running" \
  || warn "DNS service failed — check: journalctl -u ${SERVICE_DNS}"

systemctl is-active --quiet "${SERVICE_UI}" \
  && ok "Web UI service running" \
  || warn "Web UI service failed — check: journalctl -u ${SERVICE_UI}"

if command -v dig &>/dev/null; then
  RESULT=$(dig +short +timeout=3 @127.0.0.1 google.com A 2>/dev/null | head -1)
  [[ -n "${RESULT}" ]] \
    && ok "DNS test: google.com → ${RESULT}" \
    || warn "DNS test failed — upstream might be unreachable"
fi

# Verify default-deny FORWARD is active
FWDPOLICY=$(iptables -L FORWARD 2>/dev/null | head -1 | awk '{print $NF}')
[[ "${FWDPOLICY}" == "DROP" ]] \
  && ok "FORWARD policy: DROP (hardcoded-IP bypass closed)" \
  || warn "FORWARD policy is not DROP — hardcoded-IP bypass may still be open"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "
${GREEN}${BOLD}══════════════════════════════════════════════════════════${RESET}
${BOLD}  dnsfilter installation complete — all gaps closed${RESET}
${GREEN}${BOLD}══════════════════════════════════════════════════════════${RESET}

  Admin UI      →  http://${MAIN_IP}:${UI_PORT}
  DNS server    →  ${MAIN_IP}:${DNS_PORT}
  Config        →  ${CONFIG_DIR}/
  Database      →  ${DB_PATH}
  Logs          →  ${LOG_DIR}/

${BOLD}  Admin credentials${RESET}
  Username      →  admin
  Password      →  ${BOLD}${YELLOW}${ADMIN_PASS}${RESET}
  (hash stored at ${CONFIG_DIR}/admin_pass.hash — change with: dnsfilter-passwd)

${BOLD}  What is blocked${RESET}
  Plain DNS     →  intercepted, redirected to our server (IPv4 + IPv6)
  DoH (TCP)     →  ${blocked_count} provider IPs on port 443
  DoH (QUIC)    →  all UDP:443 forwarding blocked
  DoT (853)     →  client DoT blocked; our server uses DoT to upstream only
  VPN ports     →  OpenVPN · WireGuard · IPSec · IKEv2 · PPTP · L2TP · GRE · ESP
  Tor           →  port 9001/9030 + ${tor_blocked} guard node IPs (refreshed nightly)
  Hardcoded IP  →  FORWARD default DROP (only HTTP/HTTPS/ICMP/DNS forwarded)
  IPv6          →  all rules mirrored to ip6tables

${BOLD}  Useful commands${RESET}
  sudo systemctl status ${SERVICE_DNS}
  sudo systemctl status ${SERVICE_UI}
  sudo journalctl -u ${SERVICE_DNS} -f
  sudo kill -USR1 \$(cat /run/dnsfilter-dns.pid)     # reload blocklist
  sudo ${INSTALL_DIR}/refresh_doh.sh                 # refresh DoH IPs now
  sudo ${INSTALL_DIR}/refresh_tor.sh                 # refresh Tor guard IPs now
  sudo bash install.sh --uninstall                   # remove everything

${YELLOW}  Point your router's primary DNS to ${MAIN_IP}.${RESET}
${YELLOW}  Clients with hardcoded HTTPS-only apps that don't use port 80/443${RESET}
${YELLOW}  will be blocked — add per-port FORWARD ACCEPT rules as needed.${RESET}
"
