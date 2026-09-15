#!/usr/bin/env python3
"""
dnsfilter — Admin web UI.
Runs on port 8080. Manages blocklists, allowlist, and query logs
via a single-page app backed by Flask + SQLite.
"""

import sqlite3
import os
import re
import sys
import hashlib
import secrets
import urllib.request
import threading
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for

DB_PATH       = "/etc/dnsfilter/blocklist.db"
PASS_HASH_FILE= "/etc/dnsfilter/admin_pass.hash"
PORT          = 8080
HOST          = "0.0.0.0"
DNS_PID_FILE  = "/run/dnsfilter-dns.pid"
SESSION_HOURS = 8

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    stream=sys.stdout)
log = logging.getLogger("dnsfilter-ui")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # regenerates on restart; sessions invalidated

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _load_pass_hash() -> str:
    try:
        return open(PASS_HASH_FILE).read().strip()
    except FileNotFoundError:
        return hashlib.sha256(b"admin").hexdigest()

def _check_password(password: str) -> bool:
    expected = _load_pass_hash()
    got = hashlib.sha256(password.encode()).hexdigest()
    return secrets.compare_digest(expected, got)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="Unauthorized"), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def reload_dns():
    """Signal the DNS server to reload its blocklist cache."""
    try:
        pid = int(open(DNS_PID_FILE).read().strip())
        os.kill(pid, 10)  # SIGUSR1
    except Exception:
        pass

# ---------------------------------------------------------------------------
# HTML — single-page admin UI
# ---------------------------------------------------------------------------
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DNSFilter — Login</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root { --bg:#f5f5f5; --surface:#fff; --border:#ddd; --text:#1a1a1a;
          --accent:#2563eb; --danger:#dc2626; --radius:8px; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#111; --surface:#1e1e1e; --border:#333; --text:#e5e5e5; }
  }
  body { font-family: system-ui,sans-serif; background: var(--bg);
         color: var(--text); display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }
  .box { background: var(--surface); border: 1px solid var(--border);
         border-radius: 12px; padding: 36px 32px; width: 360px; }
  h1 { font-size: 18px; font-weight: 600; margin-bottom: 6px; }
  p  { font-size: 13px; color: #888; margin-bottom: 24px; }
  label { display: block; font-size: 13px; margin-bottom: 4px; }
  input { width: 100%; background: var(--bg); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 8px 12px; color: var(--text);
          font-size: 14px; margin-bottom: 14px; }
  input:focus { outline: none; border-color: var(--accent); }
  button { width: 100%; padding: 9px; background: var(--accent); color: #fff;
           border: none; border-radius: var(--radius); font-size: 14px;
           font-weight: 500; cursor: pointer; }
  .err { color: var(--danger); font-size: 13px; margin-bottom: 12px; }
</style>
</head>
<body>
<div class="box">
  <h1>DNSFilter</h1>
  <p>Admin login</p>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST" action="/login">
    <label>Password</label>
    <input type="password" name="password" autofocus autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>"""

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DNSFilter Admin</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #f5f5f5; --surface: #fff; --border: #ddd;
    --text: #1a1a1a; --muted: #666; --accent: #2563eb;
    --danger: #dc2626; --success: #16a34a; --warn: #d97706;
    --radius: 8px; --font: system-ui, sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#111; --surface:#1e1e1e; --border:#333;
            --text:#e5e5e5; --muted:#888; }
  }
  body { font-family: var(--font); background: var(--bg); color: var(--text);
         font-size: 14px; line-height: 1.6; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 0 20px; display: flex; align-items: center; gap: 16px; height: 52px; }
  header h1 { font-size: 16px; font-weight: 600; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 20px;
           background: var(--accent); color: #fff; }
  nav { display: flex; gap: 4px; margin-left: auto; }
  nav button { background: none; border: none; padding: 6px 12px;
               border-radius: var(--radius); cursor: pointer;
               color: var(--muted); font-size: 13px; }
  nav button.active, nav button:hover { background: var(--accent);
               color: #fff; }
  main { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 16px; margin-bottom: 16px; }
  .card h2 { font-size: 14px; font-weight: 600; margin-bottom: 12px; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
  input, select { background: var(--bg); border: 1px solid var(--border);
                  border-radius: var(--radius); padding: 6px 10px; color: var(--text);
                  font-size: 13px; outline: none; }
  input:focus, select:focus { border-color: var(--accent); }
  input[type=text] { flex: 1; min-width: 200px; }
  button.btn { padding: 6px 14px; border-radius: var(--radius); border: none;
               cursor: pointer; font-size: 13px; font-weight: 500; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-danger  { background: var(--danger); color: #fff; }
  .btn-success { background: var(--success); color: #fff; }
  .btn-muted   { background: var(--border); color: var(--text); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border);
       color: var(--muted); font-weight: 500; }
  td { padding: 6px 10px; border-bottom: 1px solid var(--border); }
  tr:last-child td { border: none; }
  .tag { display: inline-block; font-size: 11px; padding: 1px 7px;
         border-radius: 12px; font-weight: 500; }
  .tag-exact    { background: #dbeafe; color: #1e40af; }
  .tag-wildcard { background: #fef3c7; color: #92400e; }
  .tag-regex    { background: #ede9fe; color: #4c1d95; }
  .tag-allowed  { background: #dcfce7; color: #15803d; }
  .tag-blocked  { background: #fee2e2; color: #991b1b; }
  .tag-servfail { background: #fef3c7; color: #92400e; }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap: 12px; }
  .stat { text-align: center; padding: 12px; background: var(--bg);
          border-radius: var(--radius); border: 1px solid var(--border); }
  .stat .num { font-size: 28px; font-weight: 700; color: var(--accent); }
  .stat .lbl { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .tab { display: none; }
  .tab.active { display: block; }
  #toast { position: fixed; bottom: 24px; right: 24px; background: var(--text);
           color: var(--bg); padding: 10px 16px; border-radius: var(--radius);
           font-size: 13px; opacity: 0; transition: opacity .2s; z-index: 999; }
  #toast.show { opacity: 1; }
  .filter-row { display: flex; gap: 8px; margin-bottom: 10px; align-items: center; }
  .filter-row input { max-width: 260px; }
  #log-table-wrap { max-height: 420px; overflow-y: auto; }
  .mono { font-family: monospace; }
</style>
</head>
<body>
<header>
  <h1>DNSFilter</h1>
  <span class="badge" id="status-badge">Loading…</span>
  <nav>
    <button class="active" onclick="showTab('dashboard')">Dashboard</button>
    <button onclick="showTab('blocklist')">Blocklist</button>
    <button onclick="showTab('allowlist')">Allowlist</button>
    <button onclick="showTab('import')">Import</button>
    <button onclick="showTab('logs')">Query logs</button>
    <button onclick="showTab('settings')">Settings</button>
    <a href="/logout" style="margin-left:8px;padding:6px 12px;border-radius:8px;font-size:13px;color:var(--muted);text-decoration:none;border:1px solid var(--border)">Sign out</a>
  </nav>
</header>
<main>

<!-- Dashboard -->
<div class="tab active" id="tab-dashboard">
  <div class="card">
    <h2>Overview</h2>
    <div class="stat-grid" id="stats">
      <div class="stat"><div class="num" id="s-blocked">—</div><div class="lbl">Blocked rules</div></div>
      <div class="stat"><div class="num" id="s-queries">—</div><div class="lbl">Queries today</div></div>
      <div class="stat"><div class="num" id="s-pct">—</div><div class="lbl">Block rate</div></div>
      <div class="stat"><div class="num" id="s-allow">—</div><div class="lbl">Allowlist entries</div></div>
    </div>
  </div>
  <div class="card">
    <h2>Recent queries</h2>
    <div id="log-table-wrap">
      <table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Action</th><th>Upstream</th></tr></thead>
      <tbody id="recent-log"></tbody></table>
    </div>
  </div>
</div>

<!-- Blocklist -->
<div class="tab" id="tab-blocklist">
  <div class="card">
    <h2>Add rule</h2>
    <div class="row">
      <input type="text" id="bl-domain" placeholder="domain.com or regex pattern">
      <select id="bl-type">
        <option value="exact">Exact</option>
        <option value="wildcard">Wildcard (all subdomains)</option>
        <option value="regex">Regex</option>
      </select>
      <button class="btn btn-primary" onclick="addBlock()">Add</button>
    </div>
  </div>
  <div class="card">
    <h2>Current rules</h2>
    <div class="filter-row">
      <input type="text" id="bl-search" placeholder="Filter…" oninput="loadBlocklist()">
      <span id="bl-count" style="color:var(--muted);font-size:12px"></span>
    </div>
    <table><thead><tr><th>Domain</th><th>Type</th><th>Source</th><th>Added</th><th></th></tr></thead>
    <tbody id="bl-table"></tbody></table>
  </div>
</div>

<!-- Allowlist -->
<div class="tab" id="tab-allowlist">
  <div class="card">
    <h2>Add to allowlist</h2>
    <div class="row">
      <input type="text" id="al-domain" placeholder="domain.com">
      <button class="btn btn-success" onclick="addAllow()">Add</button>
    </div>
  </div>
  <div class="card">
    <h2>Allowed domains</h2>
    <table><thead><tr><th>Domain</th><th>Added</th><th></th></tr></thead>
    <tbody id="al-table"></tbody></table>
  </div>
</div>

<!-- Import -->
<div class="tab" id="tab-import">
  <div class="card">
    <h2>Import blocklist from URL</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:10px">
      Supports hosts-format files (e.g. StevenBlack, OISD) and plain domain lists.
    </p>
    <div class="row">
      <input type="text" id="imp-url" placeholder="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts">
      <button class="btn btn-primary" onclick="importURL()">Import</button>
    </div>
    <div id="imp-status" style="margin-top:8px;font-size:13px;color:var(--muted)"></div>
    <div style="margin-top:16px">
      <h2 style="margin-bottom:8px">Quick-add popular lists</h2>
      <div class="row" style="flex-direction:column;gap:6px">
        <button class="btn btn-muted" style="text-align:left" onclick="quickImport('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts','StevenBlack unified')">
          StevenBlack unified (ads + malware)
        </button>
        <button class="btn btn-muted" style="text-align:left" onclick="quickImport('https://big.oisd.nl/domainswild','OISD big')">
          OISD big blocklist
        </button>
        <button class="btn btn-muted" style="text-align:left" onclick="quickImport('https://raw.githubusercontent.com/nicehash/NiceHashQuickMiner/main/antivirus/blocks.txt','NiceHash malware')">
          NiceHash malware domains
        </button>
      </div>
    </div>
  </div>
</div>

<!-- Logs -->
<div class="tab" id="tab-logs">
  <div class="card">
    <h2>Query log</h2>
    <div class="filter-row">
      <input type="text" id="log-search" placeholder="Filter domain or client…" oninput="loadLogs()">
      <select id="log-action" onchange="loadLogs()">
        <option value="">All actions</option>
        <option value="ALLOWED">Allowed</option>
        <option value="BLOCKED">Blocked</option>
        <option value="SERVFAIL">Servfail</option>
      </select>
      <button class="btn btn-muted" onclick="loadLogs()">Refresh</button>
    </div>
    <div id="log-table-wrap2">
      <table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Action</th><th>Upstream</th><th></th></tr></thead>
      <tbody id="log-table"></tbody></table>
    </div>
  </div>
</div>

<!-- Settings -->
<div class="tab" id="tab-settings">
  <div class="card">
    <h2>Settings</h2>
    <table>
      <tr><td style="width:200px">Sinkhole IP</td>
          <td><input type="text" id="set-sinkhole" value="0.0.0.0"></td></tr>
      <tr><td>Log queries</td>
          <td><select id="set-log"><option value="1">Yes</option><option value="0">No</option></select></td></tr>
    </table>
    <div style="margin-top:12px">
      <button class="btn btn-primary" onclick="saveSettings()">Save settings</button>
      <button class="btn btn-muted" style="margin-left:8px" onclick="reloadDNS()">Reload DNS server</button>
    </div>
    <h2 style="margin-top:20px;margin-bottom:8px">Change password</h2>
    <div class="row">
      <input type="password" id="set-pw-new" placeholder="New password">
      <input type="password" id="set-pw-confirm" placeholder="Confirm password">
      <button class="btn btn-primary" onclick="changePassword()">Change</button>
    </div>
    <div id="pw-msg" style="font-size:13px;margin-top:6px"></div>
  </div>
</div>

</main>
<div id="toast"></div>

<script>
let currentTab = 'dashboard';

function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelectorAll('nav button').forEach((b,i) => {
    b.classList.toggle('active', b.textContent.toLowerCase().startsWith(name.split('-')[0]));
  });
  currentTab = name;
  if (name === 'dashboard') { loadDashboard(); }
  if (name === 'blocklist') { loadBlocklist(); }
  if (name === 'allowlist') { loadAllowlist(); }
  if (name === 'logs')      { loadLogs(); }
  if (name === 'settings')  { loadSettings(); }
}

function toast(msg, ok=true) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2800);
}

async function api(path, opts={}) {
  const r = await fetch('/api' + path, { headers: {'Content-Type':'application/json'}, ...opts });
  return r.json();
}

async function loadDashboard() {
  const [stats, recent] = await Promise.all([api('/stats'), api('/logs?limit=20')]);
  document.getElementById('s-blocked').textContent = stats.blocked_rules ?? '—';
  document.getElementById('s-queries').textContent = stats.queries_today ?? '—';
  document.getElementById('s-pct').textContent = stats.block_rate ? stats.block_rate + '%' : '—';
  document.getElementById('s-allow').textContent = stats.allowlist ?? '—';
  document.getElementById('status-badge').textContent = 'Running';
  const tb = document.getElementById('recent-log');
  tb.innerHTML = (recent.logs || []).map(logRow).join('');
}

async function loadBlocklist() {
  const q = document.getElementById('bl-search').value;
  const data = await api('/blocklist?q=' + encodeURIComponent(q));
  const tb = document.getElementById('bl-table');
  document.getElementById('bl-count').textContent = (data.total || 0) + ' rules';
  tb.innerHTML = (data.rules || []).map(r => `
    <tr>
      <td class="mono">${r.domain}</td>
      <td><span class="tag tag-${r.type}">${r.type}</span></td>
      <td style="color:var(--muted)">${r.source}</td>
      <td style="color:var(--muted)">${r.added.split('T')[0]}</td>
      <td><button class="btn btn-danger" style="padding:2px 8px;font-size:12px"
          onclick="deleteBlock(${r.id})">Remove</button></td>
    </tr>`).join('');
}

async function loadAllowlist() {
  const data = await api('/allowlist');
  const tb = document.getElementById('al-table');
  tb.innerHTML = (data.entries || []).map(r => `
    <tr>
      <td class="mono">${r.domain}</td>
      <td style="color:var(--muted)">${r.added.split('T')[0]}</td>
      <td><button class="btn btn-danger" style="padding:2px 8px;font-size:12px"
          onclick="deleteAllow(${r.id})">Remove</button></td>
    </tr>`).join('');
}

function logRow(r) {
  const action = r.action || 'ALLOWED';
  const cls = action === 'ALLOWED' ? 'tag-allowed' : action === 'BLOCKED' ? 'tag-blocked' : 'tag-servfail';
  return `<tr>
    <td style="color:var(--muted);white-space:nowrap">${r.ts}</td>
    <td>${r.client_ip}</td>
    <td class="mono">${r.domain}</td>
    <td><span class="tag" style="background:var(--border)">${r.qtype || ''}</span></td>
    <td><span class="tag ${cls}">${action}</span></td>
    <td style="color:var(--muted)">${r.upstream || ''}</td>
    <td>${action==='ALLOWED'
      ? `<button class="btn btn-danger" style="padding:1px 7px;font-size:11px" onclick="quickBlock('${r.domain}')">Block</button>`
      : `<button class="btn btn-success" style="padding:1px 7px;font-size:11px" onclick="quickAllow('${r.domain}')">Allow</button>`
    }</td>
  </tr>`;
}

async function loadLogs() {
  const q = document.getElementById('log-search').value;
  const action = document.getElementById('log-action').value;
  const data = await api(`/logs?limit=200&q=${encodeURIComponent(q)}&action=${action}`);
  const tb = document.getElementById('log-table');
  tb.innerHTML = (data.logs || []).map(logRow).join('');
}

async function loadSettings() {
  const data = await api('/settings');
  document.getElementById('set-sinkhole').value = data.sinkhole_ip || '0.0.0.0';
  document.getElementById('set-log').value = data.log_queries || '1';
}

async function addBlock() {
  const domain = document.getElementById('bl-domain').value.trim();
  const type = document.getElementById('bl-type').value;
  if (!domain) return;
  const r = await api('/blocklist', { method:'POST', body: JSON.stringify({domain, type, source:'manual'}) });
  if (r.ok) { toast('Rule added'); document.getElementById('bl-domain').value=''; loadBlocklist(); }
  else toast(r.error || 'Error', false);
}

async function deleteBlock(id) {
  const r = await api('/blocklist/' + id, { method:'DELETE' });
  if (r.ok) { toast('Removed'); loadBlocklist(); }
}

async function addAllow() {
  const domain = document.getElementById('al-domain').value.trim();
  if (!domain) return;
  const r = await api('/allowlist', { method:'POST', body: JSON.stringify({domain}) });
  if (r.ok) { toast('Added to allowlist'); document.getElementById('al-domain').value=''; loadAllowlist(); }
  else toast(r.error || 'Error', false);
}

async function deleteAllow(id) {
  const r = await api('/allowlist/' + id, { method:'DELETE' });
  if (r.ok) { toast('Removed'); loadAllowlist(); }
}

async function quickBlock(domain) {
  const r = await api('/blocklist', { method:'POST', body: JSON.stringify({domain, type:'exact', source:'manual'}) });
  toast(r.ok ? domain + ' blocked' : 'Error');
  loadLogs();
}

async function quickAllow(domain) {
  const r = await api('/allowlist', { method:'POST', body: JSON.stringify({domain}) });
  toast(r.ok ? domain + ' allowed' : 'Error');
  loadLogs();
}

async function importURL() {
  const url = document.getElementById('imp-url').value.trim();
  if (!url) return;
  document.getElementById('imp-status').textContent = 'Importing…';
  const r = await api('/import', { method:'POST', body: JSON.stringify({url}) });
  document.getElementById('imp-status').textContent = r.message || r.error || '';
  if (r.ok) toast(r.message);
}

async function quickImport(url, name) {
  document.getElementById('imp-url').value = url;
  showTab('import');
  document.getElementById('imp-status').textContent = `Importing ${name}…`;
  const r = await api('/import', { method:'POST', body: JSON.stringify({url}) });
  document.getElementById('imp-status').textContent = r.message || r.error || '';
}

async function saveSettings() {
  const r = await api('/settings', { method:'POST', body: JSON.stringify({
    sinkhole_ip: document.getElementById('set-sinkhole').value,
    log_queries: document.getElementById('set-log').value,
  }) });
  toast(r.ok ? 'Settings saved' : 'Error');
}

async function reloadDNS() {
  const r = await api('/reload', { method:'POST' });
  toast(r.ok ? 'DNS server reloaded' : 'Error');
}

async function changePassword() {
  const pw = document.getElementById('set-pw-new').value;
  const confirm = document.getElementById('set-pw-confirm').value;
  const msg = document.getElementById('pw-msg');
  if (!pw) { msg.textContent = 'Enter a password'; msg.style.color='var(--text-danger)'; return; }
  if (pw !== confirm) { msg.textContent = 'Passwords do not match'; msg.style.color='var(--text-danger)'; return; }
  if (pw.length < 8) { msg.textContent = 'Minimum 8 characters'; msg.style.color='var(--text-danger)'; return; }
  const r = await api('/change-password', { method:'POST', body: JSON.stringify({password: pw}) });
  msg.style.color = r.ok ? 'var(--text-success)' : 'var(--text-danger)';
  msg.textContent = r.ok ? 'Password changed' : (r.error || 'Error');
  if (r.ok) { document.getElementById('set-pw-new').value=''; document.getElementById('set-pw-confirm').value=''; }
}

loadDashboard();
setInterval(() => { if (currentTab === 'dashboard') loadDashboard(); }, 10000);
</script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        if _check_password(pw):
            session["authenticated"] = True
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=SESSION_HOURS)
            return redirect("/")
        error = "Incorrect password"
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_required
def index():
    return render_template_string(HTML)

@app.route("/api/stats")
@login_required
def stats():
    conn = get_db()
    blocked_rules = conn.execute("SELECT COUNT(*) FROM blocklist WHERE enabled=1").fetchone()[0]
    queries_today = conn.execute(
        "SELECT COUNT(*) FROM query_log WHERE date(ts)=date('now')"
    ).fetchone()[0]
    blocked_today = conn.execute(
        "SELECT COUNT(*) FROM query_log WHERE action='BLOCKED' AND date(ts)=date('now')"
    ).fetchone()[0]
    allowlist = conn.execute("SELECT COUNT(*) FROM allowlist").fetchone()[0]
    conn.close()
    block_rate = round(blocked_today / queries_today * 100, 1) if queries_today else 0
    return jsonify(blocked_rules=blocked_rules, queries_today=queries_today,
                   block_rate=block_rate, allowlist=allowlist)

@app.route("/api/blocklist", methods=["GET", "POST"])
@login_required
def blocklist():
    conn = get_db()
    if request.method == "GET":
        q = request.args.get("q", "")
        if q:
            rows = conn.execute(
                "SELECT * FROM blocklist WHERE domain LIKE ? ORDER BY added DESC LIMIT 500",
                (f"%{q}%",)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM blocklist ORDER BY added DESC LIMIT 500"
            ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM blocklist WHERE enabled=1").fetchone()[0]
        conn.close()
        return jsonify(rules=[dict(r) for r in rows], total=total)
    # POST — add rule
    data = request.get_json()
    domain = data.get("domain", "").strip().lower()
    type_  = data.get("type", "exact")
    source = data.get("source", "manual")
    if not domain:
        return jsonify(ok=False, error="domain required")
    try:
        conn.execute(
            "INSERT OR IGNORE INTO blocklist(domain,type,source) VALUES(?,?,?)",
            (domain, type_, source)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify(ok=False, error=str(e))
    conn.close()
    reload_dns()
    return jsonify(ok=True)

@app.route("/api/blocklist/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_block(rule_id):
    conn = get_db()
    conn.execute("DELETE FROM blocklist WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()
    reload_dns()
    return jsonify(ok=True)

@app.route("/api/allowlist", methods=["GET", "POST"])
@login_required
def allowlist():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM allowlist ORDER BY added DESC").fetchall()
        conn.close()
        return jsonify(entries=[dict(r) for r in rows])
    data = request.get_json()
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify(ok=False, error="domain required")
    try:
        conn.execute("INSERT OR IGNORE INTO allowlist(domain) VALUES(?)", (domain,))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify(ok=False, error=str(e))
    conn.close()
    reload_dns()
    return jsonify(ok=True)

@app.route("/api/allowlist/<int:entry_id>", methods=["DELETE"])
@login_required
def delete_allow(entry_id):
    conn = get_db()
    conn.execute("DELETE FROM allowlist WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()
    reload_dns()
    return jsonify(ok=True)

@app.route("/api/logs")
@login_required
def logs():
    conn = get_db()
    limit = int(request.args.get("limit", 100))
    q = request.args.get("q", "")
    action = request.args.get("action", "")
    clauses = []
    params = []
    if q:
        clauses.append("(domain LIKE ? OR client_ip LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if action:
        clauses.append("action=?")
        params.append(action)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM query_log {where} ORDER BY id DESC LIMIT ?",
        params + [limit]
    ).fetchall()
    conn.close()
    return jsonify(logs=[dict(r) for r in rows])

@app.route("/api/import", methods=["POST"])
@login_required
def import_list():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify(ok=False, error="url required")

    def do_import():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "dnsfilter/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return 0, str(e)

        added = 0
        conn = get_db()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # hosts format: 0.0.0.0 domain.com
            parts = line.split()
            if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1].lower()
            elif len(parts) == 1:
                domain = parts[0].lower()
            else:
                continue
            if domain in ("localhost", "0.0.0.0", "broadcasthost", "local"):
                continue
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO blocklist(domain,type,source) VALUES(?,?,?)",
                    (domain, "exact", url[:80])
                )
                added += 1
            except Exception:
                pass
        conn.commit()
        conn.close()
        return added, None

    added, err = do_import()
    if err:
        return jsonify(ok=False, error=err)
    reload_dns()
    return jsonify(ok=True, message=f"Imported {added} domains from list")

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def settings():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT key,value FROM settings").fetchall()
        conn.close()
        return jsonify(**{r["key"]: r["value"] for r in rows})
    data = request.get_json()
    for key, value in data.items():
        conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route("/api/reload", methods=["POST"])
@login_required
def reload_api():
    reload_dns()
    return jsonify(ok=True)

@app.route("/api/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json()
    pw = data.get("password", "").strip()
    if len(pw) < 8:
        return jsonify(ok=False, error="Minimum 8 characters")
    new_hash = hashlib.sha256(pw.encode()).hexdigest()
    try:
        with open(PASS_HASH_FILE, "w") as f:
            f.write(new_hash)
        os.chmod(PASS_HASH_FILE, 0o600)
    except Exception as e:
        return jsonify(ok=False, error=str(e))
    session.clear()   # force re-login after password change
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, threaded=True)
