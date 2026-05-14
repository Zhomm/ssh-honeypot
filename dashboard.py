"""
Honeypot Dashboard
==================
Flask web dashboard for visualising honeypot data.

Start:
  pip3 install flask
  python3 dashboard.py

Access via SSH tunnel:
  On your PC: ssh -L 5000:localhost:5000 user@<SERVER_IP>
  Browser:    http://localhost:5000

Flask binds to 127.0.0.1 only — never exposed on the public internet.
"""

from flask import Flask, jsonify, render_template_string
import sqlite3

app = Flask(__name__)
DB_FILE = "honey.db"


def get_db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    con = get_db()
    row = con.execute("""
        SELECT
            COUNT(DISTINCT ip)                                  as unique_ips,
            COUNT(CASE WHEN type='auth_attempt' THEN 1 END)     as attempts,
            COUNT(CASE WHEN type='connection'   THEN 1 END)     as connections,
            MIN(timestamp)                                      as first,
            MAX(timestamp)                                      as last
        FROM logs
    """).fetchone()
    scanners = con.execute("""
        SELECT COUNT(DISTINCT ip) FROM logs
        WHERE type='connection'
        AND ip NOT IN (SELECT DISTINCT ip FROM logs WHERE type='auth_attempt')
    """).fetchone()[0]
    con.close()
    return jsonify({
        "unique_ips":   row["unique_ips"],
        "attempts":     row["attempts"],
        "connections":  row["connections"],
        "scanners":     scanners,
        "first":        row["first"],
        "last":         row["last"],
    })


@app.route("/api/timeline")
def api_timeline():
    con = get_db()
    rows = con.execute("""
        SELECT substr(timestamp, 1, 13) || ':00Z' as hour, COUNT(*) n
        FROM logs WHERE type='auth_attempt'
        GROUP BY hour ORDER BY hour
    """).fetchall()
    con.close()
    return jsonify([{"hour": r["hour"], "n": r["n"]} for r in rows])


@app.route("/api/usernames")
def api_usernames():
    con = get_db()
    rows = con.execute("""
        SELECT username, COUNT(*) n FROM logs
        WHERE type='auth_attempt' AND username IS NOT NULL
        GROUP BY username ORDER BY n DESC LIMIT 12
    """).fetchall()
    con.close()
    return jsonify([{"username": r["username"], "n": r["n"]} for r in rows])


@app.route("/api/passwords")
def api_passwords():
    con = get_db()
    rows = con.execute("""
        SELECT password, COUNT(*) n FROM logs
        WHERE type='auth_attempt' AND password IS NOT NULL
        GROUP BY password ORDER BY n DESC LIMIT 12
    """).fetchall()
    con.close()
    return jsonify([{"password": r["password"], "n": r["n"]} for r in rows])


@app.route("/api/geo")
def api_geo():
    con = get_db()
    rows = con.execute("""
        SELECT g.country, g.country_code,
               COUNT(DISTINCT l.ip)                              as unique_ips,
               COUNT(CASE WHEN l.type='auth_attempt' THEN 1 END) as attempts
        FROM logs l JOIN geo g ON l.ip = g.ip
        WHERE g.country IS NOT NULL
        GROUP BY g.country ORDER BY attempts DESC LIMIT 15
    """).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/attackers")
def api_attackers():
    con = get_db()
    rows = con.execute("""
        SELECT l.ip,
               g.country_code, g.country, g.org,
               COUNT(CASE WHEN l.type='auth_attempt' THEN 1 END) as attempts,
               COUNT(CASE WHEN l.type='connection'   THEN 1 END) as connections,
               MIN(l.timestamp) as first,
               MAX(l.timestamp) as last,
               MAX(l.client_version) as client
        FROM logs l LEFT JOIN geo g ON l.ip = g.ip
        GROUP BY l.ip ORDER BY attempts DESC LIMIT 50
    """).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/clients")
def api_clients():
    con = get_db()
    rows = con.execute("""
        SELECT client_version, COUNT(DISTINCT ip) n FROM logs
        WHERE type='auth_attempt' AND client_version IS NOT NULL
        GROUP BY client_version ORDER BY n DESC
    """).fetchall()
    con.close()
    return jsonify([{"client": r["client_version"], "n": r["n"]} for r in rows])


# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSH Honeypot Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

  :root {
    --bg:    #080c10;
    --bg2:   #0d1117;
    --bg3:   #161b22;
    --border:#21262d;
    --green: #39d353;
    --cyan:  #58e6d9;
    --red:   #f85149;
    --yellow:#e3b341;
    --muted: #8b949e;
    --text:  #c9d1d9;
    --bright:#f0f6fc;
    --mono:  'Share Tech Mono', monospace;
    --ui:    'Rajdhani', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--ui); font-size: 15px; }
  body::before {
    content:''; position:fixed; inset:0; pointer-events:none; z-index:1000;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  }
  header {
    border-bottom: 1px solid var(--border); padding: 18px 28px;
    display:flex; align-items:center; justify-content:space-between;
    background: var(--bg2);
  }
  .logo { font-family: var(--mono); font-size:18px; color:var(--green); letter-spacing:2px; }
  .logo span { color:var(--muted); }
  #live { display:flex; align-items:center; gap:8px; font-family:var(--mono); font-size:12px; color:var(--muted); }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--green); animation:pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1;box-shadow:0 0 4px var(--green)} 50%{opacity:.4;box-shadow:none} }
  main { padding:24px 28px; max-width:1400px; margin:0 auto; }
  .period { font-family:var(--mono); font-size:11px; color:var(--muted); text-align:right; margin-bottom:20px; }

  .stat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }
  .stat-card { background:var(--bg2); border:1px solid var(--border); border-radius:6px; padding:18px 20px; position:relative; overflow:hidden; }
  .stat-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; }
  .stat-card.red::before    { background:var(--red); }
  .stat-card.green::before  { background:var(--green); }
  .stat-card.cyan::before   { background:var(--cyan); }
  .stat-card.yellow::before { background:var(--yellow); }
  .stat-label { font-family:var(--mono); font-size:11px; color:var(--muted); letter-spacing:1px; text-transform:uppercase; margin-bottom:8px; }
  .stat-value { font-family:var(--mono); font-size:32px; font-weight:700; line-height:1; }
  .stat-card.red    .stat-value { color:var(--red); }
  .stat-card.green  .stat-value { color:var(--green); }
  .stat-card.cyan   .stat-value { color:var(--cyan); }
  .stat-card.yellow .stat-value { color:var(--yellow); }
  .stat-sub { font-size:12px; color:var(--muted); margin-top:6px; font-family:var(--mono); }

  .chart-grid   { display:grid; grid-template-columns:2fr 1fr; gap:12px; margin-bottom:12px; }
  .chart-grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:12px; }
  .panel { background:var(--bg2); border:1px solid var(--border); border-radius:6px; padding:18px 20px; }
  .panel-title { font-family:var(--mono); font-size:11px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; margin-bottom:16px; display:flex; align-items:center; gap:8px; }
  .panel-title::before { content:'▸'; color:var(--green); }
  canvas { max-height:220px; }

  .table-wrap { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-family:var(--mono); font-size:13px; }
  th { text-align:left; padding:8px 12px; color:var(--muted); font-size:11px; letter-spacing:1px; text-transform:uppercase; border-bottom:1px solid var(--border); font-weight:400; }
  td { padding:9px 12px; border-bottom:1px solid rgba(33,38,45,.6); vertical-align:middle; }
  tr:hover td { background:rgba(255,255,255,.02); }
  td.ip { color:var(--cyan); }
  td.n  { color:var(--yellow); font-weight:700; }
  td.org { color:var(--muted); font-size:12px; }

  .badge { display:inline-block; padding:2px 7px; border-radius:3px; font-size:11px; font-family:var(--mono); }
  .b-dict   { background:rgba(248,81,73,.15);  color:var(--red);    border:1px solid rgba(248,81,73,.3); }
  .b-simple { background:rgba(227,179,65,.15); color:var(--yellow); border:1px solid rgba(227,179,65,.3); }
  .b-scan   { background:rgba(88,230,217,.1);  color:var(--cyan);   border:1px solid rgba(88,230,217,.2); }
  .b-target { background:rgba(248,81,73,.25);  color:#ff9492;       border:1px solid rgba(248,81,73,.5); }

  .bar-row { display:flex; align-items:center; gap:10px; margin-bottom:8px; font-family:var(--mono); font-size:13px; }
  .bar-label { width:130px; flex-shrink:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .bar-track { flex:1; height:6px; background:var(--bg3); border-radius:3px; overflow:hidden; }
  .bar-fill  { height:100%; border-radius:3px; transition:width .8s ease; }
  .bar-n     { width:40px; text-align:right; color:var(--muted); font-size:12px; flex-shrink:0; }

  @media(max-width:900px){
    .stat-grid{grid-template-columns:repeat(2,1fr)}
    .chart-grid,.chart-grid-3{grid-template-columns:1fr}
  }
</style>
</head>
<body>
<header>
  <div class="logo">[<span>//</span>] SSH_HONEYPOT <span>›</span> DASHBOARD</div>
  <div id="live"><div class="dot"></div><span id="live-text">loading...</span></div>
</header>
<main>
  <div class="period" id="period"></div>

  <div class="stat-grid">
    <div class="stat-card red">
      <div class="stat-label">LOGIN ATTEMPTS</div>
      <div class="stat-value" id="s-att">—</div>
      <div class="stat-sub">auth_attempt events</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">UNIQUE IPs</div>
      <div class="stat-value" id="s-ip">—</div>
      <div class="stat-sub">distinct attackers</div>
    </div>
    <div class="stat-card cyan">
      <div class="stat-label">CONNECTIONS</div>
      <div class="stat-value" id="s-con">—</div>
      <div class="stat-sub">total TCP connections</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-label">PURE SCANNERS</div>
      <div class="stat-value" id="s-scan">—</div>
      <div class="stat-sub">no credentials tried</div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="panel-title">ACTIVITY OVER TIME</div>
      <canvas id="c-timeline"></canvas>
    </div>
    <div class="panel">
      <div class="panel-title">TOP COUNTRIES</div>
      <canvas id="c-geo"></canvas>
    </div>
  </div>

  <div class="chart-grid-3">
    <div class="panel">
      <div class="panel-title">TOP USERNAMES</div>
      <div id="bars-user"></div>
    </div>
    <div class="panel">
      <div class="panel-title">TOP PASSWORDS</div>
      <div id="bars-pass"></div>
    </div>
    <div class="panel">
      <div class="panel-title">SSH CLIENTS</div>
      <canvas id="c-clients"></canvas>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">ATTACKER DETAILS</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th><th>IP</th><th>Country</th><th>Organisation</th>
            <th>Attempts</th><th>Type</th><th>Client</th><th>Last seen</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>
</main>

<script>
const OPTS = {
  color:'#8b949e', borderColor:'#21262d',
  plugins:{legend:{display:false}},
  scales:{
    x:{ticks:{color:'#8b949e',font:{family:'Share Tech Mono',size:11}},grid:{color:'#161b22'}},
    y:{ticks:{color:'#8b949e',font:{family:'Share Tech Mono',size:11}},grid:{color:'#161b22'}}
  }
};
const GEO_COLORS = ['#39d353','#58e6d9','#e3b341','#f85149','#a371f7',
                    '#fd8c73','#79c0ff','#56d364','#ffa657','#d2a8ff'];

function fmt(iso){ return iso ? iso.replace('T',' ').replace('Z','').substring(0,16) : '—'; }

function classify(attempts, client){
  if(!attempts) return ['SCANNER','b-scan'];
  if(client && (client.includes('Go')||client.includes('libssh')))
    return attempts>10 ? ['BOT_DICT','b-dict'] : ['BOT_SIMPLE','b-simple'];
  if(attempts>10) return ['BOT_DICT','b-dict'];
  if(attempts<=3) return ['TARGETED','b-target'];
  return ['BOT_SIMPLE','b-simple'];
}

function bars(id, data, labelKey, valueKey, color){
  const el = document.getElementById(id);
  if(!data.length){ el.innerHTML='<div style="color:#8b949e;font-size:12px">no data</div>'; return; }
  const max = data[0][valueKey];
  el.innerHTML = data.map(d=>`
    <div class="bar-row">
      <div class="bar-label" title="${d[labelKey]}">${d[labelKey]}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(d[valueKey]/max*100).toFixed(1)}%;background:${color}"></div></div>
      <div class="bar-n">${d[valueKey]}</div>
    </div>`).join('');
}

async function load(){
  const [stats,timeline,usernames,passwords,geo,attackers,clients] = await Promise.all([
    fetch('/api/stats').then(r=>r.json()),
    fetch('/api/timeline').then(r=>r.json()),
    fetch('/api/usernames').then(r=>r.json()),
    fetch('/api/passwords').then(r=>r.json()),
    fetch('/api/geo').then(r=>r.json()),
    fetch('/api/attackers').then(r=>r.json()),
    fetch('/api/clients').then(r=>r.json()),
  ]);

  document.getElementById('s-att').textContent  = stats.attempts.toLocaleString();
  document.getElementById('s-ip').textContent   = stats.unique_ips;
  document.getElementById('s-con').textContent  = stats.connections.toLocaleString();
  document.getElementById('s-scan').textContent = stats.scanners;

  const period = `${fmt(stats.first)}  →  ${fmt(stats.last)} UTC`;
  document.getElementById('live-text').textContent = period;
  document.getElementById('period').textContent    = 'Period: ' + period;

  new Chart(document.getElementById('c-timeline'),{
    type:'bar',
    data:{
      labels: timeline.map(d=>d.hour.substring(11,16)),
      datasets:[{data:timeline.map(d=>d.n),backgroundColor:'#39d35388',borderColor:'#39d353',borderWidth:1,borderRadius:2}]
    },
    options:{...OPTS,responsive:true,maintainAspectRatio:true}
  });

  new Chart(document.getElementById('c-geo'),{
    type:'doughnut',
    data:{
      labels: geo.map(d=>d.country_code||d.country),
      datasets:[{data:geo.map(d=>d.attempts||d.unique_ips),backgroundColor:GEO_COLORS,borderColor:'#0d1117',borderWidth:2}]
    },
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:{display:true,position:'right',labels:{color:'#8b949e',font:{family:'Share Tech Mono',size:11},boxWidth:12}}}}
  });

  bars('bars-user', usernames, 'username', 'n', '#58e6d9');
  bars('bars-pass', passwords, 'password', 'n', '#e3b341');

  new Chart(document.getElementById('c-clients'),{
    type:'bar',
    data:{
      labels: clients.map(d=>d.client.replace('SSH-2.0-','')),
      datasets:[{data:clients.map(d=>d.n),backgroundColor:['#f85149','#e3b341','#39d353','#58e6d9','#a371f7'],borderRadius:3}]
    },
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#8b949e',font:{family:'Share Tech Mono',size:11}},grid:{color:'#161b22'}},
              y:{ticks:{color:'#c9d1d9',font:{family:'Share Tech Mono',size:11}},grid:{display:false}}}}
  });

  document.getElementById('tbody').innerHTML = attackers.map((a,i)=>{
    const [type,badge] = classify(a.attempts, a.client);
    return `<tr>
      <td style="color:#8b949e;font-size:11px">${String(i+1).padStart(2,'0')}</td>
      <td class="ip">${a.ip}</td>
      <td>${a.country_code||'??'} ${a.country||''}</td>
      <td class="org">${a.org||'—'}</td>
      <td class="n">${a.attempts.toLocaleString()}</td>
      <td><span class="badge ${badge}">${type}</span></td>
      <td class="org">${(a.client||'—').replace('SSH-2.0-','')}</td>
      <td class="org">${fmt(a.last)}</td>
    </tr>`;
  }).join('');

  setTimeout(load, 30000);
}

load();
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


if __name__ == "__main__":
    import os
    if not os.path.exists(DB_FILE):
        print(f"[!] Database not found: {DB_FILE}")
        print(f"[!] Run db.py first to create it.")
        exit(1)
    print("[*] Dashboard running at http://127.0.0.1:5000")
    print("[*] Access via tunnel: ssh -L 5000:localhost:5000 user@<SERVER_IP>")
    app.run(host="127.0.0.1", port=5000, debug=False)
