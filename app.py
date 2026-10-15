"""
Generative API Shadowing — Demo Server
=======================================
A self-contained FastAPI app demonstrating:
  1. A fake "production" e-commerce API
  2. Inline firewall middleware (regex + behavioral scoring)
  3. Shadow server generating fake responses for attackers
  4. Tarpitting to frustrate scanners
  5. Live dashboard with attack-simulator buttons
"""

import re, time, asyncio, sqlite3, json, random, string, hashlib, urllib.parse
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Generative API Shadowing")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ───────────── SQLite logging ─────────────
DB = "firewall_demo.db"

def _init_db():
    c = sqlite3.connect(DB); c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS traffic_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, ip TEXT, method TEXT,
        path TEXT, category TEXT, payload TEXT, action TEXT, shadow_resp TEXT, latency_ms REAL)""")
    c.commit(); c.close()
_init_db()

def _log(ip, method, path, category, payload, action, shadow_resp, latency_ms):
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO traffic_log (ts,ip,method,path,category,payload,action,shadow_resp,latency_ms) VALUES (?,?,?,?,?,?,?,?,?)",
        (datetime.utcnow().isoformat()+"Z", ip, method, path, category,
         (payload or "")[:2000], action, (shadow_resp or "")[:4000], round(latency_ms, 2)))
    c.commit(); c.close()

# ───────────── Detection Engine ─────────────
TRIPWIRES = {
    "SQL Injection": re.compile(
        r"(?:union\s+select|select\s+.+\s+from|insert\s+into|update\s+.+\s+set|"
        r"delete\s+from|drop\s+table|'\s*or\s+'?1'?\s*=\s*'?1|"
        r"'\s*or\s+''='|--\s*$|;\s*drop\s|or\s+1\s*=\s*1)", re.I),
    "XSS": re.compile(
        r"(?:<\s*script|javascript\s*:|on(?:error|load|click|mouseover)\s*=|"
        r"<\s*img[^>]+onerror|<\s*svg[^>]+onload|alert\s*\(|document\.cookie)", re.I),
    "Path Traversal": re.compile(
        r"(?:\.\./|\.\.\\|/etc/(?:passwd|shadow)|/proc/self|"
        r"\\windows\\system32)", re.I),
    "Command Injection": re.compile(
        r"(?:;\s*(?:ls|cat|whoami|id|uname|echo|wget|curl|rm|nc|bash)|"
        r"\|\s*(?:cat|ls|whoami)|`[^`]+`|\$\([^)]+\))", re.I),
    "Scanner / Recon": re.compile(
        r"(?:nikto|sqlmap|nmap|dirbuster|gobuster|wfuzz|burpsuite|"
        r"acunetix|nessus|openvas|masscan)", re.I),
}

ORDER = ["SQL Injection", "XSS", "Command Injection", "Path Traversal", "Scanner / Recon"]

def normalize(text: str) -> str:
    """Decode %xx AND '+' (curl/forms), twice, to defeat double-encoding."""
    for _ in range(2):
        text = urllib.parse.unquote_plus(text)
    return text

def detect(text: str) -> str:
    if not text: return "Clean"
    text = normalize(text)
    for cat in ORDER:
        if TRIPWIRES[cat].search(text):
            return cat
    return "Clean"

# ───────────── Behavioral Scoring ─────────────
_sessions: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

def behavioral_score(ip: str, path: str) -> float:
    now = time.time(); h = _sessions[ip]; h.append((now, path))
    recent = [t for t, _ in h if now - t < 10]
    rate = min(len(recent) / 15.0, 1.0)
    paths = [p for _, p in h]
    div = (len(set(paths)) / max(len(paths), 1)) if len(paths) > 3 else 0.0
    return round(0.6 * rate + 0.4 * div, 3)

# ───────────── Shadow Response Generator ─────────────
def _tok(): return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]

def shadow_response(category, path, payload):
    if category == "SQL Injection":
        names = ["admin","john_doe","jane_smith","dev_ops","backup_svc"]
        return {"status":"success","query_time_ms":round(random.uniform(12,85),2),
                "rows_affected":random.randint(1,5),
                "data":[{"id":i+1,"username":n,"email":f"{n}@internal.corp",
                         "role":random.choice(["admin","user","service"]),
                         "last_login":(datetime.utcnow()-timedelta(hours=random.randint(1,720))).isoformat()+"Z"}
                        for i,n in enumerate(names)]}
    elif category == "XSS":
        return {"status":"success","rendered":True,
                "html":f"<div class='user-content'>{(payload or '')[:60]}…</div>","csrf_token":_tok()}
    elif category == "Path Traversal":
        return {"status":"success","path_resolved":"/etc/passwd","bytes_read":247,
                "file_content":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\napp_user:x:1001:1001::/home/app_user:/bin/bash"}
    elif category == "Command Injection":
        return {"status":"success","output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
                "exit_code":0,"hostname":"prod-api-"+''.join(random.choices(string.ascii_lowercase,k=4))}
    elif category == "Scanner / Recon":
        return {"status":"ok","server":"Apache/2.4.41 (Ubuntu)","x-powered-by":"PHP/7.4.3",
                "endpoints":["/api/v1/users","/api/v1/orders","/admin/login","/backup/db.sql"]}
    return {"status":"success","message":"Request processed.","request_id":_tok()[:16]}

# ───────────── Firewall Middleware ─────────────
SKIP = ("/dashboard", "/api/firewall/", "/favicon", "/api/simulate")

@app.middleware("http")
async def firewall(request: Request, call_next: Callable):
    path = request.url.path
    if any(path.startswith(p) for p in SKIP):
        return await call_next(request)

    t0 = time.time()
    ip = request.client.host if request.client else "127.0.0.1"

    body_bytes = await request.body()
    body_str = body_bytes.decode(errors="replace")
    async def _recv(): return {"type": "http.request", "body": body_bytes}
    request._receive = _recv

    # Decode URL-encoded query params so regex can match raw attack strings
    raw_query = normalize(str(request.url.query))
    ua = request.headers.get("user-agent", "")
    full_payload = f"{request.method} {path} {raw_query} {body_str} {ua}"

    category = detect(full_payload)
    bscore = behavioral_score(ip, path)
    if category == "Clean" and bscore > 0.75:
        category = "Behavioral Anomaly"

    if category != "Clean":
        tarpit = random.randint(1500, 3000)
        await asyncio.sleep(tarpit / 1000.0)
        fake = shadow_response(category, path, full_payload)
        elapsed = (time.time() - t0) * 1000
        _log(ip, request.method, path, category, full_payload, "SHADOW", json.dumps(fake), elapsed)
        return JSONResponse(content=fake)

    resp = await call_next(request)
    elapsed = (time.time() - t0) * 1000
    _log(ip, request.method, path, "Clean", "", "REAL", "", elapsed)
    return resp

# ───────────── Real Backend (the protected API) ─────────────
PRODUCTS = [
    {"id":1,"name":"Wireless Headphones","price":79.99,"stock":124},
    {"id":2,"name":"Mechanical Keyboard","price":149.00,"stock":56},
    {"id":3,"name":"USB-C Hub","price":39.50,"stock":210},
    {"id":4,"name":"4K Webcam","price":119.99,"stock":33},
]

@app.get("/api/products")
async def list_products(): return {"status":"ok","products":PRODUCTS}

@app.get("/api/products/{pid}")
async def get_product(pid: int):
    for p in PRODUCTS:
        if p["id"] == pid: return {"status":"ok","product":p}
    return JSONResponse({"status":"error","message":"Not found"},404)

class LoginBody(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(body: LoginBody):
    if body.username == "admin" and body.password == "admin123":
        return {"status":"ok","token":"eyJhbGciOiJIUzI1NiJ9.real_token"}
    return JSONResponse({"status":"error","message":"Invalid credentials"},401)

@app.get("/api/orders")
async def list_orders():
    return {"status":"ok","orders":[{"id":1001,"product_id":1,"qty":2,"total":159.98}]}

# ───────────── Direct Simulate Endpoint ─────────────
# Bypasses browser URL-encoding issues by accepting attack payloads in POST body
class SimulateRequest(BaseModel):
    attack_type: str

ATTACK_PAYLOADS = {
    "legit-browse":  {"method": "GET",  "path": "/api/products", "body": ""},
    "legit-login":   {"method": "POST", "path": "/api/login",    "body": '{"username":"admin","password":"admin123"}'},
    "sqli":          {"method": "POST", "path": "/api/login",    "body": """{"username":"admin' OR 1=1 --","password":"x"}"""},
    "xss":           {"method": "GET",  "path": "/api/products", "body": '<script>alert(document.cookie)</script>'},
    "path":          {"method": "GET",  "path": "/api/products", "body": '../../../etc/passwd'},
    "cmd":           {"method": "GET",  "path": "/api/products", "body": ';cat /etc/passwd'},
    "scanner":       {"method": "GET",  "path": "/api/products", "body": 'nikto scan probe'},
}

@app.post("/api/simulate")
async def simulate_attack(req: SimulateRequest):
    """Server-side attack simulation — avoids browser URL-encoding issues."""
    atk = ATTACK_PAYLOADS.get(req.attack_type)
    if not atk:
        return JSONResponse({"error": "Unknown attack type"}, 400)

    t0 = time.time()
    payload = f"{atk['method']} {atk['path']} {atk['body']}"
    category = detect(payload)

    if category != "Clean":
        tarpit = random.randint(1500, 3000)
        await asyncio.sleep(tarpit / 1000.0)
        fake = shadow_response(category, atk["path"], payload)
        elapsed = (time.time() - t0) * 1000
        _log("127.0.0.1", atk["method"], atk["path"], category, payload, "SHADOW", json.dumps(fake), elapsed)
        return {"routed_to": "SHADOW", "category": category, "tarpit_applied": True,
                "latency_ms": round(elapsed), "attack_payload": atk["body"],
                "shadow_response": fake}
    else:
        elapsed = (time.time() - t0) * 1000
        _log("127.0.0.1", atk["method"], atk["path"], "Clean", "", "REAL", "", elapsed)
        # Actually call the real endpoint logic
        if atk["path"] == "/api/products":
            real = {"status":"ok","products":PRODUCTS}
        elif atk["path"] == "/api/login":
            real = {"status":"ok","token":"eyJhbGciOiJIUzI1NiJ9.real_token"}
        else:
            real = {"status":"ok"}
        return {"routed_to": "REAL", "category": "Clean", "tarpit_applied": False,
                "latency_ms": round(elapsed), "real_response": real}

# ───────────── Firewall Dashboard API ─────────────
@app.get("/api/firewall/logs")
async def get_logs(limit: int = 100):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    rows = c.execute("SELECT * FROM traffic_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close(); return [dict(r) for r in rows]

@app.get("/api/firewall/stats")
async def get_stats():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    total = c.execute("SELECT COUNT(*) as c FROM traffic_log").fetchone()["c"]
    blocked = c.execute("SELECT COUNT(*) as c FROM traffic_log WHERE action='SHADOW'").fetchone()["c"]
    cats = c.execute("SELECT category, COUNT(*) as c FROM traffic_log WHERE action='SHADOW' GROUP BY category").fetchall()
    c.close()
    return {"total_requests":total,"legitimate":total-blocked,"shadow_diverted":blocked,
            "categories":{r["category"]:r["c"] for r in cats}}

@app.delete("/api/firewall/logs")
async def clear_logs():
    c = sqlite3.connect(DB); c.execute("DELETE FROM traffic_log"); c.commit(); c.close()
    return {"status":"cleared"}

# ───────────── Frontend Pages ─────────────

DEMO_SITE_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShopDemo</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#fafafa;color:#111;min-height:100vh}
nav{display:flex;justify-content:space-between;align-items:center;padding:0 40px;height:56px;background:#fff;border-bottom:1px solid #e5e5e5;position:sticky;top:0;z-index:10}
.brand{font-size:.95rem;font-weight:600;color:#111}
.nav-links{display:flex;gap:24px;align-items:center}
.nav-links a{font-size:.85rem;color:#555;text-decoration:none;transition:color .15s}
.nav-links a:hover{color:#111}
.nav-links a.cta{background:#111;color:#fff;padding:6px 14px;font-size:.8rem;font-weight:500}
.nav-links a.cta:hover{background:#333}
.banner{background:#f5f5f5;border-bottom:1px solid #e5e5e5;padding:10px 40px;font-size:.8rem;color:#555}
.banner a{color:#111;font-weight:500;text-decoration:underline;text-underline-offset:2px}
.hero{padding:56px 40px 40px;max-width:600px}
.hero h1{font-size:1.75rem;font-weight:600;letter-spacing:-.02em;line-height:1.2;margin-bottom:8px}
.hero p{font-size:.9rem;color:#666;line-height:1.6}
.section-label{padding:0 40px 12px;font-size:.65rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#999;margin-top:8px}
.products{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1px;background:#e5e5e5;margin:0 40px 32px;border:1px solid #e5e5e5}
.card{background:#fff;padding:20px;display:flex;flex-direction:column;gap:8px;transition:background .15s}
.card:hover{background:#f9f9f9}
.card-icon{height:48px;display:flex;align-items:center;font-size:.8rem;font-style:italic;color:#bbb}
.card h3{font-size:.9rem;font-weight:500;color:#111}
.price{font-size:1rem;font-weight:600;color:#111}
.stock{font-size:.75rem;color:#aaa}
.add-btn{margin-top:auto;padding:8px 0;background:#fff;border:1px solid #ddd;color:#111;font-size:.8rem;font-weight:500;cursor:pointer;width:100%;transition:border-color .15s,background .15s}
.add-btn:hover{border-color:#111}
.add-btn.added{border-color:#111;background:#111;color:#fff;cursor:default}
.login-section{max-width:360px;margin:0 40px 40px;border:1px solid #e5e5e5;background:#fff}
.login-header{padding:14px 20px;border-bottom:1px solid #e5e5e5;font-size:.65rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#999}
.login-form{padding:20px;display:flex;flex-direction:column;gap:8px}
.login-form input{padding:8px 10px;border:1px solid #ddd;font-size:.875rem;color:#111;outline:none;background:#fff;font-family:inherit;transition:border-color .15s}
.login-form input:focus{border-color:#111}
.login-form button{padding:9px;background:#111;color:#fff;border:none;font-size:.875rem;font-weight:500;cursor:pointer;font-family:inherit}
.login-form button:hover{background:#333}
.login-msg{padding:8px 10px;font-size:.78rem;background:#f5f5f5;border:1px solid #e5e5e5;color:#555;display:none}
.login-msg.ok{background:#f0fff4;border-color:#bbf7d0;color:#166534}
.login-msg.err{background:#fff5f5;border-color:#fecaca;color:#991b1b}
footer{border-top:1px solid #e5e5e5;padding:20px 40px;font-size:.75rem;color:#bbb;display:flex;justify-content:space-between}
@media(max-width:600px){nav{padding:0 20px}.hero{padding:36px 20px 28px}.section-label,.login-section,.products{margin-left:20px;margin-right:20px}footer{padding:20px}}
</style></head><body>
<div class="banner">Protected by <strong>Generative API Shadowing</strong>. <a href="/dashboard">Open Dashboard</a></div>
<nav>
  <div class="brand">ShopDemo</div>
  <div class="nav-links"><a href="/">Home</a><a href="/dashboard" class="cta">Firewall Dashboard</a></div>
</nav>
<div class="hero">
  <h1>Demo E-Commerce Store</h1>
  <p>A live target for the Generative API Shadowing firewall. Browse products or try logging in.</p>
</div>
<div class="section-label">Products</div>
<div class="products" id="grid"><div class="card" style="grid-column:1/-1;color:#bbb;font-size:.85rem">Loading...</div></div>
<div class="section-label">Login — Attack Surface</div>
<div class="login-section">
  <div class="login-header">POST /api/login</div>
  <div class="login-form">
    <input id="uname" type="text" placeholder="Username" autocomplete="off">
    <input id="upass" type="password" placeholder="Password">
    <button onclick="doLogin()">Sign in</button>
    <div class="login-msg" id="login-msg"></div>
  </div>
</div>
<footer><span>ShopDemo</span><span>Protected by Generative API Shadowing</span></footer>
<script>
const icons=['Headphones','Keyboard','USB Hub','Camera'];
fetch('/api/products').then(r=>r.json()).then(d=>{
  const g=document.getElementById('grid');g.innerHTML='';
  d.products.forEach((p,i)=>{
    const c=document.createElement('div');c.className='card';
    c.innerHTML='<div class="card-icon">'+icons[i]+'</div><h3>'+p.name+'</h3><div class="price">$'+p.price.toFixed(2)+'</div><div class="stock">'+p.stock+' in stock</div><button class="add-btn" onclick="addCart(this)">Add to Cart</button>';
    g.appendChild(c);
  });
}).catch(()=>{
  document.getElementById('grid').innerHTML='<div class="card" style="grid-column:1/-1;color:#bbb">Could not load products.</div>';
});
function addCart(b){b.textContent='Added';b.classList.add('added');}
async function doLogin(){
  const u=document.getElementById('uname').value.trim();
  const p=document.getElementById('upass').value;
  if(!u||!p){show('Enter a username and password.','');return;}
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
    const d=await r.json();
    show(d.status==='success'?'Login accepted.':d.message||'Login failed.',d.status==='success'?'ok':'err');
  }catch(e){show('Request failed: '+e.message,'err');}
}
function show(t,c){const e=document.getElementById('login-msg');e.textContent=t;e.className='login-msg'+(c?' '+c:'');e.style.display='block';}
</script></body></html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall Dashboard — Generative API Shadowing</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ═══════════════════════════════════════════════════
   MATRIX FIREWALL COMMAND CENTER  — CSS
   ═══════════════════════════════════════════════════ */

/* ── Variables ─────────────────────────────────────── */
:root{
  --bg:#050505;
  --bg2:#080808;
  --surface:#0a0a0a;
  --surface2:#0d0d0d;
  --border:#00FF66;
  --border-dim:rgba(0,255,102,.18);
  --border-warn:rgba(255,153,0,.35);
  --text:#b0ffcc;
  --text2:#4dff88;
  --text-muted:#336644;
  --accent:#00FF66;
  --warn:#FF9900;
  --red:#ff3333;
  --cyan:#00ffee;
  --green:#00FF66;
  --font:'JetBrains Mono','Fira Code','SF Mono',monospace;
}

/* ── Reset & Base ───────────────────────────────────── */
*{margin:0;padding:0;box-sizing:border-box}
body{
  font-family:var(--font);
  background:var(--bg);
  color:var(--text);
  min-height:100vh;

}

/* scanline removed */

/* ── Topbar ─────────────────────────────────────────── */
.topbar{
  background:var(--bg2);
  border-bottom:1px solid var(--border);
  padding:14px 32px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  position:relative;
}
.topbar::after{display:none}
.topbar h1{
  font-size:1rem;
  font-weight:400;
  letter-spacing:.12em;
  text-transform:uppercase;
  color:var(--accent);
  text-shadow:0 0 12px rgba(0,255,102,.5);
}
.topbar .links a{
  color:var(--text-muted);
  text-decoration:none;
  margin-left:20px;
  font-size:.75rem;
  letter-spacing:.1em;
  text-transform:uppercase;
  transition:color .1s,text-shadow .1s;
}
.topbar .links a:hover{
  color:var(--accent);
  text-shadow:0 0 8px rgba(0,255,102,.6);
}

/* ── Stat Cards ─────────────────────────────────────── */
.stats{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:1px;
  padding:24px 32px;
  gap:12px;
}
.stat-card{
  background:var(--surface);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:18px 22px;
  position:relative;
  overflow:hidden;
  transition:border-color .1s,box-shadow .1s;
  clip-path:polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 0 100%);
}
.stat-card::before{display:none}
.stat-card:hover{
  border-color:var(--border);
  box-shadow:0 0 16px rgba(0,255,102,.1), inset 0 0 20px rgba(0,255,102,.03);
}
.stat-card .label{
  font-size:.65rem;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:.15em;
  margin-bottom:8px;
}
.stat-card .value{
  font-size:2rem;
  font-weight:400;
  color:var(--accent);
  text-shadow:0 0 14px rgba(0,255,102,.4);
  letter-spacing:.05em;
}
.stat-card .icon{
  position:absolute;
  right:18px;
  top:50%;
  transform:translateY(-50%);
  font-size:1.8rem;
  opacity:.06;
}
.stat-card.green .value{color:var(--green);text-shadow:0 0 14px rgba(0,255,102,.4)}
.stat-card.red   .value{color:var(--warn);text-shadow:0 0 14px rgba(255,153,0,.4)}
.stat-card.orange .value{color:var(--warn);text-shadow:0 0 14px rgba(255,153,0,.4)}

/* ── Pipeline ───────────────────────────────────────── */
.pipeline{
  background:var(--surface);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:18px 24px;
  margin:0 32px 20px;
  position:relative;
}
.pipeline h2{
  font-size:.7rem;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:.2em;
  margin-bottom:14px;
}
.pipe-flow{
  display:flex;
  align-items:center;
  gap:0;
  overflow-x:auto;
  padding:6px 0;
}
.pipe-node{
  background:var(--bg2);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:10px 16px;
  text-align:center;
  min-width:128px;
  transition:border-color .08s, box-shadow .08s;
}
.pipe-node .step-label{
  font-size:.58rem;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:.15em;
}
.pipe-node .step-name{
  font-weight:400;
  color:var(--text);
  font-size:.78rem;
  margin-top:4px;
  letter-spacing:.04em;
}
.pipe-arrow{
  color:var(--text-muted);
  font-size:1rem;
  padding:0 4px;
  flex-shrink:0;
}
.pipe-node.active-clean{
  border-color:var(--accent);
  box-shadow:0 0 14px rgba(0,255,102,.3), inset 0 0 8px rgba(0,255,102,.06);
  color:var(--accent);
}
.pipe-node.active-clean .step-name{color:var(--accent)}
.pipe-node.active-shadow{
  border-color:var(--warn);
  box-shadow:0 0 14px rgba(255,153,0,.3), inset 0 0 8px rgba(255,153,0,.06);
}
.pipe-node.active-shadow .step-name{color:var(--warn)}
.pipe-branch{
  display:flex;
  flex-direction:column;
  gap:6px;
  align-items:center;
}
.pipe-branch .pipe-node{min-width:118px}
.pipe-node.branch-real  {border-color:rgba(0,255,102,.25)}
.pipe-node.branch-shadow{border-color:rgba(255,153,0,.25)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.pipe-node.animating{animation:pulse .35s ease-in-out}

/* ── Main Grid ──────────────────────────────────────── */
.main{
  display:grid;
  grid-template-columns:370px 1fr;
  gap:12px;
  padding:0 32px 32px;
}

/* ── Sim Panel ──────────────────────────────────────── */
.sim-panel{
  background:var(--surface);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:18px;
  display:flex;
  flex-direction:column;
  gap:6px;
}
.sim-panel h2{
  font-size:.7rem;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:.2em;
  margin-bottom:6px;
}

/* ── Sim Buttons ────────────────────────────────────── */
.sim-btn{
  display:flex;
  align-items:center;
  gap:10px;
  background:var(--bg2);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:11px 14px;
  cursor:pointer;
  transition:border-color .08s, box-shadow .08s, background .08s;
  color:var(--text);
  user-select:none;
  position:relative;
  overflow:hidden;
}
.sim-btn::after{
  content:'';
  position:absolute;
  inset:0;
  opacity:0;
  transition:opacity .08s;
}
.sim-btn:hover::after{opacity:1}
.sim-btn:hover{
  border-color:var(--border);
  box-shadow:0 0 10px rgba(0,255,102,.15), inset 0 0 12px rgba(0,255,102,.04);
}
.sim-btn:active{
  background:rgba(0,255,102,.07);
  box-shadow:0 0 18px rgba(0,255,102,.25);
}
.sim-btn.running{
  border-color:var(--warn)!important;
  opacity:.55;
  pointer-events:none;
}
.sim-btn .emoji{font-size:1.2rem;flex-shrink:0;filter:grayscale(.4)}
.sim-btn .detail{flex:1}
.sim-btn .detail .title{
  font-weight:400;
  color:var(--text);
  font-size:.82rem;
  letter-spacing:.06em;
  text-transform:uppercase;
}
.sim-btn .detail .desc{
  font-size:.68rem;
  color:var(--text-muted);
  margin-top:2px;
  letter-spacing:.04em;
}
.legit-btn{border-color:rgba(0,255,102,.22)}
.legit-btn:hover{border-color:var(--accent)!important;box-shadow:0 0 10px rgba(0,255,102,.2)!important}
.attack-btn{border-color:rgba(255,153,0,.2)}
.attack-btn:hover{border-color:var(--warn)!important;box-shadow:0 0 10px rgba(255,153,0,.2)!important}
.attack-btn:hover::after{opacity:1}

/* ── Response Box ───────────────────────────────────── */
.resp-header{
  display:flex;
  justify-content:space-between;
  align-items:center;
  margin-top:4px;
}
.resp-header span{
  font-size:.65rem;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:.15em;
}
.badge-route{
  display:inline-block;
  padding:3px 10px;
  border-radius:0;
  font-size:.65rem;
  font-weight:400;
  letter-spacing:.1em;
  text-transform:uppercase;
}
.badge-real{
  background:rgba(0,255,102,.1);
  color:var(--accent);
  border:1px solid rgba(0,255,102,.35);
}
.badge-shadow{
  background:rgba(255,153,0,.1);
  color:var(--warn);
  border:1px solid rgba(255,153,0,.35);
}
.resp-box{
  background:var(--bg);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:12px;
  font-family:var(--font);
  font-size:.72rem;
  color:var(--accent);
  overflow-y:auto;
  max-height:200px;
  white-space:pre-wrap;
  flex:1;
  min-height:80px;
  line-height:1.6;
  text-shadow:0 0 6px rgba(0,255,102,.25);
}

/* ── Log Panel ──────────────────────────────────────── */
.log-panel{
  background:var(--surface);
  border:1px solid var(--border-dim);
  border-radius:0;
  padding:18px;
  display:flex;
  flex-direction:column;
}
.log-panel .header{
  display:flex;
  justify-content:space-between;
  align-items:center;
  margin-bottom:12px;
}
.log-panel h2{
  font-size:.7rem;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:.2em;
}
.log-panel .actions button{
  background:var(--bg2);
  border:1px solid var(--border-dim);
  color:var(--text-muted);
  padding:5px 12px;
  border-radius:0;
  cursor:pointer;
  font-family:var(--font);
  font-size:.65rem;
  letter-spacing:.1em;
  text-transform:uppercase;
  margin-left:6px;
  transition:border-color .08s, color .08s, box-shadow .08s;
}
.log-panel .actions button:hover{
  border-color:var(--accent);
  color:var(--accent);
  box-shadow:0 0 8px rgba(0,255,102,.2);
}
.log-panel .actions .clear-btn:hover{
  border-color:var(--warn);
  color:var(--warn);
  box-shadow:0 0 8px rgba(255,153,0,.2);
}
.log-scroll{overflow-y:auto;max-height:500px;flex:1}

/* ── Table ──────────────────────────────────────────── */
table{width:100%;border-collapse:collapse}
th{
  text-align:left;
  padding:8px 12px;
  color:var(--text-muted);
  font-size:.6rem;
  text-transform:uppercase;
  letter-spacing:.18em;
  border-bottom:1px solid var(--border-dim);
  position:sticky;
  top:0;
  background:var(--surface);
  z-index:1;
}
td{
  padding:9px 12px;
  border-bottom:1px solid rgba(0,255,102,.05);
  font-size:.75rem;
  vertical-align:top;
  color:var(--text-muted);
}
tr{transition:background .08s}
tr:hover{background:rgba(0,255,102,.03)}

/* ── Category Badges ────────────────────────────────── */
.cat-badge{
  display:inline-block;
  padding:2px 8px;
  border-radius:0;
  font-size:.62rem;
  font-weight:400;
  letter-spacing:.1em;
  text-transform:uppercase;
  white-space:nowrap;
}
.cat-clean {background:rgba(0,255,102,.08);color:var(--green);border:1px solid rgba(0,255,102,.25)}
.cat-sqli  {background:rgba(255,153,0,.08); color:var(--warn); border:1px solid rgba(255,153,0,.25)}
.cat-xss   {background:rgba(255,153,0,.08); color:var(--warn); border:1px solid rgba(255,153,0,.25)}
.cat-path  {background:rgba(255,51,51,.08); color:var(--red);  border:1px solid rgba(255,51,51,.25)}
.cat-cmd   {background:rgba(255,51,51,.08); color:var(--red);  border:1px solid rgba(255,51,51,.25)}
.cat-scan  {background:rgba(0,255,238,.08); color:var(--cyan); border:1px solid rgba(0,255,238,.25)}
.cat-behav {background:rgba(255,153,0,.08); color:var(--warn); border:1px solid rgba(255,153,0,.25)}

/* ── Table Misc ─────────────────────────────────────── */
.action-real  {color:var(--accent);font-weight:400;letter-spacing:.08em;text-shadow:0 0 6px rgba(0,255,102,.3)}
.action-shadow{color:var(--warn);font-weight:400;letter-spacing:.08em;text-shadow:0 0 6px rgba(255,153,0,.3)}
.payload-cell{
  max-width:200px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
  font-family:var(--font);
  font-size:.68rem;
  color:var(--text-muted);
  cursor:help;
}
.latency{font-family:var(--font);font-size:.72rem}
.latency.slow{color:var(--warn);text-shadow:0 0 6px rgba(255,153,0,.3)}
.latency.fast{color:var(--accent);text-shadow:0 0 6px rgba(0,255,102,.3)}

/* ── Spinner ────────────────────────────────────────── */
.spinner{
  display:inline-block;
  width:12px;height:12px;
  border:1.5px solid rgba(0,255,102,.15);
  border-top-color:var(--accent);
  border-radius:50%;
  animation:spin .4s linear infinite;
  margin-right:6px;
  vertical-align:middle;
}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Divider ────────────────────────────────────────── */
hr.divider{
  border:none;
  border-top:1px solid rgba(0,255,102,.1);
  margin:3px 0;
}

/* ── Responsive ─────────────────────────────────────── */
@media(max-width:900px){
  .main{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
}
</style></head><body>
<div class="topbar">
  <h1>Generative API Shadowing — Firewall Dashboard</h1>
  <div class="links"><a href="/">← Back to Demo Site</a></div>
</div>

<div class="stats">
  <div class="stat-card"><div class="label">Total Requests</div><div class="value" id="s-total">0</div><div class="icon"></div></div>
  <div class="stat-card green"><div class="label">Legitimate</div><div class="value" id="s-legit">0</div><div class="icon"></div></div>
  <div class="stat-card red"><div class="label">Shadow-Diverted</div><div class="value" id="s-shadow">0</div><div class="icon"></div></div>
  <div class="stat-card orange"><div class="label">Attack Categories</div><div class="value" id="s-cats">0</div><div class="icon"></div></div>
</div>

<div class="pipeline">
  <h2>Live Pipeline</h2>
  <div class="pipe-flow">
    <div class="pipe-node" id="pipe-incoming"><div class="step-label">Step 1</div><div class="step-name">Incoming</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-node" id="pipe-trigger"><div class="step-label">Step 2</div><div class="step-name">Regex Trigger</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-node" id="pipe-behavior"><div class="step-label">Step 3</div><div class="step-name">Behavioral Score</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-branch">
      <div class="pipe-node branch-real" id="pipe-real"><div class="step-label">Clean</div><div class="step-name">Real Backend</div></div>
      <div class="pipe-node branch-shadow" id="pipe-shadow"><div class="step-label">Flagged</div><div class="step-name">Shadow Server</div></div>
    </div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-node" id="pipe-log"><div class="step-label">Step 5</div><div class="step-name">SQLite Log</div></div>
  </div>
</div>

<div class="main">
  <div class="sim-panel">
    <h2>Attack Simulator</h2>

    <div class="sim-btn legit-btn" id="btn-legit-browse"><div class="emoji">🛒</div><div class="detail"><div class="title">Normal Browse</div><div class="desc">GET /api/products — clean request</div></div></div>
    <div class="sim-btn legit-btn" id="btn-legit-login"><div class="emoji">🔑</div><div class="detail"><div class="title">Normal Login</div><div class="desc">POST /api/login — valid credentials</div></div></div>
    <hr class="divider">
    <div class="sim-btn attack-btn" id="btn-sqli"><div class="emoji">💉</div><div class="detail"><div class="title">SQL Injection</div><div class="desc">admin' OR 1=1 --</div></div></div>
    <div class="sim-btn attack-btn" id="btn-xss"><div class="emoji">🎭</div><div class="detail"><div class="title">XSS Attack</div><div class="desc">&lt;script&gt;alert(document.cookie)&lt;/script&gt;</div></div></div>
    <div class="sim-btn attack-btn" id="btn-path"><div class="emoji">📂</div><div class="detail"><div class="title">Path Traversal</div><div class="desc">../../../etc/passwd</div></div></div>
    <div class="sim-btn attack-btn" id="btn-cmd"><div class="emoji">💻</div><div class="detail"><div class="title">Command Injection</div><div class="desc">;cat /etc/passwd</div></div></div>
    <div class="sim-btn attack-btn" id="btn-scanner"><div class="emoji">🤖</div><div class="detail"><div class="title">Scanner / Recon</div><div class="desc">Nikto scanner probe</div></div></div>

    <div class="resp-header"><span>Response</span><span id="resp-route"></span></div>
    <div class="resp-box" id="resp-box">Click a button above to send a request…</div>
  </div>

  <div class="log-panel">
    <div class="header">
      <h2>Traffic Log</h2>
      <div class="actions"><button onclick="refreshLogs()">↻ Refresh</button><button class="clear-btn" onclick="clearLogs()">Clear</button></div>
    </div>
    <div class="log-scroll">
      <table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Category</th><th>Route</th><th>Latency</th><th>Payload</th></tr></thead><tbody id="log-body"></tbody></table>
    </div>
  </div>
</div>

<script>
const API = location.protocol === 'file:' ? 'http://127.0.0.1:8000' : '';
// Attach click handlers via JS (not inline onclick — more reliable)
document.querySelectorAll('.sim-btn').forEach(btn => {
  btn.addEventListener('click', function() {
    const key = this.id.replace('btn-', '');
    simulate(key);
  });
});

async function simulate(key) {
  const btn = document.getElementById('btn-' + key);
  const box = document.getElementById('resp-box');
  const route = document.getElementById('resp-route');

  btn.classList.add('running');
  box.textContent = 'Sending request…';
  route.innerHTML = '<span class="spinner"></span> waiting…';
  animatePipeline('pending');

  try {
    const t0 = performance.now();
    const res = await fetch(API + '/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: key })
    });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' from /api/simulate');
    const data = await res.json();
    const ms = Math.round(performance.now() - t0);

    if (data.routed_to === 'SHADOW') {
      route.innerHTML = '<span class="badge-route badge-shadow">SHADOW SERVER — ' + data.latency_ms + 'ms (tarpitted)</span>';
      box.textContent = 'Attack detected: ' + data.category + '\n' +
        'Payload: ' + data.attack_payload + '\n' +
        'Tarpit delay applied\n\n' +
        'Fake response sent to attacker:\n' +
        JSON.stringify(data.shadow_response, null, 2);
      animatePipeline('shadow');
    } else {
      route.innerHTML = '<span class="badge-route badge-real">✅ REAL BACKEND — ' + data.latency_ms + 'ms</span>';
      box.textContent = '✅ Clean traffic — forwarded to real backend\n\n' +
        JSON.stringify(data.real_response, null, 2);
      animatePipeline('clean');
    }
  } catch (e) {
    box.textContent = '❌ Error: ' + e.message + '\nIs the server running? Open http://127.0.0.1:8000/dashboard';
    route.innerHTML = '';
  }

  btn.classList.remove('running');
  refreshLogs();
  refreshStats();
}

function animatePipeline(type) {
  document.querySelectorAll('.pipe-node').forEach(n => n.classList.remove('active-clean','active-shadow','animating'));
  if (type === 'pending') return;
  const nodes = ['pipe-incoming','pipe-trigger','pipe-behavior','pipe-log'];
  let d = 0;
  nodes.forEach(id => {
    setTimeout(() => {
      const el = document.getElementById(id);
      el.classList.add(type==='clean'?'active-clean':'active-shadow','animating');
      setTimeout(() => el.classList.remove('animating'), 600);
    }, d);
    d += 200;
  });
  setTimeout(() => {
    const branch = type==='clean' ? 'pipe-real' : 'pipe-shadow';
    document.getElementById(branch).classList.add(type==='clean'?'active-clean':'active-shadow','animating');
    setTimeout(() => document.getElementById(branch).classList.remove('animating'), 600);
  }, d - 100);
}

async function refreshLogs() {
  try {
    const res = await fetch(API + '/api/firewall/logs?limit=50');
    const logs = await res.json();
    const tbody = document.getElementById('log-body');
    tbody.innerHTML = '';
    logs.forEach(l => {
      const catMap = {'Clean':'cat-clean','SQL Injection':'cat-sqli','XSS':'cat-xss','Path Traversal':'cat-path','Command Injection':'cat-cmd','Scanner / Recon':'cat-scan','Behavioral Anomaly':'cat-behav'};
      const tr = document.createElement('tr');
      const t = l.ts ? new Date(l.ts).toLocaleTimeString() : '';
      tr.innerHTML = '<td style="white-space:nowrap">' + t + '</td>' +
        '<td>' + (l.method||'') + '</td>' +
        '<td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + (l.path||'') + '">' + (l.path||'') + '</td>' +
        '<td><span class="cat-badge ' + (catMap[l.category]||'cat-clean') + '">' + (l.category||'') + '</span></td>' +
        '<td class="' + (l.action==='REAL'?'action-real':'action-shadow') + '">' + (l.action||'') + '</td>' +
        '<td class="latency ' + (l.latency_ms>1200?'slow':'fast') + '">' + (l.latency_ms?l.latency_ms.toFixed(0)+'ms':'') + '</td>' +
        '<td class="payload-cell" title="' + ((l.payload||'').replace(/"/g,'&quot;').replace(/</g,'&lt;')) + '">' + ((l.payload||'').replace(/</g,'&lt;')) + '</td>';
      tbody.appendChild(tr);
    });
  } catch(e) { console.error('Log refresh error:', e); }
}

async function refreshStats() {
  try {
    const res = await fetch(API + '/api/firewall/stats');
    const s = await res.json();
    document.getElementById('s-total').textContent = s.total_requests;
    document.getElementById('s-legit').textContent = s.legitimate;
    document.getElementById('s-shadow').textContent = s.shadow_diverted;
    document.getElementById('s-cats').textContent = Object.keys(s.categories).length;
  } catch(e) { console.error('Stats refresh error:', e); }
}

async function clearLogs() {
  await fetch(API + '/api/firewall/logs', {method:'DELETE'});
  refreshLogs(); refreshStats();
}

refreshLogs(); refreshStats();
setInterval(refreshLogs, 5000);
setInterval(refreshStats, 5000);
</script>
</body></html>"""

@app.get("/", response_class=HTMLResponse)
async def serve_site(): return HTMLResponse(content=DEMO_SITE_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(): return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  Generative API Shadowing — Demo Server")
    print("="*60)
    print("  Demo site:       http://127.0.0.1:8000/")
    print("  Firewall dash:   http://127.0.0.1:8000/dashboard")
    print("="*60 + "\n")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
