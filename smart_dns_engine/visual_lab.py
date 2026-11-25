import http.server
import json
import socket
import struct
import time
import webbrowser

DNS_SERVER = ("127.0.0.1", 15353)

NODES = {
    "PC1": "127.0.0.11",
    "PC2": "127.0.0.12",
    "PC3": "127.0.0.13",
    "PC4": "127.0.0.14",
    "PC5": "127.0.0.15",
}

HTML_PAGE = """<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<title>Visual DNS Network Lab</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
  h2 { text-align: center; color: #38bdf8; }
  .topology { display: flex; justify-content: space-between; align-items: center; max-width: 1000px; margin: 30px auto; background: #1e293b; padding: 25px; border-radius: 16px; border: 1px solid #334155; }
  .col { display: flex; flex-direction: column; gap: 15px; }
  .node { background: #0f172a; border: 2px solid #38bdf8; border-radius: 10px; padding: 12px 18px; text-align: center; transition: 0.2s; min-width: 150px; }
  .node.active { border-color: #22c55e; box-shadow: 0 0 18px #22c55e88; transform: scale(1.04); }
  .node.error { border-color: #ef4444; box-shadow: 0 0 18px #ef444488; }
  .switch { border-color: #a855f7; padding: 30px 20px; }
  .server { border-color: #f59e0b; padding: 30px 20px; }
  .ip { font-size: 12px; color: #94a3b8; font-family: monospace; margin-top: 4px; }
  .controls { max-width: 1000px; margin: 0 auto 20px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
  select, input, button { padding: 10px 14px; border-radius: 8px; border: 1px solid #475569; background: #1e293b; color: white; font-family: inherit; }
  button { background: #0284c7; border: none; cursor: pointer; font-weight: bold; }
  button:hover { background: #0369a1; }
  button.burst { background: #7c3aed; }
  button.burst:hover { background: #6d28d9; }
  button.attack { background: #dc2626; }
  button.attack:hover { background: #b91c1c; }
  .logs { max-width: 1000px; margin: 0 auto; background: #020617; border-radius: 12px; padding: 15px; height: 240px; overflow-y: auto; font-family: monospace; font-size: 13px; border: 1px solid #334155; direction: ltr; }
  .ok { color: #4ade80; } .err { color: #f87171; }
</style>
</head>
<body>
  <h2>Visual Network Lab &amp; ML Security Gateway Tester</h2>
  <div class="controls">
    <select id="pc">
      <option value="PC1">PC1 (127.0.0.11)</option>
      <option value="PC2">PC2 (127.0.0.12)</option>
      <option value="PC3">PC3 (127.0.0.13)</option>
      <option value="PC4">PC4 (127.0.0.14)</option>
      <option value="PC5">PC5 (127.0.0.15)</option>
    </select>
    <input id="domain" value="google.com" placeholder="Domain name (e.g. github.com)">
    <button onclick="sendSingle()">Send Query</button>
    <button class="burst" onclick="sendAll()">Concurrent Queries (All 5 PCs)</button>
    <button class="attack" onclick="simulateAttack()">Simulate DGA/Flood Attack (PC1)</button>
  </div>

  <div class="topology">
    <div class="col">
      <div class="node" id="PC1">💻 PC1<div class="ip">127.0.0.11</div></div>
      <div class="node" id="PC2">💻 PC2<div class="ip">127.0.0.12</div></div>
      <div class="node" id="PC3">💻 PC3<div class="ip">127.0.0.13</div></div>
      <div class="node" id="PC4">💻 PC4<div class="ip">127.0.0.14</div></div>
      <div class="node" id="PC5">💻 PC5<div class="ip">127.0.0.15</div></div>
    </div>
    <div class="node switch" id="SW">🔀 Virtual Switch<div class="ip">127.0.0.0/8</div></div>
    <div class="node server" id="SRV">🛡️ ML Security Gateway + DNS<div class="ip">127.0.0.1:15353</div></div>
  </div>

  <div class="logs" id="logs"></div>

<script>
function flash(id, cls) {
  const el = document.getElementById(id);
  el.classList.add(cls);
  setTimeout(() => el.classList.remove(cls), 500);
}

async function query(pc, domain) {
  flash(pc, 'active'); flash('SW', 'active');
  const res = await fetch(`/query?pc=${pc}&domain=${encodeURIComponent(domain)}`);
  const data = await res.json();
  const logs = document.getElementById('logs');
  if (data.ok) {
    flash('SRV', 'active');
    logs.innerHTML = `<div class="ok">[OK] ${pc} (${data.ip}) -> ${domain} | Resolved: ${data.answer} | Latency: ${data.ms} ms</div>` + logs.innerHTML;
  } else {
    flash(pc, 'error'); flash('SRV', 'error');
    logs.innerHTML = `<div class="err">[BLOCKED/ERR] ${pc} (${data.ip}) -> ${domain} | ${data.error}</div>` + logs.innerHTML;
  }
}

function sendSingle() {
  query(document.getElementById('pc').value, document.getElementById('domain').value);
}

function sendAll() {
  const domains = ['google.com', 'github.com', 'cloudflare.com', 'python.org', 'wikipedia.org'];
  ['PC1','PC2','PC3','PC4','PC5'].forEach((pc, i) => query(pc, domains[i]));
}

async function simulateAttack() {
  for (let i = 0; i < 35; i++) {
    const randName = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 10) + ".com";
    query('PC1', randName);
    await new Promise(r => setTimeout(r, 120));
  }
}
</script>
</body>
</html>"""

def send_dns(client_ip, domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(8.0)
    sock.bind((client_ip, 0))
    header = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.strip().split(".")) + b"\x00"
    packet = header + qname + struct.pack("!HH", 1, 1)
    t0 = time.time()
    try:
        sock.sendto(packet, DNS_SERVER)
        resp, _ = sock.recvfrom(512)
        ms = round((time.time() - t0) * 1000, 1)
        rcode = resp[3] & 0x0F
        if rcode == 5:
            return {"ok": False, "ip": client_ip, "error": "REFUSED / QUARANTINED by ML SecurityGuard"}
        ancount = struct.unpack("!H", resp[6:8])[0]
        ip_ans = ".".join(map(str, resp[-4:])) if ancount > 0 else "NXDOMAIN"
        return {"ok": True, "ip": client_ip, "answer": ip_ans, "ms": ms}
    except Exception as e:
        return {"ok": False, "ip": client_ip, "error": str(e)}
    finally:
        sock.close()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif self.path.startswith("/query"):
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            pc = qs.get("pc", ["PC1"])[0]
            domain = qs.get("domain", ["google.com"])[0]
            result = send_dns(NODES[pc], domain)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    print("Dashboard running at http://127.0.0.1:8080")
    webbrowser.open("http://127.0.0.1:8080")
    server.serve_forever()