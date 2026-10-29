import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
ROWS=[
 {"src":"1.14.191.118","action":"allowed","category":"Trojan Activity Detected (Low Confidence)","count":"1","dest_ip":"10.1.1.5","dest_port":"1433","attack_name":"HackTool.SQLScan.TDS.ServerRequest","firstTime":"2026-09-30T15:15:08","lastTime":"2026-09-30T15:15:08"},
 {"src":"1.14.199.249","action":"allowed","category":"Trojan Activity Detected (Low Confidence)","count":"2","dest_ip":"10.1.1.5, 10.1.1.9","dest_port":"1433","attack_name":"HackTool.SQLScan.TDS.ServerRequest","firstTime":"2026-10-01T04:35:56","lastTime":"2026-10-01T05:39:21"},
 {"src":"1.165.215.231","action":"allowed","category":"Trojan Activity Detected (Low Confidence)","count":"18","dest_ip":"10.1.2.7","dest_port":"9034,9035","attack_name":"Exploit.CVE-2021-35394.UDP.ServerRequest","firstTime":"2026-09-30T13:22:15","lastTime":"2026-10-01T09:06:00"},
]
COLS=["src","action","category","count","dest_ip","dest_port","attack_name","firstTime","lastTime"]
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def auth(self):
        if self.headers.get("Authorization")!="Bearer SPTOKEN":
            self.send_response(401); self.end_headers(); self.wfile.write(b'{"messages":[{"type":"WARN","text":"call not properly authenticated"}]}'); return False
        return True
    def do_GET(self):
        if not self.auth(): return
        if self.path.startswith("/services/authentication/current-context"):
            b=json.dumps({"entry":[{"content":{"username":"splunkuser","roles":["user"]}}]}).encode()
        elif self.path.startswith("/services/server/info"):
            b=json.dumps({"entry":[{"content":{"version":"10.4.0","serverName":"sh01"}}]}).encode()
        else: self.send_response(404); self.end_headers(); return
        self.send_response(200); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        if not self.auth(): return
        q=parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode(), keep_blank_values=True)
        s=q["search"][0]; mode=q.get("output_mode",["csv"])[0]
        open("/tmp/splunk_last_search.txt","w").write(s)
        rows=ROWS if ("index=suricata " in s or "index=suricata\n" in s) and "\u00a0" not in s else []
        if "| head 20" in s or "| head 5" in s: rows=rows[:5]
        self.send_response(200); self.end_headers()
        if mode=="csv":
            if rows:
                import csv, io
                f=io.StringIO(); w=csv.DictWriter(f, fieldnames=COLS); w.writeheader(); w.writerows(rows); self.wfile.write(f.getvalue().encode())
        else:
            out=[json.dumps({"preview":False,"offset":i,"result":r}) for i,r in enumerate(rows)]
            if not rows: out.append(json.dumps({"preview":False,"messages":[{"type":"INFO","text":"Your timerange was substituted based on your search string"}]}))
            self.wfile.write(("\n".join(out)+"\n").encode())
HTTPServer(("127.0.0.1",8089),H).serve_forever()
