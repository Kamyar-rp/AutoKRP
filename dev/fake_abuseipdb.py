import json, os
# FAKE_QUOTA=N: پس از N درخواست موفق، مثل تمام شدن سهمیه‌ی روزانه 429 برمی‌گرداند
QUOTA=int(os.environ.get("FAKE_QUOTA","0")); COUNT=[0]
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        u=urlsplit(self.path); q=parse_qs(u.query, keep_blank_values=True)
        if u.path!="/api/v2/check":
            b=b"<!DOCTYPE html><html><body>Not Found</body></html>"; self.send_response(404); self.send_header("Content-Type","text/html"); self.end_headers(); self.wfile.write(b); return
        if self.headers.get("Key")!="GOODKEY":
            b=json.dumps({"errors":[{"detail":"Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.","status":401}]}).encode()
            self.send_response(401); self.send_header("Content-Type","application/json"); self.end_headers(); self.wfile.write(b); return
        if self.headers.get("Accept")!="application/json":
            self.send_response(406); self.end_headers(); return
        COUNT[0]+=1
        if QUOTA and COUNT[0]>QUOTA:
            b=json.dumps({"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint.","status":429}]}).encode()
            self.send_response(429); self.send_header("Content-Type","application/json"); self.send_header("Retry-After","43200")
            self.send_header("X-RateLimit-Limit","1000"); self.send_header("X-RateLimit-Remaining","0"); self.end_headers(); self.wfile.write(b); return
        ip=q["ipAddress"][0]; age=int(q.get("maxAgeInDays",["30"])[0])
        if not 1<=age<=365:
            b=json.dumps({"errors":[{"detail":"The max age in days must be between 1 and 365.","status":422}]}).encode(); self.send_response(422); self.end_headers(); self.wfile.write(b); return
        d={"data":{"ipAddress":ip,"isPublic":True,"ipVersion":4,"isWhitelisted":False,"abuseConfidenceScore":100,"countryCode":"CN","countryName":"China",
           "usageType":"Data Center/Web Hosting/Transit","isp":"Tencent","domain":"tencent.com","hostnames":[],"isTor":False,"totalReports":1,"numDistinctUsers":1,
           "lastReportedAt":"2018-12-20T20:55:14+00:00","reports":[{"categories":[18,22]}] if "verbose" in q else []}}
        b=json.dumps(d).encode(); self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("X-RateLimit-Limit","1000"); self.send_header("X-RateLimit-Remaining","987"); self.end_headers(); self.wfile.write(b)
HTTPServer(("127.0.0.1",8899),H).serve_forever()
