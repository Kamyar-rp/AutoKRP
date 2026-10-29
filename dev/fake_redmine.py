# شبیه‌ساز Redmine برای توسعه: python dev/fake_redmine.py  (پورت 8898)
# کلید ADMINKEY ادمین است، USERKEY کاربر عادی (custom_fields.json برایش 403).
import json, re
from http.server import BaseHTTPRequestHandler, HTTPServer
CF = [
    {"id": 1, "name": "Src IP(s)", "customized_type": "issue", "field_format": "text", "is_required": True, "multiple": False,
     "default_value": "", "trackers": [{"id": 1, "name": "Incident"}]},
    {"id": 2, "name": "Severity", "customized_type": "issue", "field_format": "list", "is_required": True, "multiple": False,
     "default_value": "Medium", "possible_values": [{"value": "Low"}, {"value": "Medium"}, {"value": "High"}],
     "trackers": [{"id": 1, "name": "Incident"}, {"id": 2, "name": "Task"}]},
    {"id": 3, "name": "Owner", "customized_type": "issue", "field_format": "user", "is_required": False, "multiple": False,
     "trackers": [{"id": 1, "name": "Incident"}]},
    {"id": 4, "name": "Tags", "customized_type": "issue", "field_format": "list", "is_required": False, "multiple": True,
     "possible_values": [{"value": "ids"}, {"value": "fw"}], "trackers": [{"id": 2, "name": "Task"}]},
    {"id": 5, "name": "Detected", "customized_type": "issue", "field_format": "date", "is_required": True,
     "trackers": [{"id": 1, "name": "Incident"}]},
    {"id": 9, "name": "Other project", "customized_type": "issue", "field_format": "string", "is_required": True,
     "trackers": [{"id": 1, "name": "Incident"}]},
    {"id": 10, "name": "User CF", "customized_type": "user", "field_format": "string"},
]
TRK = [{"id": 1, "name": "Incident"}, {"id": 2, "name": "Task"}, {"id": 3, "name": "Bug"}]
ISSUES = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def j(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
    def key(self):
        return self.headers.get("X-Redmine-API-Key")
    def do_GET(self):
        k = self.key(); p = self.path.split("?")[0]
        if k not in ("ADMINKEY", "USERKEY"): return self.j(401, {})
        if p == "/users/current.json": return self.j(200, {"user": {"id": 5 if k == "USERKEY" else 1, "login": "soc" if k == "USERKEY" else "admin", "admin": k == "ADMINKEY"}})
        if p == "/custom_fields.json": return self.j(200, {"custom_fields": CF}) if k == "ADMINKEY" else self.j(403, {})
        if p == "/trackers.json": return self.j(200, {"trackers": TRK})
        if p == "/projects/soc.json": return self.j(200, {"project": {"id": 7, "identifier": "soc", "trackers": TRK[:2],
                                                     "issue_custom_fields": [{"id": i, "name": "x"} for i in (1, 2, 3, 4, 5)]}})
        if p == "/projects/soc/memberships.json": return self.j(200, {"memberships": [{"user": {"id": 5, "name": "SOC User"}}, {"group": {"id": 8, "name": "NOC"}}], "total_count": 2})
        if p == "/projects/soc/versions.json": return self.j(200, {"versions": []})
        if p == "/enumerations/issue_priorities.json": return self.j(200, {"issue_priorities": [{"id": 1, "name": "Normal"}, {"id": 2, "name": "High"}]})
        if p == "/projects/soc/issue_categories.json": return self.j(200, {"issue_categories": [{"id": 3, "name": "Security"}]})
        return self.j(404, {})
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n)
        if self.path.startswith("/uploads.json"): return self.j(201, {"upload": {"token": "tok1"}})
        if self.path == "/issues.json":
            i = json.loads(body)["issue"]; cfs = {c["id"]: c["value"] for c in i.get("custom_fields", [])}
            req = [c for c in CF if c.get("is_required") and c["customized_type"] == "issue" and c["id"] in (1, 2, 3, 4, 5)
                   and i["tracker_id"] in [t["id"] for t in c.get("trackers", [])] and not cfs.get(c["id"])]
            if req: return self.j(422, {"errors": [f"{c['name']} cannot be blank" for c in req]})
            i["id"] = len(ISSUES) + 100; ISSUES.append(i); open("/tmp/redmine_issues.jsonl", "a").write(json.dumps(i) + "\n")
            return self.j(201, {"issue": {"id": i["id"]}})
        return self.j(404, {})
HTTPServer(("127.0.0.1", 8898), H).serve_forever()
