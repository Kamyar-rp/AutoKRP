import asyncio, json, ssl, time
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
class H:
    async def handle_DATA(self, server, session, envelope):
        open("/tmp/mails.jsonl","a").write(json.dumps({"port": server._port, "from": envelope.mail_from, "to": envelope.rcpt_tos,
            "auth": getattr(session, "authenticated", None), "data": envelope.content.decode("utf8","replace")}, ensure_ascii=False) + "\n")
        return "250 OK"
def auth(server, session, envelope, mechanism, auth_data):
    ok = isinstance(auth_data, LoginPassword) and auth_data.login == b"soc@example.com" and auth_data.password == b"M@ilP4ss"
    return AuthResult(success=ok)
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); ctx.load_cert_chain("/tmp/smtp.crt", "/tmp/smtp.key")
class C(Controller):
    def factory(self):
        s = super().factory(); s._port = self.port; return s
plain = C(H(), hostname="127.0.0.1", port=2525)
starttls = C(H(), hostname="127.0.0.1", port=2587, tls_context=ctx, require_starttls=True, authenticator=auth, auth_required=True)
implicit = C(H(), hostname="127.0.0.1", port=2465, ssl_context=ctx, authenticator=auth, auth_required=True, auth_require_tls=False)
for c in (plain, starttls, implicit): c.start()
print("smtp up", flush=True)
while True: time.sleep(3600)
