import http.client
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path

from securitywatchdaily.auth import create_admin_user
from securitywatchdaily.database import connect, initialize
from securitywatchdaily.repositories.audit import audit_context, list_audit_events
from securitywatchdaily.web.server import serve


class AuditWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "app.sqlite3"
        conn = connect(self.db_path)
        try:
            initialize(conn)
            create_admin_user(conn, "admin", "correct horse battery staple")
        finally:
            conn.close()
        self.server = serve("127.0.0.1", 0, self.db_path)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, method, path, body="", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        set_cookie = response.getheader("Set-Cookie")
        location = response.getheader("Location")
        conn.close()
        return response.status, data, set_cookie, location

    def login(self):
        status, _, set_cookie, _ = self.request(
            "POST",
            "/login",
            body="username=admin&password=correct+horse+battery+staple",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        return set_cookie.split(";", 1)[0]

    def csrf_token(self, cookie, path="/"):
        status, data, _, _ = self.request("GET", path, headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', data)
        self.assertIsNotNone(match)
        return match.group(1)

    def authed_post(self, cookie, csrf_token, path, body=""):
        separator = "&" if body else ""
        return self.request(
            "POST",
            path,
            body=f"{body}{separator}csrf_token={csrf_token}",
            headers={
                "Cookie": cookie,
                "Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    def audit_rows(self):
        conn = connect(self.db_path)
        try:
            initialize(conn)
            return list_audit_events(conn)
        finally:
            conn.close()

    def test_failed_login_writes_safe_audit_event(self):
        password = "wrong-password-value"
        status, data, _, _ = self.request(
            "POST",
            "/login",
            body=f"username=admin&password={password}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 401)
        self.assertIn("Invalid username or password", data)

        rows = self.audit_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "login.failure")
        self.assertEqual(rows[0]["username"], "admin")
        self.assertEqual(rows[0]["result"], "failure")
        context = audit_context(rows[0])
        self.assertEqual(context["path"], "/login")
        self.assertNotIn(password, rows[0]["context_json"])

    def test_sensitive_web_actions_write_audit_events_without_secrets(self):
        cookie = self.login()
        token = cookie.split("=", 1)[1]
        csrf_token = self.csrf_token(cookie)

        self.authed_post(
            cookie,
            csrf_token,
            "/platforms",
            "id=audit_platform&display_name=Audit+Platform&keywords=audit&minimum_cve_year=2026&default_priority=Medium",
        )
        self.authed_post(cookie, csrf_token, "/platforms/toggle", "id=audit_platform&enabled=0")
        self.authed_post(
            cookie,
            csrf_token,
            "/sources",
            "id=audit_source&name=Audit+Source&source_type=generic&url=https%3A%2F%2Fexample.com%2Ffeed.json",
        )
        self.authed_post(cookie, csrf_token, "/sources/toggle", "id=audit_source&enabled=0")
        self.authed_post(cookie, csrf_token, "/run-sample")
        self.authed_post(cookie, csrf_token, "/assets/import", "csv_text=hostname%2Cproduct%0A%2CWindows%2011")
        self.authed_post(cookie, csrf_token, "/connectors/toggle", "id=sample_inventory&enabled=1")
        self.authed_post(cookie, csrf_token, "/connectors/test", "id=sample_inventory")
        self.authed_post(cookie, csrf_token, "/connectors/sync", "id=sample_inventory")
        self.authed_post(
            cookie,
            csrf_token,
            "/connectors/intune/settings",
            "display_name=Corporate+Intune&cloud=global&"
            "tenant_id=22222222-2222-2222-2222-222222222222&"
            "client_id=33333333-3333-3333-3333-333333333333&"
            "tenant_env_var=ACME_INTUNE_TENANT_ID&"
            "client_env_var=ACME_INTUNE_CLIENT_ID&"
            "secret_env_var=ACME_INTUNE_CLIENT_SECRET&"
            "client_secret=do-not-store-this",
        )
        self.authed_post(
            cookie,
            csrf_token,
            "/admin/users",
            "username=auditbackup&password=another+correct+horse+battery&"
            "confirm_password=another+correct+horse+battery",
        )
        conn = connect(self.db_path)
        try:
            backup_id = conn.execute("SELECT id FROM users WHERE username = ?", ("auditbackup",)).fetchone()["id"]
        finally:
            conn.close()
        self.authed_post(cookie, csrf_token, "/admin/users/delete", f"user_id={backup_id}")
        self.authed_post(cookie, csrf_token, "/logout")

        rows = self.audit_rows()
        actions = {row["action"] for row in rows}
        expected_actions = {
            "login.success",
            "platform.create",
            "platform.toggle",
            "source.create",
            "source.toggle",
            "run.sample",
            "asset_import",
            "connector.toggle",
            "connector.test",
            "connector.sync",
            "connector.settings",
            "admin_user.create",
            "admin_user.delete",
            "logout",
        }
        self.assertTrue(expected_actions.issubset(actions))
        raw_audit = "\n".join(str(dict(row)) for row in rows)
        for secret_value in [
            token,
            csrf_token,
            "correct horse battery staple",
            "another correct horse battery",
            "do-not-store-this",
        ]:
            self.assertNotIn(secret_value, raw_audit)


if __name__ == "__main__":
    unittest.main()
