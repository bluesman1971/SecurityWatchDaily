"""Local-only web server for SecurityWatchDaily."""

from __future__ import annotations

import json
import ipaddress
import re
import hmac
from http.cookies import SimpleCookie
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from securitywatchdaily.auth import (
    admin_user_count,
    authenticate_user,
    create_admin_user,
    create_session,
    delete_admin_user,
    destroy_session,
    list_admin_users,
    validate_session,
)
from securitywatchdaily.config import database_path, legacy_watchlist_path
from securitywatchdaily.database import connect, initialize
from securitywatchdaily.errors import AppError
from securitywatchdaily.models import Platform, Source
from securitywatchdaily.repositories.platforms import list_platforms, save_platform, set_platform_enabled
from securitywatchdaily.repositories.assets import (
    get_asset,
    list_asset_components,
    list_assets,
    list_matches_for_asset,
    list_matches_for_finding,
)
from securitywatchdaily.repositories.connectors import (
    get_connector,
    list_connectors,
    list_import_errors,
    list_sync_runs,
    set_connector_enabled,
)
from securitywatchdaily.repositories.runs import get_finding, latest_run, list_findings, list_runs
from securitywatchdaily.repositories.sources import list_sources, save_source, set_source_enabled
from securitywatchdaily.services.asset_import_service import csv_template, import_inventory_csv
from securitywatchdaily.services.asset_matching_service import refresh_asset_matches_for_run
from securitywatchdaily.services.connector_service import (
    INTUNE_CLOUDS,
    INTUNE_PERMISSION,
    intune_env_export,
    intune_settings_from_connector,
    save_intune_settings,
    seed_connector_catalog,
    sync_connector,
    test_connector,
)
from securitywatchdaily.services.import_service import seed_defaults
from securitywatchdaily.services.run_service import run_watch
from securitywatchdaily.validation import split_csv

from .html import badge, esc, page

STATIC_DIR = Path(__file__).with_name("static")
MAX_POST_BYTES = 2 * 1024 * 1024
CSRF_FIELD_NAME = "csrf_token"


class AppContext:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @contextmanager
    def connection(self):
        conn = connect(self.db_path)
        try:
            initialize(conn)
            seed_connector_catalog(conn)
            yield conn
        finally:
            conn.close()


class SecurityWatchHandler(BaseHTTPRequestHandler):
    context: AppContext
    session_cookie_name = "swd_session"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if self._url_contains_session_id(parsed.query):
                self.respond(page("Bad request", "<section class='panel'><h1>Bad request</h1></section>"), HTTPStatus.BAD_REQUEST)
                return
            if parsed.path.startswith("/static/"):
                self.serve_static(parsed.path)
                return
            if parsed.path == "/api/health":
                self.health()
                return
            if parsed.path == "/login":
                self.login_form()
                return
            if not self.current_user():
                self.redirect(f"/login?next={self._safe_next_path(parsed.path)}")
                return
            routes = {
                "/": self.dashboard,
                "/platforms": self.platforms,
                "/platforms/new": self.platform_form,
                "/sources": self.sources,
                "/sources/new": self.source_form,
                "/runs": self.runs,
                "/findings": self.findings,
                "/assets": self.assets,
                "/assets/import": self.asset_import_form,
                "/connectors": self.connectors,
                "/admin/users": self.admin_users,
            }
            handler = routes.get(parsed.path)
            if parsed.path == "/connectors/intune/setup":
                self.intune_setup_form()
                return
            if not handler and parsed.path.startswith("/connectors/"):
                self.connector_detail(parsed.path)
                return
            if not handler and parsed.path.startswith("/assets/"):
                self.asset_detail(parsed.path)
                return
            if not handler and parsed.path.startswith("/findings/"):
                self.finding_detail(parsed.path)
                return
            if not handler:
                self.respond(page("Not found", "<section class='panel'><h1>Not found</h1></section>"), HTTPStatus.NOT_FOUND)
                return
            handler()
        except AppError as exc:
            self.respond(page("Error", "<section class='panel'><h1>Something needs attention</h1></section>", error=exc.detail or exc.message), HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self.respond(page("Error", "<section class='panel'><h1>Unexpected local error</h1><p class='muted'>Check the terminal log for details.</p></section>", error=f"{type(exc).__name__}: {exc}"), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            if self._url_contains_session_id(parsed.query):
                self.discard_request_body()
                self.respond(page("Bad request", "<section class='panel'><h1>Bad request</h1></section>"), HTTPStatus.BAD_REQUEST)
                return
            if parsed.path == "/login":
                self.login_action()
                return
            current_user = self.current_user()
            if not current_user:
                self.discard_request_body()
                self.respond(
                    page(
                        "Authentication required",
                        "<section class='panel'><h1>Authentication required</h1></section>",
                        auth_nav=False,
                    ),
                    HTTPStatus.UNAUTHORIZED,
                )
                return
            if not self._origin_is_same_local_app():
                self.discard_request_body()
                self.forbidden()
                return
            form = self.read_form()
            if not self._csrf_token_is_valid(form, current_user):
                self.forbidden()
                return
            if parsed.path == "/logout":
                self.logout_action()
                return
            if parsed.path == "/platforms":
                self.create_platform(form)
            elif parsed.path == "/platforms/toggle":
                self.toggle_platform(form)
            elif parsed.path == "/sources":
                self.create_source(form)
            elif parsed.path == "/sources/toggle":
                self.toggle_source(form)
            elif parsed.path == "/run-now":
                self.run_now(offline_sample=False)
            elif parsed.path == "/run-sample":
                self.run_now(offline_sample=True)
            elif parsed.path == "/assets/import":
                self.import_assets(form)
            elif parsed.path == "/connectors/toggle":
                self.toggle_connector(form)
            elif parsed.path == "/connectors/test":
                self.test_connector_action(form)
            elif parsed.path == "/connectors/sync":
                self.sync_connector_action(form)
            elif parsed.path == "/connectors/intune/settings":
                self.save_intune_connector_settings(form)
            elif parsed.path == "/admin/users":
                self.create_admin_user_action(form)
            elif parsed.path == "/admin/users/delete":
                self.delete_admin_user_action(form, current_user)
            else:
                self.redirect("/")
        except AppError as exc:
            self.respond(page("Error", "<section class='panel'><h1>Could not complete the action</h1></section>", error=exc.detail or exc.message), HTTPStatus.BAD_REQUEST)

    def read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_POST_BYTES:
            raise AppError("Upload is too large.", detail="CSV imports are limited to 2 MB.")
        content_type = self.headers.get("Content-Type", "")
        raw_bytes = self.rfile.read(length)
        if content_type.startswith("multipart/form-data"):
            return self.parse_multipart(raw_bytes, content_type)
        raw = raw_bytes.decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def discard_request_body(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 0:
            self.rfile.read(min(length, MAX_POST_BYTES + 1))

    def current_user(self) -> object | None:
        token = self._session_cookie()
        if not token:
            return None
        with self.context.connection() as conn:
            return validate_session(conn, token)

    def _session_cookie(self) -> str:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return ""
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(self.session_cookie_name)
        return morsel.value if morsel else ""

    def _safe_next_path(self, path: str) -> str:
        if path.startswith("/") and not path.startswith("//"):
            return path
        return "/"

    def _url_contains_session_id(self, query: str) -> bool:
        if not query:
            return False
        names = {name.lower() for name in parse_qs(query, keep_blank_values=True)}
        return bool(names & {self.session_cookie_name, "session", "session_id"})

    def _origin_is_same_local_app(self) -> bool:
        origin = self.headers.get("Origin", "")
        host_header = self.headers.get("Host", "")
        if not origin or not host_header:
            return False
        parsed_origin = urlparse(origin)
        parsed_host = urlparse(f"//{host_header}")
        if parsed_origin.scheme != "http" or not parsed_origin.hostname or not parsed_host.hostname:
            return False
        try:
            origin_port = parsed_origin.port or 80
            host_port = parsed_host.port or 80
        except ValueError:
            return False
        return (
            _is_loopback_bind_host(parsed_origin.hostname)
            and parsed_origin.hostname.lower() == parsed_host.hostname.lower()
            and origin_port == host_port
        )

    def _csrf_token_is_valid(self, form: dict[str, str], current_user: object) -> bool:
        expected = str(current_user["csrf_token"] or "")
        supplied = form.get(CSRF_FIELD_NAME, "")
        return bool(expected and supplied and hmac.compare_digest(expected, supplied))

    def forbidden(self) -> None:
        self.respond(page("Forbidden", "<section class='panel'><h1>Forbidden</h1></section>"), HTTPStatus.FORBIDDEN)

    def parse_multipart(self, raw: bytes, content_type: str) -> dict[str, str]:
        boundary_match = re.search(r"boundary=(?P<boundary>[^;]+)", content_type)
        if not boundary_match:
            raise AppError("Upload could not be read.", detail="Missing multipart boundary.")
        boundary = boundary_match.group("boundary").strip('"').encode("utf-8")
        result: dict[str, str] = {}
        for part in raw.split(b"--" + boundary):
            part = part.strip(b"\r\n")
            if not part or part == b"--" or b"\r\n\r\n" not in part:
                continue
            header_blob, value = part.split(b"\r\n\r\n", 1)
            headers = header_blob.decode("utf-8", errors="replace")
            name_match = re.search(r'name="([^"]+)"', headers)
            if not name_match:
                continue
            name = name_match.group(1)
            if value.endswith(b"--"):
                value = value[:-2]
            result[name] = value.rstrip(b"\r\n").decode("utf-8-sig", errors="replace")
        return result

    def respond(
        self,
        body: bytes,
        status: HTTPStatus = HTTPStatus.OK,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        if content_type.startswith("text/html"):
            body = self._inject_csrf_inputs(body)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _inject_csrf_inputs(self, body: bytes) -> bytes:
        token = self._csrf_token_for_current_session()
        if not token:
            return body
        html = body.decode("utf-8")
        csrf_input = f'<input type="hidden" name="{CSRF_FIELD_NAME}" value="{esc(token)}">'
        html = re.sub(r"(<form\b[^>]*\bmethod=[\"']post[\"'][^>]*>)", rf"\1{csrf_input}", html, flags=re.IGNORECASE)
        return html.encode("utf-8")

    def _csrf_token_for_current_session(self) -> str:
        current = self.current_user()
        if not current:
            return ""
        return str(current["csrf_token"] or "")

    def redirect(self, path: str, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", path)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def serve_static(self, path: str) -> None:
        name = path.removeprefix("/static/")
        file_path = (STATIC_DIR / name).resolve()
        if STATIC_DIR.resolve() not in file_path.parents:
            self.respond(b"Not found", HTTPStatus.NOT_FOUND, "text/plain")
            return
        if not file_path.exists():
            self.respond(b"Not found", HTTPStatus.NOT_FOUND, "text/plain")
            return
        self.respond(file_path.read_bytes(), content_type="text/css; charset=utf-8")

    def login_form(self, *, error: str = "") -> None:
        parsed = urlparse(self.path)
        next_path = self._safe_next_path(parse_qs(parsed.query).get("next", ["/"])[0])
        with self.context.connection() as conn:
            has_admin = admin_user_count(conn) > 0
        setup_note = (
            ""
            if has_admin
            else "<div class='notice'>No admin user exists yet. Run <code>python3 -m securitywatchdaily create-admin</code> first.</div>"
        )
        body = f"""
        <section class="panel auth-panel">
          <h1>Login</h1>
          {setup_note}
          <form class="stack" method="post" action="/login">
            <input type="hidden" name="next" value="{esc(next_path)}">
            <label>Username<input name="username" autocomplete="username" autofocus></label>
            <label>Password<input type="password" name="password" autocomplete="current-password"></label>
            <button>Login</button>
          </form>
        </section>
        """
        self.respond(page("Login", body, error=error, auth_nav=False), HTTPStatus.UNAUTHORIZED if error else HTTPStatus.OK)

    def login_action(self) -> None:
        form = self.read_form()
        username = form.get("username", "")
        password = form.get("password", "")
        next_path = self._safe_next_path(form.get("next", "/"))
        with self.context.connection() as conn:
            user = authenticate_user(conn, username, password)
        if not user:
            self.login_form(error="Invalid username or password.")
            return
        with self.context.connection() as conn:
            token = create_session(conn, int(user["id"]))
        self.redirect(next_path, headers={"Set-Cookie": self._session_cookie_header(token)})

    def logout_action(self) -> None:
        token = self._session_cookie()
        if token:
            with self.context.connection() as conn:
                destroy_session(conn, token)
        self.redirect("/login", headers={"Set-Cookie": self._clear_session_cookie_header()})

    def _session_cookie_header(self, token: str) -> str:
        return f"{self.session_cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict"

    def _clear_session_cookie_header(self) -> str:
        return f"{self.session_cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"

    def admin_users(self, *, flash: str = "", error: str = "") -> None:
        current = self.current_user()
        if not current:
            self.redirect("/login?next=/admin/users")
            return
        with self.context.connection() as conn:
            users = list_admin_users(conn)
        rows = "".join(
            f"""
            <tr>
              <td><b>{esc(user['username'])}</b><br><span class="muted">{esc(user['role'])}</span></td>
              <td>{esc(user['created_at'])}</td>
              <td>{esc(user['last_login_at'] or 'Never')}</td>
              <td>{int(user['active_sessions'])}</td>
              <td>{self._admin_user_delete_control(user, current)}</td>
            </tr>
            """
            for user in users
        )
        body = f"""
        <section class="hero">
          <div><h1>Admin users</h1><p class="muted">Manage local administrator accounts for this SecurityWatchDaily database.</p></div>
        </section>
        <section class="panel">
          <h2>Add admin user</h2>
          <form class="stack" method="post" action="/admin/users">
            <div class="two">
              <label>Username<input name="username" autocomplete="username" placeholder="admin2" maxlength="64"></label>
              <label>Role<input value="admin" readonly></label>
            </div>
            <div class="two">
              <label>Password<input type="password" name="password" autocomplete="new-password"></label>
              <label>Confirm password<input type="password" name="confirm_password" autocomplete="new-password"></label>
            </div>
            <button>Create admin</button>
          </form>
        </section>
        <section class="panel">
          <h2>Existing admin users</h2>
          <div class="table-wrap"><table><thead><tr><th>User</th><th>Created</th><th>Last login</th><th>Sessions</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div>
        </section>
        """
        self.respond(page("Admin users", body, flash=flash, error=error))

    def _admin_user_delete_control(self, user: object, current_user: object) -> str:
        if int(user["id"]) == int(current_user["id"]):
            return "<span class='muted'>Current user</span>"
        return (
            f"<form method='post' action='/admin/users/delete'>"
            f"<input type='hidden' name='user_id' value='{int(user['id'])}'>"
            f"<button class='secondary'>Delete</button></form>"
        )

    def create_admin_user_action(self, form: dict[str, str]) -> None:
        password = form.get("password", "")
        if password != form.get("confirm_password", ""):
            self.admin_users(error="Passwords did not match.")
            return
        with self.context.connection() as conn:
            user = create_admin_user(conn, form.get("username", ""), password)
        self.admin_users(flash=f"Admin user '{user['username']}' created.")

    def delete_admin_user_action(self, form: dict[str, str], current_user: object) -> None:
        try:
            user_id = int(form.get("user_id", ""))
        except ValueError as exc:
            raise AppError("Admin user could not be deleted.", detail="The requested admin user was invalid.") from exc
        with self.context.connection() as conn:
            delete_admin_user(conn, user_id, current_user_id=int(current_user["id"]))
        self.admin_users(flash="Admin user deleted.")

    def dashboard(self) -> None:
        with self.context.connection() as conn:
            seed_defaults(conn, legacy_watchlist_path(self.context.db_path.parent))
            run = latest_run(conn)
            platforms = list_platforms(conn)
            sources = list_sources(conn)
            findings = list_findings(conn, run_id=run.run_id, visible_only=True) if run else []
        source_status = ""
        if run:
            source_status = "".join(f"<div class='source-card'><b>{esc(k)}</b><p class='muted'>{esc(v)}</p></div>" for k, v in run.source_status.items())
        body = f"""
        <section class="hero">
          <div>
            <h1>Daily vulnerability watch</h1>
            <p class="muted">Local dashboard for platform-specific vulnerability monitoring and trace-filtered daily runs.</p>
          </div>
          <div class="actions">
            <form method="post" action="/run-now"><button>Run live check</button></form>
            <form method="post" action="/run-sample"><button class="secondary">Run sample check</button></form>
          </div>
        </section>
        <section class="panel metrics">
          <div class="metric"><b>{len(platforms)}</b><span>Platforms</span></div>
          <div class="metric"><b>{len(sources)}</b><span>Sources</span></div>
          <div class="metric"><b>{run.visible_count if run else 0}</b><span>Visible findings</span></div>
          <div class="metric"><b>{run.suppressed_count if run else 0}</b><span>Suppressed</span></div>
        </section>
        <section class="panel">
          <h2>Latest run</h2>
          <p>{esc(run.run_id if run else "No runs yet")}</p>
          <div class="source-status">{source_status or "<p class='muted'>Run a check to see source health.</p>"}</div>
        </section>
        <section class="panel">
          <h2>Visible findings</h2>
          {self.findings_table(findings)}
        </section>
        """
        self.respond(page("Dashboard", body))

    def platforms(self) -> None:
        with self.context.connection() as conn:
            seed_defaults(conn, legacy_watchlist_path(self.context.db_path.parent))
            platforms = list_platforms(conn)
        rows = "".join(
            f"<tr><td><b>{esc(p.display_name)}</b><br><span class='muted'>{esc(p.id)}</span></td><td>{'Enabled' if p.enabled else 'Disabled'}</td><td>{esc(', '.join(p.keywords[:8]))}</td><td><form method='post' action='/platforms/toggle'><input type='hidden' name='id' value='{esc(p.id)}'><input type='hidden' name='enabled' value='{'0' if p.enabled else '1'}'><button class='secondary'>{'Disable' if p.enabled else 'Enable'}</button></form></td></tr>"
            for p in platforms
        )
        body = f"""
        <section class="hero"><div><h1>Platforms</h1><p class="muted">Manage products, platforms, keywords, exclusions, and default priority.</p></div><a class="button" href="/platforms/new">Add platform</a></section>
        <section class="panel"><div class="table-wrap"><table><thead><tr><th>Platform</th><th>Status</th><th>Keywords</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div></section>
        """
        self.respond(page("Platforms", body))

    def platform_form(self) -> None:
        body = """
        <section class="panel">
          <h1>Add platform</h1>
          <form class="stack" method="post" action="/platforms">
            <div class="two"><label>ID<input name="id" placeholder="example_product"></label><label>Display name<input name="display_name" placeholder="Example Product"></label></div>
            <div class="two"><label>Default priority<select name="default_priority"><option>Medium</option><option>High</option><option>Watch</option><option>Info</option><option>Critical</option></select></label><label>Minimum CVE year<input name="minimum_cve_year" value="2025"></label></div>
            <label>Vendors<input name="vendors" placeholder="Vendor, Another Vendor"></label>
            <label>Keywords<input name="keywords" placeholder="product name, exact phrase"></label>
            <label>Exclude keywords<input name="exclude_keywords" placeholder="sd-wan, unrelated product"></label>
            <label>MSRC title keywords<input name="msrc_title_keywords"></label>
            <label>CISA keywords<input name="cisa_keywords"></label>
            <label>Ubuntu releases<input name="ubuntu_releases" placeholder="Ubuntu 22.04, Ubuntu 24.04"></label>
            <label>Palo Alto products<input name="paloalto_products" placeholder="PAN-OS, Prisma Access"></label>
            <button>Save platform</button>
          </form>
        </section>
        """
        self.respond(page("Add platform", body))

    def sources(self) -> None:
        with self.context.connection() as conn:
            seed_defaults(conn, legacy_watchlist_path(self.context.db_path.parent))
            sources = list_sources(conn)
        rows = "".join(
            f"<tr><td><b>{esc(s.name)}</b><br><span class='muted'>{esc(s.id)}</span></td><td>{esc(s.source_type)}</td><td>{esc(s.url or 'dynamic default')}</td><td>{'Enabled' if s.enabled else 'Disabled'}</td><td><form method='post' action='/sources/toggle'><input type='hidden' name='id' value='{esc(s.id)}'><input type='hidden' name='enabled' value='{'0' if s.enabled else '1'}'><button class='secondary'>{'Disable' if s.enabled else 'Enable'}</button></form></td></tr>"
            for s in sources
        )
        body = f"""
        <section class="hero"><div><h1>Sources</h1><p class="muted">Manage feeds and advisory sources used by local runs.</p></div><a class="button" href="/sources/new">Add source</a></section>
        <section class="panel"><div class="table-wrap"><table><thead><tr><th>Source</th><th>Type</th><th>URL</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div></section>
        """
        self.respond(page("Sources", body))

    def source_form(self) -> None:
        body = """
        <section class="panel">
          <h1>Add source</h1>
          <form class="stack" method="post" action="/sources">
            <div class="two"><label>ID<input name="id" placeholder="vendor_feed"></label><label>Name<input name="name" placeholder="Vendor advisory feed"></label></div>
            <label>Type<select name="source_type"><option>generic</option><option>msrc</option><option>cisa</option><option>ubuntu</option><option>paloalto</option><option>hn</option></select></label>
            <label>URL<input name="url" placeholder="https://example.com/feed.json"></label>
            <label>Notes<textarea name="notes"></textarea></label>
            <button>Save source</button>
          </form>
        </section>
        """
        self.respond(page("Add source", body))

    def runs(self) -> None:
        with self.context.connection() as conn:
            runs = list_runs(conn)
        rows = "".join(
            f"<tr><td>{esc(r.run_id)}</td><td>{r.visible_count}</td><td>{r.suppressed_count}</td><td>{r.collected_count}</td></tr>"
            for r in runs
        )
        body = f"<section class='hero'><div><h1>Runs</h1><p class='muted'>Recent daily collection runs.</p></div><form method='post' action='/run-sample'><button>Run sample check</button></form></section><section class='panel'><div class='table-wrap'><table><thead><tr><th>Run</th><th>Visible</th><th>Suppressed</th><th>Collected</th></tr></thead><tbody>{rows}</tbody></table></div></section>"
        self.respond(page("Runs", body))

    def findings(self) -> None:
        with self.context.connection() as conn:
            run = latest_run(conn)
            findings = list_findings(conn, run_id=run.run_id) if run else []
        body = f"<section class='hero'><div><h1>Findings</h1><p class='muted'>Latest run findings, including suppressed trace repeats.</p></div></section><section class='panel'>{self.findings_table(findings)}</section>"
        self.respond(page("Findings", body))

    def findings_table(self, findings) -> str:
        if not findings:
            return "<p class='muted'>No findings to show yet.</p>"
        rows = "".join(
            f"<tr><td>{badge(f.priority)}<br><span class='muted'>{esc(f.trace_status)}</span></td><td>{esc(f.platform)}</td><td><b><a href='/findings/{f.id}'>{esc(f.key)}</a></b><br>{esc(f.title)}</td><td>{esc(f.description)}</td><td>{esc(', '.join(f.sources))}</td></tr>"
            for f in findings
        )
        return f"<div class='table-wrap'><table><thead><tr><th>Priority</th><th>Platform</th><th>Finding</th><th>Description</th><th>Sources</th></tr></thead><tbody>{rows}</tbody></table></div>"

    def assets(self) -> None:
        with self.context.connection() as conn:
            assets = list_assets(conn)
            components = list_asset_components(conn)
        counts: dict[int, int] = {}
        for component in components:
            counts[component.asset_id] = counts.get(component.asset_id, 0) + 1
        rows = "".join(
            f"<tr><td><b><a href='/assets/{asset.id}'>{esc(asset.hostname)}</a></b><br><span class='muted'>{esc(asset.owner)}</span></td><td>{esc(asset.asset_type)}</td><td>{esc(asset.location)}</td><td>{esc(asset.platform)}</td><td>{counts.get(asset.id or 0, 0)}</td><td>{esc(asset.last_seen)}</td></tr>"
            for asset in assets
        )
        body = f"""
        <section class="hero"><div><h1>Assets</h1><p class="muted">CSV-backed inventory and read-only connector imports used for local impact matching.</p></div><a class="button" href="/assets/import">Import CSV</a></section>
        <section class="panel"><div class="table-wrap"><table><thead><tr><th>Asset</th><th>Type</th><th>Location</th><th>Platform</th><th>Components</th><th>Last seen</th></tr></thead><tbody>{rows or "<tr><td colspan='6'>No assets imported yet.</td></tr>"}</tbody></table></div></section>
        """
        self.respond(page("Assets", body))

    def connectors(self) -> None:
        with self.context.connection() as conn:
            connectors = list_connectors(conn)
        rows = "".join(
            f"""
            <tr>
              <td><b><a href="/connectors/{esc(connector.id)}">{esc(connector.name)}</a></b><br><span class="muted">{esc(connector.description)}</span></td>
              <td>{esc(connector.connector_type)}</td>
              <td>{'Enabled' if connector.enabled else 'Disabled'}</td>
              <td>{esc(connector.last_successful_sync or 'Never')}</td>
              <td>{esc(connector.last_error or '')}</td>
              <td>{connector.imported_asset_count} / {connector.imported_component_count}</td>
            </tr>
            """
            for connector in connectors
        )
        body = f"""
        <section class="hero">
          <div><h1>Connector Catalog</h1><p class="muted">Read-only source-of-truth inventory connectors. CSV import remains the fallback workflow.</p></div>
          <a class="button secondary" href="/assets/import">Import CSV</a>
        </section>
        <section class="panel"><div class="table-wrap"><table><thead><tr><th>Connector</th><th>Type</th><th>Status</th><th>Last success</th><th>Last error</th><th>Assets / components</th></tr></thead><tbody>{rows}</tbody></table></div></section>
        """
        self.respond(page("Connector Catalog", body))

    def connector_detail(self, path: str, *, flash: str = "", error: str = "") -> None:
        connector_id = path.removeprefix("/connectors/").strip("/")
        with self.context.connection() as conn:
            connector = get_connector(conn, connector_id)
            if not connector:
                self.respond(page("Not found", "<section class='panel'><h1>Connector not found</h1></section>"), HTTPStatus.NOT_FOUND)
                return
            runs = list_sync_runs(conn, connector_id)
            latest_errors = list_import_errors(conn, int(runs[0]["id"])) if runs else []
        setup_action = ""
        if connector.connector_type == "intune":
            setup_action = '<a class="button" href="/connectors/intune/setup">Configure Intune</a>'
        run_rows = "".join(
            f"<tr><td>{esc(row['started_at'])}</td><td>{badge(row['status'])}</td><td>{esc(row['action'])}</td><td>{row['imported_asset_count']} / {row['imported_component_count']}</td><td>{esc(row['error'])}</td></tr>"
            for row in runs
        )
        error_rows = "".join(
            f"<tr><td>{esc(row['external_id'])}</td><td>{esc(row['field'])}</td><td>{esc(row['message'])}</td></tr>"
            for row in latest_errors
        )
        body = f"""
        <section class="hero">
          <div><h1>{esc(connector.name)}</h1><p class="muted">{esc(connector.description)}</p></div>
          <a class="button secondary" href="/connectors">Back to catalog</a>
        </section>
        <section class="panel metrics">
          <div class="metric"><b>{'Enabled' if connector.enabled else 'Disabled'}</b><span>Status</span></div>
          <div class="metric"><b>{esc(connector.last_successful_sync or 'Never')}</b><span>Last success</span></div>
          <div class="metric"><b>{esc(connector.last_failed_sync or 'Never')}</b><span>Last failure</span></div>
          <div class="metric"><b>{connector.imported_asset_count} / {connector.imported_component_count}</b><span>Assets / components</span></div>
        </section>
        <section class="panel">
          <h2>Actions</h2>
          <div class="actions">
            {setup_action}
            <form method="post" action="/connectors/toggle"><input type="hidden" name="id" value="{esc(connector.id)}"><input type="hidden" name="enabled" value="{'0' if connector.enabled else '1'}"><button class="secondary">{'Disable' if connector.enabled else 'Enable'}</button></form>
            <form method="post" action="/connectors/test"><input type="hidden" name="id" value="{esc(connector.id)}"><button class="secondary">Test connector</button></form>
            <form method="post" action="/connectors/sync"><input type="hidden" name="id" value="{esc(connector.id)}"><button>Sync now</button></form>
          </div>
          <p class="muted">Credentials are read from local environment variables and are not stored or shown here.</p>
          <pre class="code">{esc(connector.settings_json)}</pre>
        </section>
        <section class="panel"><h2>Recent sync runs</h2><div class="table-wrap"><table><thead><tr><th>Started</th><th>Status</th><th>Action</th><th>Assets / components</th><th>Error</th></tr></thead><tbody>{run_rows or "<tr><td colspan='5'>No sync runs yet.</td></tr>"}</tbody></table></div></section>
        <section class="panel"><h2>Latest import errors</h2><div class="table-wrap"><table><thead><tr><th>External ID</th><th>Field</th><th>Issue</th></tr></thead><tbody>{error_rows or "<tr><td colspan='3'>No import errors for the latest run.</td></tr>"}</tbody></table></div></section>
        """
        self.respond(page(connector.name, body, flash=flash, error=error))

    def intune_setup_form(self, *, flash: str = "", error: str = "") -> None:
        with self.context.connection() as conn:
            connector = get_connector(conn, "intune")
            if not connector:
                self.respond(page("Not found", "<section class='panel'><h1>Connector not found</h1></section>"), HTTPStatus.NOT_FOUND)
                return
            settings = intune_settings_from_connector(connector)
        cloud_options = "".join(
            f"<option value='{esc(key)}' {'selected' if key == settings['cloud'] else ''}>{esc(value['label'])}</option>"
            for key, value in INTUNE_CLOUDS.items()
        )
        env_output = intune_env_export(settings)
        body = f"""
        <section class="hero">
          <div>
            <h1>Add Microsoft Intune</h1>
            <p class="muted">Connect read-only device inventory from Microsoft Graph while keeping credentials local.</p>
          </div>
          <div class="actions">
            <a class="button secondary" href="/connectors/intune">Back to connector</a>
          </div>
        </section>
        <div class="setup-layout">
          <aside class="setup-steps" aria-label="Setup steps">
            <div class="setup-step done"><span class="setup-step-number">1</span><div><b>Connector</b><p class="muted">Microsoft Intune selected</p></div></div>
            <div class="setup-step current"><span class="setup-step-number">2</span><div><b>Azure app</b><p class="muted">Tenant and app registration</p></div></div>
            <div class="setup-step"><span class="setup-step-number">3</span><div><b>Secret</b><p class="muted">Local-only credential handling</p></div></div>
            <div class="setup-step"><span class="setup-step-number">4</span><div><b>Verify</b><p class="muted">Test read-only Graph access</p></div></div>
          </aside>
          <div>
            <section class="panel">
              <div class="notice">Only non-secret connector settings are saved. Client secrets stay in local environment variables or future local-only secret handling.</div>
              <h2>Azure app registration</h2>
              <p class="muted">Use a dedicated app registration with admin consent for the least-privileged read permission.</p>
              <form class="stack" method="post" action="/connectors/intune/settings">
                <div class="two">
                  <label>Connector name<input name="display_name" value="{esc(settings['display_name'])}" maxlength="255"><span class="muted">Shown on this setup screen.</span></label>
                  <label>Microsoft cloud<select name="cloud">{cloud_options}</select><span class="muted">Defaults to the public Microsoft Graph cloud.</span></label>
                </div>
                <div class="two">
                  <label>Tenant ID<input name="tenant_id" value="{esc(settings['tenant_id'])}" placeholder="00000000-0000-0000-0000-000000000000" maxlength="255"><span class="muted">Directory tenant ID from Microsoft Entra admin center.</span></label>
                  <label>Client ID<input name="client_id" value="{esc(settings['client_id'])}" placeholder="11111111-1111-1111-1111-111111111111" maxlength="255"><span class="muted">Application client ID from the app registration.</span></label>
                </div>
                <label>Required application permission<input value="{esc(INTUNE_PERMISSION)}" readonly><span class="muted">Grant admin consent before testing the connector.</span></label>
                <h2>Credential handling</h2>
                <div class="secret-note">The app reads these environment variable names at test and sync time. It does not store the client secret value.</div>
                <div class="two">
                  <label>Tenant env var<input name="tenant_env_var" value="{esc(settings['tenant_env_var'])}" maxlength="81"></label>
                  <label>Client ID env var<input name="client_env_var" value="{esc(settings['client_env_var'])}" maxlength="81"></label>
                </div>
                <label>Client secret env var<input name="secret_env_var" value="{esc(settings['secret_env_var'])}" maxlength="81"><span class="muted">Put the real secret in your shell or local service environment, not in this app.</span></label>
                <h2>Generated local setup</h2>
                <pre class="code">{esc(env_output)}</pre>
                <div class="actions">
                  <button>Save settings</button>
                  <button class="secondary" formaction="/connectors/test" name="id" value="intune">Test connector</button>
                </div>
              </form>
            </section>
            <section class="panel">
              <h2>Test before enabling</h2>
              <div class="source-status">
                <div class="source-card"><b>Settings</b><p class="muted">Tenant ID, client ID, env var names, cloud, and permission are validated before saving.</p></div>
                <div class="source-card"><b>Secrets</b><p class="muted">The client secret value is read from the configured environment variable only during test or sync.</p></div>
                <div class="source-card"><b>Read-only</b><p class="muted">The connector is designed for Microsoft Graph inventory reads and does not mutate Intune.</p></div>
                <div class="source-card"><b>Fallback</b><p class="muted">CSV import remains available if Graph permissions or tenant setup need work.</p></div>
              </div>
            </section>
          </div>
        </div>
        """
        self.respond(page("Configure Intune", body, flash=flash, error=error))

    def asset_import_form(self) -> None:
        body = f"""
        <section class="hero"><div><h1>Import assets</h1><p class="muted">Upload or paste a CSV inventory export. Imported rows replace components for matching hostnames.</p></div></section>
        <section class="panel">
          <form class="stack" method="post" action="/assets/import" enctype="multipart/form-data">
            <label>CSV file<input type="file" name="csv_file" accept=".csv,text/csv"></label>
            <label>Paste CSV<textarea name="csv_text" placeholder="{esc(csv_template())}"></textarea></label>
            <button>Import CSV</button>
          </form>
        </section>
        <section class="panel">
          <h2>Template fields</h2>
          <pre class="code">{esc(csv_template())}</pre>
        </section>
        """
        self.respond(page("Import assets", body))

    def asset_detail(self, path: str) -> None:
        asset_id = int(path.removeprefix("/assets/") or "0")
        with self.context.connection() as conn:
            asset = get_asset(conn, asset_id)
            if not asset:
                self.respond(page("Not found", "<section class='panel'><h1>Asset not found</h1></section>"), HTTPStatus.NOT_FOUND)
                return
            components = list_asset_components(conn, asset_id=asset_id)
            matches = list_matches_for_asset(conn, asset_id)
        component_rows = "".join(
            f"<tr><td>{esc(c.component_type)}</td><td>{esc(c.vendor)}</td><td>{esc(c.product)}</td><td>{esc(c.version)}</td><td>{esc(c.normalized_vendor)} / {esc(c.normalized_product)}</td></tr>"
            for c in components
        )
        match_rows = "".join(
            f"<tr><td>{badge(row['confidence'])}</td><td><b><a href='/findings/{row['finding_id']}'>{esc(row['key'])}</a></b><br>{esc(row['title'])}</td><td>{esc(row['product'])} {esc(row['version'])}</td><td>{esc(row['reason'])}</td></tr>"
            for row in matches
        )
        body = f"""
        <section class="hero"><div><h1>{esc(asset.hostname)}</h1><p class="muted">{esc(asset.owner)} {esc(asset.location)}</p></div><a class="button secondary" href="/assets">Back to assets</a></section>
        <section class="panel metrics"><div class="metric"><b>{len(components)}</b><span>Components</span></div><div class="metric"><b>{len(matches)}</b><span>Related findings</span></div><div class="metric"><b>{esc(asset.asset_type or 'Unknown')}</b><span>Type</span></div><div class="metric"><b>{esc(asset.last_seen or 'Unknown')}</b><span>Last seen</span></div></section>
        <section class="panel"><h2>Components</h2><div class="table-wrap"><table><thead><tr><th>Type</th><th>Vendor</th><th>Product</th><th>Version</th><th>Normalized</th></tr></thead><tbody>{component_rows or "<tr><td colspan='5'>No components found.</td></tr>"}</tbody></table></div></section>
        <section class="panel"><h2>Related findings</h2><div class="table-wrap"><table><thead><tr><th>Confidence</th><th>Finding</th><th>Component</th><th>Reason</th></tr></thead><tbody>{match_rows or "<tr><td colspan='4'>No related findings yet.</td></tr>"}</tbody></table></div></section>
        """
        self.respond(page(asset.hostname, body))

    def finding_detail(self, path: str) -> None:
        finding_id = int(path.removeprefix("/findings/") or "0")
        with self.context.connection() as conn:
            finding = get_finding(conn, finding_id)
            if not finding:
                self.respond(page("Not found", "<section class='panel'><h1>Finding not found</h1></section>"), HTTPStatus.NOT_FOUND)
                return
            matches = list_matches_for_finding(conn, finding_id)
        match_rows = "".join(
            f"<tr><td>{badge(row['confidence'])}</td><td><b><a href='/assets/{row['asset_id']}'>{esc(row['hostname'])}</a></b><br>{esc(row['owner'])}</td><td>{esc(row['product'])} {esc(row['version'])}</td><td>{esc(row['reason'])}</td></tr>"
            for row in matches
        )
        body = f"""
        <section class="hero"><div><h1>{esc(finding.key)}</h1><p class="muted">{esc(finding.title)}</p></div><a class="button secondary" href="/findings">Back to findings</a></section>
        <section class="panel"><h2>Finding</h2><p>{esc(finding.description)}</p><p><b>Platform:</b> {esc(finding.platform)} · <b>Priority:</b> {esc(finding.priority)}</p></section>
        <section class="panel"><h2>Impacted assets</h2><div class="table-wrap"><table><thead><tr><th>Confidence</th><th>Asset</th><th>Component</th><th>Reason</th></tr></thead><tbody>{match_rows or "<tr><td colspan='4'>No impacted assets matched yet.</td></tr>"}</tbody></table></div></section>
        """
        self.respond(page(finding.key, body))

    def health(self) -> None:
        self.respond(json.dumps({"ok": True}).encode("utf-8"), content_type="application/json")

    def create_platform(self, form: dict[str, str]) -> None:
        platform = Platform(
            id=form.get("id", "").strip(),
            display_name=form.get("display_name", "").strip(),
            enabled=True,
            vendors=split_csv(form.get("vendors", "")),
            keywords=split_csv(form.get("keywords", "")),
            exclude_keywords=split_csv(form.get("exclude_keywords", "")),
            minimum_cve_year=int(form.get("minimum_cve_year", "0") or "0"),
            default_priority=form.get("default_priority", "Medium"),
            msrc_title_keywords=split_csv(form.get("msrc_title_keywords", "")),
            cisa_keywords=split_csv(form.get("cisa_keywords", "")),
            ubuntu_releases=split_csv(form.get("ubuntu_releases", "")),
            paloalto_products=split_csv(form.get("paloalto_products", "")),
        )
        with self.context.connection() as conn:
            save_platform(conn, platform, allow_update=False)
        self.redirect("/platforms")

    def toggle_platform(self, form: dict[str, str]) -> None:
        with self.context.connection() as conn:
            set_platform_enabled(conn, form["id"], form.get("enabled") == "1")
        self.redirect("/platforms")

    def create_source(self, form: dict[str, str]) -> None:
        source = Source(
            id=form.get("id", "").strip(),
            name=form.get("name", "").strip(),
            source_type=form.get("source_type", "generic"),
            url=form.get("url", "").strip(),
            enabled=True,
            notes=form.get("notes", "").strip(),
        )
        with self.context.connection() as conn:
            save_source(conn, source, allow_update=False)
        self.redirect("/sources")

    def toggle_source(self, form: dict[str, str]) -> None:
        with self.context.connection() as conn:
            set_source_enabled(conn, form["id"], form.get("enabled") == "1")
        self.redirect("/sources")

    def run_now(self, *, offline_sample: bool) -> None:
        with self.context.connection() as conn:
            seed_defaults(conn, legacy_watchlist_path(self.context.db_path.parent))
            run_watch(conn, offline_sample=offline_sample, force_visible=offline_sample)
        self.redirect("/")

    def import_assets(self, form: dict[str, str]) -> None:
        csv_content = (form.get("csv_file") or "").strip() or (form.get("csv_text") or "").strip()
        with self.context.connection() as conn:
            result = import_inventory_csv(conn, csv_content)
            run = latest_run(conn)
            match_count = refresh_asset_matches_for_run(conn, run.run_id) if run and not result.errors else 0
        if result.errors:
            rows = "".join(
                f"<tr><td>{error.row}</td><td>{esc(error.field)}</td><td>{esc(error.message)}</td></tr>"
                for error in result.errors
            )
            body = f"""
            <section class="hero"><div><h1>Import needs changes</h1><p class="muted">Fix the listed CSV rows and import again.</p></div><a class="button secondary" href="/assets/import">Back</a></section>
            <section class="panel"><div class="table-wrap"><table><thead><tr><th>Row</th><th>Field</th><th>Issue</th></tr></thead><tbody>{rows}</tbody></table></div></section>
            """
            self.respond(page("Import errors", body), HTTPStatus.BAD_REQUEST)
            return
        body = f"""
        <section class="hero"><div><h1>Import complete</h1><p class="muted">{result.assets_imported} assets and {result.components_imported} components imported. {match_count} impact matches refreshed.</p></div><a class="button" href="/assets">View assets</a></section>
        """
        self.respond(page("Import complete", body))

    def toggle_connector(self, form: dict[str, str]) -> None:
        connector_id = form.get("id", "").strip()
        with self.context.connection() as conn:
            set_connector_enabled(conn, connector_id, form.get("enabled") == "1")
        self.redirect(f"/connectors/{connector_id}")

    def test_connector_action(self, form: dict[str, str]) -> None:
        connector_id = form.get("id", "").strip()
        with self.context.connection() as conn:
            result = test_connector(conn, connector_id)
        if result.success:
            self.connector_detail(f"/connectors/{connector_id}", flash=result.message)
        else:
            self.connector_detail(f"/connectors/{connector_id}", error=result.message)

    def sync_connector_action(self, form: dict[str, str]) -> None:
        connector_id = form.get("id", "").strip()
        with self.context.connection() as conn:
            result = sync_connector(conn, connector_id)
        if result.success:
            self.connector_detail(
                f"/connectors/{connector_id}",
                flash=(
                    f"{result.imported_asset_count} assets and {result.imported_component_count} components imported. "
                    f"{result.match_count} impact matches refreshed."
                ),
            )
        else:
            self.connector_detail(f"/connectors/{connector_id}", error=result.message)

    def save_intune_connector_settings(self, form: dict[str, str]) -> None:
        with self.context.connection() as conn:
            save_intune_settings(conn, form)
        self.intune_setup_form(flash="Intune connector settings saved. Set the local secret env var before testing.")


def _is_loopback_bind_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_bind_mode(host: str, *, shared: bool) -> None:
    if shared:
        raise AppError(
            "Shared mode is not available yet.",
            detail=(
                "Refusing to start with --shared until SSRF protections, response limits, safe error handling, "
                "browser security headers, audit events, and HTTPS or reverse-proxy deployment settings are implemented."
            ),
        )
    if not _is_loopback_bind_host(host):
        raise AppError(
            "Refusing to bind the local web UI to a non-loopback address.",
            detail=(
                "Use the default 127.0.0.1 host for local mode. "
                "Shared mode is blocked until the remaining security roadmap prerequisites are implemented."
            ),
        )


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    db_path: Path | None = None,
    *,
    shared: bool = False,
) -> ThreadingHTTPServer:
    _validate_bind_mode(host, shared=shared)
    context = AppContext(db_path or database_path())
    with context.connection() as conn:
        seed_defaults(conn, legacy_watchlist_path(context.db_path.parent))

    class Handler(SecurityWatchHandler):
        pass

    Handler.context = context
    server = ThreadingHTTPServer((host, port), Handler)
    return server
