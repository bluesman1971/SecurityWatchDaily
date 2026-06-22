"""Local-only web server for SecurityWatchDaily."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
from securitywatchdaily.repositories.runs import get_finding, latest_run, list_findings, list_runs
from securitywatchdaily.repositories.sources import list_sources, save_source, set_source_enabled
from securitywatchdaily.services.asset_import_service import csv_template, import_inventory_csv
from securitywatchdaily.services.asset_matching_service import refresh_asset_matches_for_run
from securitywatchdaily.services.import_service import seed_defaults
from securitywatchdaily.services.run_service import run_watch
from securitywatchdaily.validation import split_csv

from .html import badge, esc, page

STATIC_DIR = Path(__file__).with_name("static")
MAX_POST_BYTES = 2 * 1024 * 1024


class AppContext:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @contextmanager
    def connection(self):
        conn = connect(self.db_path)
        try:
            initialize(conn)
            yield conn
        finally:
            conn.close()


class SecurityWatchHandler(BaseHTTPRequestHandler):
    context: AppContext

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path.startswith("/static/"):
                self.serve_static(parsed.path)
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
                "/api/health": self.health,
            }
            handler = routes.get(parsed.path)
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
            form = self.read_form()
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

    def respond(self, body: bytes, status: HTTPStatus = HTTPStatus.OK, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, path: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", path)
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
        <section class="hero"><div><h1>Assets</h1><p class="muted">CSV-backed inventory used for local impact matching.</p></div><a class="button" href="/assets/import">Import CSV</a></section>
        <section class="panel"><div class="table-wrap"><table><thead><tr><th>Asset</th><th>Type</th><th>Location</th><th>Platform</th><th>Components</th><th>Last seen</th></tr></thead><tbody>{rows or "<tr><td colspan='6'>No assets imported yet.</td></tr>"}</tbody></table></div></section>
        """
        self.respond(page("Assets", body))

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


def serve(host: str = "127.0.0.1", port: int = 8765, db_path: Path | None = None) -> ThreadingHTTPServer:
    context = AppContext(db_path or database_path())
    with context.connection() as conn:
        seed_defaults(conn, legacy_watchlist_path(context.db_path.parent))

    class Handler(SecurityWatchHandler):
        pass

    Handler.context = context
    server = ThreadingHTTPServer((host, port), Handler)
    return server
