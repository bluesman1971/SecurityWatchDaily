"""Small HTML rendering helpers for the local web UI."""

from __future__ import annotations

import html
from urllib.parse import quote


def esc(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def urlq(value: object) -> str:
    return quote(str(value or ""))


def page(title: str, body: str, *, flash: str = "", error: str = "", auth_nav: bool = True) -> bytes:
    flash_html = f"<div class='notice'>{esc(flash)}</div>" if flash else ""
    error_html = f"<div class='error'>{esc(error)}</div>" if error else ""
    nav_html = (
        """
      <a href="/">Dashboard</a>
      <a href="/platforms">Platforms</a>
      <a href="/sources">Sources</a>
      <a href="/runs">Runs</a>
      <a href="/findings">Findings</a>
      <a href="/assets">Assets</a>
      <a href="/connectors">Connectors</a>
      <form class="nav-form" method="post" action="/logout"><button class="link-button">Logout</button></form>
        """
        if auth_nav
        else ""
    )
    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} · SecurityWatchDaily</title>
  <link rel="stylesheet" href="/static/app.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/"><span class="mark">S</span><span>SecurityWatchDaily<span class="brand-dot">.</span></span></a>
    <nav>
      {nav_html}
    </nav>
  </header>
  <main class="shell">
    {flash_html}
    {error_html}
    {body}
  </main>
</body>
</html>"""
    return html_text.encode("utf-8")


def badge(text: str) -> str:
    return f"<span class='badge {esc(text).lower()}'>{esc(text)}</span>"
