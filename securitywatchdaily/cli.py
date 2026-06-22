"""Command-line entry point for local operation and scheduling."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import database_path, legacy_watchlist_path
from .database import connect, initialize
from .errors import AppError
from .repositories.platforms import list_platforms
from .repositories.runs import latest_run, list_findings
from .repositories.sources import list_sources
from .services.import_service import seed_defaults
from .services.run_service import run_watch
from .web.server import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securitywatchdaily", description="Local daily vulnerability watch tool.")
    parser.add_argument("--db", type=Path, default=database_path(), help="Path to the local SQLite database.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Initialize database and import watchlist.json when present.")
    sub.add_parser("validate", help="Validate database-backed platforms and sources.")
    run_parser = sub.add_parser("run", help="Run vulnerability collection.")
    run_parser.add_argument("--sample", action="store_true", help="Use offline sample findings for practical validation.")
    run_parser.add_argument("--force-visible", action="store_true", help="Show unchanged trace items for this run.")
    serve_parser = sub.add_parser("serve", help="Start the local web UI.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument(
        "--shared",
        action="store_true",
        help="Request shared network mode. Requires authentication support.",
    )
    sub.add_parser("summary", help="Print a JSON summary of the current local state.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            server = serve(args.host, args.port, args.db, shared=args.shared)
            print(f"SecurityWatchDaily is running at http://{args.host}:{args.port}")
            server.serve_forever()
            return 0
        with connect(args.db) as conn:
            initialize(conn)
            if args.command == "init":
                result = seed_defaults(conn, legacy_watchlist_path(args.db.parent))
                print(json.dumps({"initialized": True, **result}, indent=2))
            elif args.command == "validate":
                seed_defaults(conn, legacy_watchlist_path(args.db.parent))
                print(json.dumps({"platforms": len(list_platforms(conn)), "sources": len(list_sources(conn)), "valid": True}, indent=2))
            elif args.command == "run":
                seed_defaults(conn, legacy_watchlist_path(args.db.parent))
                record = run_watch(conn, offline_sample=args.sample, force_visible=args.force_visible)
                print(json.dumps(record.__dict__, indent=2, sort_keys=True))
            elif args.command == "summary":
                seed_defaults(conn, legacy_watchlist_path(args.db.parent))
                run = latest_run(conn)
                findings = list_findings(conn, run_id=run.run_id, visible_only=True) if run else []
                print(
                    json.dumps(
                        {
                            "platforms": len(list_platforms(conn)),
                            "sources": len(list_sources(conn)),
                            "latest_run": run.run_id if run else None,
                            "visible_findings": len(findings),
                        },
                        indent=2,
                    )
                )
        return 0
    except KeyboardInterrupt:
        return 130
    except AppError as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        if exc.detail:
            print(exc.detail, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
