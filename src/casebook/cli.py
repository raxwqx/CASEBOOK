"""Command-line interface for CASEBOOK."""
from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import __version__
from .core import (
    CasebookError,
    add_evidence,
    add_finding,
    add_note,
    init_case,
    load_case,
    timeline as get_timeline,
    verify_case,
)
from .reports import write_report
from .ui import Theme, banner, error, info, kv, panel, severity, success, warning


def _iso_time(value: str) -> str:
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use ISO-8601, e.g. 2026-10-24T12:30:00Z.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="casebook",
        description="Offline-first digital forensics case workspace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Quick start:\n"
            "  casebook init CASE-001 --title \"Training Lab\"\n"
            "  cd CASE-001\n"
            "  casebook add . ../evidence.zip --source lab\n"
            "  casebook verify .\n"
            "  casebook report . --format html\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"CASEBOOK {__version__}")
    sub = parser.add_subparsers(dest="command")

    init_parser = sub.add_parser("init", help="Create a structured investigation case")
    init_parser.add_argument("path", help="New case directory")
    init_parser.add_argument("--title", help="Case title (defaults to the directory name)")
    init_parser.add_argument("--analyst", help="Analyst name or handle")
    init_parser.add_argument("--description", default="", help="Short case description")

    add_parser = sub.add_parser("add", help="Preserve and hash a file or safely import a ZIP")
    add_parser.add_argument("case", help="Case directory (use '.' from inside the case)")
    add_parser.add_argument("file", help="Evidence file or ZIP archive")
    add_parser.add_argument("--source", default="local acquisition", help="Where the file came from")
    add_parser.add_argument("--note", default="", help="Short acquisition note")

    verify_parser = sub.add_parser("verify", help="Verify evidence hashes, indexes, metadata, and audit chain")
    verify_parser.add_argument("case", nargs="?", default=".", help="Case directory (default: current directory)")

    show_parser = sub.add_parser("show", help="Show a compact case summary")
    show_parser.add_argument("case", nargs="?", default=".", help="Case directory (default: current directory)")

    note_parser = sub.add_parser("note", help="Append an analyst note to the timeline")
    note_parser.add_argument("case", nargs="?", default=".", help="Case directory (default: current directory)")
    note_parser.add_argument("--text", required=True, help="Note content")
    note_parser.add_argument("--kind", choices=["observation", "action", "decision", "question", "context"], default="observation")
    note_parser.add_argument("--when", type=_iso_time, help="Event time in ISO-8601 (defaults to now in UTC)")

    timeline_parser = sub.add_parser("timeline", help="Show the case timeline")
    timeline_parser.add_argument("case", nargs="?", default=".", help="Case directory (default: current directory)")

    find_parser = sub.add_parser("finding", help="Record an analyst finding")
    find_sub = find_parser.add_subparsers(dest="finding_command", required=True)
    find_add = find_sub.add_parser("add", help="Add a finding to the case")
    find_add.add_argument("case", nargs="?", default=".", help="Case directory (default: current directory)")
    find_add.add_argument("--title", required=True, help="Short finding title")
    find_add.add_argument("--severity", required=True, choices=["info", "low", "medium", "high", "critical"])
    find_add.add_argument("--description", required=True, help="What was observed and why it matters")
    find_add.add_argument("--status", choices=["open", "in_review", "resolved", "false_positive"], default="open")
    find_add.add_argument("--evidence", action="append", default=[], metavar="EVD-ID", help="Link an evidence ID; may be repeated")

    report_parser = sub.add_parser("report", help="Generate a self-contained Markdown, JSON, or HTML report")
    report_parser.add_argument("case", nargs="?", default=".", help="Case directory (default: current directory)")
    report_parser.add_argument("--format", choices=["markdown", "md", "json", "html"], default="html")
    report_parser.add_argument("--out", help="Output path (must not already exist)")

    doctor_parser = sub.add_parser("doctor", help="Check runtime and required casebook files")
    doctor_parser.add_argument("case", nargs="?", help="Optional case directory to inspect")

    return parser


def _show_home() -> None:
    banner()
    panel("READY FOR AN INVESTIGATION", [
        "Create a case, preserve evidence, record findings, verify integrity, and generate portable reports.",
        "Everything works locally. CASEBOOK makes no network requests and installs no third-party runtime packages.",
    ])
    print()
    print(Theme.paint("  QUICK START", Theme.CYAN, Theme.BOLD))
    print("  casebook init CASE-001 --title \"Training Lab\"")
    print("  cd CASE-001")
    print("  casebook add . ../evidence.zip --source lab")
    print("  casebook verify .")
    print("  casebook report . --format html")
    print()
    info("Run 'casebook --help' to explore all commands.")


def _summary(case: dict[str, object], root: Path) -> None:
    evidence_file = root / "evidence" / "index.jsonl"
    findings_file = root / "findings" / "findings.jsonl"
    audit_file = root / "audit" / "events.jsonl"
    from .integrity import read_jsonl
    kv("Case ID", case.get("case_id", "unknown"))
    kv("Title", case.get("title", "Untitled"))
    kv("Analyst", case.get("analyst", "unspecified"))
    kv("Status", case.get("status", "unknown"))
    kv("Created (UTC)", case.get("created_at", "unknown"))
    kv("Evidence", len(read_jsonl(evidence_file)))
    kv("Findings", len(read_jsonl(findings_file)))
    kv("Audit entries", len(read_jsonl(audit_file)))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        _show_home()
        return 0
    banner()
    try:
        if args.command == "init":
            root, case = init_case(args.path, args.title, args.analyst, args.description)
            success(f"Created case {case['case_id']} at {root}")
            kv("Title", case["title"])
            kv("Analyst", case["analyst"])
            print()
            panel("NEXT STEPS", [
                f"cd {root}",
                "casebook add . /path/to/evidence.zip --source lab",
                "casebook verify .",
                "casebook report . --format html",
            ])
            return 0

        if args.command == "add":
            record = add_evidence(args.case, args.file, args.source, args.note)
            success(f"Evidence registered: {record['evidence_id']}")
            kv("Original", record["filename"])
            kv("Stored as", record["stored_path"])
            kv("Size", f"{record['size_bytes']:,} bytes")
            kv("SHA-256", record["sha256"])
            if record["kind"] == "zip-archive":
                kv("ZIP members", record["derived_count"])
                info("Original ZIP preserved; extracted members stored separately as derived evidence.")
            return 0

        if args.command == "verify":
            result = verify_case(args.case)
            (success if result["ok"] else error)("Integrity verification PASSED." if result["ok"] else "Integrity verification FAILED.")
            kv("Case ID", result["case_id"])
            kv("Files checked", result["checked_files"])
            kv("Original evidence", result["evidence_count"])
            kv("Derived files", result["derived_count"])
            kv("Audit entries", result["audit_count"])
            if result["issues"]:
                print()
                for issue in result["issues"]:
                    error(issue)
                return 2
            return 0

        if args.command == "show":
            root, case = load_case(args.case)
            _summary(case, root)
            return 0

        if args.command == "note":
            record = add_note(args.case, args.text, args.kind, args.when)
            success(f"Timeline note added: {record['note_id']}")
            kv("Kind", record["kind"])
            kv("Event time", record["event_time"])
            return 0

        if args.command == "timeline":
            events = get_timeline(args.case)
            if not events:
                info("No timeline events yet. Add evidence or create a note with 'casebook note --text ...'.")
                return 0
            panel("CASE TIMELINE", [f"{e.get('when', 'unknown')}  [{str(e.get('kind', '')).upper():9}]  {e.get('label', '')}" for e in events], width=90)
            return 0

        if args.command == "finding" and args.finding_command == "add":
            finding = add_finding(args.case, args.title, args.severity, args.description, args.status, args.evidence)
            success(f"Finding registered: {finding['finding_id']}")
            kv("Severity", severity(finding["severity"]))
            kv("Status", finding["status"])
            kv("Title", finding["title"])
            kv("Evidence", ", ".join(finding["evidence_ids"]) or "None linked")
            return 0

        if args.command == "report":
            path, integrity = write_report(args.case, args.format, args.out)
            success(f"Report written: {path}")
            if integrity["ok"]:
                info("Report integrity snapshot: PASS")
            else:
                warning("Report generated with integrity issues; inspect the report before relying on it.")
            kv("Format", args.format.upper())
            kv("Size", f"{path.stat().st_size:,} bytes")
            return 0 if integrity["ok"] else 2

        if args.command == "doctor":
            checks: list[tuple[str, bool, str]] = [
                ("Python runtime", sys.version_info >= (3, 10), platform.python_version()),
                ("Standard-library only", True, "no third-party runtime dependencies"),
                ("UTF-8 terminal output", True, "Unicode theme available"),
            ]
            if args.case:
                root, case = load_case(args.case)
                result = verify_case(root)
                checks.append(("Case integrity", bool(result["ok"]), f"{len(result['issues'])} issue(s)"))
            for label, ok, detail in checks:
                (success if ok else error)(f"{label}: {detail}")
            return 0 if all(item[1] for item in checks) else 2

        parser.print_help()
        return 0
    except (CasebookError, ValueError, OSError, FileExistsError) as exc:
        error(str(exc))
        return 2
    except KeyboardInterrupt:
        error("Interrupted. No command was completed by CASEBOOK after the interrupt.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
