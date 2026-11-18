"""Safe, self-contained case report renderers."""
from __future__ import annotations

import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import load_case, timeline_from_events, verify_case
from .integrity import read_jsonl, sha256_bytes, utc_now

REPORT_SCHEMA_VERSION = 2
MAX_REPORT_SIZE_BYTES = 64 * 1024 * 1024


def _safe_int(value: Any) -> int:
    """Render a byte count defensively; tampered indexes may hold any JSON type."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if value >= 0 else 0
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return 0


def _collect_index(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    try:
        return read_jsonl(path)
    except (ValueError, OSError) as exc:
        errors.append(f"Cannot read {path.name}: {exc}")
        return []


def collect_report_data(case_path: str | Path) -> dict[str, Any]:
    root, metadata = load_case(case_path)
    errors: list[str] = []
    evidence = _collect_index(root / "evidence" / "index.jsonl", errors)
    findings = _collect_index(root / "findings" / "findings.jsonl", errors)
    audit = _collect_index(root / "audit" / "events.jsonl", errors)
    # Build the timeline from the already collected audit records so a damaged
    # index cannot prevent an integrity-failure report from being produced.
    collection_errors: list[str] = []
    try:
        events = timeline_from_events(audit)
    except (ValueError, OSError) as exc:
        events = []
        collection_errors.append(f"Cannot build timeline: {exc}")
    integrity = verify_case(root)
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "case": metadata,
        "integrity": integrity,
        "collection_errors": errors + collection_errors,
        "evidence": evidence,
        "findings": findings,
        "timeline": events,
        "audit": audit,
    }


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def render_markdown(data: dict[str, Any]) -> str:
    case = data["case"]
    integrity = data["integrity"]
    lines = [
        f"# CASEBOOK Investigation Report: {case.get('title', 'Untitled case')}",
        "",
        f"- **Case ID:** `{case.get('case_id', 'unknown')}`",
        f"- **Analyst:** {case.get('analyst', 'unspecified')}",
        f"- **Created (UTC):** {case.get('created_at', 'unknown')}",
        f"- **Report generated (UTC):** {data['generated_at']}",
        f"- **Status:** {case.get('status', 'unknown')}",
        "",
        "> Scope note: this report describes records held in this CASEBOOK case. It does not independently validate the truth of analyst statements or establish legal chain-of-custody requirements.",
        "",
        "## Integrity summary",
        "",
        f"- **Result:** {'PASS' if integrity['ok'] else 'FAIL'}",
        f"- Evidence files checked: {integrity['checked_files']}",
        f"- Original evidence records: {integrity['evidence_count']}",
        f"- Derived archive members: {integrity['derived_count']}",
        f"- Audit records: {integrity['audit_count']}",
    ]
    if integrity["issues"]:
        lines += ["", "### Integrity issues", ""]
        lines.extend(f"- {issue}" for issue in integrity["issues"])
    if data.get("collection_errors"):
        lines += ["", "### Record collection problems", ""]
        lines.extend(f"- {issue}" for issue in data["collection_errors"])
    lines += ["", "## Evidence register", ""]
    if data["evidence"]:
        lines += ["| ID | Filename | SHA-256 | Size (bytes) | Type |", "|---|---|---|---:|---|"]
        for record in data["evidence"]:
            filename = str(record.get("filename", "")).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {record.get('evidence_id')} | {filename} | `{record.get('sha256')}` | {_safe_int(record.get('size_bytes'))} | {record.get('kind')} |")
    else:
        lines.append("No evidence has been registered.")
    lines += ["", "## Findings", ""]
    if data["findings"]:
        for finding in data["findings"]:
            lines += [
                f"### {finding.get('finding_id')} · {finding.get('title')}",
                "",
                f"- **Severity:** {str(finding.get('severity', 'info')).upper()}",
                f"- **Status:** {finding.get('status', 'open')}",
                f"- **Created (UTC):** {finding.get('created_at', 'unknown')}",
                f"- **Evidence:** {', '.join(finding.get('evidence_ids', [])) or 'None linked'}",
                "",
                str(finding.get("description", "")),
                "",
            ]
    else:
        lines.append("No findings have been recorded.")
    lines += ["", "## Timeline", ""]
    if data["timeline"]:
        lines += ["| Time | Type | Event | Source / detail |", "|---|---|---|---|"]
        for event in data["timeline"]:
            label = str(event.get("label", "")).replace("|", "\\|").replace("\n", " ")
            source = str(event.get("source", "")).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {event.get('when', '')} | {event.get('kind', '')} | {label} | {source} |")
    else:
        lines.append("No timeline events have been recorded.")
    lines += [
        "",
        "## Methodology and limitations",
        "",
        "- Original input files are copied into the case and hashed with SHA-256.",
        "- ZIP inputs are preserved as original evidence; permitted regular members are extracted into a separate derived-evidence area under conservative import limits.",
        "- The audit journal uses a SHA-256 hash chain to detect accidental or unsophisticated modification. Because it is stored locally with the case, it is not tamper-proof against a capable actor who can rewrite the journal and recompute its hashes.",
        "- A matching hash indicates byte-for-byte consistency with the recorded digest; it does not prove who created a file, when it was originally created, or that its contents are true.",
        "",
    ]
    return "\n".join(lines)


def render_html(data: dict[str, Any]) -> str:
    case = data["case"]
    integrity = data["integrity"]
    ok = bool(integrity["ok"])
    status_class = "pass" if ok else "fail"
    evidence_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{:,}</td><td>{}</td></tr>".format(
            html.escape(str(r.get("evidence_id", ""))), html.escape(str(r.get("filename", ""))),
            html.escape(str(r.get("sha256", ""))), _safe_int(r.get("size_bytes")), html.escape(str(r.get("kind", "")))
        ) for r in data["evidence"]
    ) or '<tr><td colspan="5" class="muted">No evidence registered.</td></tr>'
    finding_cards: list[str] = []
    for finding in data["findings"]:
        finding_cards.append(
            '<article class="finding"><div class="finding-top"><span class="pill">{}</span><span class="muted">{}</span></div>'
            '<h3>{}</h3><p>{}</p><p class="muted">Evidence: {}</p></article>'.format(
                html.escape(str(finding.get("severity", "info")).upper()),
                html.escape(str(finding.get("status", "open"))),
                html.escape(str(finding.get("title", ""))),
                html.escape(str(finding.get("description", ""))),
                html.escape(", ".join(finding.get("evidence_ids", [])) or "None linked"),
            )
        )
    findings_html = "".join(finding_cards) or '<p class="muted">No findings recorded.</p>'
    timeline_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(e.get("when", ""))), html.escape(str(e.get("kind", ""))),
            html.escape(str(e.get("label", ""))), html.escape(str(e.get("source", ""))),
        ) for e in data["timeline"]
    ) or '<tr><td colspan="4" class="muted">No timeline events recorded.</td></tr>'
    issues_html = "".join(f"<li>{html.escape(str(issue))}</li>" for issue in integrity["issues"])
    collection_html = "".join(f"<li>{html.escape(str(issue))}</li>" for issue in data.get("collection_errors", []))
    collection_section = (
        '<section class="section"><h2>Record collection problems</h2><ul>' + collection_html + "</ul></section>"
    ) if collection_html else ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark"><title>CASEBOOK | {html.escape(str(case.get("title", "Case report")))}</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2d;--line:#26334b;--text:#e5edf8;--muted:#91a2bc;--cyan:#67e8f9;--blue:#60a5fa;--green:#86efac;--red:#fca5a5}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at 10% 0%,#152746 0,transparent 42%),var(--bg);color:var(--text);font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1100px;margin:auto;padding:42px 22px 70px}}.eyebrow{{text-transform:uppercase;letter-spacing:.18em;color:var(--cyan);font-size:.75rem;font-weight:800}}h1{{font-size:clamp(2rem,5vw,3.4rem);line-height:1.1;margin:.5rem 0}}h2{{font-size:1.25rem;margin:0 0 16px}}h3{{margin:.3rem 0 .6rem}}.sub{{color:var(--muted);margin:0 0 26px}}.meta-grid,.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:22px 0}}.card,.section{{background:linear-gradient(145deg,rgba(18,26,45,.96),rgba(12,19,34,.96));border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:0 10px 32px #0002}}.label{{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}}.value{{font-weight:650;overflow-wrap:anywhere}}.metric{{font-size:1.65rem;font-weight:800}}.pass{{color:var(--green)}}.fail{{color:var(--red)}}.section{{margin-top:18px;overflow:hidden}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:.88rem}}th,td{{text-align:left;border-bottom:1px solid var(--line);padding:11px 10px;vertical-align:top}}th{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.07em}}td code{{font-size:.78rem;overflow-wrap:anywhere}}.finding{{border:1px solid var(--line);border-radius:12px;padding:16px;margin:12px 0;background:#0b1325}}.finding-top{{display:flex;justify-content:space-between;gap:12px}}.pill{{font-weight:800;font-size:.72rem;letter-spacing:.08em;color:var(--cyan)}}.muted{{color:var(--muted)}}.note{{border-left:3px solid var(--blue);padding:10px 14px;background:#0d1729;color:var(--muted);font-size:.88rem;margin-top:16px}}footer{{color:var(--muted);font-size:.8rem;margin-top:28px}}@media(max-width:600px){{main{{padding:26px 14px}}.section{{padding:14px}}}}
</style></head><body><main>
<div class="eyebrow">▣ CASEBOOK / Investigation report</div><h1>{html.escape(str(case.get("title", "Untitled case")))}</h1>
<p class="sub">Case <code>{html.escape(str(case.get("case_id", "unknown")))}</code> · Generated {html.escape(str(data["generated_at"]))}</p>
<div class="meta-grid"><div class="card"><div class="label">Analyst</div><div class="value">{html.escape(str(case.get("analyst", "unspecified")))}</div></div><div class="card"><div class="label">Created (UTC)</div><div class="value">{html.escape(str(case.get("created_at", "unknown")))}</div></div><div class="card"><div class="label">Case status</div><div class="value">{html.escape(str(case.get("status", "unknown")).upper())}</div></div></div>
<div class="metrics"><div class="card"><div class="label">Integrity</div><div class="metric {status_class}">{'PASS' if ok else 'FAIL'}</div></div><div class="card"><div class="label">Original evidence</div><div class="metric">{integrity['evidence_count']}</div></div><div class="card"><div class="label">Derived files checked</div><div class="metric">{integrity['checked_files']}</div></div><div class="card"><div class="label">Audit entries</div><div class="metric">{integrity['audit_count']}</div></div></div>
{('<section class="section"><h2>Integrity issues</h2><ul>'+issues_html+'</ul></section>') if integrity['issues'] else ''}
{collection_section}
<section class="section"><h2>Evidence register</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Filename</th><th>SHA-256</th><th>Bytes</th><th>Kind</th></tr></thead><tbody>{evidence_rows}</tbody></table></div></section>
<section class="section"><h2>Findings</h2>{findings_html}</section>
<section class="section"><h2>Timeline</h2><div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Event</th><th>Source / detail</th></tr></thead><tbody>{timeline_rows}</tbody></table></div></section>
<section class="section"><h2>Methodology & limitations</h2><p>Original inputs are preserved and hashed with SHA-256. Permitted ZIP members are extracted as derived evidence under size and path restrictions. The audit journal's hash chain can reveal accidental or unsophisticated changes, but is not tamper-proof against an actor able to rewrite the entire local journal. Matching hashes prove byte consistency with the recorded digest, not authorship, original creation time, or factual truth.</p></section>
<div class="note">This report summarizes records held in the local CASEBOOK workspace. It is not a legal certification of chain of custody.</div>
<footer>Generated offline by CASEBOOK · {html.escape(str(data["generated_at"]))}</footer></main></body></html>'''


def _default_report_path(root: Path, safe_id: str, ext: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    reports_dir = root / "reports"
    candidate = reports_dir / f"{safe_id}_{stamp}.{ext}"
    counter = 2
    # Microsecond precision makes collisions unlikely; the loop keeps two
    # reports created in the same clock tick from failing the second export.
    while candidate.exists():
        candidate = reports_dir / f"{safe_id}_{stamp}-{counter}.{ext}"
        counter += 1
    return candidate


def write_report(case_path: str | Path, fmt: str, out: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    root, metadata = load_case(case_path)
    data = collect_report_data(root)
    fmt = fmt.lower()
    if fmt in {"md", "markdown"}:
        ext, content = "md", render_markdown(data)
    elif fmt == "json":
        ext, content = "json", render_json(data)
    elif fmt == "html":
        ext, content = "html", render_html(data)
    else:
        raise ValueError("Report format must be markdown, json, or html.")
    if out:
        destination = Path(out).expanduser().resolve()
    else:
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(metadata.get("case_id", "case"))) or "case"
        destination = _default_report_path(root, safe_id, ext)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Never silently overwrite prior reports.
    if destination.exists():
        raise FileExistsError(f"Report destination already exists: {destination}")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_REPORT_SIZE_BYTES:
        raise ValueError("Generated report exceeds CASEBOOK's 64 MiB report limit.")
    with destination.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    from .core import _write_case_metadata
    integrity = data["integrity"]
    integrity["report_audit_recorded"] = True
    try:
        from .integrity import append_audit
        append_audit(root, "report.generated", {"format": ext, "path": str(destination), "sha256": sha256_bytes(encoded)})
    except (ValueError, OSError):
        # The report is already durable. A damaged audit journal must not hide
        # the report that documents the integrity failure.
        integrity["report_audit_recorded"] = False
    else:
        _write_case_metadata(root, metadata)
    return destination, integrity
