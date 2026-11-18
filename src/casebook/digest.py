"""External, read-only case digest manifests for independent anchoring.

The manifest is deliberately kept outside the case directory. It records the
case metadata, evidence register, derived members, findings, notes and the
current audit-chain head, then hashes that snapshot. Verification is read-only
and never repairs or rewrites the case.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import __app_name__, __version__
from .core import CasebookError, _write_case_metadata, load_case, verify_case
from .integrity import (
    GENESIS_HASH,
    append_audit,
    canonical_json,
    read_jsonl,
    sha256_bytes,
    utc_now,
)

MANIFEST_FORMAT = "casebook-digest-v1"
MANIFEST_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
CASE_FIELDS = (
    "schema_version",
    "case_id",
    "title",
    "analyst",
    "description",
    "status",
    "created_at",
    "tool",
)


def _read_records(path: Path) -> list[dict[str, Any]]:
    try:
        return read_jsonl(path)
    except (ValueError, OSError) as exc:
        raise CasebookError(f"Cannot read case records: {exc}") from exc


def _derived_records(audit: list[dict[str, Any]]) -> list[dict[str, Any]]:
    derived: list[dict[str, Any]] = []
    for entry in audit:
        if entry.get("action") != "evidence.added" or not isinstance(entry.get("details"), dict):
            continue
        members = entry["details"].get("derived_files", [])
        if not isinstance(members, list):
            continue
        for item in members:
            if not isinstance(item, dict):
                continue
            derived.append({
                "archive_evidence_id": item.get("archive_evidence_id"),
                "member_name": item.get("member_name"),
                "stored_path": item.get("stored_path"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
            })
    derived.sort(key=lambda item: (str(item.get("archive_evidence_id")), str(item.get("member_name"))))
    return derived


def _snapshot(root: Path, metadata: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    audit = _read_records(root / "audit" / "events.jsonl")
    evidence = _read_records(root / "evidence" / "index.jsonl")
    findings = _read_records(root / "findings" / "findings.jsonl")
    notes = _read_records(root / "timeline" / "events.jsonl")
    derived = _derived_records(audit)
    last = audit[-1] if audit else {}
    snapshot = {
        "case": {field: metadata.get(field) for field in CASE_FIELDS},
        "audit": {
            "count": len(audit),
            "head_hash": str(last.get("event_hash", GENESIS_HASH)),
            "head_timestamp": last.get("timestamp"),
        },
        "counts": {
            "evidence": len(evidence),
            "derived": len(derived),
            "findings": len(findings),
            "notes": len(notes),
            "audit": len(audit),
        },
        "evidence": evidence,
        "derived": derived,
        "findings": findings,
        "notes": notes,
    }
    return snapshot, audit


def build_digest(case_path: str | Path) -> dict[str, Any]:
    """Build an in-memory, read-only digest manifest for a case."""
    root, metadata = load_case(case_path)
    body: dict[str, Any] = {
        "manifest_format": MANIFEST_FORMAT,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "tool": {"name": __app_name__, "version": __version__},
    }
    snapshot, _ = _snapshot(root, metadata)
    body.update(snapshot)
    body["digest"] = sha256_bytes(canonical_json(body))
    return body


def export_digest(case_path: str | Path, out: str | Path) -> tuple[Path, dict[str, Any], bool]:
    """Write a new digest manifest and record the export in the audit journal.

    Returns the destination, manifest and whether the audit event could be
    recorded. The manifest is written first so an audit failure cannot discard
    an otherwise valid external snapshot.
    """
    manifest = build_digest(case_path)
    destination = Path(out).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"Digest destination already exists: {destination}")
    content = (json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(content) > MAX_MANIFEST_BYTES:
        raise ValueError("Generated digest manifest exceeds CASEBOOK's 32 MiB manifest limit.")
    with destination.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    root, metadata = load_case(case_path)
    audit_recorded = True
    try:
        append_audit(root, "digest.exported", {
            "path": str(destination),
            "manifest_sha256": sha256_bytes(content),
            "digest": manifest["digest"],
            "audit_anchor": manifest["audit"],
        })
    except (ValueError, OSError):
        audit_recorded = False
    else:
        _write_case_metadata(root, metadata)
    return destination, manifest, audit_recorded


def load_manifest(manifest_path: str | Path) -> dict[str, Any]:
    path = Path(manifest_path).expanduser()
    if path.is_symlink():
        raise CasebookError("Digest manifest must not be a symbolic link.")
    if not path.is_file():
        raise CasebookError(f"Digest manifest not found: {path}")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise CasebookError("Digest manifest exceeds CASEBOOK's 32 MiB manifest limit.")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CasebookError(f"Cannot read digest manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise CasebookError("Digest manifest must contain a JSON object.")
    return manifest


def verify_digest(case_path: str | Path, manifest_path: str | Path) -> dict[str, Any]:
    """Compare a stored manifest with the current case without modifying it."""
    manifest = load_manifest(manifest_path)
    problems: list[str] = []
    if manifest.get("manifest_format") != MANIFEST_FORMAT:
        problems.append(f"Unsupported manifest format: {manifest.get('manifest_format')!r}.")
    recorded_digest = manifest.get("digest")
    body = {key: value for key, value in manifest.items() if key != "digest"}
    if not isinstance(recorded_digest, str) or len(recorded_digest) != 64:
        problems.append("Manifest does not contain a valid SHA-256 digest.")
    elif sha256_bytes(canonical_json(body)) != recorded_digest:
        problems.append("Manifest digest does not match its own contents; the file was altered.")

    snapshot: dict[str, Any] | None = None
    current_audit: list[dict[str, Any]] = []
    try:
        root, metadata = load_case(case_path)
        snapshot, current_audit = _snapshot(root, metadata)
        integrity = verify_case(root)
        for issue in integrity["issues"]:
            problems.append(f"Current case integrity check: {issue}")
    except (CasebookError, ValueError, OSError) as exc:
        problems.append(f"Cannot read the current case digest: {exc}")

    if snapshot is not None:
        for key, label in (
            ("case", "Case metadata"),
            ("evidence", "Evidence register"),
            ("derived", "Derived evidence register"),
            ("findings", "Findings register"),
            ("notes", "Notes register"),
        ):
            if manifest.get(key) != snapshot[key]:
                problems.append(f"{label} differs from the exported digest snapshot.")
        anchor = manifest.get("audit")
        if not isinstance(anchor, dict):
            problems.append("Manifest audit anchor is missing or invalid.")
        else:
            count = anchor.get("count")
            head = anchor.get("head_hash")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0 or not isinstance(head, str):
                problems.append("Manifest audit anchor is missing or invalid.")
            elif len(current_audit) == 0 and count == 0:
                if head != GENESIS_HASH:
                    problems.append("Manifest audit anchor is invalid for an empty journal.")
            elif len(current_audit) < count:
                problems.append(
                    f"Audit journal is shorter than the anchored snapshot ({len(current_audit)} < {count})."
                )
            elif str(current_audit[count - 1].get("event_hash")) != head:
                problems.append("Audit journal no longer matches the anchored snapshot hash.")

    counts = snapshot["counts"] if snapshot is not None else manifest.get("counts", {})
    source = snapshot if snapshot is not None else manifest
    case_info = source.get("case")
    case_id = str(case_info.get("case_id", "unknown")) if isinstance(case_info, dict) else "unknown"
    return {
        "ok": not problems,
        "case_id": case_id,
        "manifest_generated_at": manifest.get("generated_at"),
        "manifest_digest": recorded_digest if isinstance(recorded_digest, str) else "invalid",
        "audit_anchor": manifest.get("audit", {}),
        "counts": counts if isinstance(counts, dict) else {},
        "problems": problems,
    }
