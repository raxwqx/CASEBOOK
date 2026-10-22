"""Case operations, evidence acquisition, validation, notes, and findings."""
from __future__ import annotations

import json
import mimetypes
import os
import re
import shutil
import tempfile
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .archive import UnsafeArchiveError, extract_validated, inspect_archive
from .integrity import append_audit, append_jsonl, read_jsonl, sha256_file, utc_now, verify_audit

SCHEMA_VERSION = 1
CASE_DIRS = (
    "evidence/originals",
    "evidence/derived",
    "findings",
    "timeline",
    "audit",
    "reports",
)
SEVERITIES = {"info", "low", "medium", "high", "critical"}
FINDING_STATUSES = {"open", "in_review", "resolved", "false_positive"}
NOTE_KINDS = {"observation", "action", "decision", "question", "context"}


class CasebookError(Exception):
    """An expected, user-correctable CASEBOOK operation error."""


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # A uniquely named temporary file avoids following a pre-planted .tmp symlink.
    fd, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def load_case(case_path: str | Path) -> tuple[Path, dict[str, Any]]:
    root = Path(case_path).expanduser().resolve()
    meta_path = root / "case.json"
    if meta_path.is_symlink():
        raise CasebookError("Case metadata must not be a symbolic link.")
    if not meta_path.is_file():
        raise CasebookError(f"'{root}' is not a CASEBOOK case (case.json not found). Initialize a case first.")
    try:
        with meta_path.open("r", encoding="utf-8") as stream:
            metadata = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CasebookError(f"Cannot read case metadata: {exc}") from exc
    if not isinstance(metadata, dict) or metadata.get("schema_version") != SCHEMA_VERSION:
        raise CasebookError("Unsupported or invalid case metadata schema.")
    for relative in CASE_DIRS:
        directory = root / relative
        # Check every component so a swapped directory symlink cannot redirect writes.
        current = root
        for component in Path(relative).parts:
            current = current / component
            if current.is_symlink():
                raise CasebookError(f"Case structure contains a symbolic link at '{current.relative_to(root)}'.")
        if not directory.is_dir():
            raise CasebookError(f"Case structure is incomplete: missing '{relative}/'.")
    for relative in ("evidence/index.jsonl", "findings/findings.jsonl", "timeline/events.jsonl", "audit/events.jsonl"):
        file_path = root / relative
        if file_path.is_symlink():
            raise CasebookError(f"Case data file must not be a symbolic link: '{relative}'.")
    return root, metadata


def init_case(path: str | Path, title: str | None = None, analyst: str | None = None, description: str = "") -> tuple[Path, dict[str, Any]]:
    requested = Path(path).expanduser()
    if requested.is_symlink():
        raise CasebookError("Case target must not be a symbolic link.")
    if requested.exists() and (not requested.is_dir() or any(requested.iterdir())):
        raise CasebookError(f"Target '{requested}' already exists and is not empty.")
    requested.mkdir(parents=True, exist_ok=True)
    root = requested.resolve()
    case_title = (title or root.name or "Untitled case").strip()
    if not case_title:
        raise CasebookError("Case title cannot be empty.")
    user = analyst if analyst is not None else os.environ.get("USER", os.environ.get("USERNAME", "analyst"))
    now = utc_now()
    case_id = "CB-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + os.urandom(3).hex().upper()
    metadata: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "title": case_title,
        "analyst": user.strip() or "analyst",
        "description": description.strip(),
        "status": "open",
        "created_at": now,
        "updated_at": now,
        "tool": "CASEBOOK",
    }
    for relative in CASE_DIRS:
        (root / relative).mkdir(parents=True, exist_ok=True)
    _atomic_json(root / "case.json", metadata)
    (root / "README.md").write_text(
        f"# {case_title}\n\nCASEBOOK case: `{case_id}`\n\n"
        "Keep original evidence in `evidence/originals/`. Derived archive members are stored under `evidence/derived/`.\n"
        "Use `casebook verify .` to re-check recorded file hashes and the audit hash chain.\n",
        encoding="utf-8",
    )
    append_audit(root, "case.initialized", {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "title": case_title,
        "analyst": metadata["analyst"],
        "created_at": now,
        "description": metadata["description"],
        "status": metadata["status"],
        "tool": metadata["tool"],
    })
    return root, metadata


def _safe_name(name: str, fallback: str = "evidence.bin") -> str:
    # Keep user-controlled and archive-controlled names inside a flat evidence directory.
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    name = re.sub(r"\s+", "_", name)
    if not name or name in {".", ".."}:
        name = fallback
    return name[:120]


def _next_evidence_id(root: Path) -> str:
    records = read_jsonl(root / "evidence" / "index.jsonl")
    highest = 0
    for record in records:
        match = re.fullmatch(r"EVD-(\d{4,})", str(record.get("evidence_id", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"EVD-{highest + 1:04d}"


def _write_case_metadata(root: Path, metadata: dict[str, Any]) -> None:
    metadata["updated_at"] = utc_now()
    _atomic_json(root / "case.json", metadata)


def _safe_relative_file(root: Path, relative: str) -> Path | None:
    if not isinstance(relative, str) or not relative:
        return None
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("..", ".") for part in pure.parts):
        return None
    candidate = root.joinpath(*pure.parts)
    # Refuse symlinks anywhere under the case, even when they currently resolve inside it.
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        candidate.resolve(strict=False).relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def add_evidence(case_path: str | Path, source_path: str | Path, source: str = "local acquisition", note: str = "") -> dict[str, Any]:
    root, metadata = load_case(case_path)
    source_file = Path(source_path).expanduser()
    if not source_file.exists() or not source_file.is_file():
        raise CasebookError(f"Evidence source is not a regular file: '{source_file}'.")
    if source_file.is_symlink():
        raise CasebookError("Symbolic-link input is rejected. Add the actual regular file instead.")
    source_file = source_file.resolve()
    if source_file.stat().st_size > 1024 * 1024 * 1024:
        raise CasebookError("Input exceeds CASEBOOK's 1 GiB per-input limit.")
    is_zip = zipfile_is_zip(source_file)
    if is_zip:
        try:
            inspect_archive(source_file)
        except UnsafeArchiveError as exc:
            raise CasebookError(str(exc)) from exc

    evidence_id = _next_evidence_id(root)
    safe_name = _safe_name(source_file.name)
    stored_name = f"{evidence_id}_{safe_name}"
    stored_relative = f"evidence/originals/{stored_name}"
    stored_path = root / stored_relative
    if stored_path.exists():
        raise CasebookError("Evidence destination already exists; refusing to overwrite existing evidence.")
    source_hash = sha256_file(source_file)
    source_size = source_file.stat().st_size
    final_derived_relative = f"evidence/derived/{evidence_id}"
    final_derived = root / final_derived_relative
    if is_zip and (final_derived.exists() or final_derived.is_symlink()):
        raise CasebookError("Derived-evidence destination already exists; refusing to overwrite it.")
    fd, temporary_original_name = tempfile.mkstemp(
        prefix=f".{evidence_id}-", suffix=".partial", dir=stored_path.parent
    )
    os.close(fd)
    temp_original = Path(temporary_original_name)
    temp_work: Path | None = None
    temp_derived: Path | None = None
    if is_zip:
        try:
            temp_work = Path(tempfile.mkdtemp(
                prefix=f".tmp-{evidence_id}-", dir=root / "evidence" / "derived"
            ))
            temp_derived = temp_work / "members"
        except Exception:
            temp_original.unlink(missing_ok=True)
            raise
    derived_records: list[dict[str, Any]] = []
    original_committed = False
    derived_committed = False
    try:
        with source_file.open("rb") as src, temp_original.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        if sha256_file(temp_original) != source_hash:
            raise CasebookError("Copied evidence hash does not match the source; import aborted.")
        # Exclusive creation works on filesystems that do not support hard links.
        # It also refuses to replace an existing evidence item.
        with temp_original.open("rb") as src, stored_path.open("xb") as dst:
            original_committed = True
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        if sha256_file(stored_path) != source_hash:
            raise CasebookError("Committed evidence hash does not match the source; import aborted.")
        temp_original.unlink()
        if is_zip and temp_derived is not None and temp_work is not None:
            try:
                # Validate and extract the preserved copy, not the user's source path.
                stored_members = inspect_archive(stored_path)
                raw_derived = extract_validated(stored_path, temp_derived, stored_members)
            except (UnsafeArchiveError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError) as exc:
                raise CasebookError(f"ZIP extraction failed safely; no evidence was committed: {exc}") from exc
            for item in raw_derived:
                member_name = str(item["member_name"])
                derived_records.append({
                    "archive_evidence_id": evidence_id,
                    "member_name": member_name,
                    "stored_path": f"{final_derived_relative}/{member_name}",
                    "size_bytes": int(item["size_bytes"]),
                    "sha256": str(item["sha256"]),
                })
            os.rename(temp_derived, final_derived)
            derived_committed = True
            temp_work.rmdir()
    except Exception:
        temp_original.unlink(missing_ok=True)
        if temp_work is not None and temp_work.exists():
            shutil.rmtree(temp_work, ignore_errors=True)
        if original_committed:
            stored_path.unlink(missing_ok=True)
        if derived_committed and final_derived.exists():
            shutil.rmtree(final_derived, ignore_errors=True)
        raise

    record: dict[str, Any] = {
        "evidence_id": evidence_id,
        "filename": source_file.name,
        "stored_path": stored_relative,
        "kind": "zip-archive" if is_zip else "file",
        "media_type": mimetypes.guess_type(source_file.name)[0] or "application/octet-stream",
        "size_bytes": source_size,
        "sha256": source_hash,
        "acquired_at": utc_now(),
        "source": (source.strip() or "unspecified")[:200],
        "note": note.strip()[:2000],
        "derived_count": len(derived_records),
    }
    append_jsonl(root / "evidence" / "index.jsonl", record)
    append_audit(root, "evidence.added", {"record": record, "derived_files": derived_records})
    _write_case_metadata(root, metadata)
    return record


def zipfile_is_zip(path: Path) -> bool:
    import zipfile
    return zipfile.is_zipfile(path)


def add_note(case_path: str | Path, text: str, kind: str = "observation", event_time: str | None = None) -> dict[str, Any]:
    root, metadata = load_case(case_path)
    clean_text = text.strip()
    if not clean_text:
        raise CasebookError("Note text cannot be empty.")
    if len(clean_text) > 8000:
        raise CasebookError("Note text exceeds 8,000 characters.")
    if kind not in NOTE_KINDS:
        raise CasebookError(f"Unknown note kind '{kind}'. Choose: {', '.join(sorted(NOTE_KINDS))}.")
    when = event_time or utc_now()
    record = {
        "note_id": f"NOTE-{len(read_jsonl(root / 'timeline' / 'events.jsonl')) + 1:04d}",
        "recorded_at": utc_now(),
        "event_time": when,
        "kind": kind,
        "text": clean_text,
    }
    append_jsonl(root / "timeline" / "events.jsonl", record)
    append_audit(root, "timeline.note_added", {"record": record})
    _write_case_metadata(root, metadata)
    return record


def add_finding(case_path: str | Path, title: str, severity: str, description: str, status: str = "open", evidence_ids: list[str] | None = None) -> dict[str, Any]:
    root, metadata = load_case(case_path)
    title, description = title.strip(), description.strip()
    if not title or not description:
        raise CasebookError("Finding title and description are required.")
    if len(title) > 240 or len(description) > 8000:
        raise CasebookError("Finding title or description exceeds the allowed length.")
    severity, status = severity.lower(), status.lower()
    if severity not in SEVERITIES:
        raise CasebookError(f"Invalid severity. Choose: {', '.join(sorted(SEVERITIES))}.")
    if status not in FINDING_STATUSES:
        raise CasebookError(f"Invalid status. Choose: {', '.join(sorted(FINDING_STATUSES))}.")
    evidence_records = read_jsonl(root / "evidence" / "index.jsonl")
    available_ids = {str(item.get("evidence_id")) for item in evidence_records}
    ids = sorted(set(evidence_ids or []))
    missing = [item for item in ids if item not in available_ids]
    if missing:
        raise CasebookError(f"Unknown evidence ID(s): {', '.join(missing)}")
    record = {
        "finding_id": f"FND-{len(read_jsonl(root / 'findings' / 'findings.jsonl')) + 1:04d}",
        "created_at": utc_now(),
        "title": title,
        "severity": severity,
        "status": status,
        "description": description,
        "evidence_ids": ids,
    }
    append_jsonl(root / "findings" / "findings.jsonl", record)
    append_audit(root, "finding.added", {"record": record})
    _write_case_metadata(root, metadata)
    return record


def _same_records(actual: list[dict[str, Any]], expected: list[dict[str, Any]]) -> bool:
    from .integrity import canonical_json
    return len(actual) == len(expected) and all(canonical_json(a) == canonical_json(e) for a, e in zip(actual, expected))


def verify_case(case_path: str | Path) -> dict[str, Any]:
    root, metadata = load_case(case_path)
    issues: list[str] = []
    try:
        audit = read_jsonl(root / "audit" / "events.jsonl")
    except ValueError as exc:
        audit, issues = [], [str(exc)]
    issues.extend(verify_audit(audit))
    init_events = [item for item in audit if item.get("action") == "case.initialized"]
    if len(init_events) != 1:
        issues.append("Expected exactly one case.initialized event in the audit journal.")
    else:
        initial = init_events[0].get("details", {})
        for field in ("schema_version", "case_id", "title", "analyst", "created_at", "description", "status", "tool"):
            if metadata.get(field) != initial.get(field):
                issues.append(f"Case metadata field '{field}' does not match the initialization audit record.")

    expected_evidence = [e["details"]["record"] for e in audit if e.get("action") == "evidence.added" and isinstance(e.get("details"), dict) and isinstance(e["details"].get("record"), dict)]
    expected_derived: list[dict[str, Any]] = []
    for entry in audit:
        if entry.get("action") == "evidence.added" and isinstance(entry.get("details"), dict):
            derived = entry["details"].get("derived_files", [])
            if isinstance(derived, list):
                expected_derived.extend(item for item in derived if isinstance(item, dict))
    try:
        evidence_index = read_jsonl(root / "evidence" / "index.jsonl")
        if not _same_records(evidence_index, expected_evidence):
            issues.append("Evidence index does not match the evidence records in the audit journal.")
    except ValueError as exc:
        evidence_index = []
        issues.append(str(exc))
    checked_files = 0
    for record in expected_evidence:
        relative = record.get("stored_path")
        candidate = _safe_relative_file(root, relative) if isinstance(relative, str) else None
        if candidate is None or not candidate.is_file():
            issues.append(f"Missing or unsafe evidence file for {record.get('evidence_id', 'unknown')}.")
            continue
        checked_files += 1
        if candidate.stat().st_size != record.get("size_bytes"):
            issues.append(f"Evidence size mismatch: {record.get('evidence_id')}.")
        try:
            if sha256_file(candidate) != record.get("sha256"):
                issues.append(f"Evidence SHA-256 mismatch: {record.get('evidence_id')}.")
        except OSError as exc:
            issues.append(f"Cannot read evidence {record.get('evidence_id')}: {exc}")
    for derived in expected_derived:
        candidate = _safe_relative_file(root, str(derived.get("stored_path", "")))
        if candidate is None or not candidate.is_file():
            issues.append(f"Missing or unsafe derived archive member: {derived.get('member_name', 'unknown')}.")
            continue
        checked_files += 1
        if candidate.stat().st_size != derived.get("size_bytes"):
            issues.append(f"Derived member size mismatch: {derived.get('member_name')}.")
        try:
            if sha256_file(candidate) != derived.get("sha256"):
                issues.append(f"Derived member SHA-256 mismatch: {derived.get('member_name')}.")
        except OSError as exc:
            issues.append(f"Cannot read derived member {derived.get('member_name')}: {exc}")

    # Flag stray files left by interrupted imports or manually copied into evidence folders.
    expected_original_paths = {str(item.get("stored_path")) for item in expected_evidence}
    originals_dir = root / "evidence" / "originals"
    for candidate in originals_dir.iterdir():
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink():
            issues.append(f"Symbolic link found in original evidence directory: {relative}.")
        elif candidate.is_file() and relative not in expected_original_paths:
            issues.append(f"Unregistered file in original evidence directory: {relative}.")
        elif candidate.is_dir():
            issues.append(f"Unexpected directory in original evidence directory: {relative}.")

    expected_derived_paths = {str(item.get("stored_path")) for item in expected_derived}
    derived_dir = root / "evidence" / "derived"
    allowed_derived_dirs: set[str] = set()
    for item in expected_derived:
        pure = PurePosixPath(str(item.get("stored_path", "")))
        for parent in list(pure.parents):
            if parent.as_posix() not in (".", ""):
                allowed_derived_dirs.add(parent.as_posix())
    for record in expected_evidence:
        if record.get("kind") == "zip-archive":
            allowed_derived_dirs.add(f"evidence/derived/{record.get('evidence_id')}")
    for directory, subdirs, filenames in os.walk(derived_dir, followlinks=False):
        directory_path = Path(directory)
        for dirname in list(subdirs):
            child = directory_path / dirname
            relative = child.relative_to(root).as_posix()
            if child.is_symlink():
                issues.append(f"Symbolic link found in derived evidence directory: {relative}.")
                subdirs.remove(dirname)
            elif relative not in allowed_derived_dirs:
                issues.append(f"Unregistered directory in derived evidence: {relative}.")
        for filename in filenames:
            candidate = directory_path / filename
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                issues.append(f"Symbolic link found in derived evidence: {relative}.")
            elif relative not in expected_derived_paths:
                issues.append(f"Unregistered file in derived evidence: {relative}.")

    expected_findings = [e["details"]["record"] for e in audit if e.get("action") == "finding.added" and isinstance(e.get("details"), dict) and isinstance(e["details"].get("record"), dict)]
    try:
        finding_index = read_jsonl(root / "findings" / "findings.jsonl")
        if not _same_records(finding_index, expected_findings):
            issues.append("Finding index does not match the finding records in the audit journal.")
    except ValueError as exc:
        issues.append(str(exc))
    expected_notes = [e["details"]["record"] for e in audit if e.get("action") == "timeline.note_added" and isinstance(e.get("details"), dict) and isinstance(e["details"].get("record"), dict)]
    try:
        note_index = read_jsonl(root / "timeline" / "events.jsonl")
        if not _same_records(note_index, expected_notes):
            issues.append("Timeline index does not match the note records in the audit journal.")
    except ValueError as exc:
        issues.append(str(exc))

    return {
        "ok": not issues,
        "case_id": metadata.get("case_id", "unknown"),
        "evidence_count": len(expected_evidence),
        "derived_count": len(expected_derived),
        "finding_count": len(expected_findings),
        "note_count": len(expected_notes),
        "audit_count": len(audit),
        "checked_files": checked_files,
        "issues": issues,
    }


def timeline(case_path: str | Path) -> list[dict[str, Any]]:
    root, _ = load_case(case_path)
    audit = read_jsonl(root / "audit" / "events.jsonl")
    events: list[dict[str, Any]] = []
    for event in audit:
        action = event.get("action", "event")
        details = event.get("details", {})
        if action == "timeline.note_added" and isinstance(details, dict):
            record = details.get("record", {})
            if isinstance(record, dict):
                events.append({"when": record.get("event_time", event.get("timestamp")), "kind": record.get("kind", "note"), "label": record.get("text", ""), "source": "analyst note", "sequence": event.get("sequence")})
        elif action == "evidence.added" and isinstance(details, dict):
            record = details.get("record", {})
            if isinstance(record, dict):
                events.append({"when": record.get("acquired_at", event.get("timestamp")), "kind": "evidence", "label": f"{record.get('evidence_id')} · {record.get('filename')}", "source": record.get("source", ""), "sequence": event.get("sequence")})
        elif action == "finding.added" and isinstance(details, dict):
            record = details.get("record", {})
            if isinstance(record, dict):
                events.append({"when": record.get("created_at", event.get("timestamp")), "kind": "finding", "label": f"{record.get('finding_id')} · {record.get('title')}", "source": record.get("severity", "info"), "sequence": event.get("sequence")})
    # ISO timestamps sort lexicographically when they are normalized to UTC. Invalid/unknown values sort last.
    events.sort(key=lambda item: (str(item.get("when", "~")), int(item.get("sequence", 0))))
    return events
