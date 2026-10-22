"""Hash-chain audit journal and integrity helpers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"Expected a JSON object in {path.name} at line {line_number}")
            records.append(item)
    return records


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def audit_event_hash(event_without_hash: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(event_without_hash))


def append_audit(case_root: Path, action: str, details: dict[str, Any]) -> dict[str, Any]:
    audit_path = case_root / "audit" / "events.jsonl"
    existing = read_jsonl(audit_path)
    previous_hash = existing[-1].get("event_hash", GENESIS_HASH) if existing else GENESIS_HASH
    event: dict[str, Any] = {
        "sequence": len(existing) + 1,
        "timestamp": utc_now(),
        "action": action,
        "details": details,
        "previous_hash": previous_hash,
    }
    event["event_hash"] = audit_event_hash(event)
    append_jsonl(audit_path, event)
    return event


def verify_audit(events: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    previous_hash = GENESIS_HASH
    for index, event in enumerate(events, 1):
        if event.get("sequence") != index:
            problems.append(f"Audit sequence mismatch at entry {index}.")
        if event.get("previous_hash") != previous_hash:
            problems.append(f"Audit chain link mismatch at entry {index}.")
        stored_hash = event.get("event_hash")
        body = {key: value for key, value in event.items() if key != "event_hash"}
        calculated_hash = audit_event_hash(body)
        if stored_hash != calculated_hash:
            problems.append(f"Audit event hash mismatch at entry {index}.")
        previous_hash = stored_hash if isinstance(stored_hash, str) else "!invalid!"
    return problems


def utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
