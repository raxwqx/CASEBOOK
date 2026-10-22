# Architecture

CASEBOOK separates the terminal interface from case storage and evidence operations.

```text
CLI (argparse)
  ├── ui.py             terminal presentation, no external library
  ├── core.py           case metadata, evidence records, notes, findings, verify
  ├── archive.py        ZIP limits, path checks, extraction and derived hashes
  ├── integrity.py      SHA-256 helpers, JSONL storage, chained audit journal
  └── reports.py        JSON, Markdown and self-contained HTML exports
```

## Storage model

- `case.json` contains the case's schema version and top-level metadata.
- `evidence/index.jsonl` records original evidence files and their hashes.
- `audit/events.jsonl` records operations as a sequence of events, each linking to the preceding event hash.
- Evidence, findings, and notes are duplicated in the audit event details so verification can detect divergence between indexes and the journal.
- ZIP members are derived data, recorded by path, byte size, and digest in the corresponding `evidence.added` audit event. The original ZIP remains stored as an original evidence item.

## Deliberate design choices

- JSON and JSONL are human-inspectable and easy to diff.
- SHA-256 is provided by Python's standard library.
- No evidence is executed; only ZIP regular-file bytes are read and copied.
- ZIP paths are validated and extraction is confined to a temporary derived directory before it is committed.
- Reports are standalone and require no hosted fonts, scripts, or network assets.

## Limits

This is not a database with concurrent-writer locking. Avoid adding evidence from multiple processes to the same case simultaneously. A local hash chain detects many edits, but is not a cryptographic signature or an independently trusted timestamping service.
