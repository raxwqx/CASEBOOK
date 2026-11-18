# Case and exchange formats

## Case metadata

`case.json` is UTF-8 JSON. `schema_version` identifies the storage format. Fields added in later releases may require a migration tool; do not manually change the schema version.

## JSON Lines records

Indexes use JSON Lines: one complete JSON object per line, UTF-8, newline-terminated. This allows append-oriented records and readable diffs. An index must not be edited independently of its audit record, because `casebook verify` reports differences.

## Suggested ZIP layout

```text
casebook-bundle/
├── README.md
├── manifest.json
├── evidence/
│   ├── tool-export.json
│   └── extracted-log.txt
└── notes/
    └── acquisition-context.md
```

Use relative paths; don't include absolute filesystem paths, credentials, hidden OS metadata, or executable setup scripts. The importer rejects path traversal and special files, Windows device names, and Windows-incompatible characters/components. `manifest.json` is documentation for the bundle creator; in version 1 it is not parsed as trusted instructions.

## External digest manifest

`casebook digest CASE --out FILE` writes a UTF-8 JSON document with `manifest_format` set to `casebook-digest-v1`. It contains:

- `schema_version`, `generated_at`, and the exporting `tool` name/version;
- selected stable `case` metadata (case ID, title, analyst, description, status, creation time, schema and tool);
- `audit` with the anchored event count, head hash and head timestamp;
- `counts` for evidence, derived members, findings, notes and audit events;
- the complete `evidence`, `derived`, `findings` and `notes` registers used for the snapshot;
- `digest`, a SHA-256 over the canonical JSON of every other field.

The manifest is a snapshot, not a signature or timestamp authority. `casebook digest CASE --verify FILE` re-hashes the manifest, compares each snapshot section with the current case, re-runs case integrity checks, and confirms that the anchored audit-chain prefix is still present. Additional audit events after the anchor are allowed; changing evidence, indexes or the anchored prefix is reported as a failure.
