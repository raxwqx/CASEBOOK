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

Use relative paths; don't include absolute filesystem paths, credentials, hidden OS metadata, or executable setup scripts. The importer rejects path traversal and special files. `manifest.json` is documentation for the bundle creator; in version 1 it is not parsed as trusted instructions.
