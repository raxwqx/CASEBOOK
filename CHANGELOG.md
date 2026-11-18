# Changelog

## 1.1.0 - 2026-11-18

- Added external, read-only SHA-256 case digest manifests with `casebook digest CASE --out FILE` and `casebook digest CASE --verify FILE`.
- Digest manifests anchor case metadata, evidence and derived-member hashes, findings, notes and the audit-chain head; verification also re-checks current case integrity and detects manifest tampering or a truncated audit prefix.
- Fixed duplicate default report filenames when reports are generated within the same clock tick.
- Fixed report generation aborting when an evidence, finding, timeline or audit index cannot be parsed; the report now records the collection problem and the integrity failure.
- Hardened report rendering against non-numeric or invalid evidence sizes.
- Changed note and finding ID allocation to use the highest existing numeric ID instead of the record count.
- Rejected Windows device names and Windows-incompatible archive/evidence path components consistently on every platform.
- Added an ASCII banner/panel fallback and replacement output errors so legacy Windows console encodings cannot crash commands.
- Flushed and synced JSONL appends so completed writes are durable.
- Expanded the regression suite and updated English/Turkish documentation.

## 1.0.0 - 2026-10-22

- Initial public project structure and dependency-free Python CLI.
- Structured local cases with original and derived evidence areas.
- SHA-256 evidence hashing and a hash-chained audit journal.
- Defensive ZIP import with traversal, special-file, duplicate-name, encrypted-entry, size, count, and compression-ratio checks.
- Analyst notes, event timeline, findings, and evidence-linked reports.
- Self-contained HTML, Markdown, and JSON report renderers.
- Automated regression tests and cross-platform CI workflow.
