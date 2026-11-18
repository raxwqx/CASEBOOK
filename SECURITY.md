# Security Policy

## Scope

CASEBOOK is a local evidence organizer. Security-sensitive behavior includes ZIP parsing/extraction, path containment, evidence file copying, JSONL indexes, report rendering, verification of the local audit hash chain, and export/verification of external digest manifests.

## Reporting a vulnerability

Please do not publish exploit details for an unpatched issue. Open a private security advisory in the repository, or contact the repository maintainer through a private channel listed on the GitHub profile. Include the affected version, operating system, reproduction steps using synthetic files, and impact. Do not send personal, confidential, or live incident evidence.

## Supported baseline

- Python 3.10 or later.
- Runtime uses the Python standard library only.
- ZIP imports are subject to explicit size, entry-count, path, member-type, and compression-ratio limits.
- Archive and evidence names are checked for Windows device names and Windows-incompatible path components on every platform.
- Digest manifests use exclusive creation and are never silently overwritten. Verification is read-only.

## Security limitations

- The audit journal is hash-chained, not digitally signed. Anyone able to rewrite all local records may be able to recompute the chain.
- Digest manifests are unsigned snapshots. They detect changes relative to the stored snapshot, but an actor who can rewrite both the case and the manifest can make them agree. Keep manifests in independent, access-controlled storage.
- The tool cannot prove evidence provenance, authorship, original timestamps, or that an analyst statement is accurate.
- The local case directory is not encrypted. Use operating-system permissions and full-disk encryption for sensitive investigations.
- CASEBOOK never executes imported evidence. Users should still treat imported content as untrusted and avoid opening unknown files with unrelated applications.
- Reports may contain filenames, observations, and case details. Review them before sharing.

## Safe use

Only import files you are permitted to handle. Use synthetic lab artifacts in demonstrations and tests. Do not include credentials, tokens, private emails, or personally identifying data in public test cases.
