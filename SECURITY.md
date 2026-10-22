# Security Policy

## Scope

CASEBOOK is a local evidence organizer. Security-sensitive behavior includes ZIP parsing/extraction, path containment, evidence file copying, JSONL indexes, report rendering, and verification of the local audit hash chain.

## Reporting a vulnerability

Please do not publish exploit details for an unpatched issue. Open a private security advisory in the repository, or contact the repository maintainer through a private channel listed on the GitHub profile. Include the affected version, operating system, reproduction steps using synthetic files, and impact. Do not send personal, confidential, or live incident evidence.

## Supported baseline

- Python 3.10 or later.
- Runtime uses the Python standard library only.
- ZIP imports are subject to explicit size, entry-count, path, member-type, and compression-ratio limits.

## Security limitations

- The audit journal is hash-chained, not digitally signed. Anyone able to rewrite all local records may be able to recompute the chain.
- The tool cannot prove evidence provenance, authorship, original timestamps, or that an analyst statement is accurate.
- The local case directory is not encrypted. Use operating-system permissions and full-disk encryption for sensitive investigations.
- CASEBOOK never executes imported evidence. Users should still treat imported content as untrusted and avoid opening unknown files with unrelated applications.
- Reports may contain filenames, observations, and case details. Review them before sharing.

## Safe use

Only import files you are permitted to handle. Use synthetic lab artifacts in demonstrations and tests. Do not include credentials, tokens, private emails, or personally identifying data in public test cases.
