# Methodology and evidence handling

## Original and derived files

CASEBOOK copies an input file into `evidence/originals/`, computes SHA-256 over the source and copied bytes, and only commits the record if those digests agree. For ZIP inputs, the archive remains the original. Accepted regular members are extracted separately into `evidence/derived/<evidence-id>/` and hashed individually.

This tool does not set source timestamps as proof of origin, acquire disk images, preserve filesystem metadata comprehensively, or establish legal admissibility. Treat acquisition context as analyst-supplied notes.

## ZIP validation

The importer rejects absolute and traversal paths, Windows drive-qualified paths, Windows reserved device names, Windows-incompatible characters and path components, symbolic links and special-file entries, duplicate case-insensitive names, encrypted files, excessive input/member/expanded sizes, excessive member counts, and unusually high per-member compression ratios. This reduces common archive extraction risks but is not a formal proof that all hostile archives are harmless.

## Integrity checks

- Evidence files: recorded byte size and SHA-256 digest.
- Derived archive members: recorded byte size and SHA-256 digest.
- Index parity: evidence, finding, and note indexes must match corresponding records embedded in the audit journal.
- Audit chain: sequence numbers, previous-event links, and event hashes.
- Case metadata: selected initialization fields must match the initial audit record.

The initial audit event does not independently authenticate an investigator identity. A person with write access to the case can potentially rewrite all records, regenerate the chain, or replace both the case and its audit journal. For high-assurance work, create a separately protected digest of the completed case and store it outside the case directory in trusted, access-controlled storage.

## External anchoring

Use `casebook digest CASE --out FILE` to write a read-only snapshot of the completed case outside its directory. The manifest records the case metadata, evidence and derived-member hashes, findings, notes and the audit-chain head, then hashes that snapshot. Export does not modify evidence or indexes; it records a `digest.exported` audit event. An existing manifest is never overwritten.

Use `casebook digest CASE --verify FILE` to compare the stored manifest with the current case. Verification re-hashes the manifest, compares every snapshot section, re-runs the regular integrity checks and confirms that the anchored audit prefix is intact. It never repairs or writes to the case. A failure means the case or manifest changed; preserve both and investigate before deciding whether to create a new anchor.

The digest is a consistency anchor, not a digital signature, trusted timestamp or proof of authorship. Protect the manifest in storage that is independent from the case and document where and when it was retained.

## Reporting

Reports show the current verification result and preserve observations separately from findings. A finding records the analyst's interpretation; it is not an automatic verdict. Review all generated content before distributing it.
