"""Defensive ZIP validation and extraction. Archives are never trusted input."""
from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 100 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


class UnsafeArchiveError(ValueError):
    """Raised when an archive violates CASEBOOK's conservative import limits."""


def _safe_member_name(raw_name: str) -> str | None:
    if not raw_name or "\x00" in raw_name:
        raise UnsafeArchiveError("Archive contains an empty or invalid member name.")
    # ZIP filenames use '/', but some tools put Windows separators into archives.
    normalized = raw_name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        raise UnsafeArchiveError(f"Absolute archive path rejected: {raw_name!r}")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise UnsafeArchiveError(f"Drive-qualified archive path rejected: {raw_name!r}")
    path = PurePosixPath(normalized)
    if any(part in ("..", "") for part in path.parts):
        raise UnsafeArchiveError(f"Path traversal rejected: {raw_name!r}")
    if any(part in (".",) for part in path.parts):
        raise UnsafeArchiveError(f"Non-canonical archive path rejected: {raw_name!r}")
    clean = path.as_posix()
    if clean == ".":
        return None
    return clean


def inspect_archive(archive_path: Path) -> list[tuple[zipfile.ZipInfo, str]]:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise UnsafeArchiveError(f"ZIP archive exceeds the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB compressed-size limit.")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise UnsafeArchiveError(f"ZIP contains more than {MAX_MEMBERS} entries.")
            accepted: list[tuple[zipfile.ZipInfo, str]] = []
            seen: set[str] = set()
            total = 0
            for info in infos:
                if info.is_dir():
                    # Validate directory names too, to reject traversal entries consistently.
                    _safe_member_name(info.filename.rstrip("/"))
                    continue
                clean = _safe_member_name(info.filename)
                if clean is None:
                    continue
                # Reject symlink and other special entries, not just unsafe paths.
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                # ZIP files commonly store only permission bits (for example 0o600)
                # without a POSIX file-type marker. Reject explicit special types only.
                if stat.S_ISLNK(mode) or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise UnsafeArchiveError(f"Special or symbolic-link entry rejected: {info.filename!r}")
                if info.flag_bits & 0x1:
                    raise UnsafeArchiveError(f"Encrypted ZIP member is not supported: {info.filename!r}")
                key = clean.casefold()
                if key in seen:
                    raise UnsafeArchiveError(f"Duplicate archive path rejected: {clean!r}")
                seen.add(key)
                if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
                    raise UnsafeArchiveError(f"ZIP member exceeds the per-file size limit: {info.filename!r}")
                total += info.file_size
                if total > MAX_TOTAL_UNCOMPRESSED:
                    raise UnsafeArchiveError(f"ZIP exceeds the {MAX_TOTAL_UNCOMPRESSED // (1024 * 1024)} MiB expanded-size limit.")
                if info.file_size > 0:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > MAX_COMPRESSION_RATIO:
                        raise UnsafeArchiveError(f"Suspicious compression ratio rejected for: {info.filename!r}")
                accepted.append((info, clean))
            return accepted
    except UnsafeArchiveError:
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError) as exc:
        raise UnsafeArchiveError(f"Unable to inspect ZIP archive: {exc}") from exc


def extract_validated(archive_path: Path, destination: Path, members: list[tuple[zipfile.ZipInfo, str]]) -> list[dict[str, object]]:
    """Extract validated regular files while streaming and hashing each member."""
    import hashlib

    destination.mkdir(parents=True, exist_ok=False)
    records: list[dict[str, object]] = []
    total_written = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for info, clean_name in members:
                target = destination.joinpath(*PurePosixPath(clean_name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                # Prevent a pre-existing link or unexpected file from redirecting writes.
                current = destination
                for component in PurePosixPath(clean_name).parts[:-1]:
                    current = current / component
                    if current.is_symlink():
                        raise UnsafeArchiveError(f"Symbolic link detected in extraction path: {clean_name!r}")
                digest = hashlib.sha256()
                written = 0
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        total_written += len(chunk)
                        if written > MAX_MEMBER_BYTES:
                            raise UnsafeArchiveError(f"Extracted member exceeded size limit: {clean_name!r}")
                        if total_written > MAX_TOTAL_UNCOMPRESSED:
                            raise UnsafeArchiveError("Extracted archive exceeded the total expanded-size limit.")
                        digest.update(chunk)
                        output.write(chunk)
                if written != info.file_size:
                    raise UnsafeArchiveError(f"Expanded size mismatch for member: {clean_name!r}")
                records.append({
                    "member_name": clean_name,
                    "stored_path": target.as_posix(),
                    "size_bytes": written,
                    "sha256": digest.hexdigest(),
                })
        return records
    except Exception:
        # The caller owns the parent temporary path and removes it on failure.
        raise
