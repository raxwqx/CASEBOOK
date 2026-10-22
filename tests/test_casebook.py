from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

from casebook.cli import main
from casebook.core import (
    CasebookError,
    add_evidence,
    add_finding,
    add_note,
    init_case,
    timeline,
    verify_case,
)
from casebook.integrity import GENESIS_HASH, append_audit, audit_event_hash, sha256_file, verify_audit
from casebook.reports import render_html, render_json, render_markdown, write_report


class CasebookTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.case = self.base / "CASE-TEST"
        self.root, self.meta = init_case(self.case, "Synthetic Test Case", "test-analyst", "no real data")
        self.input_dir = self.base / "input"
        self.input_dir.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_input(self, name: str = "sample.txt", content: bytes = b"synthetic evidence\n") -> Path:
        path = self.input_dir / name
        path.write_bytes(content)
        return path

    def make_zip(self, path: Path, items: list[tuple[str, bytes]]) -> Path:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in items:
                archive.writestr(name, content)
        return path

    def test_init_creates_ordered_case_layout(self) -> None:
        for relative in ("case.json", "README.md", "evidence/originals", "evidence/derived", "findings", "timeline", "audit", "reports"):
            self.assertTrue((self.root / relative).exists(), relative)
        self.assertTrue((self.root / "case.json").is_file())
        self.assertEqual(self.meta["title"], "Synthetic Test Case")
        self.assertEqual(len(json.loads((self.root / "audit/events.jsonl").read_text().splitlines()[0])["event_hash"]), 64)

    def test_init_refuses_nonempty_directory(self) -> None:
        with self.assertRaises(CasebookError):
            init_case(self.case, "Replacement")

    def test_init_refuses_non_directory_target(self) -> None:
        file_path = self.base / "ordinary-file"
        file_path.write_text("x")
        with self.assertRaises(CasebookError):
            init_case(file_path)

    def test_add_file_copies_and_hashes_original(self) -> None:
        source = self.write_input(content=b"alpha\x00beta")
        record = add_evidence(self.root, source, source="synthetic test", note="sample note")
        stored = self.root / record["stored_path"]
        self.assertTrue(stored.is_file())
        self.assertEqual(stored.read_bytes(), source.read_bytes())
        self.assertEqual(record["sha256"], sha256_file(source))
        self.assertEqual(record["size_bytes"], source.stat().st_size)
        self.assertEqual(record["evidence_id"], "EVD-0001")
        self.assertTrue(verify_case(self.root)["ok"])

    def test_add_evidence_id_increments(self) -> None:
        one = add_evidence(self.root, self.write_input("one.txt", b"one"))
        two = add_evidence(self.root, self.write_input("two.txt", b"two"))
        self.assertEqual((one["evidence_id"], two["evidence_id"]), ("EVD-0001", "EVD-0002"))

    def test_add_rejects_missing_input(self) -> None:
        with self.assertRaises(CasebookError):
            add_evidence(self.root, self.input_dir / "missing")

    def test_add_rejects_symbolic_link_source(self) -> None:
        target = self.write_input()
        link = self.input_dir / "linked.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links unavailable on this platform")
        with self.assertRaises(CasebookError):
            add_evidence(self.root, link)

    def test_zip_archive_is_preserved_and_members_become_derived_evidence(self) -> None:
        source = self.make_zip(self.input_dir / "bundle.zip", [
            ("bundle/README.md", b"Synthetic test bundle"),
            ("bundle/evidence/sample.json", b'{"status":"demo"}'),
        ])
        record = add_evidence(self.root, source, source="lab")
        self.assertEqual(record["kind"], "zip-archive")
        self.assertEqual(record["derived_count"], 2)
        self.assertTrue((self.root / record["stored_path"]).is_file())
        self.assertEqual((self.root / "evidence/derived/EVD-0001/bundle/README.md").read_bytes(), b"Synthetic test bundle")
        result = verify_case(self.root)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["derived_count"], 2)

    def test_zip_traversal_is_rejected_before_evidence_commit(self) -> None:
        source = self.make_zip(self.input_dir / "evil.zip", [("../escape.txt", b"escape")])
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)
        self.assertFalse((self.base / "escape.txt").exists())
        self.assertFalse((self.root / "evidence/index.jsonl").exists())
        self.assertEqual(list((self.root / "evidence/originals").iterdir()), [])

    def test_zip_absolute_path_is_rejected(self) -> None:
        source = self.make_zip(self.input_dir / "absolute.zip", [("/tmp/escape.txt", b"no")])
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)

    def test_zip_windows_drive_path_is_rejected(self) -> None:
        source = self.make_zip(self.input_dir / "drive.zip", [("C:/Windows/temp.txt", b"no")])
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)

    def test_zip_duplicate_path_is_rejected(self) -> None:
        source = self.input_dir / "duplicate.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("Folder/Log.txt", b"one")
            archive.writestr("folder/log.txt", b"two")
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)

    def test_zip_symbolic_link_entry_is_rejected(self) -> None:
        source = self.input_dir / "symlink.zip"
        info = zipfile.ZipInfo("linked.txt")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr(info, "../../outside.txt")
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)

    def test_zip_suspicious_compression_ratio_is_rejected(self) -> None:
        source = self.input_dir / "compressed.zip"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("zeros.bin", b"\x00" * (2 * 1024 * 1024))
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)
        self.assertFalse((self.root / "evidence/index.jsonl").exists())

    def test_zip_prefix_collision_fails_without_committing_original(self) -> None:
        source = self.make_zip(self.input_dir / "prefix.zip", [("node", b"file"), ("node/child.txt", b"child")])
        with self.assertRaises(CasebookError):
            add_evidence(self.root, source)
        self.assertFalse((self.root / "evidence/index.jsonl").exists())
        self.assertEqual(list((self.root / "evidence/originals").iterdir()), [])

    def test_zip_bad_archive_is_not_claimed_as_zip_evidence(self) -> None:
        # A malformed archive is just an ordinary file unless it has a valid ZIP central directory.
        source = self.write_input("bad.zip", b"not really a zip")
        record = add_evidence(self.root, source)
        self.assertEqual(record["kind"], "file")
        self.assertTrue(verify_case(self.root)["ok"])

    def test_zip_member_limit_constant_is_sane(self) -> None:
        # Guard against accidental removal of resource limits during refactors.
        from casebook import archive
        self.assertGreater(archive.MAX_MEMBERS, 0)
        self.assertLessEqual(archive.MAX_MEMBER_BYTES, archive.MAX_TOTAL_UNCOMPRESSED)
        self.assertLess(archive.MAX_TOTAL_UNCOMPRESSED, 1024 * 1024 * 1024)

    def test_original_file_tampering_is_detected(self) -> None:
        record = add_evidence(self.root, self.write_input())
        (self.root / record["stored_path"]).write_bytes(b"modified")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("SHA-256 mismatch" in issue or "size mismatch" in issue for issue in result["issues"]))

    def test_derived_member_tampering_is_detected(self) -> None:
        source = self.make_zip(self.input_dir / "bundle.zip", [("a.txt", b"original")])
        add_evidence(self.root, source)
        (self.root / "evidence/derived/EVD-0001/a.txt").write_bytes(b"changed")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("Derived member" in issue for issue in result["issues"]))

    def test_evidence_index_edit_is_detected(self) -> None:
        add_evidence(self.root, self.write_input())
        index = self.root / "evidence/index.jsonl"
        record = json.loads(index.read_text().strip())
        record["filename"] = "pretend.txt"
        index.write_text(json.dumps(record) + "\n")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("index does not match" in issue for issue in result["issues"]))

    def test_case_metadata_tampering_is_detected(self) -> None:
        case_file = self.root / "case.json"
        item = json.loads(case_file.read_text())
        item["title"] = "changed title"
        case_file.write_text(json.dumps(item))
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("title" in issue for issue in result["issues"]))

    def test_unregistered_original_file_is_detected(self) -> None:
        rogue = self.root / "evidence/originals/forgotten-file.bin"
        rogue.write_bytes(b"unregistered")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("Unregistered file in original evidence" in issue for issue in result["issues"]))

    def test_unregistered_derived_file_is_detected(self) -> None:
        rogue_dir = self.root / "evidence/derived/EVD-9999"
        rogue_dir.mkdir()
        (rogue_dir / "manual-copy.txt").write_text("not registered")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("Unregistered directory in derived evidence" in issue for issue in result["issues"]))

    def test_case_metadata_symlink_is_rejected(self) -> None:
        meta = self.root / "case.json"
        target = self.base / "external-case.json"
        target.write_text(meta.read_text())
        meta.unlink()
        try:
            meta.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links unavailable on this platform")
        with self.assertRaises(CasebookError):
            verify_case(self.root)

    def test_audit_tampering_is_detected(self) -> None:
        path = self.root / "audit/events.jsonl"
        event = json.loads(path.read_text().strip())
        event["details"]["title"] = "rewritten"
        path.write_text(json.dumps(event) + "\n")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("event hash mismatch" in issue for issue in result["issues"]))

    def test_symlink_inside_case_is_rejected_by_verifier(self) -> None:
        record = add_evidence(self.root, self.write_input())
        stored = self.root / record["stored_path"]
        replacement = self.input_dir / "replacement.txt"
        replacement.write_text("external")
        stored.unlink()
        try:
            stored.symlink_to(replacement)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links unavailable on this platform")
        result = verify_case(self.root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("Missing or unsafe evidence" in issue for issue in result["issues"]))

    def test_note_appears_in_timeline(self) -> None:
        note = add_note(self.root, "Observed in synthetic lab", "observation", "2026-10-22T12:30:00Z")
        self.assertEqual(note["note_id"], "NOTE-0001")
        events = timeline(self.root)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["label"], "Observed in synthetic lab")
        self.assertTrue(verify_case(self.root)["ok"])

    def test_empty_note_is_rejected(self) -> None:
        with self.assertRaises(CasebookError):
            add_note(self.root, "   ")

    def test_finding_links_existing_evidence(self) -> None:
        record = add_evidence(self.root, self.write_input())
        finding = add_finding(self.root, "Repeated failures", "medium", "Synthetic observation", evidence_ids=[record["evidence_id"]])
        self.assertEqual(finding["evidence_ids"], [record["evidence_id"]])
        self.assertEqual(len(timeline(self.root)), 2)
        self.assertTrue(verify_case(self.root)["ok"])

    def test_finding_rejects_unknown_evidence(self) -> None:
        with self.assertRaises(CasebookError):
            add_finding(self.root, "Orphan finding", "low", "Description", evidence_ids=["EVD-9999"])

    def test_finding_rejects_invalid_severity(self) -> None:
        with self.assertRaises(CasebookError):
            add_finding(self.root, "Title", "urgent", "Description")

    def test_report_renderers_include_expected_data(self) -> None:
        record = add_evidence(self.root, self.write_input())
        add_finding(self.root, "Synthetic finding", "low", "No real target", evidence_ids=[record["evidence_id"]])
        add_note(self.root, "Analyst note")
        from casebook.reports import collect_report_data
        data = collect_report_data(self.root)
        self.assertIn("Evidence register", render_markdown(data))
        self.assertIn("Synthetic finding", render_markdown(data))
        self.assertIn('"evidence"', render_json(data))
        self.assertIn("Synthetic finding", render_html(data))
        self.assertIn("<style>", render_html(data))

    def test_html_report_escapes_untrusted_input(self) -> None:
        add_note(self.root, "<script>alert('x')</script>")
        from casebook.reports import collect_report_data
        rendered = render_html(collect_report_data(self.root))
        self.assertNotIn("<script>alert", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_write_report_creates_expected_file_and_audit(self) -> None:
        output = self.root / "reports" / "custom.html"
        path, integrity = write_report(self.root, "html", output)
        self.assertEqual(path, output)
        self.assertTrue(path.is_file())
        self.assertTrue(integrity["ok"])
        self.assertTrue(verify_case(self.root)["ok"])

    def test_report_does_not_overwrite(self) -> None:
        output = self.root / "reports" / "existing.md"
        output.write_text("keep me")
        with self.assertRaises(FileExistsError):
            write_report(self.root, "md", output)
        self.assertEqual(output.read_text(), "keep me")

    def test_audit_hash_chain_validation(self) -> None:
        event = {"sequence": 1, "timestamp": "now", "action": "test", "details": {}, "previous_hash": GENESIS_HASH}
        event["event_hash"] = audit_event_hash(event)
        self.assertEqual(verify_audit([event]), [])
        event["details"]["modified"] = True
        self.assertTrue(verify_audit([event]))

    def test_cli_home_displays_brand_and_quick_start(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([])
        self.assertEqual(code, 0)
        self.assertIn("C A S E B O O K", output.getvalue())
        self.assertIn("casebook init", output.getvalue())

    def test_cli_init_and_verify(self) -> None:
        target = self.base / "CLI-CASE"
        output = io.StringIO()
        with redirect_stdout(output):
            code_init = main(["init", str(target), "--title", "CLI Test"])
        self.assertEqual(code_init, 0)
        output = io.StringIO()
        with redirect_stdout(output):
            code_verify = main(["verify", str(target)])
        self.assertEqual(code_verify, 0)
        self.assertIn("PASSED", output.getvalue())

    def test_cli_full_workflow_commands(self) -> None:
        source = self.write_input("cli-evidence.json", b'{"synthetic":true}')

        def invoke(arguments: list[str]) -> tuple[int, str]:
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(arguments)
            return code, output.getvalue()

        code, output = invoke(["add", str(self.root), str(source), "--source", "test lab"])
        self.assertEqual(code, 0, output)
        self.assertIn("EVD-0001", output)

        code, output = invoke(["note", str(self.root), "--text", "CLI observation", "--kind", "observation", "--when", "2026-10-22T12:30:00Z"])
        self.assertEqual(code, 0, output)
        self.assertIn("NOTE-0001", output)

        code, output = invoke(["finding", "add", str(self.root), "--title", "CLI finding", "--severity", "medium", "--description", "Synthetic detail", "--evidence", "EVD-0001"])
        self.assertEqual(code, 0, output)
        self.assertIn("FND-0001", output)

        for command in (["show", str(self.root)], ["timeline", str(self.root)], ["doctor", str(self.root)], ["verify", str(self.root)]):
            code, output = invoke(list(command))
            self.assertEqual(code, 0, (command, output))

        code, output = invoke(["report", str(self.root), "--format", "markdown"])
        self.assertEqual(code, 0, output)
        self.assertIn("Report written", output)

    def test_cli_expected_error_returns_nonzero_without_traceback(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["add", str(self.root), str(self.input_dir / "missing.txt")])
        self.assertEqual(code, 2)
        self.assertIn("not a regular file", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())

    def test_timeline_sorts_by_event_time(self) -> None:
        add_note(self.root, "Later", event_time="2026-10-23T00:00:00Z")
        add_note(self.root, "Earlier", event_time="2026-10-22T00:00:00Z")
        events = timeline(self.root)
        self.assertEqual([e["label"] for e in events], ["Earlier", "Later"])


if __name__ == "__main__":
    unittest.main()
