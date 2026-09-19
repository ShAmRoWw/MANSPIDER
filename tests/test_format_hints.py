"""Backup names must not silently lose document content or bypass format policy."""

import copy
import json
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.formats import CONTENT_FORMAT_RESOLUTION, blocked_content_extension, content_name, content_suffix
from man_spider.lib.parser import FileParser
from man_spider.lib.spiderling import Spiderling
from man_spider.state import ResumeMismatchError, ScanState, normalized_scan_configuration
from tests.test_state import scan_options
from tests.optional_fixtures import require_private_directory


TESTDATA = Path(__file__).parent.parent / "testdata"


@pytest.mark.parametrize(
    ("filename", "hint", "suffix"),
    [
        ("report.docx.bak", "report.docx", ".docx"),
        ("report.PDF.OLD.2", "report.PDF", ".pdf"),
        (r"folder\report.xlsx.20260905-180001~", "report.xlsx", ".xlsx"),
        ("/scope/archive.tar.gz.backup.save", "archive.tar.gz", ".gz"),
        ("notes.txt.bak.bak.bak", "notes.txt", ".txt"),
        (".env.bak", ".env", ""),
        (".bak", ".bak", ""),
        ("profile.old.json", "profile.old.json", ".json"),
        ("report.pdf.example", "report.pdf.example", ".example"),
        ("report.pdf.1", "report.pdf.1", ".1"),
        ("settings.2026.jsonc", "settings.2026.jsonc", ".jsonc"),
    ],
)
def test_only_conventional_trailing_backup_markers_are_format_hints(filename, hint, suffix):
    assert content_name(filename) == hint
    assert content_suffix(filename) == suffix


@pytest.mark.parametrize("filename", ["archive.zip.bak", "photo.png.old", "program.exe.20260905", "archive.tar.gz~"])
def test_parser_and_retrieval_policy_agree_on_backup_blocks(filename):
    blocked = [".zip", ".png", ".exe", ".gz"]
    parser = FileParser(["Secret"], quiet=True, blocked_extensions=blocked)
    spiderling = object.__new__(Spiderling)
    spiderling.parent = SimpleNamespace(blocked_content_extensions=blocked)
    spiderling.target = "Fixtures"
    assert blocked_content_extension(filename, blocked) is not None
    assert parser.match_magic(filename) is False
    assert spiderling.is_binary_file(filename) is True
    result = parser.parse_file(filename, data_loader=lambda: pytest.fail("blocked backup must not trigger a read"))
    assert result.extracted is False
    assert result.skipped_reason


def test_original_suffix_blocks_and_explicit_format_overrides_remain_effective():
    assert blocked_content_extension("notes.txt.bak", [".bak"]) == ".bak"
    assert blocked_content_extension("archive.tar.gz.old", [".tar.gz"]) == ".tar.gz"
    assert blocked_content_extension("archive.zip.bak", []) is None
    assert blocked_content_extension("ordinary.txt", [".zip"]) is None


@pytest.mark.parametrize("extension", ["docx", "pdf", "xlsx", "doc", "xls"])
@pytest.mark.parametrize("backup", [".bak", ".old.2", ".20260905", "~"])
def test_structured_backups_preserve_actual_extraction_for_local_and_memory_paths(tmp_path, extension, backup):
    require_private_directory("testdata")
    original = TESTDATA / f"test.{extension}"
    candidate = tmp_path / f"document.{extension}{backup}"
    data = original.read_bytes()
    candidate.write_bytes(data)
    parser = FileParser([r"(?i)password\w*"], quiet=True, blocked_extensions=[])
    expected = parser.parse_file(original)
    assert expected.error is None and expected.findings
    assert parser.structured_bytes_mime_type(candidate) == parser.structured_bytes_mime_type(original)
    for result in (
        parser.parse_file(candidate),
        parser.parse_file(candidate, data=data),
    ):
        assert result.error is None
        assert [(f.value, f.start, f.end) for f in result.findings] == [
            (f.value, f.start, f.end) for f in expected.findings
        ]


def test_malformed_structured_backup_is_an_error_not_empty_success(tmp_path):
    candidate = tmp_path / "document.docx.bak"
    candidate.write_bytes(b"This is not a DOCX container")
    parser = FileParser(["Password"], quiet=True, blocked_extensions=[])
    result = parser.parse_file(candidate)
    assert result.error and "structured document extraction failed" in result.error
    assert not result.extracted


def test_plain_key_backup_is_not_sent_to_a_document_extractor(tmp_path):
    parser = FileParser(["UnmaskedKeySecret"], quiet=True, blocked_extensions=[])
    result = parser.parse_file(tmp_path / "master.key.bak", data=b"UnmaskedKeySecret")
    assert result.error is None
    assert [f.value for f in result.findings] == ["UnmaskedKeySecret"]
    passwords = FileParser._inspection_passwords("UnmaskedKeySecret.p12.bak", ())
    assert b"UnmaskedKeySecret" in {value for value, label in passwords}
    assert b"UnmaskedKeySecret.p12" in {value for value, label in passwords}


def test_changed_format_semantics_require_a_new_resume_fingerprint(tmp_path):
    current = normalized_scan_configuration(scan_options(tmp_path))
    assert current["semantic"]["policy"]["content_format_resolution"] == CONTENT_FORMAT_RESOLUTION
    old = copy.deepcopy(current)
    old["semantic"]["policy"].pop("content_format_resolution")
    state = ScanState.create(tmp_path / "scan.sqlite3", old, "2.0.0")
    state.close()
    with pytest.raises(ResumeMismatchError):
        ScanState.resume(tmp_path / "scan.sqlite3", current, "2.0.0")


def test_cli_reports_backup_document_findings_and_blocked_archive_without_changing_paths(tmp_path):
    require_private_directory("testdata")
    scope = tmp_path / "scope"
    scope.mkdir()
    document = scope / "document.docx.bak"
    document.write_bytes((TESTDATA / "test.docx").read_bytes())
    archive = scope / "archive.zip.bak"
    with zipfile.ZipFile(archive, "w") as container:
        container.writestr("secret.txt", "password=FixtureArchivePassword!")
    state = tmp_path / "state.sqlite3"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "man_spider.manspider",
            str(scope),
            "--yes",
            "--builtin-rules",
            "--state-file",
            str(state),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    with sqlite3.connect(state) as db:
        objects = dict(db.execute("SELECT path,status FROM objects WHERE kind='file'"))
        assert objects[str(document)] == "processed"
        assert objects[str(archive)] == "skipped"
        assert (
            db.execute(
                "SELECT count(*) FROM findings f JOIN objects o USING(object_id) "
                "WHERE o.path=? AND f.representation='text'",
                (str(document),),
            ).fetchone()[0]
            > 0
        )
    coverage = [json.loads(line) for line in state.with_suffix(".unclassified-files.jsonl").read_text().splitlines()]
    record = next(row for row in coverage if row["filename"] == archive.name)
    assert record["extension"] == ".zip.bak"
    assert record["content_status"] == "blocked_by_format_policy"
    assert record["content_read"] is False
