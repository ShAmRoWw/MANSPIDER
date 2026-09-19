import json
import zipfile

from kreuzberg import extract_bytes_sync, extract_file_sync

from man_spider.lib.parser.parser import STRUCTURED_BYTES_MIME_TYPES
from tests.optional_fixtures import require_private_directory

require_private_directory("tools", module=True)
require_private_directory("testdata", module=True)

from tools.build_benchmark_seed import build_seed


def test_benchmark_seed_covers_the_complete_builtin_and_legacy_rule_surfaces(tmp_path):
    archive_path = tmp_path / "benchmark-seed.zip"

    summary = build_seed(archive_path)

    assert summary["rule_pack_id"] == "manspider.default"
    assert summary["rule_pack_version"] == "2.7.0"
    assert summary["rule_count"] == 251
    assert summary["content_action_count"] == 126
    assert summary["metadata_action_count"] == 119
    assert summary["inspector_action_count"] == 9
    assert summary["legacy_content_pattern_count"] == 22
    assert summary["legacy_content_extension_count"] == 55
    assert summary["legacy_metadata_extension_count"] == 102
    assert summary["legacy_metadata_filename_count"] == 66

    with zipfile.ZipFile(archive_path) as archive:
        assert archive.testzip() is None
        manifest = json.loads(archive.read("seed-manifest.json"))
        names = set(archive.namelist())

    assert manifest["entry_count"] == 582
    assert len(manifest["entries"]) == 582
    assert "formats/template.docm" in names
    assert "formats/template.eml" in names
    assert "formats/template.pptm" in names
    assert any(name.startswith("content/russian-secret-assignment/") for name in names)
    assert any(name.startswith("inspect/private-key-candidate-file/") for name in names)


def test_benchmark_seed_structured_documents_are_parseable(tmp_path):
    archive_path = tmp_path / "benchmark-seed.zip"
    build_seed(archive_path)

    with zipfile.ZipFile(archive_path) as archive:
        names = [name for name in archive.namelist() if name.startswith("formats/template.")]
        assert "formats/template.xlsb" in names
        for name in names:
            candidate = tmp_path / name
            candidate.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(name)
            candidate.write_bytes(data)
            path_result = extract_file_sync(str(candidate))
            mime_type = STRUCTURED_BYTES_MIME_TYPES[candidate.suffix.lower()]
            bytes_result = extract_bytes_sync(data, mime_type)
            assert bytes_result.content == path_result.content, name

        metadata_xlsx = "metadata/password-inventory-document/inventory/passwords.xlsx"
        candidate = tmp_path / metadata_xlsx
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(archive.read(metadata_xlsx))
        extract_file_sync(str(candidate))
