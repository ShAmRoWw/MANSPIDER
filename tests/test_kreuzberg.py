import gzip
import subprocess
import sys
import tarfile
import zipfile

import pytest
from pathlib import Path

from man_spider.lib.parser import FileParser
from man_spider.lib.parser.parser import extract_text_file, is_text_file
from tests.optional_fixtures import require_private_directory

TESTDATA = Path(__file__).parent.parent / "testdata"


def write_minimal_pptx(path):
    parts = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>""",
        "_rels/.rels": """<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>""",
        "ppt/presentation.xml": """<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst><p:sldSz cx="9144000" cy="6858000"/></p:presentation>""",
        "ppt/_rels/presentation.xml.rels": """<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/></Relationships>""",
        "ppt/slides/slide1.xml": """<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id="2" name="TextBox"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>PPTX_STAGE7_SECRET</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>""",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in parts.items():
            archive.writestr(name, content)


@pytest.mark.parametrize(
    "filename",
    [
        "test.docx",
        "test.pdf",
        "test.xlsx",
        "test.png",
        "test.doc",
        "test.xls",
    ],
)
def test_extract_password(filename):
    """Extract text from test files and verify Password123 is found."""
    require_private_directory("testdata")
    filepath = TESTDATA / filename

    # Kreuzberg/LibreOffice can retain native worker state. Isolate each format
    # so one optional extractor cannot deadlock later SMB integration tests.
    script = """
import asyncio
import sys
from kreuzberg import extract_file
from man_spider.lib.parser.parser import extract_image_file

path = sys.argv[1]
if path.lower().endswith((".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp")):
    print(extract_image_file(path))
else:
    result = asyncio.run(extract_file(path))
    print(result.content)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(filepath)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Password123" in completed.stdout, f"Password123 not found in {filename}: {completed.stdout[:200]}"


@pytest.mark.parametrize(
    "filename",
    [
        "test-ascii.txt",
        "test-utf8.txt",
        "test-utf8-bom.txt",
        "test-utf16le.txt",
        "test-utf16be.txt",
        "test-utf16-bom.txt",
        "test-latin1.txt",
        "test-cp1252.txt",
    ],
)
def test_extract_text_encodings(filename):
    """Extract text from various encodings using charset-normalizer."""
    require_private_directory("testdata")
    filepath = TESTDATA / filename
    assert is_text_file(str(filepath)), f"{filename} should be detected as text file"
    content = extract_text_file(str(filepath))
    assert content is not None, f"Failed to extract text from {filename}"
    assert "Password123" in content, f"Password123 not found in {filename}: {content[:200]}"


def test_pptx_uses_the_structured_extractor(tmp_path):
    presentation = tmp_path / "presentation.pptx"
    write_minimal_pptx(presentation)

    result = FileParser(["PPTX_STAGE7_SECRET"], quiet=True, blocked_extensions=[]).parse_file(presentation)

    assert result.error is None
    assert result.extracted is True
    assert [finding.value for finding in result.findings] == ["PPTX_STAGE7_SECRET"]


def test_enabled_archive_formats_are_read_completely_and_return_every_occurrence(tmp_path):
    payload = "ARCHIVE_STAGE7_SECRET\n" + ("x" * 200_000) + "\nARCHIVE_STAGE7_SECRET"
    source = tmp_path / "inside.txt"
    source.write_text(payload, encoding="utf-8")
    archives = [tmp_path / "sample.zip", tmp_path / "sample.tar", tmp_path / "sample.txt.gz"]

    with zipfile.ZipFile(archives[0], "w") as archive:
        archive.write(source, "nested/inside.txt")
    with tarfile.open(archives[1], "w") as archive:
        archive.add(source, arcname="nested/inside.txt")
    with gzip.open(archives[2], "wb") as archive:
        archive.write(source.read_bytes())

    parser = FileParser(["ARCHIVE_STAGE7_SECRET"], quiet=True, blocked_extensions=[])
    for archive in archives:
        result = parser.parse_file(archive)
        assert result.error is None, f"{archive.name}: {result.error}"
        assert result.extracted is True
        assert [finding.value for finding in result.findings] == [
            "ARCHIVE_STAGE7_SECRET",
            "ARCHIVE_STAGE7_SECRET",
        ]
        assert result.findings[-1].start > 200_000
