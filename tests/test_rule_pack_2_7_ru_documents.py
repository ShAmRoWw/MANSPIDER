"""Real, self-authored Unicode office-document extraction without OCR.

The fixtures contain text/cells/shapes, never screenshots or scanned pages.
They prove embedded-text coverage only: recognizing Russian text in an image
still depends on separately configured OCR and Russian language support.
All packages are built in memory with the standard library, without office
applications, third-party documents, external relationships, or macros.
"""

import io
import zipfile
from pathlib import PurePosixPath
from xml.sax.saxutils import escape

import pytest
from kreuzberg import ExtractionConfig, extract_bytes_sync

from man_spider.lib.parser import FileParser
from man_spider.lib.parser import parser as parser_module
from man_spider.rules import load_builtin_rules
from tests.rule_pack_2_5_document_fixtures import _odf_payload


PASSWORD = "СложныйРусскийПароль!"
RUSSIAN = f"Пароль = «{PASSWORD}»"
ENGLISH = f'password="{PASSWORD}"'
FORMATS = (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".rtf")
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
XML = '<?xml version="1.0" encoding="UTF-8"?>'


def _zip(parts):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in parts.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, content.encode("utf-8"))
    return output.getvalue()


def _relationships(relationships):
    return XML + f'<Relationships xmlns="{REL_NS}">' + "".join(
        f'<Relationship Id="{identity}" Type="{OFFICE_REL_NS}/{kind}" Target="{target}"/>'
        for identity, kind, target in relationships
    ) + "</Relationships>"


def _content_types(parts):
    return (
        XML + f'<Types xmlns="{CONTENT_NS}">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(f'<Override PartName="/{path}" ContentType="{mime}"/>' for path, mime in parts)
        + "</Types>"
    )


def _docx(lines):
    # Splitting each paragraph into runs also checks that extraction joins
    # Russian words rather than feeding serialized XML to the rule engine.
    paragraphs = "".join(
        '<w:p><w:r><w:t xml:space="preserve">' + escape(line[:3])
        + '</w:t></w:r><w:r><w:t xml:space="preserve">' + escape(line[3:])
        + "</w:t></w:r></w:p>"
        for line in lines
    )
    return _zip({
        "[Content_Types].xml": _content_types([
            ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
        ]),
        "_rels/.rels": _relationships([("rId1", "officeDocument", "word/document.xml")]),
        "word/document.xml": XML + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        + "<w:body>" + paragraphs + "<w:sectPr/></w:body></w:document>",
    })


def _xlsx(lines):
    rows = "".join(
        f'<row r="{index}"><c r="A{index}" t="inlineStr"><is><t xml:space="preserve">'
        + escape(line) + "</t></is></c></row>"
        for index, line in enumerate(lines, start=1)
    )
    spreadsheet_ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    return _zip({
        "[Content_Types].xml": _content_types([
            ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
            ("xl/worksheets/sheet1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"),
        ]),
        "_rels/.rels": _relationships([("rId1", "officeDocument", "xl/workbook.xml")]),
        "xl/workbook.xml": XML + f'<workbook xmlns="{spreadsheet_ns}" xmlns:r="{OFFICE_REL_NS}">'
        '<sheets><sheet name="Учётные данные" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": _relationships([("rId1", "worksheet", "worksheets/sheet1.xml")]),
        "xl/worksheets/sheet1.xml": XML + f'<worksheet xmlns="{spreadsheet_ns}"><sheetData>'
        + rows + "</sheetData></worksheet>",
    })


def _pptx(lines):
    presentation_ns = "http://schemas.openxmlformats.org/presentationml/2006/main"
    drawing_ns = "http://schemas.openxmlformats.org/drawingml/2006/main"
    paragraphs = "".join("<a:p><a:r><a:t>" + escape(line) + "</a:t></a:r></a:p>" for line in lines)
    return _zip({
        "[Content_Types].xml": _content_types([
            ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
            ("ppt/slides/slide1.xml", "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"),
        ]),
        "_rels/.rels": _relationships([("rId1", "officeDocument", "ppt/presentation.xml")]),
        "ppt/presentation.xml": XML + f'<p:presentation xmlns:r="{OFFICE_REL_NS}" xmlns:p="{presentation_ns}">'
        '<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>'
        '<p:sldSz cx="9144000" cy="6858000"/></p:presentation>',
        "ppt/_rels/presentation.xml.rels": _relationships([("rId1", "slide", "slides/slide1.xml")]),
        "ppt/slides/slide1.xml": XML + f'<p:sld xmlns:a="{drawing_ns}" xmlns:p="{presentation_ns}">'
        '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id="2" name="Пароли"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
        '<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>' + paragraphs
        + '</p:txBody></p:sp></p:spTree></p:cSld></p:sld>',
    })


def _rtf(lines):
    def escaped(text):
        result = []
        for char in text:
            if char in "\\{}":
                result.append("\\" + char)
            elif ord(char) <= 127:
                result.append(char)
            else:
                # RTF \u represents a signed UTF-16 code unit, followed by the
                # one fallback character selected by \uc1.
                encoded = char.encode("utf-16-le")
                for index in range(0, len(encoded), 2):
                    unit = int.from_bytes(encoded[index:index + 2], "little", signed=True)
                    result.append(f"\\u{unit}?")
        return "".join(result)

    return (r"{\rtf1\ansi\ansicpg1251\uc1 " + r"\par ".join(escaped(line) for line in lines) + "}").encode("ascii")


def document_payload(extension, lines):
    if extension == ".docx":
        return _docx(lines)
    if extension == ".xlsx":
        return _xlsx(lines)
    if extension == ".pptx":
        return _pptx(lines)
    if extension == ".rtf":
        return _rtf(lines)
    if extension == ".odt":
        paragraphs = "".join("<text:p>" + escape(line) + "</text:p>" for line in lines)
        return _odf_payload("text", f"<office:text>{paragraphs}</office:text>")
    if extension == ".ods":
        rows = "".join(
            '<table:table-row><table:table-cell office:value-type="string"><text:p>'
            + escape(line) + "</text:p></table:table-cell></table:table-row>"
            for line in lines
        )
        return _odf_payload(
            "spreadsheet",
            '<office:spreadsheet><table:table table:name="Учётные данные">'
            + rows + "</table:table></office:spreadsheet>",
        )
    raise AssertionError(extension)


def parse_document(monkeypatch, extension, lines):
    payload = document_payload(extension, lines)
    calls = []

    def real_extraction_no_ocr(data, mime_type, **_kwargs):
        calls.append(mime_type)
        return extract_bytes_sync(data, mime_type, config=ExtractionConfig(disable_ocr=True, force_ocr=False))

    def forbid_ocr(*args, **kwargs):
        raise AssertionError("Embedded-text office documents must not need OCR")

    monkeypatch.setattr(parser_module, "extract_bytes_sync", real_extraction_no_ocr)
    monkeypatch.setattr(parser_module, "extract_image_file", forbid_ocr)
    parser = FileParser([], quiet=True, rules=load_builtin_rules())
    candidate = PurePosixPath("Документы/Учётные данные" + extension)
    route = parser.route_rules({
        "share": "Fixtures", "directory": str(candidate.parent), "path": str(candidate),
        "filename": candidate.name, "extension": extension, "size": len(payload), "mtime": 0,
    })
    assert {"rule:russian-secret-assignment", "rule:assigned-secret"}.issubset(route.matched_rule_ids)
    result = parser.parse_file(candidate, data=payload, rule_route=route)
    assert result.error is None
    assert result.extracted
    assert len(calls) == 1
    return result


@pytest.mark.parametrize("extension", FORMATS)
@pytest.mark.parametrize("copies", [1, 2])
def test_real_unicode_documents_retain_both_labels_and_all_occurrences_without_ocr(monkeypatch, extension, copies):
    result = parse_document(monkeypatch, extension, (RUSSIAN, ENGLISH) * copies)
    for rule_id, label in (("russian-secret-assignment", "Пароль"), ("assigned-secret", "password")):
        findings = [finding for finding in result.findings if finding.rule_id == f"rule:{rule_id}"]
        assert len(findings) == copies
        assert all(PASSWORD in finding.value and label in finding.value for finding in findings)
        assert all(finding.value in finding.context for finding in findings)
        assert len({(finding.start, finding.end) for finding in findings}) == copies


@pytest.mark.parametrize("extension", FORMATS)
def test_public_document_labels_do_not_become_precise_password_findings(monkeypatch, extension):
    result = parse_document(monkeypatch, extension, ("Логин = Алиса", "Открытый ключ = ПубличныеДанные", "Сертификат = Общедоступный"))
    assert not {"rule:russian-secret-assignment", "rule:assigned-secret"}.intersection(
        finding.rule_id for finding in result.findings
    )
