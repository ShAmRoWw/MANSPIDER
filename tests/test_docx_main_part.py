"""Offline regressions for internal OPC main-part relocation during analysis."""

import hashlib
import io
import socket
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from man_spider.lib.parser import FileParser
from man_spider.lib.parser import parser as parser_module
from man_spider.lib.parser import wordprocessingml as word
from test_docx_namespaces import R, STRICT_W, W, document, parse
from tests.optional_fixtures import require_private_directory


PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
MAIN_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
MACRO_CT = "application/vnd.ms-word.document.macroEnabled.main+xml"
MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def packed(parts):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return output.getvalue()


def relationships(records, prefix="", declaration=""):
    p = prefix + ":" if prefix else ""
    xmlns = "xmlns:" + prefix if prefix else "xmlns"
    children = []
    for index, attrs in enumerate(records):
        attrs = {"Id": "r" + str(index), **attrs}
        values = " ".join(f'{key}="{value}"' for key, value in attrs.items())
        children.append(f"<{p}Relationship {values}/>")
    return declaration + f'<{p}Relationships {xmlns}="{PKG}">' + "".join(children) + f"</{p}Relationships>"


def source_parts(main="custom/main.xml", target=None, prefix="alias", content_type=MAIN_CT,
                 rel_prefix="", namespace=W):
    return {
        "[Content_Types].xml": f'<Types xmlns="{CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        f'<Default Extension="xml" ContentType="application/xml"/><Override PartName="/{main}" ContentType="{content_type}"/></Types>',
        "_rels/.rels": relationships([{"Type": R + "/officeDocument", "Target": target or main}], rel_prefix),
        main: document(prefix, namespace=namespace),
    }


@pytest.mark.parametrize("main,target", [
    ("custom/main.xml", "custom/main.xml"),
    ("document.xml", "document.xml"),
    ("deep/more/body.data", "/deep/more/body.data"),
    ("custom/main.xml", "folder/../custom/./main.xml"),
    ("custom/main.xml", "custom/%6dain.xml"),
    ("custom/main file.xml", "custom/main%20file.xml"),
    ("custom/main.xml", "CUSTOM/MAIN.XML"),
    ("WORD/document.xml", "WORD/document.xml"),
])
@pytest.mark.parametrize("rel_prefix", ["", "package"])
def test_nonstandard_main_is_found_with_internal_uri_resolution(main, target, rel_prefix):
    data = packed(source_parts(main, target, rel_prefix=rel_prefix))
    result = parse(data)
    assert result.error is None
    assert [finding.value for finding in result.findings] == ["NAMESPACE_SECRET"]
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(data))) as archive:
        assert "word/document.xml" in archive.namelist()
        assert main not in archive.namelist()


@pytest.mark.parametrize("namespace", [W, STRICT_W])
@pytest.mark.parametrize("name,content_type", [
    ("source.docx", MAIN_CT), ("source.docx.old", MAIN_CT),
    ("source.docx.bak.20260601", MAIN_CT), ("source.docm", MACRO_CT),
    ("source.docm.old", MACRO_CT),
])
def test_strict_macro_and_backup_containers(name, content_type, namespace):
    parts = source_parts(content_type=content_type, namespace=namespace)
    parts["custom/vbaProject.bin"] = b"SYNTHETIC_MACRO_BYTES"
    data = packed(parts)
    result = parse(data, name)
    assert result.error is None and result.findings[0].value == "NAMESPACE_SECRET"
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(data))) as archive:
        assert archive.read("custom/vbaProject.bin") == b"SYNTHETIC_MACRO_BYTES"
        types = ET.fromstring(archive.read("[Content_Types].xml"))
        override = next(item for item in types if item.get("PartName") == "/word/document.xml")
        assert override.get("ContentType") == content_type


def linked_parts(main):
    parts = source_parts(main, prefix="w")
    parts[main] = (
        f'<w:document xmlns:w="{W}" xmlns:r="{R}" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><w:body><w:p>'
        '<w:hyperlink r:id="link"><w:r><w:t>NAMESPACE_SECRET</w:t></w:r></w:hyperlink>'
        '<w:r><w:footnoteReference w:id="1"/><w:drawing><wp:inline><a:graphic>'
        '<a:graphicData><a:blip r:embed="image"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>'
        '</w:p><w:sectPr><w:headerReference w:type="default" r:id="header"/></w:sectPr></w:body></w:document>'
    )
    parts["shared/header.xml"] = f'<x:hdr xmlns:x="{W}"><x:p><x:r><x:t>HEADER_SECRET</x:t></x:r></x:p></x:hdr>'
    parts["shared/footnotes.xml"] = f'<x:footnotes xmlns:x="{W}"><x:footnote x:id="1"><x:p><x:r><x:t>NOTE_SECRET</x:t></x:r></x:p></x:footnote></x:footnotes>'
    parts["images/test image.png"] = b"SYNTHETIC_OPAQUE_IMAGE_BYTES"
    parts[word._relationship_name(main)] = relationships([
        {"Id": "link", "Type": R + "/hyperlink", "Target": "https://example.invalid/never-connect?q=1&amp;x=2", "TargetMode": "External"},
        {"Id": "image", "Type": R + "/image", "Target": "../images/test%20image.png"},
        {"Id": "header", "Type": R + "/header", "Target": "../shared/header.xml"},
        {"Id": "notes", "Type": R + "/footnotes", "Target": "../shared/footnotes.xml"},
    ], prefix="pkg")
    parts["shared/_rels/header.xml.rels"] = relationships([
        {"Type": R + "/hyperlink", "Target": "../" + main + "#local"},
        {"Type": R + "/image", "Target": "../images/test%20image.png"},
    ])
    return parts


def test_relocation_preserves_resolved_relationships_and_native_output(monkeypatch):
    parts = linked_parts("custom/main.xml")
    source = packed(parts)
    normalized = word.normalize_wordprocessingml(source)
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        root = ET.fromstring(archive.read("_rels/.rels"))
        assert root[0].get("Target") == "word/document.xml"
        rels = ET.fromstring(archive.read("word/_rels/document.xml.rels"))
        targets = {node.get("Id"): node.get("Target") for node in rels}
        assert targets == {
            "link": "https://example.invalid/never-connect?q=1&x=2",
            "image": "../images/test%20image.png",
            "header": "../shared/header.xml",
            "notes": "../shared/footnotes.xml",
        }
        other = ET.fromstring(archive.read("shared/_rels/header.xml.rels"))
        assert other[0].get("Target") == "../word/document.xml#local"
        assert other[1].get("Target") == "../images/test%20image.png"
        assert archive.read("images/test image.png") == parts["images/test image.png"]
        assert b"<w:hdr" in archive.read("shared/header.xml")
        assert b"<w:footnotes" in archive.read("shared/footnotes.xml")
    # Canonical baseline goes directly through the same pinned native extractor.
    # Keep all auxiliary parts identical; this is relocation parity, not a new
    # promise that the dependency extracts every possible DOCX feature.
    canonical = linked_parts("word/document.xml")
    for name in ("shared/header.xml", "shared/footnotes.xml"):
        canonical[name] = word._canonical_xml(canonical[name].encode(), name)
    config = parser_module._kreuzberg_extraction_config()
    expected = parser_module.extract_bytes_sync(packed(canonical), MIME, config=config).content
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: pytest.fail("no network socket is allowed"))
    actual = parser_module.extract_bytes_sync(source, MIME, config=config).content
    assert actual == expected
    assert "NAMESPACE_SECRET" in actual


def test_nested_main_rebases_own_links_and_preserves_other_parts():
    parts = linked_parts("custom/main.xml")
    parts["nested/custom/main.xml"] = parts.pop("custom/main.xml")
    parts["nested/custom/_rels/main.xml.rels"] = parts.pop("custom/_rels/main.xml.rels").replace('Target="../', 'Target="../../')
    parts["[Content_Types].xml"] = parts["[Content_Types].xml"].replace("/custom/main.xml", "/nested/custom/main.xml")
    parts["_rels/.rels"] = parts["_rels/.rels"].replace('Target="custom/', 'Target="nested/custom/')
    parts["shared/_rels/header.xml.rels"] = parts["shared/_rels/header.xml.rels"].replace("../custom/main.xml", "../nested/custom/main.xml")
    normalized = word.normalize_wordprocessingml(packed(parts))
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        targets = {node.get("Id"): node.get("Target") for node in ET.fromstring(archive.read("word/_rels/document.xml.rels"))}
        assert targets["image"] == "../images/test%20image.png"
        assert targets["header"] == "../shared/header.xml"
        assert targets["notes"] == "../shared/footnotes.xml"


def test_relationship_owner_case_alias_is_resolved_before_rebase():
    parts = source_parts("Nested/Custom/main.xml")
    parts["nested/custom/_rels/main.xml.rels"] = relationships([
        {"Type": R + "/image", "Target": "../../images/picture.png"},
    ])
    parts["images/picture.png"] = b"SYNTHETIC_OPAQUE_IMAGE"
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(packed(parts)))) as archive:
        rel = ET.fromstring(archive.read("word/_rels/document.xml.rels"))[0]
        assert rel.get("Target") == "../images/picture.png"


def test_rewritten_relationship_attributes_preserve_character_reference_whitespace():
    parts = source_parts()
    parts["custom/_rels/main.xml.rels"] = relationships([
        {"Type": R + "/image", "Target": "image.png"},
        {"Type": R + "/hyperlink", "TargetMode": "External", "Target": "https://example.invalid/a&#13;b&#10;c&#9;d"},
    ])
    original = ET.fromstring(parts["custom/_rels/main.xml.rels"])[1].attrib
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(packed(parts)))) as archive:
        rewritten = ET.fromstring(archive.read("word/_rels/document.xml.rels"))[1].attrib
        assert rewritten == original


@pytest.mark.parametrize("with_numbering", [False, True])
def test_relocated_whole_word_directory_matches_real_canonical_document(with_numbering):
    require_private_directory("testdata")
    with zipfile.ZipFile(Path(__file__).resolve().parents[1] / "testdata/test.docx") as archive:
        canonical = {name: archive.read(name) for name in archive.namelist()}
    if with_numbering:
        root = ET.fromstring(canonical["word/document.xml"])
        body = root.find("{" + W + "}body")
        paragraph = ET.fromstring(
            f'<w:p xmlns:w="{W}"><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr>'
            '<w:r><w:t>NUMBERED_SECRET</w:t></w:r></w:p>'
        )
        body.insert(0, paragraph)
        canonical["word/document.xml"] = ET.tostring(root)
        canonical["word/numbering.xml"] = (
            f'<w:numbering xmlns:w="{W}"><w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0">'
            '<w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/></w:lvl></w:abstractNum>'
            '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num></w:numbering>'
        ).encode()
        rels = ET.fromstring(canonical["word/_rels/document.xml.rels"])
        ET.SubElement(rels, "{" + PKG + "}Relationship", {"Id": "numbering", "Type": R + "/numbering", "Target": "numbering.xml"})
        canonical["word/_rels/document.xml.rels"] = ET.tostring(rels)
        types = ET.fromstring(canonical["[Content_Types].xml"])
        ET.SubElement(types, "{" + CT + "}Override", {"PartName": "/word/numbering.xml", "ContentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"})
        canonical["[Content_Types].xml"] = ET.tostring(types)
    renamed = {}
    for name, data in canonical.items():
        destination = name.replace("word/", "custom/", 1) if name.startswith("word/") else name
        destination = destination.replace("custom/document.xml", "custom/main.xml").replace("custom/_rels/document.xml.rels", "custom/_rels/main.xml.rels")
        if name in {"[Content_Types].xml", "_rels/.rels"}:
            data = data.replace(b"word/", b"custom/").replace(b"custom/document.xml", b"custom/main.xml")
        renamed[destination] = data
    config = parser_module._kreuzberg_extraction_config()
    expected = parser_module.extract_bytes_sync(packed(canonical), MIME, config=config).content
    actual = parser_module.extract_bytes_sync(packed(renamed), MIME, config=config).content
    assert actual == expected


@pytest.mark.parametrize("target", [
    "../custom/main.xml", "http://example.invalid/main.xml", "//example.invalid/main.xml",
    "file:///tmp/main.xml", "custom%2fmain.xml", "custom%5cmain.xml", "custom\\main.xml",
    "custom/%zz.xml", "custom/main.xml?query=1", "custom/main.xml#fragment", "missing.xml",
])
def test_unsafe_missing_or_external_main_is_never_used(target, monkeypatch):
    monkeypatch.setattr(parser_module, "_kreuzberg_extraction_config", lambda: object())
    monkeypatch.setattr(parser_module, "_load_kreuzberg", lambda: pytest.fail("unsafe package reached native extractor"))
    result = parse(packed(source_parts(target=target)))
    assert result.error and not result.findings


@pytest.mark.parametrize("manifest", ["_rels/.rels", "[Content_Types].xml", "custom/_rels/main.xml.rels"])
def test_metadata_dtd_is_rejected_without_native_or_network(manifest, monkeypatch):
    parts = linked_parts("custom/main.xml")
    parts[manifest] = '<!DOCTYPE a SYSTEM "https://example.invalid/never-connect">' + parts[manifest]
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: pytest.fail("no socket is allowed"))
    monkeypatch.setattr(parser_module, "_kreuzberg_extraction_config", lambda: object())
    monkeypatch.setattr(parser_module, "_load_kreuzberg", lambda: pytest.fail("DTD reached native extractor"))
    result = parse(packed(parts))
    assert result.error and "DTD and entity" in result.error
    assert not result.findings


@pytest.mark.parametrize("case", ["foreign-root", "wrong-type", "missing-type", "external-main", "multiple-main", "duplicate-id", "collision", "rels-collision", "orphan-rels-collision"])
def test_ambiguous_packages_are_rejected_explicitly(case):
    parts = source_parts()
    if case == "foreign-root":
        parts["custom/main.xml"] = '<secret>NAMESPACE_SECRET</secret>'
    elif case == "wrong-type":
        parts["[Content_Types].xml"] = parts["[Content_Types].xml"].replace(MAIN_CT, "application/xml")
    elif case == "missing-type":
        parts.pop("[Content_Types].xml")
    elif case == "external-main":
        parts["_rels/.rels"] = parts["_rels/.rels"].replace('Target="custom/main.xml"', 'Target="custom/main.xml" TargetMode="External"')
    elif case == "multiple-main":
        parts["_rels/.rels"] = relationships([{"Type": R + "/officeDocument", "Target": "custom/main.xml"}] * 2)
    elif case == "duplicate-id":
        parts["custom/_rels/main.xml.rels"] = relationships([{"Id": "same", "Type": R + "/image", "Target": "../image.png"}] * 2)
    elif case == "collision":
        parts["word/document.xml"] = document()
    elif case == "rels-collision":
        parts["custom/_rels/main.xml.rels"] = relationships([])
        parts["word/_rels/document.xml.rels"] = relationships([])
    elif case == "orphan-rels-collision":
        parts["word/_rels/document.xml.rels"] = relationships([])
    result = parse(packed(parts))
    assert result.error and not result.findings


def test_default_extension_content_type_is_preserved_and_new_main_overridden():
    parts = source_parts("custom/main.data")
    parts["[Content_Types].xml"] = f'<Types xmlns="{CT}"><Default Extension="data" ContentType="{MAIN_CT}"/></Types>'
    assert parse(packed(parts)).findings
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(packed(parts)))) as archive:
        root = ET.fromstring(archive.read("[Content_Types].xml"))
        assert root[0].get("Extension") == "data"
        assert root[1].get("PartName") == "/word/document.xml"


def test_main_uses_strict_office_document_relationship_type():
    parts = source_parts(namespace=STRICT_W)
    parts["_rels/.rels"] = parts["_rels/.rels"].replace(R, "http://purl.oclc.org/ooxml/officeDocument/relationships")
    assert parse(packed(parts)).findings[0].value == "NAMESPACE_SECRET"


def test_minimal_canonical_package_without_manifests_still_works():
    source = packed({"word/document.xml": document()})
    assert word.normalize_wordprocessingml(source) is source
    assert parse(source).findings[0].value == "NAMESPACE_SECRET"


def test_arbitrary_custom_xml_without_declared_main_is_not_promoted():
    assert not parse(packed({"custom/main.xml": document()})).findings


@pytest.mark.parametrize("budget", ["_MAX_MANIFEST_RECORDS", "_MAX_XML_BYTES", "_MAX_XML_DEPTH", "_MAX_PACKAGE_BYTES", "_MAX_PARTS"])
def test_relocation_budgets_fail_explicitly_without_native(budget, monkeypatch):
    source = packed(source_parts())
    monkeypatch.setattr(word, budget, 1)
    monkeypatch.setattr(parser_module, "_kreuzberg_extraction_config", lambda: object())
    monkeypatch.setattr(parser_module, "_load_kreuzberg", lambda: pytest.fail("over-budget package reached native"))
    result = parse(source)
    assert result.error and not result.findings


@pytest.mark.parametrize("target", ["../escape.xml", "https://example.invalid/never-connect", "//example.invalid/never-connect"])
def test_internal_child_relationship_cannot_escape_package(target, monkeypatch):
    parts = source_parts()
    parts["custom/_rels/main.xml.rels"] = relationships([{"Type": R + "/image", "Target": "../" + target}])
    if target.startswith(("https:", "//")):
        parts["custom/_rels/main.xml.rels"] = relationships([{"Type": R + "/image", "Target": target}])
    monkeypatch.setattr(parser_module, "_kreuzberg_extraction_config", lambda: object())
    monkeypatch.setattr(parser_module, "_load_kreuzberg", lambda: pytest.fail("unsafe child reached native"))
    result = parse(packed(parts))
    assert result.error and not result.findings


def test_source_file_raw_macro_and_signatures_are_unchanged(tmp_path):
    parts = source_parts(content_type=MACRO_CT)
    parts.update({"custom/vbaProject.bin": b"MACRO_BYTES", "_xmlsignatures/sig1.xml": b"SIGNATURE_BYTES"})
    source = packed(parts)
    path = tmp_path / "source.docm"
    path.write_bytes(source)
    before = path.stat()
    assert FileParser(["NAMESPACE_SECRET"], quiet=True, blocked_extensions=[]).parse_file(path).findings
    after = path.stat()
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(source).digest()
    assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino)
    assert list(tmp_path.iterdir()) == [path]
    parser = FileParser([], quiet=True, blocked_extensions=[], rules=[
        {"id": "structured", "match": {}, "actions": [{"type": "scan", "representation": "structured", "pattern": "NAMESPACE_SECRET"}]},
        {"id": "raw", "match": {}, "actions": [{"type": "scan", "representation": "raw", "pattern": "custom/main\\.xml"}]},
    ])
    loads = []
    result = parser.parse_file("source.docm", data_loader=lambda: loads.append(1) or source)
    assert loads == [1]
    assert {finding.representation for finding in result.findings} == {"raw", "structured"}
    for finding in result.findings:
        if finding.representation == "raw":
            assert source[finding.start:finding.end].decode("latin-1") == finding.value
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(source))) as archive:
        assert archive.read("custom/vbaProject.bin") == b"MACRO_BYTES"
        assert archive.read("_xmlsignatures/sig1.xml") == b"SIGNATURE_BYTES"


def test_batch_mixed_custom_main_good_and_invalid_are_independent():
    parser = FileParser(["NAMESPACE_SECRET"], quiet=True, blocked_extensions=[])
    outcomes = parser.preextract_structured_batch([
        (1, "custom.docx.old", None, lambda: packed(source_parts())),
        (2, "bad.docm", None, lambda: packed(source_parts(target="../escape.xml"))),
        (3, "normal.docx", None, lambda: packed(source_parts("word/document.xml"))),
    ])
    assert outcomes[1][0] is True and "NAMESPACE_SECRET" in outcomes[1][1]
    assert outcomes[2][0] is False
    assert outcomes[3][0] is True and "NAMESPACE_SECRET" in outcomes[3][1]
