"""Small offline regressions for the pinned extractor's lexical-prefix bug."""

import hashlib
import io
import socket
import stat
import zipfile
from xml.etree import ElementTree as ET

import pytest

from man_spider.lib.parser import FileParser
from man_spider.lib.parser import parser as parser_module
from man_spider.lib.parser import wordprocessingml as word


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
STRICT_W = "http://purl.oclc.org/ooxml/wordprocessingml/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CONTENT_TYPES = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
ROOT_RELS = f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{R}/officeDocument" Target="word/document.xml"/></Relationships>'


def package(xml, extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in [
            ("[Content_Types].xml", CONTENT_TYPES),
            ("_rels/.rels", ROOT_RELS),
            ("word/document.xml", xml),
            *extra,
        ]:
            archive.writestr(name, data)
    return output.getvalue()


def document(prefix="w", marker="NAMESPACE_SECRET", namespace=W):
    def qualify(name):
        return f"{prefix}:{name}" if prefix else name

    declaration = f'xmlns:{prefix}="{namespace}"' if prefix else f'xmlns="{namespace}"'
    return (
        f"<{qualify('document')} {declaration}><{qualify('body')}><{qualify('p')}>"
        f"<{qualify('r')}><{qualify('t')}>{marker}</{qualify('t')}></{qualify('r')}>"
        f"</{qualify('p')}><{qualify('sectPr')}/></{qualify('body')}></{qualify('document')}>"
    )


def parse(data, name="test.docx", pattern="NAMESPACE_SECRET"):
    return FileParser([pattern], quiet=True, blocked_extensions=[]).parse_file(name, data=data)


def xml_shape(data):
    root = ET.fromstring(data)

    def shape(element):
        return element.tag, element.attrib, element.text, element.tail, tuple(map(shape, element))

    return shape(root)


@pytest.mark.parametrize("prefix", ["w", "ns0", "other", ""])
@pytest.mark.parametrize("namespace", [W, STRICT_W])
def test_equivalent_namespace_spellings_are_not_silently_empty(prefix, namespace):
    result = parse(package(document(prefix, namespace=namespace)))
    assert result.error is None
    assert result.extracted is True
    assert [finding.value for finding in result.findings] == ["NAMESPACE_SECRET"]


def test_canonical_package_and_parts_are_returned_without_repacking():
    source = package(document())
    assert word.normalize_wordprocessingml(source) is source


def test_mixed_prefix_partial_extraction_preserves_nested_tables_whitespace_and_breaks():
    body = (
        "<w:p><w:r><w:t>FIRST_SECRET</w:t></w:r></w:p>"
        '<w:tbl><w:tr><w:tc><x:p><x:r><x:t xml:space="preserve">  SECOND_SECRET  </x:t>'
        "<x:tab/><x:t>TAB_SECRET</x:t><x:br/><x:t>BREAK_SECRET</x:t></x:r></x:p>"
        "<x:tbl><x:tr><x:tc><w:p><w:r><w:t>NESTED_SECRET</w:t></w:r></w:p></x:tc></x:tr></x:tbl>"
        "</w:tc></w:tr></w:tbl>"
    )
    xml = f'<w:document xmlns:w="{W}" xmlns:x="{W}"><w:body>{body}</w:body></w:document>'
    data = package(xml)
    normalized = word.normalize_wordprocessingml(data)
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        assert xml_shape(archive.read("word/document.xml")) == xml_shape(xml)
    result = parse(data, pattern=r"[A-Z]+_SECRET")
    assert result.error is None
    assert {finding.value for finding in result.findings} == {
        "FIRST_SECRET",
        "SECOND_SECRET",
        "TAB_SECRET",
        "BREAK_SECRET",
        "NESTED_SECRET",
    }


def test_all_word_parts_and_qname_only_namespace_declarations_are_preserved():
    xml = (
        f'<x:document xmlns:x="{W}" xmlns:q="urn:only-in-values" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'mc:Ignorable="q" xsi:type="q:DocumentType"><x:body>'
        '<mc:AlternateContent><mc:Choice Requires="q"><x:p><x:r>'
        '<x:t xml:space="preserve"> a&#13;b&#10;c&#9;d </x:t>'
        "</x:r></x:p></mc:Choice></mc:AlternateContent></x:body></x:document>"
    )
    extras = [
        ("word/header1.xml", f'<x:hdr xmlns:x="{W}"><x:p><x:r><x:t>HEADER_SECRET</x:t></x:r></x:p></x:hdr>'),
        ("word/footer1.xml", f'<x:ftr xmlns:x="{W}"><x:p><x:r><x:t>FOOTER_SECRET</x:t></x:r></x:p></x:ftr>'),
        (
            "word/footnotes.xml",
            f'<x:footnotes xmlns:x="{W}"><x:footnote x:id="1"><x:p><x:r><x:t>FOOTNOTE_SECRET</x:t></x:r></x:p></x:footnote></x:footnotes>',
        ),
        (
            "word/endnotes.xml",
            f'<x:endnotes xmlns:x="{W}"><x:endnote x:id="1"><x:p><x:r><x:t>ENDNOTE_SECRET</x:t></x:r></x:p></x:endnote></x:endnotes>',
        ),
        (
            "word/numbering.xml",
            f'<x:numbering xmlns:x="{W}"><x:abstractNum x:abstractNumId="0"><x:lvl x:ilvl="0"><x:numFmt x:val="bullet"/><x:lvlText x:val="•"/></x:lvl></x:abstractNum></x:numbering>',
        ),
    ]
    original = package(xml, extras)
    normalized = word.normalize_wordprocessingml(original)
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        for name, content in [("word/document.xml", xml), *extras]:
            rewritten = archive.read(name)
            assert xml_shape(rewritten) == xml_shape(content)
            assert b"xmlns:x=" in rewritten
            assert b"xmlns:w=" in rewritten
        rewritten = archive.read("word/document.xml")
        assert b'xmlns:q="urn:only-in-values"' in rewritten
        assert b'mc:Ignorable="q"' in rewritten
        assert b'Requires="q"' in rewritten
        assert b'xsi:type="q:DocumentType"' in rewritten


def test_relationship_alias_and_hyperlink_are_retained():
    xml = (
        f'<x:document xmlns:x="{W}" xmlns:rel="{R}"><x:body><x:p>'
        '<x:hyperlink x:anchor="localBookmark" rel:id="internalLink"><x:r><x:t>NAMESPACE_SECRET</x:t>'
        "</x:r></x:hyperlink></x:p></x:body></x:document>"
    )
    canonical = (
        xml.replace("x:", "w:").replace("xmlns:x=", "xmlns:w=").replace("rel:", "r:").replace("xmlns:rel=", "xmlns:r=")
    )
    transformed = word.normalize_wordprocessingml(package(xml))
    with zipfile.ZipFile(io.BytesIO(transformed)) as archive:
        assert xml_shape(archive.read("word/document.xml")) == xml_shape(xml)
    actual = parse(package(xml))
    expected = parse(package(canonical))
    assert actual.error == expected.error is None
    assert [finding.value for finding in actual.findings] == [finding.value for finding in expected.findings]


def test_lists_headers_footers_notes_and_links_keep_complete_native_output():
    def feature_package(prefix):
        body = (
            f'<{prefix}:p><{prefix}:pPr><{prefix}:numPr><{prefix}:ilvl {prefix}:val="0"/>'
            f'<{prefix}:numId {prefix}:val="1"/></{prefix}:numPr></{prefix}:pPr>'
            f"<{prefix}:r><{prefix}:t>LIST_SECRET</{prefix}:t></{prefix}:r></{prefix}:p>"
            f'<{prefix}:p><{prefix}:hyperlink {prefix}:anchor="local"><{prefix}:r>'
            f"<{prefix}:t>LINK_SECRET</{prefix}:t></{prefix}:r></{prefix}:hyperlink></{prefix}:p>"
            f"<{prefix}:p><{prefix}:r><{prefix}:t>MAIN_SECRET</{prefix}:t>"
            f'<{prefix}:footnoteReference {prefix}:id="1"/><{prefix}:endnoteReference {prefix}:id="1"/>'
            f"</{prefix}:r></{prefix}:p><{prefix}:sectPr>"
            f'<{prefix}:headerReference {prefix}:type="default" r:id="header"/>'
            f'<{prefix}:footerReference {prefix}:type="default" r:id="footer"/></{prefix}:sectPr>'
        )
        main = f'<{prefix}:document xmlns:{prefix}="{W}" xmlns:r="{R}"><{prefix}:body>{body}</{prefix}:body></{prefix}:document>'
        extras = []
        links = []
        for filename, root, inner, marker, kind in [
            ("header1.xml", "hdr", None, "HEADER_SECRET", "header"),
            ("footer1.xml", "ftr", None, "FOOTER_SECRET", "footer"),
            ("footnotes.xml", "footnotes", "footnote", "FOOTNOTE_SECRET", "footnotes"),
            ("endnotes.xml", "endnotes", "endnote", "ENDNOTE_SECRET", "endnotes"),
        ]:
            paragraph = f"<{prefix}:p><{prefix}:r><{prefix}:t>{marker}</{prefix}:t></{prefix}:r></{prefix}:p>"
            if inner:
                paragraph = f'<{prefix}:{inner} {prefix}:id="1">{paragraph}</{prefix}:{inner}>'
            extras.append(("word/" + filename, f'<{prefix}:{root} xmlns:{prefix}="{W}">{paragraph}</{prefix}:{root}>'))
            links.append(f'<Relationship Id="{kind}" Type="{R}/{kind}" Target="{filename}"/>')
        extras.append(
            (
                "word/_rels/document.xml.rels",
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + "".join(links)
                + "</Relationships>",
            )
        )
        extras.append(
            (
                "word/numbering.xml",
                f'<{prefix}:numbering xmlns:{prefix}="{W}"><{prefix}:abstractNum {prefix}:abstractNumId="0"><{prefix}:lvl {prefix}:ilvl="0"><{prefix}:start {prefix}:val="1"/><{prefix}:numFmt {prefix}:val="decimal"/><{prefix}:lvlText {prefix}:val="%1."/></{prefix}:lvl></{prefix}:abstractNum><{prefix}:num {prefix}:numId="1"><{prefix}:abstractNumId {prefix}:val="0"/></{prefix}:num></{prefix}:numbering>',
            )
        )
        return package(main, extras)

    mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    config = parser_module._kreuzberg_extraction_config()
    expected = parser_module.extract_bytes_sync(feature_package("w"), mime, config=config).content
    actual = parser_module.extract_bytes_sync(feature_package("alternate"), mime, config=config).content
    assert expected == actual
    assert "MAIN_SECRET" in actual
    assert "LIST_SECRET" in actual
    assert "LINK_SECRET" in actual


@pytest.mark.parametrize(
    "name", ["test.docx", "test.docx.old", "test.docx.bak.20260601", "test.docm", "test.docm.old"]
)
def test_backups_and_macro_enabled_containers_use_the_same_namespace_fix(name):
    result = parse(package(document("alias")), name)
    assert result.error is None
    assert [finding.value for finding in result.findings] == ["NAMESPACE_SECRET"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_xml_character_semantics_and_encodings_are_preserved(encoding):
    xml = document("alias", marker="NAMESPACE_SECRET &amp; &lt; &#x1f642;")
    data = ('<?xml version="1.0" encoding="' + encoding + '"?>' + xml).encode(encoding)
    normalized = word.normalize_wordprocessingml(package(data))
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        assert xml_shape(archive.read("word/document.xml")) == xml_shape(data)
    assert parse(package(data)).findings[0].value == "NAMESPACE_SECRET"


@pytest.mark.parametrize(
    "declaration",
    [
        '<!DOCTYPE a SYSTEM "http://127.0.0.1:9/never-request">',
        '<!DOCTYPE a [<!ENTITY secret "NAMESPACE_SECRET">]>',
        '<!DOCTYPE a [<!ENTITY secret SYSTEM "file:///not-read">]>',
    ],
)
@pytest.mark.parametrize("prefix", ["w", "alias"])
def test_dtd_entities_never_reach_native_extraction_or_plaintext_fallback(declaration, prefix, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: pytest.fail("no socket is allowed"))
    monkeypatch.setattr(parser_module, "_kreuzberg_extraction_config", lambda: object())
    monkeypatch.setattr(parser_module, "_load_kreuzberg", lambda: pytest.fail("DTD reached native code"))
    result = parse(package(declaration + document(prefix)))
    assert result.error and "DTD and entity declarations are disabled" in result.error
    assert result.findings == ()
    assert result.representation_errors


@pytest.mark.parametrize(
    "xml",
    [
        '<x:document xmlns:x="' + W + '"><x:body>',
        "<x:document><x:body/></x:document>",
        '<x:document xmlns:x="' + W + '" xmlns:w="urn:foreign"><x:body/></x:document>',
        '<w:document xmlns:w="urn:foreign"><w:body><w:t>NAMESPACE_SECRET</w:t></w:body></w:document>',
    ],
)
def test_malformed_or_ambiguous_namespace_is_an_explicit_error(xml):
    result = parse(package(xml))
    assert result.error is not None
    assert result.findings == ()


def test_foreign_namespace_text_is_not_promoted_to_word_text():
    xml = (
        f'<w:document xmlns:w="{W}" xmlns:evil="urn:not-word"><w:body>'
        "<evil:p><evil:r><evil:t>NAMESPACE_SECRET</evil:t></evil:r></evil:p></w:body></w:document>"
    )
    source = package(xml)
    assert word.normalize_wordprocessingml(source) is source
    assert parse(source).findings == ()


@pytest.mark.parametrize(
    "name", ["../escape.xml", "/absolute.xml", "word/../document.xml", "word\\bad.xml", "C:/file.xml"]
)
def test_unsafe_archive_members_are_rejected_without_extraction(name):
    result = parse(package(document("alias"), [(name, "x")]))
    assert result.error and "unsafe part name" in result.error


def test_duplicate_and_symlink_archive_members_are_rejected():
    result = parse(package(document("alias"), [("WORD/document.xml", document())]))
    assert result.error and "duplicate/ambiguous" in result.error
    entry = zipfile.ZipInfo("word/linked.xml")
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    result = parse(package(document("alias"), [(entry, "../../outside")]))
    assert result.error and "symbolic-link" in result.error


@pytest.mark.parametrize("budget", ["_MAX_PARTS", "_MAX_PACKAGE_BYTES", "_MAX_XML_BYTES", "_MAX_XML_DEPTH"])
def test_resource_budget_exhaustion_is_explicit_without_partial_results(budget, monkeypatch):
    monkeypatch.setattr(word, budget, 1)
    result = parse(package(document("alias")))
    assert result.error is not None
    assert result.findings == ()


def test_original_source_macro_signature_and_other_members_are_never_rewritten(tmp_path):
    opaque = [
        ("word/vbaProject.bin", b"SYNTHETIC_MACRO_BYTES"),
        ("_xmlsignatures/sig1.xml", b"SYNTHETIC_SIGNATURE_BYTES"),
        ("word/media/picture.png", b"SYNTHETIC_IMAGE_BYTES"),
    ]
    source = package(document("alias"), opaque)
    path = tmp_path / "source.docm"
    path.write_bytes(source)
    before = path.stat()
    result = FileParser(["NAMESPACE_SECRET"], quiet=True, blocked_extensions=[]).parse_file(path)
    after = path.stat()
    assert result.error is None and result.findings
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(source).digest()
    assert (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino) == (
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_ino,
    )
    assert sorted(item.name for item in tmp_path.iterdir()) == ["source.docm"]
    with zipfile.ZipFile(io.BytesIO(word.normalize_wordprocessingml(source))) as archive:
        for name, payload in opaque:
            assert archive.read(name) == payload


def test_raw_representation_retains_original_bytes_and_loader_is_called_once():
    source = package(document("alias"))
    loads = []
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            {
                "id": "structured",
                "match": {},
                "actions": [{"type": "scan", "representation": "structured", "pattern": "NAMESPACE_SECRET"}],
            },
            {
                "id": "raw",
                "match": {},
                "actions": [{"type": "scan", "representation": "raw", "pattern": "word/document\\.xml"}],
            },
        ],
    )
    result = parser.parse_file("source.docx", data_loader=lambda: loads.append(1) or source)
    assert result.error is None
    assert loads == [1]
    assert {finding.representation for finding in result.findings} == {"raw", "structured"}
    for finding in result.findings:
        if finding.representation == "raw":
            assert source[finding.start : finding.end].decode("latin-1") == finding.value


def test_batch_and_single_paths_find_noncanonical_and_mixed_documents():
    parser = FileParser(["NAMESPACE_SECRET"], quiet=True, blocked_extensions=[])
    first, second = package(document("alias")), package(document("other"))
    loads = []
    outcomes = parser.preextract_structured_batch(
        [
            (1, "one.docx", None, lambda: loads.append(1) or first),
            (2, "two.docx.old", None, lambda: loads.append(2) or second),
        ]
    )
    assert loads == [1, 2]
    assert all(succeeded and "NAMESPACE_SECRET" in text for succeeded, text in outcomes.values())


def test_batch_error_never_hides_the_bad_xml_or_the_valid_sibling():
    parser = FileParser(["NAMESPACE_SECRET"], quiet=True, blocked_extensions=[])
    malformed = package("<broken>")
    outcomes = parser.preextract_structured_batch(
        [
            (1, "good.docx", None, lambda: package(document("alias"))),
            (2, "bad.docx", None, lambda: malformed),
        ]
    )
    assert outcomes[1][0] is True and "NAMESPACE_SECRET" in outcomes[1][1]
    assert outcomes[2][0] is False and "invalid XML" in str(outcomes[2][1])


def test_repacking_unchanged_binary_parts_never_uses_unbounded_reads(monkeypatch):
    source = package(document("alias"), [("word/vbaProject.bin", b"SMALL_SYNTHETIC_BINARY")])
    reads = []
    original_read = zipfile.ZipExtFile.read

    def checked_read(stream, size=-1):
        assert 0 <= size <= word._MAX_PACKAGE_BYTES + 1
        reads.append((stream.name, size))
        return original_read(stream, size)

    with monkeypatch.context() as context:
        context.setattr(zipfile.ZipExtFile, "read", checked_read)
        normalized = word.normalize_wordprocessingml(source)
    assert ("word/vbaProject.bin", word._MAX_PACKAGE_BYTES + 1) in reads
    assert ("[Content_Types].xml", word._MAX_PACKAGE_BYTES + 1) in reads
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        assert archive.read("word/vbaProject.bin") == b"SMALL_SYNTHETIC_BINARY"
