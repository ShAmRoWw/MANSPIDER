"""Explicit Unicode must not be reinterpreted by a short-text language guess."""

import codecs

import pytest

from man_spider.lib.parser import parser as parser_module
from man_spider.lib.parser.parser import decode_text_bytes


TEXT = "БД_password='СложныйПарольЁжик!2027'\r\n"
BOM_ENCODINGS = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
)


def forbid_detector(data):
    raise AssertionError("deterministic Unicode must not require charset detection")


@pytest.mark.parametrize(
    "text",
    ["", "password=PlainAscii!\n", TEXT, "api_key=кириллицаБезЛатиницы", "пароль='漢字🔐Ёжик!'", "e\u0301=Ё\r\n"],
)
def test_valid_non_nul_utf8_is_exact_without_detection(monkeypatch, text):
    monkeypatch.setattr(parser_module, "from_bytes", forbid_detector)
    assert decode_text_bytes(text.encode("utf-8")) == text


@pytest.mark.parametrize(("bom", "encoding"), BOM_ENCODINGS)
@pytest.mark.parametrize("text", [TEXT, "", "пароль='🔐Ёжик!'\n", "password='До\x00После!'", "\ufeffпароль='Секрет!'\ufeff"])
def test_unicode_bom_is_authoritative_and_only_the_bom_is_removed(monkeypatch, bom, encoding, text):
    monkeypatch.setattr(parser_module, "from_bytes", forbid_detector)
    assert decode_text_bytes(bom + text.encode(encoding)) == text


@pytest.mark.parametrize(
    "data",
    [
        codecs.BOM_UTF8 + b"password='\xffBroken!'",
        codecs.BOM_UTF8 + b"\xed\xa0\x80",  # UTF-8 encoded surrogate.
        codecs.BOM_UTF8 + b"\xc0\xaf",  # Overlong UTF-8.
        codecs.BOM_UTF16_LE + b"p",
        codecs.BOM_UTF16_BE + b"p",
        codecs.BOM_UTF16_LE + b"\x00\xd8",  # Unpaired high surrogate.
        codecs.BOM_UTF16_BE + b"\xdc\x00",  # Unpaired low surrogate.
        codecs.BOM_UTF32_LE + b"p\x00\x00",
        codecs.BOM_UTF32_BE + b"\x00\x00p",
        codecs.BOM_UTF32_LE + b"\x00\x00\x11\x00",  # Code point beyond Unicode.
        codecs.BOM_UTF32_BE + b"\x00\x00\xd8\x00",  # Surrogate is not a scalar.
    ],
)
def test_malformed_explicit_unicode_is_not_lossily_relabelled(monkeypatch, data):
    monkeypatch.setattr(parser_module, "from_bytes", forbid_detector)
    assert decode_text_bytes(data) is None


@pytest.mark.parametrize(
    "data",
    [
        TEXT.encode("cp1251"),
        TEXT.encode("koi8-r"),
        TEXT.encode("cp866"),
        "password=PlainAscii!".encode("utf-16-le"),
        "password=PlainAscii!".encode("utf-32-be"),
        b"prefix\x00suffix",
        b"\xff\x80\xfe\xc0legacy",
    ],
)
def test_ambiguous_non_bom_legacy_and_nul_streams_keep_detector_semantics(monkeypatch, data):
    calls = []

    class Match:
        encoding = "fixture-legacy"

        def __str__(self):
            return "UnchangedDetectorResult"

    class Detection:
        def best(self):
            return Match()

    monkeypatch.setattr(parser_module, "from_bytes", lambda raw: calls.append(raw) or Detection())
    assert decode_text_bytes(data) == "UnchangedDetectorResult"
    assert calls == [data]


@pytest.mark.parametrize("missing_encoding", [False, True])
def test_unrecognized_legacy_stream_remains_none(monkeypatch, missing_encoding):
    class Match:
        encoding = None

    class Detection:
        def best(self):
            return Match() if missing_encoding else None

    monkeypatch.setattr(parser_module, "from_bytes", lambda raw: Detection())
    assert decode_text_bytes(b"\xfflegacy") is None
