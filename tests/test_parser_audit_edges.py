"""Malformed Unicode, shared exact contexts and safe diagnostic rendering."""

import codecs
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from man_spider.lib.finding_log import display_text
from man_spider.lib.parser import parser as parser_module
from man_spider.lib.parser.parser import FileParser, decode_text_bytes
from man_spider.lib.spiderling import Spiderling
from man_spider.rules import load_builtin_rules


def rule(rule_id, representation, pattern):
    return {
        "id": rule_id,
        "match": {},
        "actions": [{"type": "scan", "representation": representation, "pattern": pattern, "flags": []}],
    }


UNICODE_CASES = (
    (codecs.BOM_UTF8, "utf-8", b"\xff"),
    (codecs.BOM_UTF16_LE, "utf-16-le", b"x"),
    (codecs.BOM_UTF16_BE, "utf-16-be", b"x"),
    (codecs.BOM_UTF32_LE, "utf-32-le", b"x"),
    (codecs.BOM_UTF32_BE, "utf-32-be", b"x"),
)


@pytest.mark.parametrize("bom,encoding,tail", UNICODE_CASES)
@pytest.mark.parametrize("remote_bytes", [False, True])
def test_malformed_bom_keeps_fallback_findings_but_reports_partial_analysis(
    monkeypatch, tmp_path, bom, encoding, tail, remote_bytes
):
    data = bom + "password=ЁжикAudit!2026\n".encode(encoding) + tail
    path = tmp_path / "damaged.txt"
    path.write_bytes(data)
    loads = []
    extractions = []
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: extractions.append("fallback") or SimpleNamespace(content="FALLBACK_SECRET"),
    )
    parser = FileParser(["FALLBACK_SECRET"], quiet=True, blocked_extensions=[])
    arguments = {"data_loader": lambda: loads.append("bytes") or data, "path_factory": lambda: path}
    result = parser.parse_file(path, **(arguments if remote_bytes else {}))

    assert [finding.value for finding in result.findings] == ["FALLBACK_SECRET"]
    assert result.extracted is True
    assert len(result.representation_errors) == 1
    assert result.representation_errors[0].representation == "text"
    assert "explicit utf-" in result.error
    assert "fallback text analysis may be incomplete or inexact" in result.error
    assert extractions == ["fallback"]
    assert loads == (["bytes"] if remote_bytes else [])
    worker = Spiderling.__new__(Spiderling)
    worker.remember_parser_analysis(path, result)
    assert worker.file_analysis_observations[id(path)]["analysis_status"] == "partial"

    # The previous return contract discarded diagnostics; every former finding
    # must still survive unchanged, including its exact context and offsets.
    monkeypatch.setattr(parser_module, "decode_text_bytes", lambda data, **_kwargs: decode_text_bytes(data))
    previous = parser.parse_file(path, **(arguments if remote_bytes else {}))
    assert previous.error is None
    assert previous.findings == result.findings


@pytest.mark.parametrize("bom,encoding,_tail", UNICODE_CASES)
def test_valid_bom_has_no_extra_decode_or_materialization(monkeypatch, bom, encoding, _tail):
    decoded = []

    class CountingBytes(bytes):
        def decode(self, encoding="utf-8", errors="strict"):
            decoded.append((encoding, errors))
            return super().decode(encoding, errors)

    text = "password=ЁжикAudit!2026\n"
    data = CountingBytes(bom + text.encode(encoding))
    parser = FileParser(["password=ЁжикAudit!2026"], quiet=True)
    result = parser.parse_file(
        "valid.txt",
        data=data,
        path_factory=lambda: (_ for _ in ()).throw(AssertionError("valid text stays in memory")),
    )
    assert result.error is None
    assert len(result.findings) == 1
    assert len(decoded) == 1
    assert decoded[0][1] == "strict"


def test_malformed_bom_decodes_once_and_keeps_independent_raw_findings(monkeypatch):
    decoded = []

    class CountingBytes(bytes):
        def decode(self, encoding="utf-8", errors="strict"):
            decoded.append((encoding, errors))
            return super().decode(encoding, errors)

    data = CountingBytes(codecs.BOM_UTF8 + b"RAW_SECRET\xff")
    parser = FileParser(
        ["FALLBACK_SECRET"],
        quiet=True,
        rules=[rule("raw", "raw", "RAW_SECRET"), rule("structured", "structured", "FALLBACK_SECRET")],
    )
    monkeypatch.setattr(parser, "_extract_structured", lambda *_args, **_kwargs: "FALLBACK_SECRET")
    result = parser.parse_file("damaged.txt", data=data)
    assert [finding.value for finding in result.findings] == ["FALLBACK_SECRET", "RAW_SECRET", "FALLBACK_SECRET"]
    assert decoded == [("utf-8-sig", "strict"), ("latin-1", "strict")]
    assert len(result.representation_errors) == 1
    assert result.representation_errors[0].rule_ids == ("content:FALLBACK_SECRET",)


def test_malformed_bom_still_has_diagnostic_if_both_fallbacks_fail(monkeypatch):
    parser = FileParser(["SECRET"], quiet=True)

    def fail(*_args, **_kwargs):
        raise RuntimeError("fallback failed")

    monkeypatch.setattr(parser, "_extract_structured", fail)
    monkeypatch.setattr(parser_module, "extract_strings_from_binary", fail)
    result = parser.parse_file("damaged.txt", data=codecs.BOM_UTF16_LE + b"x")
    assert "fallback failed" in result.error
    assert "explicit utf-16 decoding failed" in result.error
    assert len(result.representation_errors) == 2
    assert result.analysis_completed == 0


def test_malformed_bom_strings_fallback_keeps_full_ascii_values(monkeypatch):
    parser = FileParser(["RAW_SECRET"], quiet=True)
    monkeypatch.setattr(
        parser, "_extract_structured", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("unavailable"))
    )
    result = parser.parse_file("damaged.txt", data=codecs.BOM_UTF8 + b"RAW_SECRET\xff")
    assert [finding.value for finding in result.findings] == ["RAW_SECRET"]
    assert "explicit utf-8-sig decoding failed" in result.error


def test_unknown_binary_is_not_misclassified_as_malformed_unicode(monkeypatch):
    parser = FileParser(["FALLBACK_SECRET"], quiet=True)
    monkeypatch.setattr(parser_module, "from_bytes", lambda _data: SimpleNamespace(best=lambda: None))
    monkeypatch.setattr(parser, "_extract_structured", lambda *_args, **_kwargs: "FALLBACK_SECRET")
    result = parser.parse_file("binary.txt", data=b"\x80\x81\x82")
    assert result.error is None
    assert [finding.value for finding in result.findings] == ["FALLBACK_SECRET"]


def test_raw_only_does_not_declare_a_text_decode_failure():
    parser = FileParser([], quiet=True, rules=[rule("raw", "raw", "RAW_SECRET")])
    result = parser.parse_file("binary.txt", data=codecs.BOM_UTF8 + b"RAW_SECRET\xff")
    assert result.error is None
    assert [finding.value for finding in result.findings] == ["RAW_SECRET"]


@pytest.mark.parametrize(
    "text,pattern",
    [
        ("FIRST SECOND\n", "FIRST|SECOND"),
        ("FIRST SECOND\r\n", "FIRST|SECOND"),
        ("FIRST SECOND\r\r\n", "FIRST|SECOND"),
        ("FIRST\nSECOND\nTHIRD", "FIRST|SECOND|THIRD|(?s:FIRST.*?SECOND)"),
        ("FIRST\rSECOND\r", "FIRST|SECOND"),
        ("FIRST SECOND", "FIRST|SECOND"),
        ("FIRST\nSECOND\n", r"(?m:^)|(?m:$)|FIRST|SECOND"),
        ("FIRST\u2028SECOND\n", "FIRST|SECOND"),
        ("FIRST\n\nSECOND\r\n", "(?s:FIRST.*?SECOND)|SECOND"),
        ("🔐 FIRST Ёжик SECOND\n", "FIRST|SECOND"),
    ],
)
def test_shared_context_preserves_all_fields_against_uncached_logic(monkeypatch, text, pattern):
    parser = FileParser([pattern], quiet=True)
    result = parser.parse_file("context.txt", data=text.encode())
    original = FileParser._match_context_with_offset
    monkeypatch.setattr(
        FileParser,
        "_match_context_with_offset",
        staticmethod(lambda content, start, end, **_kwargs: original(content, start, end)),
    )
    uncached = parser.parse_file("context.txt", data=text.encode())
    assert result == uncached


def test_dense_context_is_shared_across_matches_and_builtin_rules():
    parser = FileParser([], quiet=True, rules=load_builtin_rules())
    text = " ".join(f"password=AuditDense{index:04d}!" for index in range(128)) + "\n"
    route = parser.route_rules({"path": "dense.txt", "filename": "dense.txt", "extension": ".txt", "size": len(text)})
    result = parser.parse_file("dense.txt", data=text.encode(), rule_route=route)
    assert result.error is None
    assert len(result.findings) > 128
    assert {finding.context for finding in result.findings} == {text[:-1]}
    assert len({id(finding.context) for finding in result.findings}) == 1


def test_context_cache_does_not_cross_representations_or_files():
    parser = FileParser(["SECRET"], quiet=True, rules=[rule("raw", "raw", "SECRET")])
    first = parser.parse_file("one.txt", data="А SECRET ONE\n".encode())
    second = parser.parse_file("two.txt", data="Б SECRET TWO\n".encode())
    for result, word in ((first, "ONE"), (second, "TWO")):
        assert len(result.findings) == 2
        text, raw = result.findings
        assert word in text.context and word in raw.context
        assert text.context != raw.context
        assert text.context is not raw.context
    assert "ONE" in first.findings[0].context
    assert "TWO" in second.findings[0].context
    assert not any("cache" in key for key in vars(parser))


def test_context_cache_is_independent_for_concurrent_parse_calls():
    parser = FileParser(["SECRET"], quiet=True)

    def parse(index):
        text = f"SECRET {index:04d} SECRET\n"
        return parser.parse_file(f"{index}.txt", data=text.encode()), text[:-1]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(parse, range(8)))
    for result, expected in results:
        assert [finding.context for finding in result.findings] == [expected, expected]
        assert result.findings[0].context is result.findings[1].context


def test_context_cache_eviction_limits_only_metadata_and_preserves_every_finding(monkeypatch):
    monkeypatch.setattr(parser_module, "_CONTEXT_CACHE_MAX_ENTRIES", 2)
    parser = FileParser(["FIRST", "SECOND"], quiet=True)
    data = "\n".join(f"FIRST_{index} SECOND_{index}" for index in range(3)).encode() + b"\n"
    original = FileParser._match_context_with_offset
    sizes = []

    def observed(content, start, end, *, cache=None):
        result = original(content, start, end, cache=cache)
        sizes.append(len(cache))
        return result

    monkeypatch.setattr(FileParser, "_match_context_with_offset", staticmethod(observed))
    bounded = parser.parse_file("lines.txt", data=data)
    assert len(bounded.findings) == 6
    assert sizes == [1, 2, 1, 2, 1, 2]
    monkeypatch.setattr(
        FileParser,
        "_match_context_with_offset",
        staticmethod(lambda content, start, end, **_kwargs: original(content, start, end)),
    )
    uncached = parser.parse_file("lines.txt", data=data)
    assert bounded == uncached


def test_parser_warning_escapes_path_and_exception_without_mutating_evidence(monkeypatch, caplog):
    dirty_path = "server/share/hostile\nFORGED\x1b[2J\u202efile.txt"
    dirty_error = "failure\rFORGED\x1b[31m\u2028tail"
    parser = FileParser(["SECRET"], quiet=True)
    monkeypatch.setattr(
        parser, "_extract_representation", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(dirty_error))
    )
    with caplog.at_level(logging.DEBUG, logger="manspider.parser"):
        result = parser.parse_file(dirty_path, data=b"SECRET")
    assert dirty_error in result.error
    assert display_text(dirty_path) in caplog.text
    assert display_text(dirty_error) in caplog.text
    for record in caplog.records:
        assert not re.search(r"[\x00-\x1f\x7f-\x9f\u2028\u202e]", record.getMessage())


def test_parser_debug_match_escapes_rule_and_value_only_for_display(caplog):
    value = "SECRET\nFORGED\x1b[2J"
    parser = FileParser([re.escape(value)], quiet=True)
    with caplog.at_level(logging.DEBUG, logger="manspider.parser"):
        result = parser.parse_file("file.txt", data=value.encode())
    assert result.findings[0].value == value
    assert display_text(value) in caplog.text
    assert all("\x1b" not in record.getMessage() and "\n" not in record.getMessage() for record in caplog.records)
