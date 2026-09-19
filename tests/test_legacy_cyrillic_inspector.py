"""Legacy codec candidates: exact bytes, ownership, ambiguity and resource bounds."""

import base64
import codecs
import json
import tracemalloc
from importlib import import_module

import pytest

from man_spider.lib.parser.legacy_cyrillic import inspect_russian_legacy_credentials


ENCODINGS = ("cp1251", "cp866", "koi8-r")
PASSWORD = "СекретнаяФраза!2026"
SOURCE = "Учётные данные для сервера\nлогин: администратор\nпароль: " + PASSWORD + "\n"


def inspect(data):
    return inspect_russian_legacy_credentials(data)


def context(row):
    return json.loads(row[3])


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_legacy_passwords_have_correct_unmasked_value_and_exact_matched_source_bytes(encoding, ending):
    source = SOURCE.replace("\n", ending).encode(encoding)
    found = inspect(source)
    assert [row[0] for row in found] == [PASSWORD]
    row = found[0]
    evidence = context(row)
    assert evidence["encoding_candidates"] == [encoding]
    assert evidence["decoded_value"] == PASSWORD
    assert evidence["source_key"] == "пароль"
    assert evidence["line"] == 3
    assert evidence["source_start"] == row[1]
    assert evidence["source_end"] == row[2]
    assert base64.b64decode(evidence["source_fragment_base64"]) == source[row[1] : row[2]]
    assert source[row[1] : row[2]] == ("пароль: " + PASSWORD).encode(encoding)


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize(
    "label", ["ПАРОЛЬ", "Пароль БД", "ключ API", "API_ключ", "пин-код", "парольная фраза", "секрет", "токен"]
)
def test_shared_sensitive_field_helper_owns_localized_labels(encoding, label):
    data = (label + " = '" + PASSWORD + "'").encode(encoding)
    assert PASSWORD in [row[0] for row in inspect(data)]


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_inline_object_properties_do_not_borrow_another_quoted_fields_text(encoding):
    source = '{"описание":"пароль=ЭтоОписание!", "пароль":"' + PASSWORD + '", "логин":"НеПароль!"}'
    found = inspect(source.encode(encoding))
    assert [row[0] for row in found] == [PASSWORD]
    assert context(found[0])["source_key"] == "пароль"


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_distinct_equal_occurrences_keep_independent_source_offsets(encoding):
    found = inspect(("пароль=" + PASSWORD + "\nпароль=" + PASSWORD).encode(encoding))
    assert [row[0] for row in found] == [PASSWORD, PASSWORD]
    assert found[0][1] != found[1][1]


def test_english_label_with_nonascii_value_keeps_all_distinct_candidate_decodings():
    data = ("password=" + PASSWORD).encode("cp1251")
    found = inspect(data)
    values = {row[0] for row in found}
    assert PASSWORD in values
    assert len(values) > 1
    encodings = {codec for row in found for codec in context(row)["encoding_candidates"]}
    assert encodings == set(ENCODINGS)
    for row in found:
        evidence = context(row)
        assert "exact source encoding" in evidence["evidence"]
        assert base64.b64decode(evidence["source_fragment_base64"]) == data[row[1] : row[2]]
        for codec in evidence["encoding_candidates"]:
            assert data[row[1] : row[2]].decode(codec) == "password=" + row[0]


def test_identical_interpretations_are_grouped_without_arbitrarily_selecting_one_codec(monkeypatch):
    # A codec alias exercises grouping directly without inventing a shared
    # Cyrillic byte mapping between the three distinct production code pages.
    module = import_module("man_spider.lib.parser.legacy_cyrillic")
    monkeypatch.setattr(module, "_ENCODINGS", ("cp1251", "windows-1251", "cp866"))
    data = ("password=" + PASSWORD).encode("cp1251")
    found = inspect(data)
    same = [row for row in found if row[0] == PASSWORD]
    assert len(same) == 1
    assert set(context(same[0])["encoding_candidates"]) == {"cp1251", "windows-1251"}


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize(
    "source", ["пароль='   '", "пароль=не задан", "пароль=${PASSWORD}", "пароль=***", "токен=скрыто"]
)
def test_shared_literal_filter_rejects_placeholders(encoding, source):
    assert not inspect(source.encode(encoding))


@pytest.mark.parametrize(
    "source",
    [
        "логин=администратор",
        "идентификатор токена=Идентификатор!",
        "открытый ключ=ПубличныйМатериал!",
        "описание='пароль=СодержимоеОписания!'",
        '# пароль="Комментарий!"',
        '; пароль="Комментарий!"',
        'пароль="НезакрытаяСтрока',
        'пароль="ПерваяЧасть" + "ВтораяЧасть"',
        "мойпароль=НеверноеПоле!",
    ],
)
def test_nonsecret_fields_and_unowned_or_nonliteral_strings_are_not_assignments(source):
    assert not inspect(source.encode("cp1251"))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-be", "utf-16-le", "utf-32"])
def test_standard_unicode_documents_are_left_to_existing_representations(encoding):
    assert not inspect(SOURCE.encode(encoding))


def test_ascii_only_secret_search_remains_unchanged():
    assert not inspect(b"password=AsciiFixture!\n")
    assert not inspect("Заголовок\npassword=AsciiFixture!".encode("cp1251"))


@pytest.mark.parametrize(
    "prefix",
    [
        b"MZ",
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"BZh",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF89a",
        b"%PDF-1.7\n",
        b"\x7fELF",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        codecs.BOM_UTF16_LE,
        codecs.BOM_UTF32_BE,
    ],
)
def test_binary_signatures_or_declared_unicode_never_use_legacy_decoding(prefix):
    assert not inspect(prefix + SOURCE.encode("cp1251"))


def test_nul_and_dense_binary_controls_are_not_legacy_plaintext():
    assert not inspect(b"\x00" + SOURCE.encode("cp1251"))
    assert not inspect(bytes(range(1, 32)) * 30 + SOURCE.encode("cp1251"))


def test_invalid_codec_byte_in_an_unrelated_line_does_not_hide_a_valid_sibling():
    data = b"\x98 unrelated\n" + SOURCE.encode("cp1251")
    assert PASSWORD in [row[0] for row in inspect(data)]


def test_quoted_spaces_and_language_escapes_are_preserved_without_execution():
    value = r"  Пароль\tСтенда\"!  "
    source = ('пароль="' + value + '"').encode("cp1251")
    assert inspect(source)[0][0] == value


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("operator", [":", "=", ":=", "=>"])
def test_assignment_operators_are_not_part_of_the_decoded_password(encoding, operator):
    source = (f'пароль {operator} "{PASSWORD}"').encode(encoding)
    found = inspect(source)
    assert [row[0] for row in found] == [PASSWORD]
    assert source[found[0][1] : found[0][2]] == source
    assert base64.b64decode(context(found[0])["source_fragment_base64"]) == source


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("operator", ["=", ":=", "=>"])
def test_one_leading_variable_marker_keeps_its_exact_source_owner(encoding, operator):
    source = (f'$Пароль {operator} "{PASSWORD}"').encode(encoding)
    found = inspect(source)
    assert [row[0] for row in found] == [PASSWORD]
    assert context(found[0])["source_key"] == "$Пароль"
    assert source[found[0][1] : found[0][2]] == source


@pytest.mark.parametrize(
    "source",
    [
        '$$Пароль="Секрет!"',
        '$ Пароль="Секрет!"',
        '${Пароль}="Секрет!"',
        '"$Пароль"="Секрет!"',
        '$Параметры.Пароль="Секрет!"',
        'пароль=="Секрет!"',
        'пароль::"Секрет!"',
        'пароль:=="Секрет!"',
        'пароль=>>"Секрет!"',
    ],
)
def test_dynamic_variable_owners_and_nonassignment_operators_are_not_rewritten(source):
    assert not inspect(source.encode("cp1251"))


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize(
    "expression",
    ["ПолучитьПароль()", "Секреты.ПолучитьПароль()", "Read-Host -AsSecureString", "Get-Credential"],
)
def test_unquoted_function_and_prompt_expressions_are_not_password_values(encoding, expression):
    assert not inspect(("пароль=" + expression).encode(encoding))


@pytest.mark.parametrize("value", ["ПолучитьПароль()", "Read-Host -AsSecureString", "=РусскийПароль!"])
def test_quoted_expression_looking_words_remain_exact_literal_values(value):
    assert inspect(('пароль="' + value + '"').encode("cp1251"))[0][0] == value


@pytest.mark.parametrize(
    "instruction",
    ["не менее 12 символов", "укажите пароль в конфигурации", "хранится в хранилище"],
)
def test_shared_instruction_placeholders_are_not_literal_values(instruction):
    assert not inspect(('пароль="' + instruction + '"').encode("cp1251"))


@pytest.mark.parametrize("value", ["Пароль,сЗапятой!", "Пароль}сФигурой!", "Пароль;сТочкой!", "${PASSWORD}суффикс"])
def test_unquoted_line_password_punctuation_is_not_silently_truncated(value):
    assert inspect(("пароль=" + value).encode("cp1251"))[0][0] == value


def test_no_file_reads_or_network_calls(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Legacy inspection must use already loaded bytes only")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert inspect(SOURCE.encode("cp866"))[0][0] == PASSWORD


def test_budget_exhaustion_is_explicit_and_never_returns_truncated_candidates(monkeypatch):
    module = import_module("man_spider.lib.parser.legacy_cyrillic")
    monkeypatch.setattr(module, "_MAX_EVIDENCE_BUDGET", 100)
    with pytest.raises(
        ValueError, match="context budget of 100 bytes; inspection is incomplete.*no partial or truncated"
    ):
        inspect(SOURCE.encode("cp1251"))


def test_many_assignments_have_a_bounded_explicit_failure_not_excessive_context_memory():
    data = ("пароль=" + PASSWORD + "\n").encode("cp1251") * 4000
    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="context budget"):
            inspect(data)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 12 * 1024 * 1024


def test_nested_objects_are_not_scalar_literals_and_template_depth_is_explicitly_bounded():
    assert not inspect(('{"пароль":' + "[" * 2000 + "0" + "]" * 2000 + "}").encode("cp1251"))
    with pytest.raises(ValueError, match="value nesting exceeds 64 delimiters"):
        inspect(('{"пароль":$' + "{" * 100 + "x" + "}" * 101).encode("cp1251"))
