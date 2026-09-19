"""Russian owned JSON fields: exact values, ownership and explicit failures."""

import json

import pytest

from man_spider.lib.parser.localized_credentials import (
    inspect_russian_json_credentials as inspect,
    literal_secret,
    sensitive_field,
)


@pytest.mark.parametrize(
    "field",
    [
        "Пароль",
        "ПАРОЛЬ",
        "пароль_БД",
        "БД_Пароль",
        "БД_password",
        "ПарольАдминистратора",
        "пароль учётной записи",
        "пароль учетной записи",
        "Пароль к серверу",
        "пароль от базы данных",
        "пароль администратора БД",
        "ТОКЕН_ОБНОВЛЕНИЯ",
        "API-ключ",
        "ключ API",
        "парольная фраза",
        "ПИН-код",
        "код восстановления",
        "резервный код",
        "кодовое слово",
    ],
)
@pytest.mark.parametrize("escaped", [False, True])
def test_owned_localized_labels_and_exact_unicode_values(field, escaped):
    value = '  ЁжикЯзык!\\"\nИЕщёСтрока  '
    data = json.dumps({field: value}, ensure_ascii=escaped).encode()
    found = inspect(data)
    assert len(found) == 1
    actual, start, end, context = found[0]
    assert actual == value
    assert (start, end) == (0, len(data))
    evidence = json.loads(context)
    assert evidence["source_value"] == evidence["decoded_value"] == value
    assert evidence["source_key"] == field
    assert evidence["pointer"] == "/" + field


@pytest.mark.parametrize(
    "encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16le", "utf-16be", "utf-32", "utf-32le", "utf-32be"]
)
def test_all_json_unicode_encodings(encoding):
    data = json.dumps({"Пароль": "РусскийСекрет!"}, ensure_ascii=False).encode(encoding)
    assert inspect(data)[0][0] == "РусскийСекрет!"


@pytest.mark.parametrize(
    "field",
    [
        "логин",
        "имя пользователя",
        "ключ",
        "открытый ключ",
        "публичный ключ",
        "Описание",
        "ПолитикаПароля",
        "ПарольТребуется",
        "ДлинаПароля",
        "id_пароль",
        "парольная политика",
        "credential_count",
        "pwd_hint",
        "password_policy",
    ],
)
def test_nonsecret_labels_are_not_credentials(field):
    assert not sensitive_field(field)
    assert inspect(json.dumps({field: "ПарольЯвноНеЗдесь!"}).encode()) == ()


@pytest.mark.parametrize(
    "value",
    [
        None,
        False,
        True,
        3,
        -1234,
        1.25,
        {},
        [False, None],
        "",
        " ",
        "не задан",
        "не указан",
        "скрыто",
        "[скрыто]",
        "${ПАРОЛЬ}",
        "$ПАРОЛЬ",
        "%ПАРОЛЬ%",
        "{{ секрет }}",
        "***",
    ],
)
def test_placeholders_and_nonliteral_payloads(value):
    assert inspect(json.dumps({"Пароль": value}).encode()) == ()


@pytest.mark.parametrize(
    "value",
    [
        "я",
        "true",
        "false",
        " Скрыто!2027 ",
        "НеЗадан!2027",
        "Обычное русское слово",
        "Функция()",
        "$Сложно!",
        "abc",
        "Укажите пароль!27",
    ],
)
def test_weak_and_placeholder_like_real_strings_are_preserved(value):
    assert literal_secret(value)
    assert inspect(json.dumps({"Пароль": value}).encode())[0][0] == value


def test_arrays_numeric_codes_and_distinct_owner_pointers():
    data = json.dumps({"a/~": [{"Пароль": ["Повтор!", "Повтор!", 1234]}, {"Пароль": "Повтор!"}]}).encode()
    found = inspect(data)
    assert [f[0] for f in found] == ["Повтор!", "Повтор!", "1234", "Повтор!"]
    assert [json.loads(f[3])["pointer"] for f in found] == [
        "/a~1~0/0/Пароль/0",
        "/a~1~0/0/Пароль/1",
        "/a~1~0/0/Пароль/2",
        "/a~1~0/1/Пароль",
    ]


@pytest.mark.parametrize("data", [b'{"password":"AsciiOnly!"}', b"{broken ascii", b""])
def test_fast_ascii_noncandidate_path(data):
    assert inspect(data) == ()


@pytest.mark.parametrize("encoding", ["cp1251", "cp866", "koi8-r"])
def test_legacy_encodings_belong_to_separate_candidate_inspector(encoding):
    assert inspect('{"Пароль":"РусскийПароль!"}'.encode(encoding)) == ()


@pytest.mark.parametrize(
    "data",
    [
        '{"Пароль": "Первый!", "Пароль": "Второй!"}'.encode(),
        '{"Пароль": "Секрет!",'.encode(),
        '{"Пароль": NaN}'.encode(),
    ],
)
def test_malformed_duplicate_or_excessively_deep_json_fails_explicitly(data):
    with pytest.raises(ValueError, match="invalid JSON during localized"):
        inspect(data)


def test_recursion_failure_is_an_explicit_inspection_error(monkeypatch):
    def fail(*args, **kwargs):
        raise RecursionError("fixture depth")

    monkeypatch.setattr(json, "loads", fail)
    with pytest.raises(ValueError, match="invalid JSON during localized"):
        inspect('{"Пароль":"Секрет!"}'.encode())


def test_invalid_surrogate_is_not_a_value_and_no_cross_property_inference():
    data = b'{"\\u041f\\u0430\\u0440\\u043e\\u043b\\u044c":"\\ud800","description":"password=secret","caption":"\\u041f\\u0430\\u0440\\u043e\\u043b\\u044c","value":"Unowned!"}'
    assert inspect(data) == ()


def test_evidence_budget_failure_never_returns_partial_native_findings():
    data = json.dumps({"пароль": ["я"] * 20000}).encode()
    with pytest.raises(ValueError, match="context budget"):
        inspect(data)


def test_deep_sibling_pointers_do_not_leak_ancestral_segments():
    document = {"a": {"b": [{"Пароль": "Один!"}]}, "c": {"Пароль": "Два!"}}
    assert [json.loads(f[3])["pointer"] for f in inspect(json.dumps(document).encode())] == [
        "/a/b/0/Пароль",
        "/c/Пароль",
    ]


@pytest.mark.parametrize("label_key", ["name", "key", "имя", "ключ", "наименование", "параметр", "КЛЮЧ"])
@pytest.mark.parametrize("value_key", ["value", "значение", "ЗНАЧЕНИЕ"])
def test_unicode_escaped_named_parameters_belong_to_same_object(label_key, value_key):
    data = json.dumps({label_key: "ПарольБД", value_key: "РусскийСекрет!"}).encode()
    found = inspect(data)
    assert [f[0] for f in found] == ["РусскийСекрет!"]
    evidence = json.loads(found[0][3])
    assert evidence["pointer"] == "/" + value_key
    assert evidence["label_key"] == label_key
    assert evidence["source_label"] == "ПарольБД"


@pytest.mark.parametrize(
    "document",
    [
        [{"имя": "Пароль"}, {"значение": "РусскийСекрет!"}],
        {"имя": "Пароль", "ключ": "публичное", "значение": "РусскийСекрет!"},
        {"имя": "Пароль", "значение": "РусскийСекрет!", "value": "Другое!"},
        {"имя": "логин", "значение": "РусскийИдентификатор"},
        {"имя": "Пароль", "вложено": {"значение": "РусскийСекрет!"}},
    ],
)
def test_named_parameter_ownership_never_crosses_objects_or_ambiguous_aliases(document):
    assert inspect(json.dumps(document).encode()) == ()
