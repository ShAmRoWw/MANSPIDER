"""Owned localized JSON credential values, without speculative source rewrites.

Only labels are normalized. Secret values remain exact; source offsets denote
the complete JSON container, and pointers identify their individual owners.
"""

import json
import re
import sys


_RUSSIAN = re.compile(r"[А-Яа-яЁё]")
_ESCAPED_CYRILLIC = re.compile(rb"\\u04[0-9a-fA-F]{2}")
_LABEL_SEPARATORS = re.compile(r"[\s_-]+")
_RU_QUALIFIER = (
    r"(?:администратора|админа|пользователя|сервиса|службы|сервера|бд|базыданных|"
    r"почты|почтовогосервера|приложения|клиента|учетнойзаписи|домена|доступа|"
    r"подключения|хранилища|архива|сайта|vpn|api|ssh|rdp|ftp|smtp|ldap|1с|1c)"
)
_RU_SECRET_FIELD = re.compile(
    rf"(?:(?:новый|старый|текущий|временный|резервный|основной|локальный|доменный|"
    rf"административный|сервисный|сохраненный)?(?:пароль|секрет|токен)(?:{_RU_QUALIFIER})?"
    rf"|(?:бд|базыданных|vpn|api|ssh|rdp|ftp|smtp|ldap|1с|1c)(?:пароль|секрет|токен)"
    rf"|парольнаяфраза(?:{_RU_QUALIFIER})?"
    rf"|(?:ключ(?:api|апи|доступа|шифрования|подписания)|(?:api|апи)ключ|"
    rf"(?:закрытый|приватный|секретный)ключ)(?:{_RU_QUALIFIER})?"
    rf"|пин(?:код)?|(?:резервный|одноразовый)код|коды?восстановления)"
)
_LEXICAL_RU_SECRET_FIELD = re.compile(
    "(?:(?!(?:id|ид|идентификатор|имя|название|длина|политика|срок|истечение|требуется|проверка|public|публичн[а-яё]{0,8}|открыт[а-яё]{0,8})[_-])[\\w]{1,40}[_-]|(?:новый|старый|текущий|временный|основной|резервный|доменный|локальный|служебный)[ \\t_\\-\\u00a0]{0,4})?(?:(?:пароль(?:[ \\t_\\-\\u00a0]{0,4}(?:(?:для|от|к)[ \\t_\\-\\u00a0]{0,4})?(?:администратора(?:[ \\t_\\-]{0,4}(?:бд|домена|сервера))?|админа|пользователя|уч[её]тной[ \\t_\\-\\u00a0]{0,4}записи|уч[её]тки|аккаунта|домена|сервер[ау]|сервис[ау]|службы|приложения|клиента|сайта|архив[ау]|хранилищ[ау]|конфигуратора|входа|подключения|доступа|базы[ \\t_\\-\\u00a0]{0,4}данных|бд|database|db|vpn|api|апи|wi[ \\t_\\-\\u00a0]{0,4}fi|wifi|1с|1c))?|парольн(?:ая|ую)[ \\t_\\-\\u00a0]{0,4}фраза|пароль[ \\t_\\-\\u00a0]{0,4}фраза)|(?:(?:api|апи)[ \\t_\\-\\u00a0]{0,4}токен|токен(?:[ \\t_\\-\\u00a0]{0,4}(?:доступа|обновления|авторизации|аутентификации|бота|клиента|приложения|сервиса|api|апи))?)|(?:секрет(?:[ \\t_\\-\\u00a0]{0,4}(?:клиента|приложения|сервиса|бота|api|апи))?|клиентск(?:ий|ого)[ \\t_\\-\\u00a0]{0,4}секрет)|(?:(?:api|апи)[ \\t_\\-\\u00a0]{0,4}ключ|ключ[ \\t_\\-\\u00a0]{0,4}(?:api|апи|доступа|авторизации)|(?:секретн(?:ый|ого)|закрыт(?:ый|ого)|приватн(?:ый|ого))[ \\t_\\-\\u00a0]{0,4}ключ)|(?:(?:пин|pin)(?:[ \\t_\\-\\u00a0]{0,4}код)?|(?:резервн(?:ый|ого)|одноразов(?:ый|ого))[ \\t_\\-\\u00a0]{0,4}код|код[ \\t_\\-\\u00a0]{0,4}(?:доступа|восстановления|подтверждения)|кодовое[ \\t_\\-\\u00a0]{0,4}слово))",
    re.IGNORECASE,
)
_EN_SECRET_FIELD = re.compile(
    r"(?:(?:[a-zа-яё0-9]+[_-]){0,6}(?a:password|passwd|pwd|passphrase|secret|token|"
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|"
    r"recovery[_-]?code|backup[_-]?codes?|pin[_-]?code))",
    re.IGNORECASE,
)
_REFERENCE = re.compile(
    r"(?:\$\{[^{}\r\n]+\}|\$\([^()\r\n]+\)|\{\{[^{}\r\n]+\}\}|"
    r"<%[^%\r\n]+%>|\$[^\W\d]\w*|%[^\W\d]\w*%)"
)
_PLACEHOLDER = re.compile(
    r"(?:null|none|redacted|masked|placeholder|changeme|changeit|"
    r"не[\s_-]*(?:задан[ао]?|указан[ао]?|установлен[ао]?|известен)|отсутствует|"
    r"скрыт[ао]?|удален[ао]?|замаскирован[ао]?|значение[\s_-]*скрыто|"
    r"(?:укажите|введите|задайте|ваш)[\s_-]+(?:пароль|секрет|токен|ключ)|"
    r"\[(?:скрыто|удалено|redacted)\]|<(?:скрыто|удалено|redacted)>|\*{3,}|x{4,})"
)


_LEXICAL_PLACEHOLDER = re.compile(
    "(?:null|none|redacted|masked|undefined|unknown|changeme|change_me|password_here|your_password|not[ \\t_\\-\\u00a0]{0,4}set|\\*{3,}|\\[redacted\\]|<redacted>|не[ \\t_\\-\\u00a0]{0,4}(?:задан[ао]?|указан[ао]?|установлен[ао]?|известен|известно|требуется)|отсутствует|пусто|нет|неизвестно|скрыт[ао]?|удал[её]н[ао]?|заменить|по[ \\t_\\-\\u00a0]{0,4}запросу|(?:укажите|введите|вставьте|задайте)[ \\t_\\-\\u00a0]{0,4}(?:ваш[ \\t_\\-\\u00a0]{0,4})?(?:пароль|секрет|токен|ключ)(?:[ \\t]{1,4}(?:здесь|тут|ниже|в[ \\t_\\-\\u00a0]{0,4}настройках))?|\\[(?:скрыт[ао]?|удал[её]н[ао]?|не[ \\t_\\-\\u00a0]{0,4}задан[ао]?)\\]|<(?:пароль|скрыт[ао]?|секрет|токен)>|\\$[\\w][\\w.:-]{0,127}|\\$\\{[^{}\\x00\\r\\n]{1,128}\\}|\\$\\([^()\\x00\\r\\n]{1,128}\\)|\\{\\{[^{}\\x00\\r\\n]{1,128}\\}\\}|%[\\w]{1,128}%|(?:переменные|параметры|окружение)(?:\\.[\\w]{1,64}){1,6}|не[ \\t\\u00a0]{1,8}(?:менее|более)[ \\t\\u00a0]{1,8}[0-9]{1,4}[ \\t\\u00a0]{1,8}(?:символ(?:а|ов)?|знак(?:а|ов)?)|(?:хранится|находится)[ \\t\\u00a0]{1,8}(?:в|на)[ \\t\\u00a0]{1,8}(?:хранилище|сейфе|vault|сервере|переменной)|(?:укажите|введите)[ \\t\\u00a0]{1,8}(?:ваш[ \\t\\u00a0]{1,8})?пароль[ \\t\\u00a0]{1,8}в[ \\t\\u00a0]{1,8}(?:конфигурации|хранилище)|(?:спросите|запросите|уточните)[ \\t\\u00a0]{1,8}у[ \\t\\u00a0]{1,8}(?:администратора|владельца))",
    re.IGNORECASE,
)


def sensitive_field(label):
    """Recognize credential field names, never identifiers or public-key labels."""
    if not isinstance(label, str) or len(label) > 192:
        return False
    normalized = label.casefold().replace("ё", "е")
    return bool(
        _LEXICAL_RU_SECRET_FIELD.fullmatch(label)
        or _RU_SECRET_FIELD.fullmatch(_LABEL_SEPARATORS.sub("", normalized))
        or _EN_SECRET_FIELD.fullmatch(label)
    )


def literal_secret(value):
    """Reject explicit placeholder/reference values, not their substrings."""
    if not isinstance(value, str) or not value.strip():
        return False
    if any(ord(c) < 32 and c not in "\t\r\n" for c in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    stripped = value.strip()
    normalized = stripped.casefold().replace("ё", "е")
    return not (
        _REFERENCE.fullmatch(stripped)
        or _PLACEHOLDER.fullmatch(normalized)
        or _LEXICAL_PLACEHOLDER.fullmatch(stripped)
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key during localized credential inspection")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError(f"non-JSON numeric constant {value}")


def _children(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield child, key.replace("~", "~0").replace("/", "~1")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                yield child, str(index)


def _objects(document):
    pending = [iter(((document, None),))]
    segments = []
    while pending:
        try:
            value, segment = next(pending[-1])
        except StopIteration:
            pending.pop()
            if segments:
                segments.pop()
            continue
        if segment is not None:
            segments.append(segment)
        if isinstance(value, dict):
            # Synchronous path view: no retained full pointer per ancestor.
            yield value, segments
        pending.append(_children(value))


def _values(value):
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str) or type(item) is int:
                yield item, f"/{index}"
    elif isinstance(value, str) or type(value) is int:
        yield value, ""


def _owned_properties(obj):
    for key, payload in obj.items():
        if sensitive_field(key):
            yield key, payload, key, {}
    # A named-parameter object is a separate, explicit schema shape. Never
    # combine labels and values from neighbouring objects or ambiguous aliases.
    labels = [
        (key, value)
        for key, value in obj.items()
        if key.casefold() in {"name", "key", "имя", "ключ", "наименование", "параметр"}
    ]
    payloads = [(key, value) for key, value in obj.items() if key.casefold() in {"value", "значение"}]
    if len(labels) == len(payloads) == 1 and sensitive_field(labels[0][1]):
        label_key, label = labels[0]
        key, payload = payloads[0]
        yield key, payload, label, {"label_key": label_key, "source_label": label}


def inspect_russian_json_credentials(data):
    """Decode owned Russian labels/values, including escaped Unicode in JSON."""
    if data.isascii() and b"\x00" not in data and not _ESCAPED_CYRILLIC.search(data):
        return ()
    # Non-Unicode legacy JSON-like exports belong to the explicit legacy-codec
    # candidate inspector, not a guessed replacement of this representation.
    try:
        data.decode(json.detect_encoding(data))
    except UnicodeError:
        return ()
    try:
        document = json.loads(data, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"invalid JSON during localized credential inspection: {exc}") from exc
    findings = []
    evidence_size = 0
    budget = min(32 * 1024 * 1024, max(1024 * 1024, len(data) * 16))
    for obj, segments in _objects(document):
        for key, payload, label, owner in _owned_properties(obj):
            for source_value, suffix in _values(payload):
                value = str(source_value)
                if type(source_value) is int and (source_value < 0 or not 4 <= len(value) <= 32):
                    continue
                if not (_RUSSIAN.search(label) or _RUSSIAN.search(value)) or not literal_secret(value):
                    continue
                pointer = "/" + "/".join(segments) if segments else ""
                pointer += "/" + key.replace("~", "~0").replace("/", "~1") + suffix
                context = json.dumps(
                    {
                        "format": "json",
                        "pointer": pointer,
                        "source_key": key,
                        **owner,
                        "source_value": source_value,
                        "decoded_value": value,
                        "value_kind": "localized-credential-value-candidate",
                        "evidence": "literal owned sensitive property; no live credential validity check",
                        "span": "complete source JSON; source_value is the parsed property, not verbatim JSON syntax",
                    },
                    ensure_ascii=True,
                )
                finding = (value, 0, len(data), context)
                evidence_size += sys.getsizeof(finding) + sys.getsizeof(value) + sys.getsizeof(context)
                if evidence_size > budget:
                    raise ValueError(
                        f"localized JSON derived evidence exceeds context budget of {budget} bytes; "
                        "inspection is incomplete, no partial or truncated native findings were returned"
                    )
                findings.append(finding)
    return tuple(findings)
