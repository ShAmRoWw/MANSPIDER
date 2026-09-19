"""Synthetic native localized-credential fixtures, never real credentials."""

import json


STRUCTURED_INSPECTOR_CASES = [
    ("настройки.json", json.dumps({"Пароль": "СложныйРусскийПароль!"}), "russian-json-credential-value"),
    ("параметры.txt", 'пароль="СложныйРусскийПароль!"\n'.encode("cp866"), "russian-legacy-credential-value"),
]
