import json
import math
import re
import sys
import threading
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


RULE_SCHEMA_VERSION = 3
SUPPORTED_SCHEMA_VERSIONS = {1, 2, RULE_SCHEMA_VERSION}
RULE_DETAIL_DISPLAY_LIMIT = 12
RULE_FILE_FIELDS = {"schema_version", "pack", "rules"}
PACK_FIELDS = {"id", "version"}
SUPPORTED_FLAGS = {
    "ignorecase": re.IGNORECASE,
    "multiline": re.MULTILINE,
    "dotall": re.DOTALL,
    "ascii": re.ASCII,
}
LEGACY_RULE_FIELDS = {"id", "pattern", "description", "flags", "enabled"}
V2_RULE_FIELDS = {"id", "description", "enabled", "match", "actions"}
V3_RULE_FIELDS = {
    *V2_RULE_FIELDS,
    "severity",
    "confidence",
    "category",
    "tags",
    "exclude",
}
MATCH_FIELDS = {"condition", "predicates"}
PREDICATE_FIELDS = {"field", "operator", "value", "negate", "flags", "case_sensitive"}
STRING_METADATA_FIELDS = {"share", "directory", "path", "filename", "extension"}
NUMERIC_METADATA_FIELDS = {"size", "mtime"}
STRING_OPERATORS = {"exact", "contains", "startswith", "endswith", "regex"}
NUMERIC_OPERATORS = {"eq", "gt", "gte", "lt", "lte", "between"}
ACTION_FIELDS = {
    "type",
    "representation",
    "pattern",
    "flags",
    "condition",
    "predicates",
    "detector",
    "passwords",
}
ACTION_TYPES = {"report", "scan", "inspect"}
CONTENT_REPRESENTATIONS = {"text", "strings", "raw", "ocr", "structured"}
IMPLEMENTED_REPRESENTATIONS = {"metadata", *CONTENT_REPRESENTATIONS}
INSPECTION_DETECTORS = {
    "private-key-material",
    "kubernetes-secret-json",
    "group-policy-preference-password",
    "active-directory-ldif-secrets",
    "active-directory-json-secrets",
    "russian-json-credential-value",
    "russian-legacy-credential-value",
}
CONTENT_PREDICATE_FIELDS = {"operator", "value", "negate", "flags", "case_sensitive"}
BUILTIN_RULES_PATH = Path(__file__).with_name("builtin_rules_v3.json")
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}
CLASSIFICATION_NAME = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SURROGATE_CHARACTER = re.compile(r"[\ud800-\udfff]")
DEFAULT_SEVERITY = "medium"
DEFAULT_CONFIDENCE = "medium"
DEFAULT_CATEGORY = "uncategorized"
_ROUTE_CACHE_MAX_ENTRIES = 512
_ROUTE_CACHE_MAX_BYTES = 512 * 1024
_ROUTE_CACHE_MAX_KEY_BYTES = 4096
_ROUTE_CACHE_MAX_VALUE_CHARS = 1024


class _RouteGroupCache:
    """Bounded, process-local memoization of pure metadata group results.

    Published result dictionaries are never mutated. A concurrent reader can
    therefore use its snapshot after eviction without holding the cache lock.
    FIFO eviction avoids a write on every hit. Pickling intentionally starts a
    fresh cache in the receiving process, without transporting locks or names.
    """

    def __init__(self, fields):
        self.fields = fields
        self._key_tuple_bytes = sys.getsizeof((None,) * len(fields))
        self._entries = OrderedDict()
        self._bytes = 0
        self._lock = threading.Lock()

    def key(self, metadata):
        # Custom objects can have mutable/side-effectful __str__/__hash__.
        # Preserve the original evaluator for them, including str subclasses.
        values = []
        size = self._key_tuple_bytes
        for field in self.fields:
            value = metadata.get(field)
            if value is not None and (type(value) is not str or len(value) > _ROUTE_CACHE_MAX_VALUE_CHARS):
                return None
            size += sys.getsizeof(value)
            if size > _ROUTE_CACHE_MAX_KEY_BYTES:
                return None
            values.append(value)
        return tuple(values)

    def get(self, key):
        with self._lock:
            entry = self._entries.get(key)
            if entry is None and "filename" in self.fields:
                # A one-off basename should not pay for retaining dozens of
                # group results. An empty, bounded probation entry admits it
                # only on another observation; extensions cache immediately.
                self._store(key, {})
                return False, None
            return True, entry[0] if entry is not None else None

    def update(self, key, results):
        with self._lock:
            self._store(key, results)

    def _store(self, key, results):
        previous = self._entries.get(key)
        merged = dict(previous[0]) if previous is not None else {}
        merged.update(results)
        # Group keys and bool values are shared with the immutable engine.
        # Account for retained input strings, tuple/dict and entry overhead.
        size = sys.getsizeof(key) + sum(sys.getsizeof(value) for value in key) + sys.getsizeof(merged) + 256
        if size > _ROUTE_CACHE_MAX_BYTES:
            return
        if previous is not None:
            del self._entries[key]
            self._bytes -= previous[1]
        while self._entries and (
            len(self._entries) >= _ROUTE_CACHE_MAX_ENTRIES or self._bytes + size > _ROUTE_CACHE_MAX_BYTES
        ):
            _old_key, (_old_results, old_size) = self._entries.popitem(last=False)
            self._bytes -= old_size
        if _ROUTE_CACHE_MAX_ENTRIES > 0:
            self._entries[key] = (merged, size)
            self._bytes += size

    def __getstate__(self):
        return {"fields": self.fields}

    def __setstate__(self, state):
        self.__init__(state["fields"])


class RuleConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class RuleContentPredicateSpec:
    operator: str
    value: str
    negate: bool = False
    flags: tuple[str, ...] = ()
    case_sensitive: bool = False


@dataclass(frozen=True)
class RuleContentSpec:
    rule_id: str
    predicates: tuple[RuleContentPredicateSpec, ...]
    condition: str = "all"
    description: str = ""
    representation: str = "text"
    rule_source: str = "unknown"
    rule_schema_version: int | None = None
    rule_pack_id: str | None = None
    rule_pack_version: str | None = None
    severity: str = DEFAULT_SEVERITY
    confidence: str = DEFAULT_CONFIDENCE
    category: str = DEFAULT_CATEGORY
    tags: tuple[str, ...] = ()

    @property
    def pattern(self) -> str:
        """Compatibility view for the historical one-regex scan action."""

        if len(self.predicates) == 1 and self.predicates[0].operator == "regex":
            return self.predicates[0].value
        return " | ".join(
            f"{'not ' if predicate.negate else ''}{predicate.operator}:{predicate.value}"
            for predicate in self.predicates
        )

    @property
    def flags(self) -> tuple[str, ...]:
        if len(self.predicates) == 1:
            return self.predicates[0].flags
        return ()


@dataclass(frozen=True)
class RuleMetadataSpec:
    rule_id: str
    representation: str = "metadata"
    rule_source: str = "unknown"
    rule_schema_version: int | None = None
    rule_pack_id: str | None = None
    rule_pack_version: str | None = None
    severity: str = DEFAULT_SEVERITY
    confidence: str = DEFAULT_CONFIDENCE
    category: str = DEFAULT_CATEGORY
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleInspectorSpec:
    rule_id: str
    detector: str
    passwords: tuple[str, ...] = ()
    description: str = ""
    rule_source: str = "unknown"
    rule_schema_version: int | None = None
    rule_pack_id: str | None = None
    rule_pack_version: str | None = None
    severity: str = DEFAULT_SEVERITY
    confidence: str = DEFAULT_CONFIDENCE
    category: str = DEFAULT_CATEGORY
    tags: tuple[str, ...] = ()

    @property
    def representation(self) -> str:
        return f"inspect:{self.detector}"


@dataclass(frozen=True)
class RuleRoute:
    matched_rule_ids: tuple[str, ...] = ()
    metadata_rules: tuple[RuleMetadataSpec, ...] = ()
    content_rules: tuple[RuleContentSpec, ...] = ()
    inspector_rules: tuple[RuleInspectorSpec, ...] = ()

    @property
    def matched(self) -> bool:
        return bool(self.matched_rule_ids)

    @property
    def requires_content(self) -> bool:
        return bool(self.content_rules or self.inspector_rules)

    @property
    def metadata_rule_ids(self) -> tuple[str, ...]:
        """Compatibility view for callers that only need stable rule IDs."""

        return tuple(rule.rule_id for rule in self.metadata_rules)


def regex_flags(flag_names) -> re.RegexFlag:
    flags = re.NOFLAG
    for name in flag_names:
        flags |= SUPPORTED_FLAGS[name]
    return flags


def _normalize_flags(raw_flags, *, rule_id: str, location: str, default=("ignorecase",)) -> list[str]:
    flags = list(default) if raw_flags is None else raw_flags
    if isinstance(flags, str):
        flags = [flags]
    if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
        raise RuleConfigurationError(f'Rule "{rule_id}" {location} has invalid flags')
    flags = list(dict.fromkeys(flag.lower() for flag in flags))
    unsupported_flags = sorted(set(flags) - set(SUPPORTED_FLAGS))
    if unsupported_flags:
        raise RuleConfigurationError(
            f'Rule "{rule_id}" {location} has unsupported flags: {", ".join(unsupported_flags)}'
        )
    return flags


def _validate_regex(pattern: str, flags: list[str], *, rule_id: str, location: str) -> None:
    try:
        re.compile(pattern, regex_flags(flags))
    except (re.error, OverflowError, RecursionError) as exc:
        raise RuleConfigurationError(f'Rule "{rule_id}" {location} has invalid regex: {exc}') from exc


def _normalize_legacy_rule(raw: dict, source: Path, index: int) -> dict:
    unknown = sorted(set(raw) - LEGACY_RULE_FIELDS)
    if unknown:
        raise RuleConfigurationError(f"Rule #{index} in {source} has unsupported fields: {', '.join(unknown)}")

    rule_id = raw.get("id")
    pattern = raw.get("pattern")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleConfigurationError(f"Rule #{index} in {source} requires a non-empty string id")
    if not isinstance(pattern, str) or not pattern:
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} requires a non-empty string pattern')
    flags = _normalize_flags(raw.get("flags"), rule_id=rule_id, location=f"in {source}")
    _validate_regex(pattern, flags, rule_id=rule_id, location=f"in {source}")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} description must be a string')
    return {
        "schema_version": 1,
        "id": rule_id.strip(),
        "description": description,
        "match": {"condition": "all", "predicates": []},
        "actions": [
            {
                "type": "scan",
                "representation": "text",
                "pattern": pattern,
                "flags": flags,
            }
        ],
    }


def _normalize_predicate(raw, *, rule_id: str, source: Path, index: int) -> dict:
    location = f'predicate #{index} of rule "{rule_id}" in {source}'
    if not isinstance(raw, dict):
        raise RuleConfigurationError(f"{location} must be a JSON object")
    unknown = sorted(set(raw) - PREDICATE_FIELDS)
    if unknown:
        raise RuleConfigurationError(f"{location} has unsupported fields: {', '.join(unknown)}")

    field = raw.get("field")
    operator = raw.get("operator")
    if not isinstance(field, str) or field not in STRING_METADATA_FIELDS | NUMERIC_METADATA_FIELDS:
        raise RuleConfigurationError(f'{location} has unsupported field "{field}"')
    supported_operators = STRING_OPERATORS if field in STRING_METADATA_FIELDS else NUMERIC_OPERATORS
    if not isinstance(operator, str) or operator not in supported_operators:
        raise RuleConfigurationError(f'{location} has unsupported operator "{operator}" for field "{field}"')
    negate = raw.get("negate", False)
    if not isinstance(negate, bool):
        raise RuleConfigurationError(f"{location} negate must be a boolean")

    value = raw.get("value")
    if field in STRING_METADATA_FIELDS:
        if not isinstance(value, str) or not value:
            raise RuleConfigurationError(f"{location} requires a non-empty string value")
        case_sensitive = raw.get("case_sensitive", False)
        if not isinstance(case_sensitive, bool):
            raise RuleConfigurationError(f"{location} case_sensitive must be a boolean")
        if operator == "regex":
            if "case_sensitive" in raw and "flags" in raw:
                raise RuleConfigurationError(f"{location} cannot combine case_sensitive with flags")
            default_flags = () if case_sensitive else ("ignorecase",)
            flags = _normalize_flags(
                raw.get("flags"),
                rule_id=rule_id,
                location=location,
                default=default_flags,
            )
            _validate_regex(value, flags, rule_id=rule_id, location=location)
        else:
            if "flags" in raw:
                raise RuleConfigurationError(f"{location} only supports flags with the regex operator")
            flags = []
        return {
            "field": field,
            "operator": operator,
            "value": value,
            "negate": negate,
            "case_sensitive": case_sensitive,
            "flags": flags,
        }

    if "flags" in raw or "case_sensitive" in raw:
        raise RuleConfigurationError(f"{location} does not support string matching flags")
    if operator == "between":
        if (
            not isinstance(value, list)
            or len(value) != 2
            or not all(_is_finite_number(item) for item in value)
            or value[0] > value[1]
        ):
            raise RuleConfigurationError(f"{location} between requires an ordered two-number value with finite bounds")
    elif not _is_finite_number(value):
        raise RuleConfigurationError(f"{location} requires a numeric value that is finite")
    return {
        "field": field,
        "operator": operator,
        "value": value,
        "negate": negate,
    }


def _is_finite_number(value) -> bool:
    # Large exact JSON integers are valid bounds: math.isfinite(int) would
    # coerce them to float and can itself raise OverflowError.
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _normalize_match(raw, *, rule_id: str, source: Path, location_name: str = "match") -> dict:
    if raw is None:
        return {"condition": "all", "predicates": []}
    if not isinstance(raw, dict):
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} {location_name} must be a JSON object')
    unknown = sorted(set(raw) - MATCH_FIELDS)
    if unknown:
        raise RuleConfigurationError(
            f'Rule "{rule_id}" in {source} {location_name} has unsupported fields: {", ".join(unknown)}'
        )
    condition = raw.get("condition", "all")
    if condition not in ("all", "any"):
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} {location_name} condition must be "all" or "any"')
    predicates = raw.get("predicates", [])
    if not isinstance(predicates, list):
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} {location_name} predicates must be a JSON array')
    if condition == "any" and not predicates:
        raise RuleConfigurationError(
            f'Rule "{rule_id}" in {source} {location_name} condition "any" requires predicates'
        )
    return {
        "condition": condition,
        "predicates": [
            _normalize_predicate(predicate, rule_id=rule_id, source=source, index=index)
            for index, predicate in enumerate(predicates, start=1)
        ],
    }


def _normalize_content_predicate(raw, *, rule_id: str, source: Path, action_index: int, index: int) -> dict:
    location = f'predicate #{index} of action #{action_index} of rule "{rule_id}" in {source}'
    if not isinstance(raw, dict):
        raise RuleConfigurationError(f"{location} must be a JSON object")
    unknown = sorted(set(raw) - CONTENT_PREDICATE_FIELDS)
    if unknown:
        raise RuleConfigurationError(f"{location} has unsupported fields: {', '.join(unknown)}")

    operator = raw.get("operator")
    if not isinstance(operator, str) or operator not in STRING_OPERATORS:
        raise RuleConfigurationError(f'{location} has unsupported operator "{operator}"')
    value = raw.get("value")
    if not isinstance(value, str) or not value:
        raise RuleConfigurationError(f"{location} requires a non-empty string value")
    negate = raw.get("negate", False)
    if not isinstance(negate, bool):
        raise RuleConfigurationError(f"{location} negate must be a boolean")
    case_sensitive = raw.get("case_sensitive", False)
    if not isinstance(case_sensitive, bool):
        raise RuleConfigurationError(f"{location} case_sensitive must be a boolean")

    if operator == "regex":
        if "case_sensitive" in raw and "flags" in raw:
            raise RuleConfigurationError(f"{location} cannot combine case_sensitive with flags")
        default_flags = () if case_sensitive else ("ignorecase",)
        flags = _normalize_flags(raw.get("flags"), rule_id=rule_id, location=location, default=default_flags)
        _validate_regex(value, flags, rule_id=rule_id, location=location)
    else:
        if "flags" in raw:
            raise RuleConfigurationError(f"{location} only supports flags with the regex operator")
        flags = []
    return {
        "operator": operator,
        "value": value,
        "negate": negate,
        "case_sensitive": case_sensitive,
        "flags": flags,
    }


def _normalize_action(raw, *, rule_id: str, source: Path, index: int, schema_version: int) -> dict:
    location = f'action #{index} of rule "{rule_id}" in {source}'
    if not isinstance(raw, dict):
        raise RuleConfigurationError(f"{location} must be a JSON object")
    unknown = sorted(set(raw) - ACTION_FIELDS)
    if unknown:
        raise RuleConfigurationError(f"{location} has unsupported fields: {', '.join(unknown)}")
    action_type = raw.get("type")
    if not isinstance(action_type, str) or action_type not in ACTION_TYPES:
        raise RuleConfigurationError(f'{location} has unsupported type "{action_type}"')
    if action_type == "report":
        if set(raw) - {"type", "representation"}:
            raise RuleConfigurationError(f"{location} report does not accept pattern or flags")
        representation = raw.get("representation", "metadata")
        if representation != "metadata":
            raise RuleConfigurationError(f"{location} report currently supports only metadata representation")
        return {"type": "report", "representation": "metadata"}

    if action_type == "inspect":
        if schema_version < 3:
            raise RuleConfigurationError(f"{location} inspect requires schema_version 3")
        unsupported = set(raw) - {"type", "detector", "passwords"}
        if unsupported:
            raise RuleConfigurationError(
                f"{location} inspect has unsupported fields: {', '.join(sorted(unsupported))}"
            )
        detector = raw.get("detector")
        if not isinstance(detector, str) or detector not in INSPECTION_DETECTORS:
            raise RuleConfigurationError(f'{location} has unsupported detector "{detector}"')
        passwords = raw.get("passwords", [])
        if detector != "private-key-material" and passwords:
            raise RuleConfigurationError(f"{location} passwords are only supported by private-key-material")
        if (
            not isinstance(passwords, list)
            or len(passwords) > 64
            or not all(isinstance(password, str) and len(password) <= 256 for password in passwords)
        ):
            raise RuleConfigurationError(
                f"{location} passwords must be an array of at most 64 strings, each at most 256 characters"
            )
        return {
            "type": "inspect",
            "detector": detector,
            "passwords": list(dict.fromkeys(passwords)),
        }

    unsupported = set(raw) & {"detector", "passwords"}
    if unsupported:
        raise RuleConfigurationError(f"{location} scan has unsupported fields: {', '.join(sorted(unsupported))}")

    representation = raw.get("representation", "text")
    if not isinstance(representation, str) or representation not in CONTENT_REPRESENTATIONS:
        raise RuleConfigurationError(f'{location} has unsupported representation "{representation}"')

    grouped = "predicates" in raw or "condition" in raw
    if grouped:
        if "pattern" in raw or "flags" in raw:
            raise RuleConfigurationError(f"{location} cannot combine pattern/flags with condition/predicates")
        condition = raw.get("condition", "all")
        if condition not in ("all", "any"):
            raise RuleConfigurationError(f'{location} condition must be "all" or "any"')
        predicates = raw.get("predicates")
        if not isinstance(predicates, list) or not predicates:
            raise RuleConfigurationError(f"{location} requires a non-empty predicates array")
        return {
            "type": "scan",
            "representation": representation,
            "condition": condition,
            "predicates": [
                _normalize_content_predicate(
                    predicate,
                    rule_id=rule_id,
                    source=source,
                    action_index=index,
                    index=predicate_index,
                )
                for predicate_index, predicate in enumerate(predicates, start=1)
            ],
        }

    pattern = raw.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise RuleConfigurationError(f"{location} requires a non-empty string pattern")
    flags = _normalize_flags(raw.get("flags"), rule_id=rule_id, location=location)
    _validate_regex(pattern, flags, rule_id=rule_id, location=location)
    return {
        "type": "scan",
        "representation": representation,
        "pattern": pattern,
        "flags": flags,
    }


def _normalize_classification(raw: dict, *, rule_id: str, source: Path, schema_version: int) -> dict:
    if schema_version < 3:
        return {
            "severity": DEFAULT_SEVERITY,
            "confidence": DEFAULT_CONFIDENCE,
            "category": DEFAULT_CATEGORY,
            "tags": [],
        }

    severity = raw.get("severity", DEFAULT_SEVERITY)
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise RuleConfigurationError(
            f'Rule "{rule_id}" in {source} severity must be one of: {", ".join(sorted(SEVERITIES))}'
        )
    confidence = raw.get("confidence", DEFAULT_CONFIDENCE)
    if not isinstance(confidence, str) or confidence not in CONFIDENCE_LEVELS:
        raise RuleConfigurationError(
            f'Rule "{rule_id}" in {source} confidence must be one of: {", ".join(sorted(CONFIDENCE_LEVELS))}'
        )
    category = raw.get("category", DEFAULT_CATEGORY)
    if not isinstance(category, str) or CLASSIFICATION_NAME.fullmatch(category) is None:
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} category must be a lower-case classification name')
    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(
        isinstance(tag, str) and CLASSIFICATION_NAME.fullmatch(tag) is not None for tag in tags
    ):
        raise RuleConfigurationError(
            f'Rule "{rule_id}" in {source} tags must be an array of lower-case classification names'
        )
    return {
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "tags": sorted(set(tags)),
    }


def _normalize_extended_rule(raw: dict, source: Path, index: int, schema_version: int) -> dict:
    allowed_fields = V3_RULE_FIELDS if schema_version >= 3 else V2_RULE_FIELDS
    unknown = sorted(set(raw) - allowed_fields)
    if unknown:
        raise RuleConfigurationError(f"Rule #{index} in {source} has unsupported fields: {', '.join(unknown)}")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleConfigurationError(f"Rule #{index} in {source} requires a non-empty string id")
    rule_id = rule_id.strip()
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} description must be a string')
    actions = raw.get("actions")
    if not isinstance(actions, list) or not actions:
        raise RuleConfigurationError(f'Rule "{rule_id}" in {source} requires a non-empty actions array')
    normalized_actions = [
        _normalize_action(
            action,
            rule_id=rule_id,
            source=source,
            index=action_index,
            schema_version=schema_version,
        )
        for action_index, action in enumerate(actions, start=1)
    ]
    action_payloads = list(dict.fromkeys(json.dumps(action, sort_keys=True) for action in normalized_actions))
    classification = _normalize_classification(
        raw,
        rule_id=rule_id,
        source=source,
        schema_version=schema_version,
    )
    exclude = None
    if raw.get("exclude") is not None:
        exclude = _normalize_match(
            raw["exclude"],
            rule_id=rule_id,
            source=source,
            location_name="exclude",
        )
        if not exclude["predicates"]:
            raise RuleConfigurationError(f'Rule "{rule_id}" in {source} exclude requires at least one predicate')
    normalized = {
        "schema_version": schema_version,
        "id": rule_id,
        "description": description,
        "match": _normalize_match(raw.get("match"), rule_id=rule_id, source=source),
        "actions": [json.loads(action) for action in action_payloads],
    }
    if schema_version >= 3:
        normalized.update(classification)
        normalized["exclude"] = exclude
    return normalized


def _normalize_rule(raw, source: Path, index: int, schema_version: int) -> dict | None:
    if not isinstance(raw, dict):
        raise RuleConfigurationError(f"Rule #{index} in {source} must be a JSON object")
    if not isinstance(raw.get("enabled", True), bool):
        raise RuleConfigurationError(f"Rule #{index} in {source} enabled must be a boolean")
    if raw.get("enabled", True) is False:
        return None
    extended = "match" in raw or "actions" in raw or bool(set(raw) & (V3_RULE_FIELDS - V2_RULE_FIELDS))
    if extended and schema_version == 1:
        raise RuleConfigurationError(
            f"Rule #{index} in {source} uses extended fields but the file schema_version is not 2 or 3"
        )
    if extended:
        return _normalize_extended_rule(raw, source, index, schema_version)
    return _normalize_legacy_rule(raw, source, index)


def _source_label(source: Path) -> str:
    value = str(source)
    if value.startswith("<") and value.endswith(">"):
        return value
    return str(source.resolve())


def _normalize_pack(raw, *, schema_version: int, source: Path) -> dict:
    if raw is None:
        if schema_version == 1:
            return {"id": "legacy-json", "version": "1"}
        return {"id": "user", "version": "unversioned"}
    if schema_version not in {2, RULE_SCHEMA_VERSION}:
        raise RuleConfigurationError(f"Rule file {source} pack metadata requires schema_version 2 or 3")
    if not isinstance(raw, dict):
        raise RuleConfigurationError(f"Rule file {source} pack must be a JSON object")
    unknown = sorted(set(raw) - PACK_FIELDS)
    if unknown:
        raise RuleConfigurationError(f"Rule file {source} pack has unsupported fields: {', '.join(unknown)}")
    missing = sorted(PACK_FIELDS - set(raw))
    if missing:
        raise RuleConfigurationError(f"Rule file {source} pack requires: {', '.join(missing)}")
    for field in sorted(PACK_FIELDS):
        if not isinstance(raw[field], str) or not raw[field].strip():
            raise RuleConfigurationError(f"Rule file {source} pack {field} must be a non-empty string")
    return {"id": raw["id"].strip(), "version": raw["version"].strip()}


def _with_provenance(rule: dict, *, source: Path, pack: Mapping | None = None) -> dict:
    value = dict(rule)
    normalized_pack = (
        _normalize_pack(None, schema_version=value["schema_version"], source=source) if pack is None else dict(pack)
    )
    value["rule_source"] = value.get("rule_source", _source_label(source))
    value["rule_pack_id"] = value.get("rule_pack_id", normalized_pack["id"])
    value["rule_pack_version"] = value.get("rule_pack_version", normalized_pack["version"])
    if not isinstance(value["rule_source"], str) or not value["rule_source"]:
        raise RuleConfigurationError(f'Rule "{value.get("id", "")}" has invalid rule_source')
    for field in ("rule_pack_id", "rule_pack_version"):
        if not isinstance(value[field], str) or not value[field]:
            raise RuleConfigurationError(f'Rule "{value.get("id", "")}" has invalid {field}')
    _validate_rule_unicode(value)
    return value


def _validate_rule_unicode(rule: dict) -> None:
    """Reject strings that cannot be persisted, without changing rule content.

    JSON can decode escaped unpaired surrogates even when its source is valid
    UTF-8. Check the active normalized rule, including provenance, at loading
    time rather than discovering the problem after creating a state database.
    The normalized shape is acyclic; disabled raw rules never reach this path.
    Searching avoids allocating UTF-8 copies of large valid patterns/values.
    """

    pending = [rule]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            if _SURROGATE_CHARACTER.search(value) is not None:
                # Do not echo the invalid string into the UTF-8 diagnostic.
                raise RuleConfigurationError("Rule contains an unpaired Unicode surrogate")
        elif isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def load_rule_files(paths) -> list[dict]:
    rules = []
    ids = set()
    for value in paths:
        path = Path(value).expanduser()
        if not path.is_file():
            raise RuleConfigurationError(f"Rule file not found: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise RuleConfigurationError(f"Unable to read rule file {path}: {exc}") from exc
        except UnicodeError as exc:
            raise RuleConfigurationError(f"Rule file must be valid UTF-8: {path}: {exc}") from exc
        except ValueError as exc:
            # Includes JSONDecodeError and the interpreter's decimal-integer
            # conversion limit. Keep that limit; only normalize diagnostics.
            raise RuleConfigurationError(f"Invalid JSON rule file {path}: {exc}") from exc

        if isinstance(payload, dict):
            unknown = sorted(set(payload) - RULE_FILE_FIELDS)
            if unknown:
                raise RuleConfigurationError(f"Rule file {path} has unsupported fields: {', '.join(unknown)}")
            schema_version = payload.get("schema_version", 1)
            raw_pack = payload.get("pack")
            raw_rules = payload.get("rules")
        else:
            schema_version = 1
            raw_pack = None
            raw_rules = payload
        if not isinstance(schema_version, int) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise RuleConfigurationError(f'Rule file {path} has unsupported schema_version "{schema_version}"')
        pack = _normalize_pack(raw_pack, schema_version=schema_version, source=path)
        if not isinstance(raw_rules, list):
            raise RuleConfigurationError(
                f'Rule file {path} must contain a JSON array or an object with a "rules" array'
            )
        for index, raw in enumerate(raw_rules, start=1):
            rule = _normalize_rule(raw, path, index, schema_version)
            if rule is None:
                continue
            rule = _with_provenance(rule, source=path, pack=pack)
            if rule["id"] in ids:
                raise RuleConfigurationError(f'Duplicate active rule id "{rule["id"]}"')
            ids.add(rule["id"])
            rules.append(rule)
    return sorted(rules, key=lambda rule: rule["id"])


def load_builtin_rules() -> list[dict]:
    rules = load_rule_files([BUILTIN_RULES_PATH])
    return [dict(rule, rule_source="builtin:manspider.default") for rule in rules]


def compose_rules(rule_sets=(), *, overrides=(), disabled_rule_ids=()) -> list[dict]:
    """Compose packs without allowing implicit replacement or unknown controls."""

    composed = {}
    for rules in rule_sets:
        for rule in rules:
            rule_id = rule["id"]
            if rule_id in composed:
                raise RuleConfigurationError(
                    f'Duplicate active rule id "{rule_id}"; use --rule-overrides for explicit replacement'
                )
            composed[rule_id] = rule

    for rule in overrides:
        rule_id = rule["id"]
        if rule_id not in composed:
            raise RuleConfigurationError(f'Rule override "{rule_id}" does not replace any loaded rule')
        composed[rule_id] = rule

    disabled = set(disabled_rule_ids)
    unknown_disabled = sorted(disabled - set(composed))
    if unknown_disabled:
        raise RuleConfigurationError("Unknown rule IDs requested for disable: " + ", ".join(unknown_disabled))
    return [composed[rule_id] for rule_id in sorted(set(composed) - disabled)]


def format_rule(rule: Mapping) -> str:
    actions = []
    for action in rule["actions"]:
        if action["type"] == "report":
            actions.append("report:metadata")
        elif action["type"] == "inspect":
            actions.append(f"inspect:{action['detector']}")
        elif "predicates" in action:
            predicates = ",".join(
                f"{'!' if predicate['negate'] else ''}{predicate['operator']}:{predicate['value']}"
                for predicate in action["predicates"]
            )
            actions.append(f"{action['representation']}:{action['condition']}({predicates})")
        else:
            actions.append(f"{action['representation']}:{action['pattern']}")
    label = rule["id"]
    if rule.get("schema_version", 1) >= 3:
        tags = ",".join(rule.get("tags", ())) or "none"
        label += (
            f"[severity={rule['severity']};confidence={rule['confidence']};category={rule['category']};tags={tags}]"
        )
    return f"{label}=>{','.join(actions)}"


def build_rule_representation_plan(rules) -> dict[str, list[str]]:
    """Return the deterministic representation-to-rule routing plan."""

    plan = {}
    for rule in sorted(rules, key=lambda item: item["id"]):
        for action in rule["actions"]:
            if action["type"] == "report":
                representation = "metadata"
            elif action["type"] == "inspect":
                representation = f"inspect:{action['detector']}"
            else:
                representation = action["representation"]
            plan.setdefault(representation, [])
            if rule["id"] not in plan[representation]:
                plan[representation].append(rule["id"])
    return {representation: plan[representation] for representation in sorted(plan)}


def format_rule_representation_plan(rules) -> str:
    plan = build_rule_representation_plan(rules)
    if not plan:
        return "none"
    return "; ".join(f"{representation}=[{','.join(rule_ids)}]" for representation, rule_ids in plan.items())


def normalize_rule_objects(rules) -> list[dict]:
    """Accept normalized rules and the legacy in-memory FileParser API."""

    normalized = []
    ids = set()
    source = Path("<in-memory rules>")
    for index, rule in enumerate(rules, start=1):
        if isinstance(rule, dict) and {"schema_version", "id", "match", "actions"} <= set(rule):
            schema_version = rule["schema_version"]
            if not isinstance(schema_version, int) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
                raise RuleConfigurationError(
                    f'Rule "{rule.get("id", "")}" has unsupported schema_version "{schema_version}"'
                )
            allowed_fields = V3_RULE_FIELDS if schema_version >= 3 else V2_RULE_FIELDS
            raw = {field: deepcopy(rule[field]) for field in allowed_fields if field in rule and field != "enabled"}
            # Loaded rules are already canonical: string predicates always carry
            # `case_sensitive`, and non-regex predicates also carry `flags=[]`.
            # Remove those derived defaults before applying the strict input
            # validator again.
            if isinstance(raw.get("match"), dict) and isinstance(raw["match"].get("predicates"), list):
                for predicate in raw["match"]["predicates"]:
                    if (
                        not isinstance(predicate, dict)
                        or not isinstance(predicate.get("field"), str)
                        or predicate["field"] not in STRING_METADATA_FIELDS
                    ):
                        continue
                    if predicate.get("operator") == "regex" and "flags" in predicate:
                        predicate.pop("case_sensitive", None)
                    elif predicate.get("operator") != "regex":
                        predicate.pop("flags", None)
            if isinstance(raw.get("exclude"), dict) and isinstance(raw["exclude"].get("predicates"), list):
                for predicate in raw["exclude"]["predicates"]:
                    if (
                        not isinstance(predicate, dict)
                        or not isinstance(predicate.get("field"), str)
                        or predicate["field"] not in STRING_METADATA_FIELDS
                    ):
                        continue
                    if predicate.get("operator") == "regex" and "flags" in predicate:
                        predicate.pop("case_sensitive", None)
                    elif predicate.get("operator") != "regex":
                        predicate.pop("flags", None)
            if isinstance(raw.get("actions"), list):
                for action in raw["actions"]:
                    if not isinstance(action, dict) or not isinstance(action.get("predicates"), list):
                        continue
                    for predicate in action["predicates"]:
                        if not isinstance(predicate, dict):
                            continue
                        if predicate.get("operator") == "regex" and "flags" in predicate:
                            predicate.pop("case_sensitive", None)
                        elif predicate.get("operator") != "regex":
                            predicate.pop("flags", None)
            value = _normalize_extended_rule(raw, source, index, schema_version)
            for field in ("rule_source", "rule_pack_id", "rule_pack_version"):
                if field in rule:
                    value[field] = rule[field]
        else:
            schema_version = (
                RULE_SCHEMA_VERSION
                if isinstance(rule, dict)
                and ("match" in rule or "actions" in rule or bool(set(rule) & (V3_RULE_FIELDS - V2_RULE_FIELDS)))
                else 1
            )
            value = _normalize_rule(rule, source, index, schema_version)
        if value is None:
            continue
        value = _with_provenance(value, source=source)
        if value["id"] in ids:
            raise RuleConfigurationError(f'Duplicate active rule id "{value["id"]}"')
        ids.add(value["id"])
        normalized.append(value)
    return sorted(normalized, key=lambda rule: rule["id"])


class RuleEngine:
    """Route normalized rules using metadata available before file retrieval."""

    def __init__(self, rules=()):
        self.rules = tuple(normalize_rule_objects(rules))
        content_rules = []
        inspector_rules = []
        prepared_groups = {}
        routing = []
        extension_predicates = {}
        for rule in self.rules:
            metadata_specs = []
            rule_content_specs = []
            rule_inspector_specs = []
            for action in rule["actions"]:
                if action["type"] == "report":
                    metadata_specs.append(self._metadata_spec(rule))
                elif action["type"] == "scan":
                    specification = self._content_spec(rule, action)
                    content_rules.append(specification)
                    rule_content_specs.append(specification)
                elif action["type"] == "inspect":
                    specification = self._inspector_spec(rule, action)
                    inspector_rules.append(specification)
                    rule_inspector_specs.append(specification)
            match_key = self._prepare_group(rule["match"], prepared_groups)
            for predicate in rule["match"]["predicates"]:
                if predicate["field"] != "extension" or predicate["negate"]:
                    continue
                predicate_key = json.dumps(predicate, sort_keys=True, separators=(",", ":"))
                if predicate_key in extension_predicates:
                    continue
                expression = None
                if predicate["operator"] == "regex":
                    expression = re.compile(predicate["value"], regex_flags(predicate["flags"]))
                extension_predicates[predicate_key] = (predicate, expression)
            exclude_key = None
            if rule.get("exclude") is not None:
                exclude_key = self._prepare_group(rule["exclude"], prepared_groups)
            routing.append(
                (
                    f"rule:{rule['id']}",
                    match_key,
                    exclude_key,
                    tuple(metadata_specs),
                    tuple(rule_content_specs),
                    tuple(rule_inspector_specs),
                )
            )
        self.all_content_rules = tuple(content_rules)
        self.all_inspector_rules = tuple(inspector_rules)
        self._prepared_groups = prepared_groups
        self._routing = tuple(routing)
        self._extension_recognition_group = ("any", tuple(extension_predicates.values()))
        self._extension_recognition_cache = {}
        cache_fields = {}
        cache_owners = {}
        for key, (_condition, predicates) in prepared_groups.items():
            fields = tuple(sorted({predicate["field"] for predicate, _expression in predicates}))
            if fields and set(fields) <= {"extension", "filename"}:
                if fields not in cache_fields:
                    cache_fields[fields] = len(cache_fields)
                cache_owners[key] = cache_fields[fields]
        self._route_group_caches = tuple(_RouteGroupCache(fields) for fields in cache_fields)
        self._route_cache_owners = cache_owners

    @property
    def active(self) -> bool:
        return bool(self.rules)

    @staticmethod
    def _content_spec(rule, action) -> RuleContentSpec:
        if "predicates" in action:
            condition = action["condition"]
            predicates = tuple(
                RuleContentPredicateSpec(
                    operator=predicate["operator"],
                    value=predicate["value"],
                    negate=predicate["negate"],
                    flags=tuple(predicate["flags"]),
                    case_sensitive=predicate["case_sensitive"],
                )
                for predicate in action["predicates"]
            )
        else:
            condition = "all"
            predicates = (
                RuleContentPredicateSpec(
                    operator="regex",
                    value=action["pattern"],
                    flags=tuple(action["flags"]),
                    case_sensitive="ignorecase" not in action["flags"],
                ),
            )
        return RuleContentSpec(
            rule_id=f"rule:{rule['id']}",
            predicates=predicates,
            condition=condition,
            description=rule.get("description", ""),
            representation=action["representation"],
            rule_source=rule["rule_source"],
            rule_schema_version=rule["schema_version"],
            rule_pack_id=rule["rule_pack_id"],
            rule_pack_version=rule["rule_pack_version"],
            severity=rule.get("severity", DEFAULT_SEVERITY),
            confidence=rule.get("confidence", DEFAULT_CONFIDENCE),
            category=rule.get("category", DEFAULT_CATEGORY),
            tags=tuple(rule.get("tags", ())),
        )

    @staticmethod
    def _metadata_spec(rule) -> RuleMetadataSpec:
        return RuleMetadataSpec(
            rule_id=f"rule:{rule['id']}",
            rule_source=rule["rule_source"],
            rule_schema_version=rule["schema_version"],
            rule_pack_id=rule["rule_pack_id"],
            rule_pack_version=rule["rule_pack_version"],
            severity=rule.get("severity", DEFAULT_SEVERITY),
            confidence=rule.get("confidence", DEFAULT_CONFIDENCE),
            category=rule.get("category", DEFAULT_CATEGORY),
            tags=tuple(rule.get("tags", ())),
        )

    @staticmethod
    def _inspector_spec(rule, action) -> RuleInspectorSpec:
        return RuleInspectorSpec(
            rule_id=f"rule:{rule['id']}",
            detector=action["detector"],
            passwords=tuple(action["passwords"]),
            description=rule.get("description", ""),
            rule_source=rule["rule_source"],
            rule_schema_version=rule["schema_version"],
            rule_pack_id=rule["rule_pack_id"],
            rule_pack_version=rule["rule_pack_version"],
            severity=rule.get("severity", DEFAULT_SEVERITY),
            confidence=rule.get("confidence", DEFAULT_CONFIDENCE),
            category=rule.get("category", DEFAULT_CATEGORY),
            tags=tuple(rule.get("tags", ())),
        )

    def route(self, metadata: Mapping) -> RuleRoute:
        matched_rule_ids = []
        metadata_rules = []
        content_rules = []
        inspector_rules = []
        group_results = {}
        cache_owners = self._route_cache_owners
        cache_keys = [None] * len(self._route_group_caches)
        cache_updates = [{} for _cache in self._route_group_caches]
        # Mapping subclasses may implement stateful get(); retain the exact
        # original evaluation path instead of adding speculative field reads.
        if type(metadata) is dict:
            for index, cache in enumerate(self._route_group_caches):
                key = cache.key(metadata)
                if key is not None:
                    admitted, cached = cache.get(key)
                    if admitted:
                        cache_keys[index] = key
                    if cached is not None:
                        group_results.update(cached)

        def group_matches(key):
            if key not in group_results:
                result = self._prepared_group_matches(self._prepared_groups[key], metadata)
                group_results[key] = result
                owner = cache_owners.get(key)
                if owner is not None and cache_keys[owner] is not None:
                    cache_updates[owner][key] = result
            return group_results[key]

        for finding_rule_id, match_key, exclude_key, metadata_specs, content_specs, inspector_specs in self._routing:
            if not group_matches(match_key):
                continue
            if exclude_key is not None and group_matches(exclude_key):
                continue
            matched_rule_ids.append(finding_rule_id)
            metadata_rules.extend(metadata_specs)
            content_rules.extend(content_specs)
            inspector_rules.extend(inspector_specs)
        for index, updates in enumerate(cache_updates):
            if updates:
                self._route_group_caches[index].update(cache_keys[index], updates)
        return RuleRoute(
            matched_rule_ids=tuple(matched_rule_ids),
            metadata_rules=tuple(metadata_rules),
            content_rules=tuple(content_rules),
            inspector_rules=tuple(inspector_rules),
        )

    def recognizes_extension(self, extension: str) -> bool:
        """Report whether any active positive extension predicate covers a suffix."""

        if not extension or not self._extension_recognition_group[1]:
            return False
        cached = self._extension_recognition_cache.get(extension)
        if cached is not None:
            return cached
        recognized = self._prepared_group_matches(
            self._extension_recognition_group,
            {"extension": extension},
        )
        if len(self._extension_recognition_cache) >= 4096:
            self._extension_recognition_cache.clear()
        self._extension_recognition_cache[extension] = recognized
        return recognized

    @staticmethod
    def _prepare_group(group, prepared_groups):
        key = json.dumps(group, sort_keys=True, separators=(",", ":"))
        if key in prepared_groups:
            return key
        predicates = []
        for predicate in group["predicates"]:
            expression = None
            if predicate["field"] in STRING_METADATA_FIELDS and predicate["operator"] == "regex":
                expression = re.compile(predicate["value"], regex_flags(predicate["flags"]))
            predicates.append((predicate, expression))
        prepared_groups[key] = (group["condition"], tuple(predicates))
        return key

    @staticmethod
    def _prepared_group_matches(prepared_group, metadata: Mapping) -> bool:
        condition, predicates = prepared_group
        for predicate, expression in predicates:
            actual = metadata.get(predicate["field"])
            operator = predicate["operator"]
            expected = predicate["value"]
            if predicate["field"] in STRING_METADATA_FIELDS:
                actual = "" if actual is None else str(actual)
                if expression is not None:
                    matched = expression.search(actual) is not None
                else:
                    if not predicate["case_sensitive"]:
                        actual = actual.casefold()
                        expected = expected.casefold()
                    matched = {
                        "exact": actual == expected,
                        "contains": expected in actual,
                        "startswith": actual.startswith(expected),
                        "endswith": actual.endswith(expected),
                    }[operator]
            elif actual is None or isinstance(actual, bool) or not isinstance(actual, (int, float)):
                matched = False
            elif operator == "between":
                matched = expected[0] <= actual <= expected[1]
            else:
                matched = {
                    "eq": actual == expected,
                    "gt": actual > expected,
                    "gte": actual >= expected,
                    "lt": actual < expected,
                    "lte": actual <= expected,
                }[operator]
            matched = not matched if predicate["negate"] else matched
            if condition == "any" and matched:
                return True
            if condition == "all" and not matched:
                return False
        return condition == "all"

    def _rule_matches(self, rule, metadata: Mapping) -> bool:
        if not self._group_matches(rule["match"], metadata):
            return False
        exclude = rule.get("exclude")
        return exclude is None or not self._group_matches(exclude, metadata)

    def _group_matches(self, group, metadata: Mapping) -> bool:
        results = [self._predicate_matches(predicate, metadata) for predicate in group["predicates"]]
        return any(results) if group["condition"] == "any" else all(results)

    @staticmethod
    def _predicate_matches(predicate, metadata: Mapping) -> bool:
        actual = metadata.get(predicate["field"])
        operator = predicate["operator"]
        expected = predicate["value"]
        if predicate["field"] in STRING_METADATA_FIELDS:
            actual = "" if actual is None else str(actual)
            if operator == "regex":
                matched = re.search(expected, actual, regex_flags(predicate["flags"])) is not None
            else:
                if not predicate["case_sensitive"]:
                    actual = actual.casefold()
                    expected = expected.casefold()
                matched = {
                    "exact": actual == expected,
                    "contains": expected in actual,
                    "startswith": actual.startswith(expected),
                    "endswith": actual.endswith(expected),
                }[operator]
        elif actual is None or isinstance(actual, bool) or not isinstance(actual, (int, float)):
            matched = False
        elif operator == "between":
            matched = expected[0] <= actual <= expected[1]
        else:
            matched = {
                "eq": actual == expected,
                "gt": actual > expected,
                "gte": actual >= expected,
                "lt": actual < expected,
                "lte": actual <= expected,
            }[operator]
        return not matched if predicate["negate"] else matched
