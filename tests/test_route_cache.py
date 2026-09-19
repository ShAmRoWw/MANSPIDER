"""Exact routing equivalence, bounded retention and process-local cache safety."""

import multiprocessing
import pickle
from collections import UserDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath

import pytest

import man_spider.rules as rules_module
from man_spider.rules import RuleEngine, RuleRoute, load_builtin_rules


def uncached_route(engine, metadata):
    """The pre-cache lazy routing algorithm, independent of cache internals."""
    groups = {}
    matched, metadata_rules, content_rules, inspectors = [], [], [], []

    def group_matches(key):
        if key not in groups:
            groups[key] = engine._prepared_group_matches(engine._prepared_groups[key], metadata)
        return groups[key]

    for rule_id, match, exclude, reports, scans, inspections in engine._routing:
        if not group_matches(match):
            continue
        if exclude is not None and group_matches(exclude):
            continue
        matched.append(rule_id)
        metadata_rules.extend(reports)
        content_rules.extend(scans)
        inspectors.extend(inspections)
    return RuleRoute(tuple(matched), tuple(metadata_rules), tuple(content_rules), tuple(inspectors))


def metadata(path, **overrides):
    candidate = PurePosixPath(path.replace("\\", "/"))
    return {
        "share": "Fixtures",
        "directory": str(candidate.parent),
        "path": path,
        "filename": candidate.name,
        "extension": "".join(candidate.suffixes).lower(),
        "size": 1024,
        "mtime": 1700000000,
        **overrides,
    }


def rule(rule_id, predicates, *, condition="all", exclude=None, actions=None):
    result = {
        "id": rule_id,
        "match": {"condition": condition, "predicates": predicates},
        "actions": actions or [{"type": "report"}],
    }
    if exclude is not None:
        result["exclude"] = exclude
    return result


def predicate(field, operator, value, **options):
    return {"field": field, "operator": operator, "value": value, **options}


@pytest.mark.parametrize("windows", [False, True])
def test_builtin_cache_matches_all_route_fields_for_cold_hits_and_unique_names(windows):
    engine = RuleEngine(load_builtin_rules())
    names = (
        "notes.txt",
        "settings.json",
        "deploy.yml",
        "ordinary.bin",
        "main.py",
        ".netrc",
        ".pgpass",
        ".erlang.cookie",
        "msal_token_cache.json",
        "redis.conf",
        "rndc.key",
        "deployment.ini",
        "package.zip",
        "database.sql",
        "rclone.conf",
        "logo.png",
        "пароли",
        "учётные_данные.txt",
        "CONFIG.JSON",
        "settings.json.bak",
        "file.unknown.gz",
        "публичный_ключ.pem",
        "secrets.txt.orig",
        "NTUSER.DAT",
    )
    for unique in (False, True, False):
        for index in range(480):
            name = names[index % len(names)]
            if unique:
                name = f"{index}-{name}"
            path = f"{'vendor' if index % 3 else 'projects'}/{index}/{name}"
            if windows:
                path = path.replace("/", "\\")
            item = metadata(path, share="SYSVOL" if index % 2 else "Fixtures")
            assert engine.route(item) == uncached_route(engine, item)


@pytest.mark.parametrize("matched", [False, True])
def test_static_groups_cache_both_positive_and_negative_results(monkeypatch, matched):
    engine = RuleEngine([rule("test", [predicate("extension", "exact", ".conf")])])
    item = metadata("app.conf" if matched else "app.other")
    original = engine._prepared_group_matches
    calls = []

    def counted(group, item):
        calls.append(group)
        return original(group, item)

    monkeypatch.setattr(engine, "_prepared_group_matches", counted)
    assert engine.route(item).matched is matched
    assert len(calls) == 1
    assert engine.route(item).matched is matched
    assert len(calls) == 1


@pytest.mark.parametrize("matched", [False, True])
def test_filename_results_are_admitted_only_on_second_observation(monkeypatch, matched):
    engine = RuleEngine([rule("test", [predicate("filename", "exact", "app.conf")])])
    item = metadata("app.conf" if matched else "app.txt")
    original = engine._prepared_group_matches
    calls = []

    def counted(group, item):
        calls.append(group)
        return original(group, item)

    monkeypatch.setattr(engine, "_prepared_group_matches", counted)
    assert engine.route(item).matched is matched
    cache = engine._route_group_caches[0]
    assert all(not results for results, _size in cache._entries.values())
    assert engine.route(item).matched is matched
    assert len(calls) == 2
    assert engine.route(item).matched is matched
    assert len(calls) == 2


def test_partial_cached_snapshots_are_not_mutated_when_another_exclude_is_reached():
    engine = RuleEngine(
        [
            rule(
                "one",
                [predicate("path", "contains", "one/")],
                exclude={"predicates": [predicate("filename", "contains", "hidden")]},
            ),
            rule(
                "two",
                [predicate("path", "contains", "two/")],
                exclude={"predicates": [predicate("filename", "contains", "public")]},
            ),
        ]
    )
    first, second = metadata("one/ordinary.txt"), metadata("two/ordinary.txt")
    engine.route(first)
    engine.route(first)
    cache = engine._route_group_caches[0]
    key = cache.key(first)
    _admitted, snapshot = cache.get(key)
    assert len(snapshot) == 1
    assert engine.route(second) == uncached_route(engine, second)
    _admitted, updated = cache.get(key)
    assert len(updated) == 2
    assert len(snapshot) == 1


def test_flags_operators_negation_and_exact_combination_keys_keep_custom_semantics():
    custom = [
        rule("case-sensitive", [predicate("filename", "exact", "Config", case_sensitive=True)]),
        rule("casefold", [predicate("filename", "exact", "Straße")]),
        rule("contains", [predicate("filename", "contains", "secret", negate=True)]),
        rule("starts", [predicate("filename", "startswith", "api")]),
        rule("ends", [predicate("filename", "endswith", ".conf")]),
        rule("unicode-regex", [predicate("filename", "regex", r"^k.$", flags=["ignorecase"])]),
        rule("ascii-regex", [predicate("filename", "regex", r"^k.$", flags=["ignorecase", "ascii"])]),
        rule("multiline", [predicate("filename", "regex", r"^secret$", flags=["multiline"])]),
        rule("dotall", [predicate("filename", "regex", r"a.b", flags=["dotall"])]),
        rule("combination", [predicate("extension", "exact", ".txt"), predicate("filename", "exact", "chosen")]),
        rule(
            "any",
            [predicate("extension", "exact", ".conf"), predicate("filename", "contains", "key")],
            condition="any",
        ),
        rule("empty-all", []),
    ]
    engine = RuleEngine(custom)
    for _ in range(3):
        for name in (
            "Config",
            "config",
            "STRASSE",
            "K1",
            "k1",
            "api-key.conf",
            "a\nb",
            "\nsecret\n",
            "chosen",
            "",
            None,
        ):
            for suffix in (".txt", ".TXT", ".conf", ".txt.bak", "", None):
                item = {"filename": name, "extension": suffix}
                assert engine.route(item) == uncached_route(engine, item)


def test_dynamic_path_size_time_share_and_excludes_are_never_reused_by_filename():
    engine = RuleEngine(
        [
            rule("static", [predicate("extension", "exact", ".conf")]),
            rule(
                "path",
                [predicate("path", "contains", "allowed")],
                exclude={"predicates": [predicate("filename", "contains", "example")]},
            ),
            rule("size", [predicate("size", "between", [1, 4096])]),
            rule("time", [predicate("mtime", "gte", 100)]),
            rule("share", [predicate("share", "exact", "Finance")]),
            rule("directory", [predicate("directory", "contains", "allowed")]),
            rule("mixed", [predicate("extension", "exact", ".conf"), predicate("path", "contains", "allowed")]),
            rule(
                "static-exclude",
                [predicate("extension", "exact", ".conf")],
                exclude={"predicates": [predicate("filename", "exact", "example.conf")]},
            ),
        ]
    )
    for path in ("allowed/app.conf", "denied/app.conf", "allowed/example.conf"):
        for size in (0, 1, 4096, 4097, None, True, "2"):
            for mtime in (99, 100, None):
                for share in ("Finance", "Public"):
                    item = metadata(path, size=size, mtime=mtime, share=share)
                    assert engine.route(item) == uncached_route(engine, item)


def test_unreached_exclusion_is_not_evaluated_speculatively(monkeypatch):
    engine = RuleEngine(
        [
            rule(
                "conditional",
                [predicate("path", "contains", "enabled")],
                exclude={"predicates": [predicate("extension", "exact", ".blocked")]},
            )
        ]
    )
    original = engine._prepared_group_matches
    seen = []

    def checked(group, item):
        fields = {pred["field"] for pred, _expression in group[1]}
        seen.append(fields)
        if item["path"] == "disabled/app.txt":
            assert fields != {"extension"}
        return original(group, item)

    monkeypatch.setattr(engine, "_prepared_group_matches", checked)
    assert not engine.route(metadata("disabled/app.txt")).matched
    assert engine.route(metadata("enabled/app.txt")).matched
    assert not engine.route(metadata("disabled/app.txt")).matched
    assert seen.count({"extension"}) == 1


class _RecordingMapping(UserDict):
    def __init__(self, values):
        super().__init__(values)
        self.reads = []

    def get(self, key, default=None):
        self.reads.append(key)
        return super().get(key, default)


class _CustomText:
    def __init__(self):
        self.reads = 0

    def __str__(self):
        self.reads += 1
        return "app.conf" if self.reads % 2 else "app.txt"


class _StringSubclass(str):
    def __hash__(self):
        raise AssertionError("custom hashing must not be used")


def test_unusual_mappings_preserve_original_get_order_and_do_not_cache():
    engine = RuleEngine([rule("test", [predicate("filename", "exact", "app.conf")])])
    item = _RecordingMapping({"filename": "app.conf"})
    reference = _RecordingMapping({"filename": "app.conf"})
    for _ in range(3):
        assert engine.route(item) == uncached_route(engine, reference)
        assert item.reads == reference.reads
    assert all(not cache._entries for cache in engine._route_group_caches)


@pytest.mark.parametrize("value", [42, True, ["app.conf"], {"name": "app.conf"}, _StringSubclass("app.conf")])
def test_unusual_field_values_use_the_original_string_conversion(value):
    engine = RuleEngine([rule("test", [predicate("filename", "contains", "app.conf")])])
    for _ in range(2):
        item = {"filename": value}
        assert engine.route(item) == uncached_route(engine, item)
    assert all(not cache._entries for cache in engine._route_group_caches)


def test_mutable_custom_string_values_are_not_memoized():
    engine = RuleEngine([rule("test", [predicate("filename", "exact", "app.conf")])])
    actual, reference = _CustomText(), _CustomText()
    for _ in range(4):
        assert engine.route({"filename": actual}) == uncached_route(engine, {"filename": reference})
        assert actual.reads == reference.reads


def test_missing_fields_and_mutated_plain_input_are_keyed_by_current_exact_values():
    engine = RuleEngine(
        [
            rule(
                "test",
                [predicate("filename", "regex", "^$"), predicate("extension", "exact", ".conf")],
                condition="any",
            )
        ]
    )
    item = {}
    for values in (
        {},
        {"filename": None},
        {"filename": ""},
        {"filename": "app", "extension": ".conf"},
        {"filename": "app", "extension": ".other"},
    ):
        item.clear()
        item.update(values)
        assert engine.route(item) == uncached_route(engine, item)


def test_cache_entry_count_and_accounted_bytes_remain_bounded_under_churn(monkeypatch):
    monkeypatch.setattr(rules_module, "_ROUTE_CACHE_MAX_ENTRIES", 3)
    monkeypatch.setattr(rules_module, "_ROUTE_CACHE_MAX_BYTES", 1200)
    engine = RuleEngine([rule("test", [predicate("filename", "endswith", ".conf")])])
    for index in range(100):
        item = metadata(f"{index}-файл.conf")
        assert engine.route(item) == uncached_route(engine, item)
        for cache in engine._route_group_caches:
            assert len(cache._entries) <= 3
            assert cache._bytes == sum(entry[1] for entry in cache._entries.values())
            assert cache._bytes <= 1200
    assert engine.route(metadata("0-файл.conf")) == uncached_route(engine, metadata("0-файл.conf"))


@pytest.mark.parametrize("name", ["a" * 1025, "😀" * 1000])
def test_oversized_field_values_bypass_cache_without_changing_routing(name):
    engine = RuleEngine([rule("test", [predicate("filename", "contains", "a", negate=True)])])
    assert engine.route({"filename": name}) == uncached_route(engine, {"filename": name})
    assert all(not cache._entries for cache in engine._route_group_caches)


@pytest.mark.parametrize(("entry_cap", "byte_cap"), [(0, 1024), (10, 1)])
def test_no_retention_when_budget_cannot_hold_an_entry(monkeypatch, entry_cap, byte_cap):
    monkeypatch.setattr(rules_module, "_ROUTE_CACHE_MAX_ENTRIES", entry_cap)
    monkeypatch.setattr(rules_module, "_ROUTE_CACHE_MAX_BYTES", byte_cap)
    engine = RuleEngine([rule("test", [predicate("extension", "exact", ".conf")])])
    for _ in range(3):
        assert engine.route(metadata("app.conf")).matched
    assert all(not cache._entries and cache._bytes == 0 for cache in engine._route_group_caches)


def test_new_engine_does_not_reuse_results_for_replaced_or_disabled_rules():
    first = RuleEngine([rule("same-id", [predicate("extension", "exact", ".conf")])])
    replacement = RuleEngine([rule("same-id", [predicate("extension", "exact", ".txt")])])
    disabled = RuleEngine([])
    item = metadata("app.conf")
    assert first.route(item).matched
    assert not replacement.route(item).matched
    assert not disabled.route(item).matched


def test_concurrent_routes_and_fifo_eviction_keep_exact_results(monkeypatch):
    monkeypatch.setattr(rules_module, "_ROUTE_CACHE_MAX_ENTRIES", 5)
    engine = RuleEngine(load_builtin_rules())
    items = [metadata(f"projects/{i}/{'secret' if i % 2 else 'example'}-{i % 17}.conf") for i in range(256)]
    expected = [uncached_route(engine, item) for item in items]
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(engine.route, items)) == expected
        assert list(pool.map(engine.route, reversed(items))) == list(reversed(expected))
    for cache in engine._route_group_caches:
        assert len(cache._entries) <= 5
        assert cache._bytes == sum(entry[1] for entry in cache._entries.values())


def _route_in_child(engine, item):
    return engine.route(item)


def test_pickle_and_spawn_start_with_empty_process_local_caches():
    engine = RuleEngine([rule("test", [predicate("filename", "endswith", ".conf")])])
    item = metadata("CachedSensitiveFilename42.conf")
    expected = engine.route(item)
    assert any(cache._entries for cache in engine._route_group_caches)
    serialized = pickle.dumps(engine)
    assert b"CachedSensitiveFilename42" not in serialized
    restored = pickle.loads(serialized)
    assert all(not cache._entries and cache._bytes == 0 for cache in restored._route_group_caches)
    assert restored.route(item) == expected
    with multiprocessing.get_context("spawn").Pool(1) as pool:
        assert pool.apply(_route_in_child, (engine, item)) == expected
