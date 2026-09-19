"""Resume ownership uses canonical endpoints, never ambiguous IPv6 displays."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target, parse_host_port
from man_spider.state import (
    ScanState,
    directory_object_key,
    local_object_key,
    share_object_key,
    smb_object_key,
    target_object_key,
)


@pytest.fixture
def state(tmp_path):
    current = ScanState.create(tmp_path / "scan.sqlite3", {}, "test")
    try:
        yield current
    finally:
        current.close()


def frontier(state, target):
    worker = SimpleNamespace(target=target, parent=SimpleNamespace(object_retry_limit=2), open_state=lambda: state)
    before = [tuple(row) for row in state.connection.execute("SELECT * FROM objects ORDER BY object_id")]
    result = Spiderling.build_resume_frontier(worker)
    assert [tuple(row) for row in state.connection.execute("SELECT * FROM objects ORDER BY object_id")] == before
    return result


def remote_values(target, kind, *, folder="second", share="Data"):
    if kind == "target":
        return dict(object_key=target_object_key(target), kind=kind, target=str(target), path=str(target))
    if kind == "share_enumeration":
        return dict(
            object_key=f"share-enumeration|{target_object_key(target)}",
            kind=kind, target=str(target), path=str(target),
        )
    if kind == "share":
        key, path = share_object_key(target, share), share
    elif kind == "directory":
        path = f"{folder}/nested"
        key = directory_object_key(target, share, path)
    else:
        path = f"{folder}/nested/secret.txt"
        key = smb_object_key(target, share, path)
    return dict(object_key=key, kind=kind, target=str(target), share=share, path=path)


def expected_frontier(target, kind, *, folder="second", share="Data"):
    own_key = remote_values(target, kind, folder=folder, share=share)["object_key"]
    keys = {target_object_key(target), own_key}
    if kind not in {"target", "share_enumeration"}:
        keys.update({share_object_key(target, share), directory_object_key(target, share, "")})
    if kind in {"directory", "file"}:
        keys.update({
            directory_object_key(target, share, folder),
            directory_object_key(target, share, f"{folder}/nested"),
        })
    return frozenset(keys)


def seed(state, target, kind, *, status="in_progress", folder="second", share="Data"):
    values = remote_values(target, kind, folder=folder, share=share)
    decision = state.register_object(**values)
    if status != "pending":
        state.begin_object(decision.object_id)
    if status in {"processed", "error"}:
        state.complete_object(decision.object_id, status, reason="fixture error" if status == "error" else None)
    return decision.object_id


def collision_pair():
    first = Target(*parse_host_port("[2001:db8::1]:1445"))
    second = Target(*parse_host_port("2001:db8::1:1445"))
    assert first != second
    assert str(first) == str(second) == "2001:db8::1:1445"
    assert target_object_key(first) != target_object_key(second)
    return first, second


@pytest.mark.parametrize("kind", ["file", "directory", "share", "target", "share_enumeration"])
@pytest.mark.parametrize("status", ["pending", "in_progress", "error"])
def test_foreign_ipv6_work_cannot_reopen_a_completed_target(state, kind, status):
    first, second = collision_pair()
    seed(state, first, "target", status="processed")
    seed(state, second, kind, status=status)
    # This deliberately proves that the existing display-only SQL selection
    # returns the ambiguous foreign row; the frontier must reject it itself.
    assert state.resumable_objects(targets=[str(first)], retry_limit=2)
    assert frontier(state, first) == frozenset()
    assert frontier(state, second) == expected_frontier(second, kind)


@pytest.mark.parametrize("kind", ["file", "directory", "share", "target", "share_enumeration"])
def test_both_ambiguous_ipv6_targets_keep_only_their_own_work(state, kind):
    first, second = collision_pair()
    seed(state, first, kind, folder="first", share="FirstData")
    seed(state, second, kind, folder="second", share="SecondData")
    assert frontier(state, first) == expected_frontier(first, kind, folder="first", share="FirstData")
    assert frontier(state, second) == expected_frontier(second, kind, folder="second", share="SecondData")


@pytest.mark.parametrize(
    "first, second",
    [
        (Target("2001:db8::1", 1445), Target("2001:db8::2")),
        (Target("192.0.2.10", 1445), Target("192.0.2.10")),
        (Target("192.0.2.10"), Target("192.0.2.100")),
        (Target("FILES-A.example", 1445), Target("files-b.example")),
    ],
)
def test_ordinary_network_targets_retain_their_frontiers(state, first, second):
    assert str(first) != str(second)
    for target, folder in ((first, "first"), (second, "second")):
        for kind in ("target", "share", "directory", "file", "share_enumeration"):
            seed(state, target, kind, folder=folder)
    for target, folder in ((first, "first"), (second, "second")):
        expected = set()
        for kind in ("target", "share", "directory", "file", "share_enumeration"):
            expected.update(expected_frontier(target, kind, folder=folder))
        assert frontier(state, target) == frozenset(expected)


def test_remote_prefix_is_delimited_and_does_not_accept_similar_port(state):
    target = Target("192.0.2.10", 445)
    foreign = Target("192.0.2.10", 4450)
    values = remote_values(foreign, "file")
    # A display-only prefilter is not an ownership guarantee, even if a legacy
    # row's display happens to be stale. Endpoint prefixes must include '|'.
    values["target"] = str(target)
    state.register_object(**values)
    assert frontier(state, target) == frozenset()


@pytest.mark.parametrize("relative", [False, True])
def test_local_frontier_and_relative_target_display_are_unchanged(state, tmp_path, monkeypatch, relative):
    root = tmp_path / "scope"
    root.mkdir()
    monkeypatch.chdir(tmp_path)
    target = Path("scope") if relative else root
    other = tmp_path / "other"
    state.register_object(
        object_key=local_object_key(other / "secret.txt"), kind="file", target=str(other), path=str(other / "secret.txt"),
    )
    path = root / "nested" / "secret.txt"
    state.register_object(object_key=local_object_key(path), kind="file", target=str(root), path=str(path))
    assert frontier(state, target) == frozenset({
        local_object_key(path),
        target_object_key(target),
        directory_object_key(target, None, root),
        directory_object_key(target, None, path.parent),
    })
