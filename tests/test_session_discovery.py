"""Bounded, no-follow discovery of flat and per-session local storage."""

from contextlib import contextmanager

import man_spider.session_paths as session_paths
from man_spider.path_safety import UnsafeWritePath
from man_spider.session_paths import iter_scan_state_paths


def test_discovery_is_shallow_and_only_yields_requested_database_suffixes(tmp_path):
    legacy = tmp_path / "legacy.sqlite3"
    legacy.touch()
    session = tmp_path / "new-session"
    session.mkdir()
    current = session / "current.sqlite3"
    current.touch()
    alternative = session / "other.db"
    alternative.touch()
    (session / "current.sqlite3.review").touch()
    (session / "current.sqlite3-wal").touch()
    (session / "current.run_001.log").touch()
    nested = session / "loot"
    nested.mkdir()
    (nested / "not-a-session.sqlite3").touch()

    assert set(iter_scan_state_paths(tmp_path)) == {legacy, current}
    assert set(iter_scan_state_paths(tmp_path, suffixes={".sqlite3", ".db"})) == {
        legacy, current, alternative,
    }


def test_missing_scan_directory_is_not_created(tmp_path):
    directory = tmp_path / "absent"
    warnings = []
    assert list(iter_scan_state_paths(directory, warnings=warnings)) == []
    assert not directory.exists()
    assert warnings == []


def test_discovery_never_follows_file_or_directory_links(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    database = outside / "private.sqlite3"
    database.touch()
    (scans / "linked-session").symlink_to(outside, target_is_directory=True)
    (scans / "linked.sqlite3").symlink_to(database)
    (scans / "loop").symlink_to(scans, target_is_directory=True)
    assert list(iter_scan_state_paths(scans)) == []

    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    warnings = []
    assert list(iter_scan_state_paths(alias, warnings=warnings)) == []
    assert warnings == ["Cannot read local scan directory: alias"]


def test_each_child_directory_must_pass_the_local_safety_guard(tmp_path, monkeypatch):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    (unsafe / "not-local.sqlite3").touch()
    safe = tmp_path / "safe.sqlite3"
    safe.touch()
    original = session_paths.local_directory_descriptor
    visited = []

    @contextmanager
    def guard(path, **kwargs):
        visited.append(path)
        assert kwargs["create"] is False
        if path == unsafe:
            raise UnsafeWritePath("synthetic unsafe backing filesystem")
        with original(path, **kwargs) as opened:
            yield opened

    monkeypatch.setattr(session_paths, "local_directory_descriptor", guard)
    warnings = []
    assert list(iter_scan_state_paths(tmp_path, warnings=warnings)) == [safe]
    assert set(visited) == {tmp_path, unsafe}
    assert warnings == ["Cannot read local scan directory: unsafe"]


def test_expired_deadline_does_not_open_any_directory(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("No directory should be opened after the deadline")

    monkeypatch.setattr(session_paths, "local_directory_descriptor", forbidden)
    monkeypatch.setattr(session_paths.time, "monotonic", lambda: 2.0)
    warnings = []
    assert list(iter_scan_state_paths(tmp_path, warnings=warnings, deadline=1.0)) == []
    assert warnings == ["Scan directory discovery time limit reached"]


def test_deadline_also_stops_discovery_inside_a_session_directory(tmp_path, monkeypatch):
    session = tmp_path / "session"
    session.mkdir()
    for index in range(3):
        (session / f"{index}.sqlite3").touch()
    clock = [0.0]
    monkeypatch.setattr(session_paths.time, "monotonic", lambda: clock[0])
    warnings = []
    candidates = iter_scan_state_paths(tmp_path, warnings=warnings, deadline=1.0)
    assert next(candidates).parent == session
    clock[0] = 2.0
    assert list(candidates) == []
    assert warnings == ["Scan directory discovery time limit reached"]


def test_stopping_discovery_closes_both_directory_descriptors(tmp_path, monkeypatch):
    session = tmp_path / "session"
    session.mkdir()
    (session / "scan.sqlite3").touch()
    original = session_paths.local_directory_descriptor
    active = []

    @contextmanager
    def tracked(path, **kwargs):
        with original(path, **kwargs) as opened:
            active.append(path)
            try:
                yield opened
            finally:
                active.remove(path)

    monkeypatch.setattr(session_paths, "local_directory_descriptor", tracked)
    candidates = iter_scan_state_paths(tmp_path)
    assert next(candidates) == session / "scan.sqlite3"
    assert active == [tmp_path, session]
    candidates.close()
    assert active == []
