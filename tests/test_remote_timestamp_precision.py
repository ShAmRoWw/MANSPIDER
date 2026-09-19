"""Directory dates use precise LastWriteTime without changing SMB identity."""

import os
import socket
import time
from datetime import datetime
from types import SimpleNamespace

import pytest
from impacket.smb import SharedFile

import man_spider.lib.spiderling as spiderling_module
from man_spider.cli import parse_options
from man_spider.filters import ScopeMatcher
from man_spider.lib.errors import ReadOnlySMBViolation
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.rules import RuleEngine
from man_spider.state import ScanState, normalized_scan_configuration, smb_object_key


FILETIME_ORIGIN = 116_444_736_000_000_000
MIDNIGHT_2026 = 1_767_225_600


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("timestamp regression checks must not connect to a server")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.fixture
def timezone():
    if not hasattr(time, "tzset"):
        pytest.skip("local calendar regression requires time.tzset")
    previous = os.environ.get("TZ")

    def select(zone):
        os.environ["TZ"] = zone
        time.tzset()

    select("UTC")
    try:
        yield select
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()


def entry(name, timestamp, *, change_timestamp=None):
    ticks = FILETIME_ORIGIN + round(timestamp * 10_000_000)
    change = ticks if change_timestamp is None else FILETIME_ORIGIN + round(change_timestamp * 10_000_000)
    return SharedFile(ticks, ticks, ticks, change, 12, 12, 0, "", name)


@pytest.fixture
def worker_factory(tmp_path):
    allocated = []

    def make(entries, *, after=None, before=None):
        events = SimpleNamespace(listings=[], handled=[], counters=[], files=[], directories=[])

        def ls(share, path):
            events.listings.append((share, path))
            return entries

        worker = Spiderling.__new__(Spiderling)
        worker.target = Target("192.0.2.25")
        worker.smb_client = SimpleNamespace(ls=ls, handle_impacket_error=events.handled.append)
        worker.parent = SimpleNamespace(
            maxdepth=15,
            max_filesize=10 * 1024**2,
            parser=SimpleNamespace(content_filters=[]),
            scope_matcher=ScopeMatcher(date_active=bool(after or before)),
            modified_after=after,
            modified_before=before,
            no_download=True,
            state_path=None,
            state_run_id=None,
            tmp_dir=tmp_path,
        )
        worker.prepare_container = lambda **_kwargs: None
        worker.complete_container = lambda object_id, status, **values: events.directories.append((status, values))
        worker.record_counter = lambda name, amount=1: events.counters.append((name, amount))

        def complete_file(file, status, **values):
            events.files.append((file, status, values))
            allocated.append(file)

        worker.complete_file = complete_file
        return worker, events

    def collect(worker):
        files = list(worker.list_files("Audit$"))
        allocated.extend(files)
        return files

    yield make, collect
    for file in allocated:
        file.cleanup()


@pytest.mark.parametrize("zone", ["UTC", "America/New_York", "Asia/Kathmandu"])
@pytest.mark.parametrize("date", ["2026-01-01", "2026-03-08", "2026-11-01"])
@pytest.mark.parametrize("delta", [-0.2, 0, 0.2])
@pytest.mark.parametrize("direction", ["after", "before"])
def test_real_shared_file_date_boundary_is_inclusive(worker_factory, timezone, zone, date, delta, direction):
    timezone(zone)
    boundary = datetime.strptime(date, "%Y-%m-%d")
    source = entry("boundary.txt", boundary.timestamp() + delta)
    make, collect = worker_factory
    worker, events = make([source], **{direction: boundary})

    files = collect(worker)

    assert bool(files) == (delta >= 0 if direction == "after" else delta <= 0)
    assert events.listings == [("Audit$", "")]
    assert events.handled == events.counters == events.files == []
    assert events.directories == [("processed", {})]


@pytest.mark.parametrize(
    ("zone", "boundary", "instant", "expected"),
    [
        ("Pacific/Apia", datetime(2011, 12, 30), datetime(2011, 12, 31), False),
        ("America/Havana", datetime(2026, 11, 1), datetime(2026, 11, 1, fold=1), True),
    ],
)
def test_skipped_day_and_repeated_midnight_keep_calendar_semantics(
    worker_factory, timezone, zone, boundary, instant, expected,
):
    timezone(zone)
    source = entry("calendar.txt", instant.timestamp())
    make, collect = worker_factory
    worker, events = make([source], before=boundary)

    assert bool(collect(worker)) is expected
    assert events.directories == [("processed", {})]


def test_precise_last_write_routes_numeric_metadata_without_changing_impacket_or_change_time(
    worker_factory, timezone,
):
    source = entry("boundary.txt", MIDNIGHT_2026, change_timestamp=MIDNIGHT_2026 + 60)
    historical_write = source.get_wtime_epoch()
    historical_change = source.get_mtime_epoch()
    make, collect = worker_factory
    worker, events = make([source])
    engine = RuleEngine([
        {
            "id": "precise-boundary",
            "match": {"predicates": [{"field": "mtime", "operator": "eq", "value": MIDNIGHT_2026}]},
            "actions": [{"type": "report"}],
        },
    ])
    worker.parent.parser = SimpleNamespace(content_filters=[], has_rules=True, route_rules=engine.route)

    files = collect(worker)

    assert len(files) == 1
    file = files[0]
    assert file.last_write_time == MIDNIGHT_2026
    assert file.mtime == historical_change
    assert [rule.rule_id for rule in file.rule_route.metadata_rules] == ["rule:precise-boundary"]
    assert source.get_wtime_epoch() == historical_write
    assert source.get_mtime_epoch() == historical_change
    assert historical_write != MIDNIGHT_2026  # The installed library was not patched.
    assert events.listings == [("Audit$", "")]


def test_no_date_filter_does_not_convert_any_calendar_date(worker_factory, timezone, monkeypatch):
    def forbidden(_timestamp):
        pytest.fail("calendar conversion is unnecessary without a date filter")

    monkeypatch.setattr(spiderling_module, "datetime", SimpleNamespace(fromtimestamp=forbidden))
    make, collect = worker_factory
    worker, events = make([
        entry("first.txt", MIDNIGHT_2026 + 60),
        entry("year10000.txt", 253_402_387_200),
        entry("last.txt", MIDNIGHT_2026 + 120),
    ])

    assert [file.name for file in collect(worker)] == ["first.txt", "year10000.txt", "last.txt"]
    assert events.directories == [("processed", {})]
    assert events.handled == events.counters == events.files == []


def test_out_of_calendar_range_affects_only_its_file(worker_factory, timezone, caplog):
    make, collect = worker_factory
    worker, events = make([
        entry("first.txt", MIDNIGHT_2026 + 60),
        entry("year10000.txt", 253_402_387_200),
        entry("last.txt", MIDNIGHT_2026 + 120),
    ], after=datetime(2026, 1, 1))

    assert [file.name for file in collect(worker)] == ["first.txt", "last.txt"]
    assert events.directories == [("processed", {})]
    assert events.counters == [("metadata_errors", 1)]
    assert len(events.handled) == len(events.files) == 1
    file, status, values = events.files[0]
    assert file.name == "year10000.txt"
    assert file.mtime is None
    assert status == "error"
    assert values["content_read"] is False
    assert values["content_status"] == "metadata_unavailable"
    assert "year 10000" in values["reason"]
    assert "year10000.txt" in caplog.text


@pytest.mark.parametrize("failure_type", [ValueError, OverflowError, OSError])
def test_platform_calendar_conversion_errors_preserve_neighbours(
    worker_factory, timezone, monkeypatch, failure_type,
):
    def convert(timestamp):
        if timestamp == MIDNIGHT_2026 + 60:
            raise failure_type("unsupported calendar value")
        return datetime.fromtimestamp(timestamp)

    monkeypatch.setattr(spiderling_module, "datetime", SimpleNamespace(fromtimestamp=convert))
    make, collect = worker_factory
    worker, events = make([
        entry("first.txt", MIDNIGHT_2026),
        entry("unsupported.txt", MIDNIGHT_2026 + 60),
        entry("last.txt", MIDNIGHT_2026 + 120),
    ], after=datetime(2026, 1, 1))

    assert [file.name for file in collect(worker)] == ["first.txt", "last.txt"]
    assert events.directories == [("processed", {})]
    assert events.counters == [("metadata_errors", 1)]
    assert isinstance(events.handled[0], failure_type)
    assert events.files[0][1] == "error"


def test_readonly_violation_in_raw_timestamp_is_not_downgraded(worker_factory, timezone, monkeypatch):
    source = entry("blocked.txt", MIDNIGHT_2026)

    def forbidden():
        raise ReadOnlySMBViolation("unsafe adapter operation")

    monkeypatch.setattr(source, "get_wtime", forbidden)
    make, collect = worker_factory
    worker, events = make([source], after=datetime(2026, 1, 1))

    with pytest.raises(ReadOnlySMBViolation, match="unsafe adapter operation"):
        collect(worker)
    assert events.handled == events.counters == events.files == events.directories == []


@pytest.mark.parametrize("ticks", [-1, 2**64, 12.5, "12", None, True])
def test_invalid_raw_filetime_is_rejected(ticks, monkeypatch):
    source = entry("invalid.txt", MIDNIGHT_2026)
    monkeypatch.setattr(source, "get_wtime", lambda: ticks)
    with pytest.raises(ValueError, match="invalid raw LastWriteTime"):
        Spiderling.remote_last_write_time(source, 123)


def test_custom_adapter_last_write_and_change_time_fallbacks_are_unchanged():
    adapter = SimpleNamespace(get_wtime=lambda: 999, get_wtime_epoch=lambda: 123.5)
    assert Spiderling.remote_last_write_time(adapter, 120) == 123.5
    assert Spiderling.remote_last_write_time(SimpleNamespace(), 120) == 120
    assert Spiderling.remote_last_write_time(SimpleNamespace(get_wtime_epoch=None), None) is None


def test_existing_resume_identity_is_reused_and_post_read_verification_is_unchanged(
    worker_factory, timezone, tmp_path,
):
    source = entry("boundary.txt", MIDNIGHT_2026, change_timestamp=MIDNIGHT_2026 + 60)
    make, collect = worker_factory
    worker, events = make([source], after=datetime(2026, 1, 1))
    file = collect(worker)[0]
    historical_change = source.get_mtime_epoch()
    options = parse_options([str(tmp_path), "-f", "boundary"])
    state = ScanState.create(tmp_path / "timestamp.sqlite3", normalized_scan_configuration(options), "2.0.0")
    try:
        old = state.claim_object(
            object_key=smb_object_key(worker.target, "Audit$", source.get_longname()),
            kind="file",
            target=str(worker.target),
            share="Audit$",
            path=source.get_longname(),
            size=12,
            mtime=historical_change,
            file_id=None,
        )
        state.complete_object(old.object_id, "processed")
        worker.parent.state_path = str(state.path)
        worker.parent.state_run_id = state.run_id
        worker.scan_state = state
        reused = worker.prepare_remote_file(file)
        assert reused.should_process is False
        assert reused.object_id == old.object_id
        assert state.object_row(old.object_id)["attempts"] == 1

        worker.verify_remote_files("Audit$", "", [file])
        assert file.changed is False
        assert file.mtime == historical_change
        assert file.last_write_time == MIDNIGHT_2026
        assert events.listings == [("Audit$", ""), ("Audit$", "")]
        assert events.counters == []
    finally:
        state.close()
