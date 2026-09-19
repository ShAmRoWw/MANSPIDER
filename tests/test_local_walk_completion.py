"""A completed local directory must include discovery of its whole subtree."""

from pathlib import Path

import pytest

from man_spider.lib.util import list_files


def test_parent_completion_follows_every_descendant(tmp_path):
    for name in ("root.txt", "one/first.txt", "one/nested/deep.txt", "two/last.txt"):
        file = tmp_path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("synthetic fixture")
    events = []
    files = list_files(
        tmp_path,
        enter_directory=lambda path: events.append(("enter", path)),
        leave_directory=lambda path: events.append(("leave", path)),
    )
    for file in files:
        events.append(("file", file))
    assert len([event for event in events if event[0] == "file"]) == 4
    for index, (event, directory) in enumerate(events):
        if event == "leave":
            assert not any(directory in path.parents for _kind, path in events[index + 1 :])
    assert events[-1] == ("leave", tmp_path)


@pytest.mark.parametrize("termination", ["close", "interrupt"])
def test_partial_iteration_never_completes_its_parent(tmp_path, termination):
    for name in ("one", "two"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "secret.txt").write_text("synthetic fixture")
    entered, completed = [], []
    iterator = list_files(tmp_path, enter_directory=entered.append, leave_directory=completed.append)
    assert isinstance(next(iterator), Path)
    assert tmp_path in entered
    if termination == "close":
        iterator.close()
    else:
        with pytest.raises(KeyboardInterrupt):
            iterator.throw(KeyboardInterrupt())
    assert not completed


def test_pruned_subtree_is_not_entered_or_completed(tmp_path):
    skipped = tmp_path / "skipped"
    kept = tmp_path / "kept"
    for directory in (skipped, kept):
        directory.mkdir()
        (directory / "secret.txt").write_text("synthetic fixture")
    completed = []
    files = list(list_files(tmp_path, enter_directory=lambda path: path != skipped, leave_directory=completed.append))
    assert files == [kept / "secret.txt"]
    assert completed == [kept, tmp_path]
