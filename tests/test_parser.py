import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import man_spider.path_safety as path_safety_module
from man_spider.lib.parser import FileParser
from man_spider.lib.spiderling import Spiderling
from man_spider.state import local_object_key
from tests.optional_fixtures import require_private_directory


parser_module = importlib.import_module("man_spider.lib.parser.parser")


def representation_rule(rule_id, representation, pattern):
    return {
        "id": rule_id,
        "match": {},
        "actions": [
            {
                "type": "scan",
                "representation": representation,
                "pattern": pattern,
                "flags": [],
            }
        ],
    }


def test_parser_returns_every_occurrence_with_exact_value_span_and_context(tmp_path):
    path = tmp_path / "many.txt"
    lines = [f"prefix Secret_{index} suffix" for index in range(8)]
    content = "\n".join(lines)
    path.write_text(content, encoding="utf-8")
    parser = FileParser([r"Secret_\d+"], quiet=True, blocked_extensions=[])

    result = parser.parse_file(path)

    assert result.error is None
    assert result.extracted is True
    assert len(result.findings) == 8
    assert [finding.value for finding in result.findings] == [f"Secret_{index}" for index in range(8)]
    for index, finding in enumerate(result.findings):
        assert content[finding.start : finding.end] == finding.value
        assert finding.context == lines[index]
        assert finding.rule_id == r"content:Secret_\d+"


def test_parser_searches_through_the_end_of_the_complete_text(tmp_path):
    path = tmp_path / "end.txt"
    prefix = "x" * 200_000
    path.write_text(prefix + "TAIL_SECRET", encoding="utf-8")
    parser = FileParser(["TAIL_SECRET"], quiet=True, blocked_extensions=[])

    result = parser.parse_file(path)

    assert len(result.findings) == 1
    assert result.findings[0].start == len(prefix)
    assert result.findings[0].value == "TAIL_SECRET"


def test_remote_text_bytes_are_scanned_without_materializing_a_named_file():
    payload = b"prefix REMOTE_SECRET suffix\n"
    loads = []
    parser = FileParser(["REMOTE_SECRET"], quiet=True, blocked_extensions=[])

    result = parser.parse_file(
        r"folder\remote.txt",
        pretty_filename=r"server\share\folder\remote.txt",
        data_loader=lambda: loads.append("bytes") or payload,
        path_factory=lambda: (_ for _ in ()).throw(AssertionError("plain text must stay memory-backed")),
    )

    assert result.error is None
    assert [finding.value for finding in result.findings] == ["REMOTE_SECRET"]
    assert loads == ["bytes"]


def test_remote_structured_content_uses_bytes_once_for_all_rules(monkeypatch):
    payload = b"structured fixture"
    loads = []
    extractions = []
    monkeypatch.setattr(
        parser_module,
        "extract_bytes_sync",
        lambda data, mime_type, **_kwargs: extractions.append((data, mime_type)) or SimpleNamespace(content="ONE TWO"),
    )
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("one", "text", "ONE"),
            representation_rule("two", "structured", "TWO"),
        ],
    )

    result = parser.parse_file(
        r"folder\remote.docx",
        data_loader=lambda: loads.append("bytes") or payload,
        path_factory=lambda: (_ for _ in ()).throw(AssertionError("bytes-compatible extraction must not materialize")),
    )

    assert result.error is None
    assert [finding.rule_id for finding in result.findings] == ["rule:one", "rule:two"]
    assert loads == ["bytes"]
    assert extractions == [(payload, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")]


def test_remote_supplied_bytes_never_fall_back_to_a_logical_unc_path(monkeypatch):
    calls = []
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *args, **kwargs: calls.append((args, kwargs)) or SimpleNamespace(content="SECRET"),
    )
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[representation_rule("structured", "structured", "SECRET")],
    )

    result = parser.parse_file(r"\\server\share\document.pages", data=b"untrusted bytes")

    assert not calls
    assert "explicit local materialization factory" in result.error


def test_kreuzberg_cache_is_disabled_for_customer_bytes(monkeypatch):
    observed = []

    def extract(data, mime_type, *, config):
        observed.append((data, mime_type, config.use_cache))
        return SimpleNamespace(content="SECRET")

    monkeypatch.setattr(parser_module, "extract_bytes_sync", extract)
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[representation_rule("structured", "structured", "SECRET")],
    )
    result = parser.parse_file("document.docx", data=b"bytes", path_factory=lambda: None)

    assert result.error is None
    assert observed == [(b"bytes", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", False)]


def test_structured_batch_uses_exact_filename_mime_hints_and_cached_results(monkeypatch):
    parser = FileParser(["ONE", "TWO"], quiet=True, blocked_extensions=[])
    calls = []

    def extract(data, mime_types, **_kwargs):
        calls.append((data, mime_types))
        return [
            SimpleNamespace(content="ONE", mime_type=mime_types[0]),
            SimpleNamespace(content="TWO", mime_type=mime_types[1]),
        ]

    monkeypatch.setattr(parser_module, "batch_extract_bytes_sync", extract)
    outcomes = parser.preextract_structured_batch(
        (
            (1, "remote.docx", None, lambda: b"docx"),
            (2, "remote.xlsb", None, lambda: b"xlsb"),
        )
    )

    assert calls == [
        (
            [b"docx", b"xlsb"],
            [
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
            ],
        )
    ]
    result = parser.parse_file(
        "remote.docx",
        data_loader=lambda: (_ for _ in ()).throw(AssertionError("cached batch result must be reused")),
        precomputed_representations={"structured": outcomes[1]},
    )
    assert result.error is None
    assert [finding.value for finding in result.findings] == ["ONE"]


def test_structured_batch_error_placeholder_falls_back_to_precise_single_error(monkeypatch):
    parser = FileParser(["SECRET"], quiet=True, blocked_extensions=[])
    monkeypatch.setattr(
        parser_module,
        "batch_extract_bytes_sync",
        lambda _data, _mimes, **_kwargs: [
            SimpleNamespace(content="Error: Parsing error", mime_type="text/plain"),
            SimpleNamespace(content="Error: Parsing error", mime_type="text/plain"),
        ],
    )
    single_calls = []

    def fail_single(data, mime_type, **_kwargs):
        single_calls.append((data, mime_type))
        raise ValueError("invalid structured fixture")

    monkeypatch.setattr(parser_module, "extract_bytes_sync", fail_single)
    outcomes = parser.preextract_structured_batch(
        (
            (1, "one.docx", None, lambda: b"one"),
            (2, "two.docx", None, lambda: b"two"),
        )
    )
    result = parser.parse_file(
        "one.docx",
        data_loader=lambda: (_ for _ in ()).throw(AssertionError("failed batch outcome must be reused")),
        precomputed_representations={"structured": outcomes[1]},
    )

    assert len(single_calls) == 2
    assert result.findings == ()
    assert result.error is not None
    assert "structured document extraction failed: invalid structured fixture" in result.error


def test_structured_batch_data_loader_failure_keeps_normal_representation_error(monkeypatch):
    parser = FileParser(["SECRET"], quiet=True, blocked_extensions=[])
    monkeypatch.setattr(
        parser_module,
        "batch_extract_bytes_sync",
        lambda *_args: (_ for _ in ()).throw(AssertionError("one prepared input must not start a batch")),
    )
    outcomes = parser.preextract_structured_batch(
        (
            (1, "broken.docx", None, lambda: (_ for _ in ()).throw(OSError("spool unavailable"))),
            (2, "working.docx", None, lambda: b"working"),
        )
    )

    result = parser.parse_file(
        "broken.docx",
        data_loader=lambda: (_ for _ in ()).throw(AssertionError("cached failure must be reused")),
        precomputed_representations={"structured": outcomes[1]},
    )

    assert result.findings == ()
    assert result.error is not None
    assert "structured document extraction failed: spool unavailable" in result.error


def test_ascii_fast_path_preserves_content_without_running_charset_detector(monkeypatch):
    monkeypatch.setattr(
        parser_module,
        "from_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("ASCII must use the exact fast path")),
    )
    parser = FileParser(["ASCII_SECRET"], quiet=True, blocked_extensions=[])

    result = parser.parse_file("remote.txt", data=b"ASCII_SECRET\n")

    assert result.error is None
    assert [finding.value for finding in result.findings] == ["ASCII_SECRET"]


def test_spiderling_accepts_post_read_identity_after_successful_local_change(tmp_path):
    candidate = tmp_path / "changing.txt"
    candidate.write_text("FIRST_SECRET", encoding="utf-8")
    initial = candidate.stat()
    parser = FileParser(["FIRST_SECRET"], quiet=True, blocked_extensions=[])
    parse = parser.parse_file

    def parse_then_change(*args, **kwargs):
        result = parse(*args, **kwargs)
        candidate.write_text("SECOND_VALUE_IS_LONGER", encoding="utf-8")
        return result

    parser.parse_file = parse_then_change
    worker = Spiderling.__new__(Spiderling)
    worker.target = tmp_path
    worker.parent = SimpleNamespace(
        parser=parser,
        quiet=True,
        modified_after=None,
        modified_before=None,
        scope_matcher=SimpleNamespace(final_include=lambda **_kwargs: True),
    )
    worker.local_rule_routes = {}
    worker.local_initial_metadata = {
        local_object_key(candidate): (
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_dev,
            initial.st_ino,
        )
    }
    completed = []
    worker.complete_file = lambda file, status, **kwargs: completed.append((file, status, kwargs))

    worker.parse_file(candidate)

    current = candidate.stat()
    assert len(completed) == 1
    assert completed[0][1] == "processed"
    assert completed[0][2]["changed"] is True
    assert completed[0][2]["post_read_identity"] == (
        current.st_size,
        current.st_mtime_ns,
        f"{current.st_dev}:{current.st_ino}",
    )
    assert [finding.value for finding in completed[0][2]["findings"]] == ["FIRST_SECRET"]


def test_local_parser_never_follows_a_file_swapped_to_network_storage(monkeypatch, tmp_path):
    candidate = tmp_path / "candidate.txt"
    displaced = tmp_path / "displaced.txt"
    network_root = tmp_path / "network"
    network_root.mkdir()
    protected = network_root / "protected.txt"
    candidate.write_text("LOCAL", encoding="utf-8")
    protected.write_text("CUSTOMER_DATA", encoding="utf-8")
    initial_key = local_object_key(candidate)
    initial = candidate.stat()
    candidate.rename(displaced)
    candidate.symlink_to(protected)

    real_filesystem_type = path_safety_module.filesystem_type

    def filesystem_type(path):
        resolved = Path(path).resolve(strict=False)
        if resolved == network_root or resolved.is_relative_to(network_root):
            return "cifs"
        return real_filesystem_type(path)

    monkeypatch.setattr(path_safety_module, "filesystem_type", filesystem_type)

    parser_called = False

    class Parser:
        def parse_file(self, *_args, **_kwargs):
            nonlocal parser_called
            parser_called = True
            raise AssertionError("network-backed source reached parser")

    worker = Spiderling.__new__(Spiderling)
    worker.target = tmp_path
    worker.parent = SimpleNamespace(parser=Parser())
    worker.local_rule_routes = {initial_key: None}
    worker.local_initial_metadata = {
        initial_key: (initial.st_size, initial.st_mtime_ns, initial.st_dev, initial.st_ino)
    }
    completed = []
    worker.complete_file = lambda file, status, **kwargs: completed.append((file, status, kwargs))

    worker.parse_file(candidate)

    assert parser_called is False
    assert protected.read_text(encoding="utf-8") == "CUSTOMER_DATA"
    assert completed and completed[0][1] == "error"


def test_real_pdfium_materialization_uses_private_run_temp_not_configured_shared_child(tmp_path):
    require_private_directory("testdata")
    hostile_temp = tmp_path / "shared-temp"
    network_sink = tmp_path / "network-sink"
    hostile_temp.mkdir()
    network_sink.mkdir()
    (hostile_temp / "kreuzberg-pdfium").symlink_to(network_sink, target_is_directory=True)
    script = r"""
import json
from pathlib import Path
from man_spider.lib.spider import MANSPIDER
from man_spider.lib.parser import FileParser

scanner = MANSPIDER.__new__(MANSPIDER)
scanner.tmp_dir = None
scanner._owned_tmp_dir = None
scanner._owned_tmp_identity = None
scanner._previous_temp_environment = None
scanner._previous_tempfile_directory = None
scanner.prepare_temp_dir()
private_root = Path(scanner.tmp_dir)
result = FileParser(["MANSPIDER_PDFIUM_TEMP_PROBE"], quiet=True, blocked_extensions=[]).parse_file(Path("testdata/test.pdf"))
payload = {
    "error": result.error,
    "private_root": str(private_root),
    "private_pdfium": bool(list(private_root.glob("manspider-extractor-*/kreuzberg-pdfium/libpdfium.so"))),
}
print(json.dumps(payload))
scanner.cleanup_temp_dir()
"""
    environment = os.environ.copy()
    environment.update(
        {
            "TMPDIR": str(hostile_temp),
            "TEMP": str(hostile_temp),
            "TMP": str(hostile_temp),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(completed.stdout.strip().splitlines()[-1])

    assert payload["error"] is None
    assert payload["private_pdfium"] is True
    assert list(network_sink.iterdir()) == []
    assert not Path(payload["private_root"]).exists()


def test_direct_file_parser_pdfium_materialization_is_private_and_cleaned(tmp_path):
    require_private_directory("testdata")
    ambient_temp = tmp_path / "ambient-temp"
    network_sink = tmp_path / "network-sink"
    ambient_temp.mkdir()
    network_sink.mkdir()
    (ambient_temp / "kreuzberg-pdfium").symlink_to(network_sink, target_is_directory=True)
    script = r"""
import json
from pathlib import Path
from man_spider.lib.parser import FileParser

result = FileParser(["MANSPIDER_PDFIUM_TEMP_PROBE"], quiet=True, blocked_extensions=[]).parse_file(
    Path("testdata/test.pdf")
)
ambient = Path(__import__("os").environ["TMPDIR"])
private_libraries = list(ambient.glob("manspider-extractor-*/kreuzberg-pdfium/libpdfium.so"))
print(json.dumps({"error": result.error, "private_libraries": [str(path) for path in private_libraries]}))
"""
    environment = os.environ.copy()
    environment.update(
        {
            "TMPDIR": str(ambient_temp),
            "TEMP": str(ambient_temp),
            "TMP": str(ambient_temp),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(completed.stdout.strip().splitlines()[-1])

    assert payload["error"] is None
    assert payload["private_libraries"]
    assert list(network_sink.iterdir()) == []
    assert not list(ambient_temp.glob("manspider-extractor-*"))


def test_nested_extractor_guards_reuse_the_pinned_environment(monkeypatch, tmp_path):
    root = tmp_path / "extractor-temp"
    root.mkdir(mode=0o700)
    calls = []
    state = SimpleNamespace(pid=None, depth=0, root=None)
    previous_environment = {name: os.environ.get(name) for name in parser_module._EXTRACTOR_ENVIRONMENT_NAMES}
    previous_tempdir = parser_module.tempfile.tempdir

    monkeypatch.setattr(parser_module, "_EXTRACTOR_GUARD_STATE", state)
    monkeypatch.setattr(
        parser_module,
        "_private_extractor_temp",
        lambda: calls.append("validated") or root,
    )

    with parser_module.guarded_extractor_environment() as outer:
        assert outer == root
        assert state.depth == 1
        with parser_module.guarded_extractor_environment() as inner:
            assert inner == root
            assert state.depth == 2
            assert calls == ["validated"]
            assert parser_module.tempfile.tempdir == str(root)
            assert all(os.environ.get(name) == str(root) for name in parser_module._EXTRACTOR_ENVIRONMENT_NAMES)
        assert state.depth == 1

    assert state.depth == 0
    assert state.root is None
    assert parser_module.tempfile.tempdir == previous_tempdir
    assert {name: os.environ.get(name) for name in parser_module._EXTRACTOR_ENVIRONMENT_NAMES} == previous_environment


def test_nested_extractor_guard_fails_if_pinned_environment_was_changed(monkeypatch, tmp_path):
    root = tmp_path / "extractor-temp"
    root.mkdir(mode=0o700)
    state = SimpleNamespace(pid=None, depth=0, root=None)
    monkeypatch.setattr(parser_module, "_EXTRACTOR_GUARD_STATE", state)
    monkeypatch.setattr(parser_module, "_private_extractor_temp", lambda: root)

    with parser_module.guarded_extractor_environment():
        os.environ["TMPDIR"] = str(tmp_path / "changed")
        with pytest.raises(
            path_safety_module.UnsafeWritePath,
            match="environment changed inside a guarded call",
        ):
            with parser_module.guarded_extractor_environment():
                pass


def test_cached_extractor_temp_uses_pinned_identity_without_revalidating_mount(monkeypatch, tmp_path):
    root = tmp_path / "extractor-temp"
    root.mkdir(mode=0o700)
    info = root.stat()

    monkeypatch.setattr(parser_module, "_EXTRACTOR_TEMP_ROOT", root)
    monkeypatch.setattr(parser_module, "_EXTRACTOR_TEMP_IDENTITY", (info.st_dev, info.st_ino))
    monkeypatch.setattr(parser_module, "_EXTRACTOR_TEMP_PID", os.getpid())
    monkeypatch.setattr(
        parser_module,
        "safe_temporary_directory",
        lambda: (_ for _ in ()).throw(AssertionError("cached root must not re-read mount policy")),
    )
    monkeypatch.setattr(
        parser_module,
        "create_private_local_directory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("cached root must be reused")),
    )

    assert parser_module._private_extractor_temp() == root


def test_cached_extractor_temp_rejects_a_replaced_directory(monkeypatch, tmp_path):
    root = tmp_path / "extractor-temp"
    displaced = tmp_path / "displaced"
    replacement = tmp_path / "replacement"
    root.mkdir(mode=0o700)
    original = root.stat()
    root.rename(displaced)
    root.mkdir(mode=0o700)
    replacement.mkdir(mode=0o700)
    replacement_info = replacement.stat()
    creations = []

    monkeypatch.setattr(parser_module, "_EXTRACTOR_TEMP_ROOT", root)
    monkeypatch.setattr(parser_module, "_EXTRACTOR_TEMP_IDENTITY", (original.st_dev, original.st_ino))
    monkeypatch.setattr(parser_module, "_EXTRACTOR_TEMP_PID", os.getpid())
    monkeypatch.setattr(parser_module, "safe_temporary_directory", lambda: tmp_path)
    monkeypatch.setattr(
        parser_module,
        "create_private_local_directory",
        lambda *_args, **_kwargs: (
            creations.append("created") or (replacement, (replacement_info.st_dev, replacement_info.st_ino))
        ),
    )

    assert parser_module._private_extractor_temp() == replacement
    assert creations == ["created"]
    assert root.is_dir()


def test_extractor_guard_does_not_reuse_inherited_nested_state_after_fork_boundary(monkeypatch, tmp_path):
    root = tmp_path / "extractor-temp"
    root.mkdir(mode=0o700)
    stale = SimpleNamespace(pid=os.getpid() + 1, depth=3, root=tmp_path / "parent-temp")
    calls = []
    monkeypatch.setattr(parser_module, "_EXTRACTOR_GUARD_STATE", stale)
    monkeypatch.setattr(
        parser_module,
        "_private_extractor_temp",
        lambda: calls.append("validated-for-child") or root,
    )

    with parser_module.guarded_extractor_environment() as guarded_root:
        assert guarded_root == root
        assert stale.pid == os.getpid()
        assert stale.depth == 1
        assert calls == ["validated-for-child"]


def test_importing_parser_does_not_import_kreuzberg_before_temp_guard():
    script = "import sys; import man_spider.lib.parser; print('kreuzberg' in sys.modules)"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == "False"


def test_duplicate_rules_do_not_duplicate_findings(tmp_path):
    path = tmp_path / "one.txt"
    path.write_text("SECRET", encoding="utf-8")
    parser = FileParser(["SECRET", "SECRET"], quiet=True, blocked_extensions=[])

    assert len(parser.parse_file(path).findings) == 1


def test_parser_reports_policy_skip_and_read_error_structurally(tmp_path):
    blocked = tmp_path / "archive.zip"
    blocked.write_bytes(b"SECRET")
    skipped = FileParser(["SECRET"], quiet=True, blocked_extensions=[".zip"]).parse_file(blocked)
    failed = FileParser(["SECRET"], quiet=True, blocked_extensions=[]).parse_file(tmp_path / "missing.txt")

    assert skipped.skipped_reason == "content disabled by current format policy"
    assert skipped.extracted is False
    assert failed.error is not None
    assert failed.extracted is False


def test_required_image_extraction_failure_is_an_object_error(monkeypatch, tmp_path):
    image = tmp_path / "broken.png"
    image.write_bytes(bytes(range(256)))
    monkeypatch.setattr(
        parser_module,
        "extract_image_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("OCR failed")),
    )

    result = FileParser(["SECRET"], quiet=True, blocked_extensions=[]).parse_file(image)

    assert result.error == "representation=text; rules=content:SECRET; RuntimeError: OCR failed"
    assert result.representation_errors[0].representation == "text"
    assert result.representation_errors[0].rule_ids == ("content:SECRET",)
    assert result.extracted is False


def test_required_structured_document_failure_does_not_fall_back_to_raw_strings(monkeypatch, tmp_path):
    document = tmp_path / "broken.pdf"
    document.write_bytes(bytes(range(256)))
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("PDF decoder failed")),
    )
    monkeypatch.setattr(
        parser_module,
        "extract_strings_from_binary",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw fallback must not run")),
    )

    result = FileParser(["SECRET"], quiet=True, blocked_extensions=[]).parse_file(document)

    assert result.error == (
        "representation=text; rules=content:SECRET; "
        "RuntimeError: structured document extraction failed: PDF decoder failed"
    )
    assert result.extracted is False


@pytest.mark.parametrize("extension", ["docm", "eml", "pptm"])
def test_additional_legacy_document_formats_use_structured_extraction(monkeypatch, tmp_path, extension):
    document = tmp_path / f"fixture.{extension}"
    document.write_bytes(b"opaque fixture")
    calls = []
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: calls.append("structured") or SimpleNamespace(content="LEGACY_SECRET"),
    )
    monkeypatch.setattr(
        parser_module,
        "from_path",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("structured format was decoded as text")),
    )

    result = FileParser(["LEGACY_SECRET"], quiet=True, blocked_extensions=[]).parse_file(document)

    assert result.error is None
    assert calls == ["structured"]
    assert [finding.value for finding in result.findings] == ["LEGACY_SECRET"]


def test_required_archive_failure_does_not_fall_back_to_raw_strings(monkeypatch, tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"not a valid archive but it contains SECRET")
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("ZIP decoder failed")),
    )
    monkeypatch.setattr(
        parser_module,
        "extract_strings_from_binary",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw fallback must not run")),
    )

    result = FileParser(["SECRET"], quiet=True, blocked_extensions=[]).parse_file(archive)

    assert result.error == (
        "representation=text; rules=content:SECRET; "
        "RuntimeError: structured document extraction failed: ZIP decoder failed"
    )
    assert result.extracted is False


def test_ambiguous_key_extension_prefers_plain_text_without_zip_magic(monkeypatch, tmp_path):
    key = tmp_path / "master.key"
    key.write_text("0123456789abcdef0123456789abcdef\n", encoding="utf-8")
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("plain key must not use iWork extraction")),
    )

    result = FileParser([r"[0-9a-f]{32}"], quiet=True, blocked_extensions=[]).parse_file(key)

    assert result.error is None
    assert [finding.value for finding in result.findings] == ["0123456789abcdef0123456789abcdef"]


def test_ambiguous_key_extension_uses_structured_extractor_for_zip_signature(monkeypatch, tmp_path):
    presentation = tmp_path / "briefing.key"
    presentation.write_bytes(b"PK\x03\x04opaque fixture")
    calls = []
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: calls.append("structured") or SimpleNamespace(content="KEYNOTE_SECRET"),
    )

    result = FileParser(["KEYNOTE_SECRET"], quiet=True, blocked_extensions=[]).parse_file(presentation)

    assert result.error is None
    assert [finding.value for finding in result.findings] == ["KEYNOTE_SECRET"]
    assert calls == ["structured"]


def test_raw_and_printable_strings_are_independent_representations(monkeypatch, tmp_path):
    binary = tmp_path / "fixture.bin"
    binary.write_bytes(b"\x00RAW_SECRET\xffPRINTABLE_SECRET\x00")
    read_bytes = parser_module.Path.read_bytes
    reads = []

    def counted_read(path):
        reads.append(path)
        return read_bytes(path)

    monkeypatch.setattr(parser_module.Path, "read_bytes", counted_read)
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("raw-secret", "raw", "RAW_SECRET\\xffPRINTABLE_SECRET"),
            representation_rule("printable-secret", "strings", "PRINTABLE_SECRET"),
        ],
    )

    result = parser.parse_file(binary)

    assert result.error is None
    assert [(finding.rule_id, finding.representation, finding.value) for finding in result.findings] == [
        ("rule:printable-secret", "strings", "PRINTABLE_SECRET"),
        ("rule:raw-secret", "raw", "RAW_SECRETÿPRINTABLE_SECRET"),
    ]
    raw_finding = result.findings[1]
    assert raw_finding.start == 1
    assert raw_finding.end == 28
    assert reads == [binary]


def test_same_underlying_ocr_result_is_reused_across_text_and_ocr(monkeypatch, tmp_path):
    image = tmp_path / "fixture.png"
    image.write_bytes(bytes(range(256)))
    calls = []

    class NoDecodedText:
        @staticmethod
        def best():
            return None

    monkeypatch.setattr(parser_module, "from_path", lambda *_args, **_kwargs: NoDecodedText())
    monkeypatch.setattr(
        parser_module,
        "extract_image_file",
        lambda *_args, **_kwargs: calls.append("ocr") or "OCR_SECRET",
    )
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("automatic", "text", "OCR_SECRET"),
            representation_rule("explicit-ocr", "ocr", "OCR_SECRET"),
        ],
    )

    result = parser.parse_file(image)

    assert calls == ["ocr"]
    assert [(finding.rule_id, finding.representation) for finding in result.findings] == [
        ("rule:automatic", "text"),
        ("rule:explicit-ocr", "ocr"),
    ]


def test_representation_failure_does_not_hide_other_representation_findings(monkeypatch, tmp_path):
    image = tmp_path / "fixture.png"
    image.write_bytes(bytes(range(256)))
    monkeypatch.setattr(
        parser_module,
        "extract_image_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("isolated OCR failure")),
    )
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: SimpleNamespace(content="STRUCTURED_SECRET"),
    )
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("broken-ocr", "ocr", "OCR_SECRET"),
            representation_rule("working-structured", "structured", "STRUCTURED_SECRET"),
        ],
    )

    result = parser.parse_file(image)

    assert result.extracted is True
    assert [(finding.rule_id, finding.representation) for finding in result.findings] == [
        ("rule:working-structured", "structured"),
    ]
    assert result.representation_errors[0].representation == "ocr"
    assert result.representation_errors[0].rule_ids == ("rule:broken-ocr",)
    assert "isolated OCR failure" in result.error


def test_rule_evaluation_failure_does_not_hide_other_rules_in_same_representation(monkeypatch, tmp_path):
    candidate = tmp_path / "fixture.txt"
    candidate.write_text("WORKING_SECRET", encoding="utf-8")
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("broken", "text", "BROKEN_SECRET"),
            representation_rule("working", "text", "WORKING_SECRET"),
        ],
    )
    evaluate = parser._evaluate_content_rule

    def isolated_evaluation(rule, content):
        if rule.rule_id == "rule:broken":
            raise RuntimeError("isolated rule failure")
        return evaluate(rule, content)

    monkeypatch.setattr(parser, "_evaluate_content_rule", isolated_evaluation)

    result = parser.parse_file(candidate, rule_route=parser.route_rules({}))

    assert [(finding.rule_id, finding.value) for finding in result.findings] == [("rule:working", "WORKING_SECRET")]
    assert result.extracted is True
    assert result.representation_errors[0].representation == "text"
    assert result.representation_errors[0].rule_ids == ("rule:broken",)
    assert "rule evaluation failed: RuntimeError: isolated rule failure" in result.error


def test_structured_representation_is_extracted_once_for_all_routed_rules(monkeypatch, tmp_path):
    document = tmp_path / "fixture.docx"
    document.write_bytes(b"opaque fixture")
    calls = []
    monkeypatch.setattr(
        parser_module,
        "extract_file_sync",
        lambda *_args, **_kwargs: calls.append("structured") or SimpleNamespace(content="ONE TWO"),
    )
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("one", "structured", "ONE"),
            representation_rule("two", "structured", "TWO"),
        ],
    )

    result = parser.parse_file(document)

    assert calls == ["structured"]
    assert [finding.rule_id for finding in result.findings] == ["rule:one", "rule:two"]


def test_spiderling_commits_successful_findings_when_another_representation_fails(monkeypatch, tmp_path):
    image = tmp_path / "fixture.png"
    image.write_bytes(b"RAW_SECRET")
    monkeypatch.setattr(
        parser_module,
        "extract_image_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("isolated OCR failure")),
    )
    parser = FileParser(
        [],
        quiet=True,
        blocked_extensions=[],
        rules=[
            representation_rule("raw", "raw", "RAW_SECRET"),
            representation_rule("ocr", "ocr", "OCR_SECRET"),
        ],
    )
    route = parser.route_rules(
        {
            "filename": image.name,
            "path": str(image),
            "extension": ".png",
            "size": image.stat().st_size,
            "mtime": image.stat().st_mtime,
        }
    )
    worker = Spiderling.__new__(Spiderling)
    worker.parent = SimpleNamespace(
        parser=parser,
        quiet=True,
        scope_matcher=SimpleNamespace(final_include=lambda **_kwargs: True),
    )
    worker.local_rule_routes = {local_object_key(image): route}
    worker.local_initial_metadata = {}
    completed = []
    worker.complete_file = lambda file, status, reason=None, findings=(), changed=None: completed.append(
        (file, status, reason, findings, changed)
    )

    worker.parse_file(image)

    assert len(completed) == 1
    assert completed[0][1] == "error"
    assert "representation=ocr; rules=rule:ocr" in completed[0][2]
    assert [(finding.rule_id, finding.value) for finding in completed[0][3]] == [("rule:raw", "RAW_SECRET")]
