import atexit
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib.metadata import version
from importlib.util import find_spec
from pathlib import Path
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
    load_ssh_private_key,
    pkcs12,
)
from charset_normalizer import from_bytes, from_path

from man_spider.formats import blocked_content_extension, content_name, content_suffix
from man_spider.lib.finding_log import display_text
from man_spider.lib.parser.credential_json import inspect_kubernetes_secret_json
from man_spider.lib.parser.group_policy import inspect_group_policy_preference_password
from man_spider.lib.parser.localized_credentials import inspect_russian_json_credentials
from man_spider.lib.parser.legacy_cyrillic import inspect_russian_legacy_credentials
from man_spider.lib.parser.regex_guard import RegexGuard, build_regex_guard
from man_spider.lib.parser.wordprocessingml import WORD_MIME_TYPES, normalize_wordprocessingml
from man_spider.lib.parser.ad_directory_export import (
    inspect_active_directory_ldif_secrets,
    inspect_active_directory_json_secrets,
)
from man_spider.path_safety import (
    UnsafeWritePath,
    create_private_local_directory,
    remove_owned_local_tree,
    require_local_path,
    safe_temporary_directory,
)
from man_spider.rules import RULE_DETAIL_DISPLAY_LIMIT, RuleEngine, regex_flags

log = logging.getLogger("manspider.parser")

IMAGE_EXTENSIONS = {
    ".bmp",
    ".gif",
    ".jpeg",
    ".jpg",
    ".png",
    ".tif",
    ".tiff",
    ".webp",
}

# These formats require a structured extractor. Falling back to printable
# byte strings after a decoder failure would silently turn an incomplete
# analysis into a successful result.
STRUCTURED_DOCUMENT_EXTENSIONS = {
    ".doc",
    ".docx",
    ".docm",
    ".eml",
    ".epub",
    ".msg",
    ".numbers",
    ".odp",
    ".ods",
    ".odt",
    ".pages",
    ".pdf",
    ".ppt",
    ".pptx",
    ".pptm",
    ".rtf",
    ".xls",
    ".xlsb",
    ".xlsm",
    ".xlsx",
}
# `.key` is shared by Apple Keynote packages, PEM/DER key material, and Rails'
# plain-text `master.key`. Treat it as a structured document only when the
# bytes actually identify a ZIP container; otherwise normal text detection and
# structural key inspection remain available.
AMBIGUOUS_ZIP_DOCUMENT_EXTENSIONS = {".key"}
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
STRUCTURED_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".gz",
    ".tar",
    ".bz2",
    ".7z",
    ".rar",
    ".xz",
    ".tgz",
    ".tbz2",
}
STRUCTURED_CONTENT_EXTENSIONS = STRUCTURED_DOCUMENT_EXTENSIONS | STRUCTURED_ARCHIVE_EXTENSIONS
# Bytes extraction needs an explicit MIME type. These filename-derived hints
# mirror Kreuzberg's path dispatcher for formats whose container signature is
# ambiguous (notably OOXML macro variants and XLSB). Formats not present here
# retain the path API rather than risking a different parser.
STRUCTURED_BYTES_MIME_TYPES = {
    ".7z": "application/x-7z-compressed",
    ".doc": "application/msword",
    ".docm": "application/vnd.ms-word.document.macroEnabled.12",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".eml": "message/rfc822",
    ".epub": "application/epub+zip",
    ".gz": "application/gzip",
    ".msg": "application/vnd.ms-outlook",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".pdf": "application/pdf",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".rtf": "application/rtf",
    ".tar": "application/x-tar",
    ".tgz": "application/gzip",
    ".xls": "application/vnd.ms-excel",
    ".xlsb": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".zip": "application/zip",
}
REPRESENTATION_ORDER = ("text", "strings", "raw", "ocr", "structured")
# Bound only optimization metadata, never the number or length of findings.
# A file with one hit per line should not require an unbounded context index.
_CONTEXT_CACHE_MAX_ENTRIES = 4096

_KREUZBERG_VERSION = "4.10.2"
_KREUZBERG_API = None

_EXTRACTOR_TEMP_LOCK = threading.RLock()
_EXTRACTOR_TEMP_ROOT = None
_EXTRACTOR_TEMP_IDENTITY = None
_EXTRACTOR_TEMP_PID = None
_EXTRACTOR_TEMP_CLEANUP_REGISTERED = False
_EXTRACTOR_GUARD_STATE = threading.local()
_EXTRACTOR_ENVIRONMENT_NAMES = (
    "TMPDIR",
    "TEMP",
    "TMP",
    "HOME",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
)


def _load_kreuzberg():
    """Import the exact audited extractor only inside the guarded temp scope."""

    global _KREUZBERG_API
    if _KREUZBERG_API is None:
        specification = find_spec("kreuzberg")
        if specification is None or specification.origin is None:
            raise RuntimeError("Kreuzberg installation cannot be located")
        require_local_path(Path(specification.origin).parent, purpose="Kreuzberg installation")
        installed = version("kreuzberg")
        if installed != _KREUZBERG_VERSION:
            raise RuntimeError(f"Unsupported Kreuzberg version {installed}; expected audited {_KREUZBERG_VERSION}")
        from kreuzberg import (
            ExtractionConfig,
            batch_extract_bytes_sync as kreuzberg_batch_extract_bytes_sync,
            extract_bytes_sync as kreuzberg_extract_bytes_sync,
            extract_file_sync as kreuzberg_extract_file_sync,
        )

        _KREUZBERG_API = (
            ExtractionConfig,
            kreuzberg_batch_extract_bytes_sync,
            kreuzberg_extract_bytes_sync,
            kreuzberg_extract_file_sync,
        )
    return _KREUZBERG_API


def _kreuzberg_extraction_config():
    # Never let the extractor cache customer content under HOME/XDG paths.
    with guarded_extractor_environment():
        return _load_kreuzberg()[0](use_cache=False)


def batch_extract_bytes_sync(data_list, mime_types, **kwargs):
    with guarded_extractor_environment():
        prepared = [
            normalize_wordprocessingml(data) if mime_type in WORD_MIME_TYPES else data
            for data, mime_type in zip(data_list, mime_types, strict=True)
        ]
        return _load_kreuzberg()[1](prepared, mime_types, **kwargs)


def extract_bytes_sync(data, mime_type, **kwargs):
    with guarded_extractor_environment():
        if mime_type in WORD_MIME_TYPES:
            data = normalize_wordprocessingml(data)
        return _load_kreuzberg()[2](data, mime_type, **kwargs)


def extract_file_sync(file_path, mime_type=None, **kwargs):
    with guarded_extractor_environment():
        effective_mime = mime_type or STRUCTURED_BYTES_MIME_TYPES.get(content_suffix(file_path))
        if effective_mime in WORD_MIME_TYPES:
            # Read only: this path compatibility API still passes a private
            # analysis copy, never a rewritten original, to the native parser.
            return extract_bytes_sync(Path(file_path).read_bytes(), effective_mime, **kwargs)
        if mime_type is not None:
            kwargs["mime_type"] = mime_type
        return _load_kreuzberg()[3](file_path, **kwargs)


def _cleanup_extractor_temp() -> None:
    """Remove only the private local extractor tree owned by this process."""

    global _EXTRACTOR_TEMP_ROOT, _EXTRACTOR_TEMP_IDENTITY
    with _EXTRACTOR_TEMP_LOCK:
        if _EXTRACTOR_TEMP_PID != os.getpid() or _EXTRACTOR_TEMP_ROOT is None:
            return
        root = _EXTRACTOR_TEMP_ROOT
        identity = _EXTRACTOR_TEMP_IDENTITY
        _EXTRACTOR_TEMP_ROOT = None
        _EXTRACTOR_TEMP_IDENTITY = None
        try:
            remove_owned_local_tree(
                root,
                expected_identity=identity,
                purpose="extractor temporary cleanup",
            )
        except (FileNotFoundError, OSError, UnsafeWritePath):
            # Cleanup must never broaden into a path-based fallback. Leaving a
            # local private directory is safer than deleting an unproven tree.
            pass


def _private_extractor_temp() -> Path:
    """Return a process-owned 0700 local directory, recreating it after fork.

    The directory's filesystem, ancestry, ownership, and permissions are
    proven when it is created.  Later calls pin the same directory with
    ``O_NOFOLLOW`` and compare its device/inode identity.  Re-reading mountinfo
    for every document cannot strengthen that original identity proof unless a
    privileged actor changes mounts, which is outside the in-process trust
    boundary.
    """

    global _EXTRACTOR_TEMP_ROOT, _EXTRACTOR_TEMP_IDENTITY
    global _EXTRACTOR_TEMP_PID, _EXTRACTOR_TEMP_CLEANUP_REGISTERED

    process_id = os.getpid()
    if _EXTRACTOR_TEMP_PID != process_id:
        _EXTRACTOR_TEMP_ROOT = None
        _EXTRACTOR_TEMP_IDENTITY = None
        _EXTRACTOR_TEMP_PID = process_id

    if _EXTRACTOR_TEMP_ROOT is not None:
        descriptor = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(_EXTRACTOR_TEMP_ROOT, flags)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != _EXTRACTOR_TEMP_IDENTITY:
                raise UnsafeWritePath("extractor temporary directory identity changed")
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise UnsafeWritePath("extractor temporary directory is not private")
            return _EXTRACTOR_TEMP_ROOT
        except (FileNotFoundError, OSError, UnsafeWritePath):
            # Never delete an object whose identity no longer matches. Allocate
            # a new capability below a freshly revalidated local parent.
            _EXTRACTOR_TEMP_ROOT = None
            _EXTRACTOR_TEMP_IDENTITY = None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    root, identity = create_private_local_directory(
        safe_temporary_directory(),
        prefix="manspider-extractor-",
        purpose="extractor temporary directory",
    )
    _EXTRACTOR_TEMP_ROOT = root
    _EXTRACTOR_TEMP_IDENTITY = identity
    if not _EXTRACTOR_TEMP_CLEANUP_REGISTERED:
        atexit.register(_cleanup_extractor_temp)
        _EXTRACTOR_TEMP_CLEANUP_REGISTERED = True
    return root


@contextmanager
def guarded_extractor_environment():
    """Run a third-party extractor with every temp selector pinned locally.

    Environment variables are process-global, so the lock remains held for
    the complete external-library/subprocess call. Nested wrappers in the same
    thread reuse the already-pinned environment instead of repeating mount,
    ancestry, and environment work. This also protects direct use of
    ``FileParser`` outside the normal MANSPIDER CLI lifecycle.
    """

    with _EXTRACTOR_TEMP_LOCK:
        process_id = os.getpid()
        if getattr(_EXTRACTOR_GUARD_STATE, "pid", None) != process_id:
            _EXTRACTOR_GUARD_STATE.pid = process_id
            _EXTRACTOR_GUARD_STATE.depth = 0
            _EXTRACTOR_GUARD_STATE.root = None

        depth = _EXTRACTOR_GUARD_STATE.depth
        if depth:
            root = _EXTRACTOR_GUARD_STATE.root
            expected = str(root)
            if tempfile.tempdir != expected or any(
                os.environ.get(name) != expected for name in _EXTRACTOR_ENVIRONMENT_NAMES
            ):
                raise UnsafeWritePath("extractor temporary environment changed inside a guarded call")
            _EXTRACTOR_GUARD_STATE.depth = depth + 1
            try:
                yield root
            finally:
                _EXTRACTOR_GUARD_STATE.depth = depth
            return

        root = _private_extractor_temp()
        previous_environment = {name: os.environ.get(name) for name in _EXTRACTOR_ENVIRONMENT_NAMES}
        previous_tempdir = tempfile.tempdir
        for name in previous_environment:
            os.environ[name] = str(root)
        tempfile.tempdir = str(root)
        _EXTRACTOR_GUARD_STATE.depth = 1
        _EXTRACTOR_GUARD_STATE.root = root
        try:
            yield root
        finally:
            try:
                for name, previous in previous_environment.items():
                    if previous is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = previous
                tempfile.tempdir = previous_tempdir
            finally:
                _EXTRACTOR_GUARD_STATE.depth = 0
                _EXTRACTOR_GUARD_STATE.root = None


def extract_image_file(filepath, language="eng", timeout=60):
    """Extract image text with the system Tesseract command.

    Kreuzberg's hOCR preprocessing can classify compact screenshots as photo-only
    blocks and return empty content even when Tesseract recognizes their text. The
    plain-text renderer preserves that text and keeps OCR in a separate process.
    """

    tesseract = shutil.which("tesseract")
    if tesseract is None:
        raise RuntimeError("Tesseract OCR executable is not installed")

    with guarded_extractor_environment():
        completed = subprocess.run(
            [tesseract, str(filepath), "stdout", "-l", language, "--psm", "3"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"Tesseract exited with status {completed.returncode}"
        raise RuntimeError(message)
    return completed.stdout


@dataclass(frozen=True)
class ParsedFinding:
    rule_id: str
    pattern: str
    value: str
    start: int
    end: int
    context: str
    representation: str = "text"
    rule_source: str = "unknown"
    rule_schema_version: int | None = None
    rule_pack_id: str | None = None
    rule_pack_version: str | None = None
    severity: str = "medium"
    confidence: str = "medium"
    category: str = "uncategorized"
    tags: tuple[str, ...] = ()
    context_offset: int | None = None


@dataclass(frozen=True)
class RepresentationError:
    representation: str
    rule_ids: tuple[str, ...]
    error: str

    def render(self) -> str:
        return f"representation={self.representation}; rules={','.join(self.rule_ids)}; {self.error}"


@dataclass(frozen=True)
class ParseResult:
    findings: tuple[ParsedFinding, ...] = ()
    extracted: bool = False
    error: str | None = None
    skipped_reason: str | None = None
    representation_errors: tuple[RepresentationError, ...] = ()
    # Execution observations, independent of whether any secret was found.
    # None preserves conservative semantics for legacy/custom parser results.
    analysis_selected: int | None = None
    analysis_completed: int | None = None
    analysis_read: bool | None = None

    def __bool__(self):
        return bool(self.findings)


@dataclass
class _AnalysisProgress:
    selected: int = 0
    completed: int = 0
    read: bool | None = False

    def fields(self):
        return {
            "analysis_selected": self.selected,
            "analysis_completed": self.completed,
            "analysis_read": self.read,
        }


@dataclass(frozen=True)
class ContentPredicate:
    operator: str
    value: str
    negate: bool
    expression: re.Pattern
    guard: RegexGuard | None = field(default=None, init=False, compare=False)

    def __post_init__(self):
        object.__setattr__(self, "guard", build_regex_guard(self.expression))


@dataclass(frozen=True)
class ContentRule:
    rule_id: str
    predicates: tuple[ContentPredicate, ...]
    condition: str = "all"
    description: str = ""
    representation: str = "text"
    rule_source: str = "unknown"
    rule_schema_version: int | None = None
    rule_pack_id: str | None = None
    rule_pack_version: str | None = None
    severity: str = "medium"
    confidence: str = "medium"
    category: str = "uncategorized"
    tags: tuple[str, ...] = ()

    @property
    def pattern(self) -> str:
        if len(self.predicates) == 1 and self.predicates[0].operator == "regex":
            return self.predicates[0].value
        return " | ".join(
            f"{'not ' if predicate.negate else ''}{predicate.operator}:{predicate.value}"
            for predicate in self.predicates
        )


def is_text_file(filepath):
    """Detect if file is plain text using charset-normalizer."""
    result = from_path(filepath)
    best = result.best()
    # Only consider it a text file if we have high confidence
    # and the encoding is detected (not binary)
    return best is not None and best.encoding is not None


def extract_text_file(filepath):
    """Extract text from plain text file, auto-detecting encoding."""
    result = from_path(filepath)
    best = result.best()
    return str(best) if best else None


def decode_text_bytes(data, *, _errors=None):
    """Decode text; optionally retain explicit Unicode errors for the caller.

    The public return contract remains text/None. The parser's private error
    sink distinguishes malformed BOM-declared text from unrecognized binary
    input without a second decode or retaining an exception's source buffer.
    """

    # UTF-32 LE starts with the UTF-16 LE BOM, so test the longer markers first.
    # An explicit but malformed Unicode stream must not become a different
    # legacy encoding, nor have invalid bytes silently dropped or replaced.
    encoding = None
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encoding = "utf-32"
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif data.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    if encoding is not None:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as exc:
            if _errors is not None:
                _errors.append(
                    f"explicit {encoding} decoding failed: {exc}; fallback text analysis may be incomplete or inexact"
                )
            return None

    # Strict UTF-8 is deterministic, unlike a language guess on short Cyrillic
    # configurations. NUL-bearing data keeps the established UTF-16/32/binary
    # detector path instead of being mistaken for an ASCII-compatible stream.
    if b"\x00" not in data:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    detection = from_bytes(data)
    best = detection.best()
    return str(best) if best is not None and best.encoding is not None else None


def extract_strings_from_binary(filepath, min_length=4, data=None):
    """
    Extract printable ASCII strings from a binary file.
    Similar to the Unix 'strings' command.
    """
    import string

    printable = set(string.printable) - set("\x0b\x0c")  # Exclude vertical tab and form feed

    if data is None:
        with open(filepath, "rb") as f:
            data = f.read()

    result = []
    current = []
    for byte in data:
        char = chr(byte) if byte < 128 else None
        if char and char in printable:
            current.append(char)
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []
    if len(current) >= min_length:
        result.append("".join(current))

    return "\n".join(result)


class FileParser:
    # don't parse files with these extensions
    extension_blacklist = {
        # Archive formats
        ".zip",
        ".gz",
        ".tar",
        ".bz2",
        ".7z",
        ".rar",
        ".xz",
        ".tgz",
        ".tbz2",
        # Encrypted/protected formats
        ".enc",
        ".gpg",
        ".pgp",
        ".asc",
        # Compiled/binary formats that are rarely useful to parse
        ".exe",
        ".dll",
        ".so",
        ".dylib",
    }

    def __init__(self, filters, quiet=False, blocked_extensions=None, rules=()):
        self.rule_engine = RuleEngine(rules)
        self.init_content_filters(filters)
        self.quiet = quiet
        self.blocked_extensions = {
            str(extension).lower()
            for extension in (self.extension_blacklist if blocked_extensions is None else blocked_extensions)
        }

    def init_content_filters(self, file_content):
        """
        Get ready to search by file content
        """

        # strings to look for in file content
        # if empty, content is ignored
        self.cli_content_filters = []
        seen = set()
        for f in file_content:
            if f in seen:
                continue
            seen.add(f)
            try:
                self.cli_content_filters.append(
                    ContentRule(
                        rule_id=f"content:{f}",
                        predicates=(
                            ContentPredicate(
                                operator="regex",
                                value=f,
                                negate=False,
                                expression=re.compile(f, re.I),
                            ),
                        ),
                        rule_source="cli",
                    )
                )
            except re.error as e:
                log.error('Unsupported file content regex "%s": %s', display_text(f), display_text(e))
        self.rule_content_filters = {
            specification: ContentRule(
                rule_id=specification.rule_id,
                predicates=tuple(
                    ContentPredicate(
                        operator=predicate.operator,
                        value=predicate.value,
                        negate=predicate.negate,
                        expression=self._compile_content_predicate(predicate),
                    )
                    for predicate in specification.predicates
                ),
                condition=specification.condition,
                description=specification.description,
                representation=specification.representation,
                rule_source=specification.rule_source,
                rule_schema_version=specification.rule_schema_version,
                rule_pack_id=specification.rule_pack_id,
                rule_pack_version=specification.rule_pack_version,
                severity=specification.severity,
                confidence=specification.confidence,
                category=specification.category,
                tags=specification.tags,
            )
            for specification in self.rule_engine.all_content_rules
        }
        self.content_filters = [*self.cli_content_filters, *self.rule_content_filters.values()]
        self.rule_inspectors = self.rule_engine.all_inspector_rules
        if self.content_filters:
            content_filter_str = (
                '"' + '", "'.join(f"{rule.rule_id}={rule.pattern}" for rule in self.content_filters) + '"'
            )
            if len(self.content_filters) <= RULE_DETAIL_DISPLAY_LIMIT or log.isEnabledFor(logging.DEBUG):
                log.info("Searching by file content: %s", display_text(content_filter_str))
            else:
                representations = {}
                for rule in self.content_filters:
                    representations[rule.representation] = representations.get(rule.representation, 0) + 1
                summary = ", ".join(
                    f"{representation}={count}" for representation, count in sorted(representations.items())
                )
                log.info(
                    f"Searching file content with {len(self.content_filters)} rules ({summary}); "
                    "use --verbose to display every expression"
                )
                log.debug("Content rule expressions: %s", display_text(content_filter_str))

    @staticmethod
    def _compile_content_predicate(predicate):
        flags = regex_flags(predicate.flags)
        if predicate.operator != "regex" and not predicate.case_sensitive:
            flags |= re.IGNORECASE
        escaped = re.escape(predicate.value)
        expression = {
            "exact": rf"\A(?:{escaped})\Z",
            "contains": escaped,
            "startswith": rf"\A(?:{escaped})",
            "endswith": rf"(?:{escaped})\Z",
            "regex": predicate.value,
        }[predicate.operator]
        return re.compile(expression, flags)

    @property
    def has_rules(self):
        return self.rule_engine.active

    @property
    def has_cli_content_filters(self):
        return bool(self.cli_content_filters)

    def route_rules(self, metadata):
        return self.rule_engine.route(metadata)

    def recognizes_extension(self, extension):
        return self.rule_engine.recognizes_extension(extension)

    def requires_content(self, rule_route) -> bool:
        return self.has_cli_content_filters or bool(rule_route and rule_route.requires_content)

    def active_content_rules(self, rule_route=None):
        active_rules = list(self.cli_content_filters)
        if rule_route is None:
            active_rules.extend(self.rule_content_filters.values())
        else:
            active_rules.extend(self.rule_content_filters[specification] for specification in rule_route.content_rules)
        return tuple(active_rules)

    def active_inspector_rules(self, rule_route=None):
        if rule_route is None:
            return self.rule_inspectors
        return rule_route.inspector_rules

    def match(self, file_content, rule_route=None, representation="text"):
        """
        Finds all regex matches in file content
        """

        for rule in self.active_content_rules(rule_route):
            if rule.representation != representation:
                continue
            for _predicate, match in self._evaluate_content_rule(rule, file_content):
                yield rule, match

    @staticmethod
    def _evaluate_content_rule(rule, content):
        evaluated = []
        for predicate in rule.predicates:
            if predicate.guard is not None and predicate.guard.impossible(content):
                matches = ()
            else:
                matches = tuple(predicate.expression.finditer(content))
            satisfied = not matches if predicate.negate else bool(matches)
            evaluated.append((predicate, matches, satisfied))
        matched = any(item[2] for item in evaluated) if rule.condition == "any" else all(item[2] for item in evaluated)
        if not matched:
            return ()

        evidence = []
        for predicate, matches, satisfied in evaluated:
            if not satisfied:
                continue
            if predicate.negate:
                evidence.append((predicate, None))
            else:
                evidence.extend((predicate, match) for match in matches)
        return tuple(evidence)

    def match_magic(self, file):
        """
        Returns True if the file isn't of a blacklisted file type
        """
        blocked = blocked_content_extension(file, self.blocked_extensions)
        if blocked is not None:
            log.debug(
                'Not parsing %s: content disabled for extension: "%s"', display_text(file), display_text(blocked)
            )
            return False

        return True

    @staticmethod
    def match_context(content: str, start: int, end: int) -> str:
        """Return the complete logical line containing a match, without truncation."""

        return FileParser._match_context_with_offset(content, start, end)[0]

    @staticmethod
    def _match_context_with_offset(content: str, start: int, end: int, *, cache=None) -> tuple[str, int]:
        line_start = content.rfind("\n", 0, start) + 1
        line_end = content.find("\n", end)
        if line_end < 0:
            line_end = len(content)
        # The cache belongs to one immutable representation of one parse call.
        # Equal bounds reuse the same complete string across matches/rules;
        # offsets remain individual, and multiline spans retain their bounds.
        if cache is None:
            context = content[line_start:line_end].rstrip("\r")
        else:
            key = (line_start, line_end)
            if key not in cache:
                if len(cache) >= _CONTEXT_CACHE_MAX_ENTRIES:
                    cache.clear()
                cache[key] = content[line_start:line_end].rstrip("\r")
            context = cache[key]
        return context, start - line_start

    def parse_file(
        self,
        file,
        pretty_filename=None,
        rule_route=None,
        *,
        data=None,
        data_loader=None,
        path_factory=None,
        precomputed_representations=None,
    ):
        """
        Parse a file on the local filesystem
        """

        if pretty_filename is None:
            pretty_filename = str(file)

        log.debug("Parsing file: %s", display_text(pretty_filename))
        analysis = _AnalysisProgress()
        try:
            return self.extract_representations(
                file,
                pretty_filename=pretty_filename,
                rule_route=rule_route,
                data=data,
                data_loader=data_loader,
                path_factory=path_factory,
                precomputed_representations=precomputed_representations,
                _analysis=analysis,
            )

        except Exception as e:
            if log.level <= logging.DEBUG:
                log.warning(
                    "Error extracting representations from %s: %s", display_text(pretty_filename), display_text(e)
                )
            else:
                log.warning("Error extracting representations from %s (-v to debug)", display_text(pretty_filename))
            return ParseResult(error=f"{type(e).__name__}: {e}", **analysis.fields())

    def extract_text(self, file, pretty_filename, rule_route=None):
        """Compatibility wrapper for the former single-representation parser."""

        return self.extract_representations(file, pretty_filename, rule_route=rule_route)

    @staticmethod
    def _cached(cache, key, loader):
        if key not in cache:
            try:
                cache[key] = (True, loader())
            except Exception as exc:
                cache[key] = (False, exc)
        succeeded, value = cache[key]
        if not succeeded:
            raise value
        return value

    def _source_bytes(self, file, cache, data_loader=None):
        analysis = cache.get("analysis-progress")
        if analysis is not None and analysis.read is not True:
            # A loader can fail after partial access. Until it returns, bytes
            # accessed are unknown rather than falsely reported as zero.
            analysis.read = None
        data = self._cached(
            cache,
            "bytes",
            data_loader if data_loader is not None else lambda: Path(file).read_bytes(),
        )
        if analysis is not None:
            analysis.read = True
        return data

    def _source_path(self, file, cache, path_factory=None):
        if path_factory is None and cache.get("caller-provided-bytes", False):
            raise RuntimeError(
                "path-based extraction of supplied bytes requires an explicit local materialization factory"
            )
        analysis = cache.get("analysis-progress")
        if analysis is not None and analysis.read is not True:
            # Path-based extractors do not expose a byte callback. Success
            # below confirms access; failure alone cannot prove a read.
            analysis.read = None
        return self._cached(
            cache,
            "path",
            (lambda: Path(path_factory())) if path_factory is not None else lambda: Path(file),
        )

    def _extract_structured(self, file, cache, data_loader=None, path_factory=None):
        def load():
            try:
                with guarded_extractor_environment():
                    mime_type = STRUCTURED_BYTES_MIME_TYPES.get(content_suffix(file))
                    if cache.get("prefer-structured-bytes", False) and mime_type is not None:
                        data = self._source_bytes(file, cache, data_loader)
                        result = extract_bytes_sync(data, mime_type, config=_kreuzberg_extraction_config())
                    else:
                        source = str(self._source_path(file, cache, path_factory))
                        if mime_type is not None and content_suffix(file) != Path(file).suffix.lower():
                            result = extract_file_sync(
                                source,
                                mime_type=mime_type,
                                config=_kreuzberg_extraction_config(),
                            )
                        else:
                            result = extract_file_sync(source, config=_kreuzberg_extraction_config())
            except Exception as exc:
                raise RuntimeError(f"structured document extraction failed: {exc}") from exc
            return result.content or ""

        return self._cached(cache, "structured", load)

    def structured_bytes_mime_type(self, file, rule_route=None):
        """Return a proven filename MIME hint when this route needs structured text."""

        suffix = content_suffix(file)
        mime_type = STRUCTURED_BYTES_MIME_TYPES.get(suffix)
        if mime_type is None:
            return None
        representations = {rule.representation for rule in self.active_content_rules(rule_route)}
        if "structured" in representations:
            return mime_type
        if "text" in representations and suffix in STRUCTURED_CONTENT_EXTENSIONS:
            return mime_type
        return None

    @staticmethod
    def _structured_result_matches_request(result, mime_type):
        """Reject batch error placeholders and any ambiguous parser dispatch."""

        return getattr(result, "mime_type", None) == mime_type

    def preextract_structured_batch(self, requests):
        """Extract independent structured byte inputs while preserving per-file errors.

        Each request is ``(identity, filename, rule_route, data_loader)``. A
        batch-level failure or an error placeholder is retried with the normal
        single-input API so its established success/error semantics are kept.
        """

        prepared = []
        outcomes = {}
        for identity, file, rule_route, data_loader in requests:
            mime_type = self.structured_bytes_mime_type(file, rule_route)
            if mime_type is None:
                continue
            try:
                data = data_loader()
            except Exception as exc:
                outcomes[identity] = (
                    False,
                    RuntimeError(f"structured document extraction failed: {exc}"),
                )
                continue
            prepared.append((identity, data, mime_type))
        if len(prepared) < 2:
            return outcomes

        with guarded_extractor_environment():
            try:
                results = batch_extract_bytes_sync(
                    [data for _identity, data, _mime_type in prepared],
                    [mime_type for _identity, _data, mime_type in prepared],
                    config=_kreuzberg_extraction_config(),
                )
                if len(results) != len(prepared):
                    raise RuntimeError(f"structured batch returned {len(results)} results for {len(prepared)} inputs")
            except Exception:
                results = [None] * len(prepared)

            for (identity, data, mime_type), result in zip(prepared, results, strict=True):
                if result is not None and self._structured_result_matches_request(result, mime_type):
                    outcomes[identity] = (True, result.content or "")
                    continue
                try:
                    result = extract_bytes_sync(data, mime_type, config=_kreuzberg_extraction_config())
                except Exception as exc:
                    outcomes[identity] = (
                        False,
                        RuntimeError(f"structured document extraction failed: {exc}"),
                    )
                else:
                    outcomes[identity] = (True, result.content or "")
        return outcomes

    def _extract_representation(
        self,
        file,
        representation,
        cache,
        pretty_filename,
        *,
        data_loader=None,
        path_factory=None,
    ):
        suffix = content_suffix(file)
        if representation == "raw":
            return self._cached(
                cache,
                "raw",
                lambda: self._source_bytes(file, cache, data_loader).decode("latin-1"),
            )
        if representation == "strings":
            return self._cached(
                cache,
                "strings",
                lambda: extract_strings_from_binary(
                    str(file),
                    data=self._source_bytes(file, cache, data_loader),
                ),
            )
        if representation == "ocr":
            if suffix not in IMAGE_EXTENSIONS:
                raise RuntimeError(f'OCR representation does not support extension "{suffix or "<none>"}"')
            return self._cached(
                cache,
                "ocr",
                lambda: extract_image_file(str(self._source_path(file, cache, path_factory))),
            )
        if representation == "structured":
            return self._extract_structured(file, cache, data_loader, path_factory)
        if representation != "text":
            raise RuntimeError(f'unsupported representation "{representation}"')

        if suffix in IMAGE_EXTENSIONS:
            return self._cached(
                cache,
                "ocr",
                lambda: extract_image_file(str(self._source_path(file, cache, path_factory))),
            )
        if suffix in AMBIGUOUS_ZIP_DOCUMENT_EXTENSIONS:
            data = self._source_bytes(file, cache, data_loader)
            if data.startswith(ZIP_SIGNATURES):
                return self._extract_structured(file, cache, data_loader, path_factory)
        if suffix in STRUCTURED_CONTENT_EXTENSIONS:
            return self._extract_structured(file, cache, data_loader, path_factory)

        def decode_text():
            return decode_text_bytes(
                self._source_bytes(file, cache, data_loader), _errors=cache.setdefault("text-decoding-errors", [])
            )

        decoded = self._cached(cache, "decoded-text", decode_text)
        if decoded is not None:
            log.debug("Extracted text from %s using charset-normalizer", display_text(pretty_filename))
            return decoded
        try:
            return self._extract_structured(file, cache, data_loader, path_factory)
        except RuntimeError:
            log.debug("Structured extraction failed for %s, trying printable strings", display_text(pretty_filename))
            return self._cached(
                cache,
                "strings",
                lambda: extract_strings_from_binary(
                    str(file),
                    data=self._source_bytes(file, cache, data_loader),
                ),
            )

    @staticmethod
    def _inspection_passwords(file, configured_passwords):
        """Return deterministic byte passwords plus unmasked display labels."""

        candidates = [(None, "<none>"), (b"", '""')]
        for password in configured_passwords:
            candidates.append((password.encode("utf-8"), json.dumps(password, ensure_ascii=False)))
        for stem in dict.fromkeys((Path(str(file).replace("\\", "/")).stem, Path(content_name(file)).stem)):
            if stem:
                candidates.append((stem.encode("utf-8"), json.dumps(stem, ensure_ascii=False)))
        unique = []
        seen = set()
        for encoded, label in candidates:
            key = encoded
            if key in seen:
                continue
            seen.add(key)
            unique.append((encoded, label))
        return tuple(unique)

    @classmethod
    def _inspect_private_key_material(cls, data, file, configured_passwords):
        """Return semantic evidence only when private-key material is present."""

        passwords = cls._inspection_passwords(file, configured_passwords)
        header = re.search(
            rb"-----BEGIN (?:(?:ENCRYPTED|RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----",
            data,
        )
        if header is not None:
            for password, label in passwords:
                for loader in (load_pem_private_key, load_ssh_private_key):
                    try:
                        key = loader(data, password=password)
                    except (TypeError, ValueError, UnsupportedAlgorithm):
                        continue
                    algorithm = type(key).__name__
                    value = header.group(0).decode("ascii")
                    context = f"private key parsed; container=pem; algorithm={algorithm}; password={label}"
                    return ((value, header.start(), header.end(), context),)
            value = header.group(0).decode("ascii")
            context = "private-key PEM header present; key is encrypted or uses an unsupported algorithm"
            return ((value, header.start(), header.end(), context),)

        for password, label in passwords:
            try:
                key = load_der_private_key(data, password=password)
            except (TypeError, ValueError, UnsupportedAlgorithm):
                continue
            algorithm = type(key).__name__
            context = f"private key parsed; container=der; algorithm={algorithm}; password={label}"
            return (("DER private key material", 0, len(data), context),)

        for password, label in passwords:
            try:
                key, certificate, _additional = pkcs12.load_key_and_certificates(data, password)
            except (TypeError, ValueError, UnsupportedAlgorithm):
                continue
            if key is None:
                return ()
            algorithm = type(key).__name__
            subject = certificate.subject.rfc4514_string() if certificate is not None else "<none>"
            context = (
                f"private key parsed; container=pkcs12; algorithm={algorithm}; password={label}; subject={subject}"
            )
            return (("PKCS#12 private key material", 0, len(data), context),)
        return ()

    @classmethod
    def _run_inspector(cls, inspector, data, file):
        if inspector.detector == "private-key-material":
            return cls._inspect_private_key_material(data, file, inspector.passwords)
        if inspector.detector == "kubernetes-secret-json":
            return inspect_kubernetes_secret_json(data)
        if inspector.detector == "group-policy-preference-password":
            return inspect_group_policy_preference_password(data)
        if inspector.detector == "active-directory-ldif-secrets":
            return inspect_active_directory_ldif_secrets(data)
        if inspector.detector == "active-directory-json-secrets":
            return inspect_active_directory_json_secrets(data)
        if inspector.detector == "russian-json-credential-value":
            return inspect_russian_json_credentials(data)
        if inspector.detector == "russian-legacy-credential-value":
            return inspect_russian_legacy_credentials(data)
        raise RuntimeError(f'unsupported inspector "{inspector.detector}"')

    @staticmethod
    def _finding(rule, predicate, match, content, *, context_cache=None):
        if match is None:
            value = f"not {predicate.operator}:{predicate.value}"
            return ParsedFinding(
                rule_id=rule.rule_id,
                pattern=value,
                value=value,
                start=0,
                end=0,
                context=(
                    f'negated content predicate satisfied by absence: representation "{rule.representation}" '
                    f'does not match {predicate.operator} "{predicate.value}"'
                ),
                representation=rule.representation,
                rule_source=rule.rule_source,
                rule_schema_version=rule.rule_schema_version,
                rule_pack_id=rule.rule_pack_id,
                rule_pack_version=rule.rule_pack_version,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                tags=rule.tags,
            )
        start, end = match.span()
        context, context_offset = FileParser._match_context_with_offset(content, start, end, cache=context_cache)
        return ParsedFinding(
            rule_id=rule.rule_id,
            pattern=predicate.value,
            value=match.group(0),
            start=start,
            end=end,
            context=context,
            context_offset=context_offset,
            representation=rule.representation,
            rule_source=rule.rule_source,
            rule_schema_version=rule.rule_schema_version,
            rule_pack_id=rule.rule_pack_id,
            rule_pack_version=rule.rule_pack_version,
            severity=rule.severity,
            confidence=rule.confidence,
            category=rule.category,
            tags=rule.tags,
        )

    def extract_representations(
        self,
        file,
        pretty_filename,
        rule_route=None,
        *,
        data=None,
        data_loader=None,
        path_factory=None,
        precomputed_representations=None,
        _analysis=None,
    ):
        """
        Extract each requested representation once and retain independent errors.

        The legacy/CLI `text` representation uses the appropriate complete
        extractor: OCR for known images, Kreuzberg for known documents and
        archives, charset-normalizer for text, and printable strings for
        otherwise opaque formats.
        """

        analysis = _analysis if _analysis is not None else _AnalysisProgress()
        rules_by_representation = {}
        for rule in self.active_content_rules(rule_route):
            rules_by_representation.setdefault(rule.representation, []).append(rule)
        inspectors = tuple(self.active_inspector_rules(rule_route))
        analysis.selected = sum(len(rules) for rules in rules_by_representation.values()) + len(inspectors)
        if not self.match_magic(file):
            return ParseResult(skipped_reason="content disabled by current format policy", **analysis.fields())
        ordered_representations = [
            representation for representation in REPRESENTATION_ORDER if representation in rules_by_representation
        ]
        findings = []
        representation_errors = []
        cache = {"analysis-progress": analysis}
        if data is not None:
            cache["bytes"] = (True, data)
            analysis.read = True
        if data is not None or data_loader is not None:
            cache["prefer-structured-bytes"] = True
            cache["caller-provided-bytes"] = True
        if precomputed_representations:
            cache.update(precomputed_representations)
        extracted = False
        for representation in ordered_representations:
            active_rules = rules_by_representation[representation]
            try:
                content = self._extract_representation(
                    file,
                    representation,
                    cache,
                    pretty_filename,
                    data_loader=data_loader,
                    path_factory=path_factory,
                )
                extracted = True
                analysis.read = True
            except Exception as exc:
                error = RepresentationError(
                    representation=representation,
                    rule_ids=tuple(dict.fromkeys(rule.rule_id for rule in active_rules)),
                    error=f"{type(exc).__name__}: {exc}",
                )
                representation_errors.append(error)
                log.warning("%s: %s", display_text(pretty_filename), display_text(error.render()))
                continue
            finally:
                # A successful fallback is still incomplete if an explicit
                # Unicode encoding failed. Keep all fallback/other findings,
                # but never report that representation as cleanly analyzed.
                if representation == "text":
                    for diagnostic in cache.pop("text-decoding-errors", ()):
                        error = RepresentationError(
                            representation=representation,
                            rule_ids=tuple(dict.fromkeys(rule.rule_id for rule in active_rules)),
                            error=diagnostic,
                        )
                        representation_errors.append(error)
                        log.warning("%s: %s", display_text(pretty_filename), display_text(error.render()))
            context_cache = {}
            for rule in active_rules:
                try:
                    evidence = self._evaluate_content_rule(rule, content)
                except Exception as exc:
                    error = RepresentationError(
                        representation=representation,
                        rule_ids=(rule.rule_id,),
                        error=f"rule evaluation failed: {type(exc).__name__}: {exc}",
                    )
                    representation_errors.append(error)
                    log.warning("%s: %s", display_text(pretty_filename), display_text(error.render()))
                    continue
                for predicate, match in evidence:
                    finding = self._finding(rule, predicate, match, content, context_cache=context_cache)
                    findings.append(finding)
                    if log.isEnabledFor(logging.DEBUG):
                        provenance = f"{rule.rule_pack_id or rule.rule_source}@{rule.rule_pack_version or '-'}"
                        log.debug(
                            '%s: matched "%s" [%s; %s] / "%s" at %s:%s: %s',
                            display_text(pretty_filename),
                            display_text(rule.rule_id),
                            display_text(provenance),
                            display_text(rule.representation),
                            display_text(predicate.value),
                            finding.start,
                            finding.end,
                            display_text(finding.value),
                        )
                analysis.completed += 1

        for inspector in inspectors:
            try:
                data = self._source_bytes(file, cache, data_loader)
                extracted = True
                evidence = self._run_inspector(inspector, data, pretty_filename)
            except Exception as exc:
                error = RepresentationError(
                    representation=inspector.representation,
                    rule_ids=(inspector.rule_id,),
                    error=f"inspection failed: {type(exc).__name__}: {exc}",
                )
                representation_errors.append(error)
                log.warning("%s: %s", display_text(pretty_filename), display_text(error.render()))
                continue
            for value, start, end, context in evidence:
                findings.append(
                    ParsedFinding(
                        rule_id=inspector.rule_id,
                        pattern=inspector.detector,
                        value=value,
                        start=start,
                        end=end,
                        context=context,
                        representation=inspector.representation,
                        rule_source=inspector.rule_source,
                        rule_schema_version=inspector.rule_schema_version,
                        rule_pack_id=inspector.rule_pack_id,
                        rule_pack_version=inspector.rule_pack_version,
                        severity=inspector.severity,
                        confidence=inspector.confidence,
                        category=inspector.category,
                        tags=inspector.tags,
                    )
                )
            analysis.completed += 1

        rendered_error = " | ".join(error.render() for error in representation_errors) or None
        return ParseResult(
            findings=tuple(findings),
            extracted=extracted,
            error=rendered_error,
            representation_errors=tuple(representation_errors),
            **analysis.fields(),
        )
