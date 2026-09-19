from dataclasses import dataclass
from pathlib import Path


CONTENT_UNKNOWN = object()


def normalize_directory_filter(value) -> str:
    """Canonicalize separators without trimming or changing substring semantics."""

    return str(value).lower().replace("/", "\\")


@dataclass(frozen=True)
class IncludeEvaluation:
    results: dict[str, bool]
    content_pending: bool


class ScopeMatcher:
    """Apply include categories consistently and hard exclusions first."""

    def __init__(
        self,
        *,
        filename_filters=(),
        extensions=(),
        excluded_extensions=(),
        content_active=False,
        included_shares=(),
        excluded_shares=(),
        included_directories=(),
        excluded_directories=(),
        date_active=False,
        or_logic=False,
    ):
        self.filename_filters = tuple(filename_filters)
        self.extensions = tuple(value.lower() for value in extensions)
        self.excluded_extensions = tuple(value.lower() for value in excluded_extensions)
        self.content_active = bool(content_active)
        self.included_shares = tuple(value.lower() for value in included_shares)
        self.excluded_shares = tuple(value.lower() for value in excluded_shares)
        self.included_directories = tuple(normalize_directory_filter(value) for value in included_directories)
        self.excluded_directories = tuple(normalize_directory_filter(value) for value in excluded_directories)
        self.date_active = bool(date_active)
        self.or_logic = bool(or_logic)

    @staticmethod
    def extension(filename) -> str:
        return "".join(Path(str(filename)).suffixes).lower()

    @staticmethod
    def normalize_directory(directory) -> str:
        value = str(directory).lower().replace("/", "\\")
        return "" if value in ("", ".") else value.strip("\\")

    def share_exclusion(self, share: str, share_type: int | None = None) -> str | None:
        normalized = share.lower()
        if normalized in self.excluded_shares:
            return f'share name "{share}" is excluded'
        if share_type is None:
            return f'share "{share}" has unknown SMB type; only confirmed disk shares are safe to scan'
        if (int(share_type) & 0xFFFF) != 0:
            return f'share "{share}" has non-file SMB type {int(share_type) & 0xFFFF}'
        return None

    def directory_exclusion(self, directory) -> str | None:
        normalized = self.normalize_directory(directory)
        for value in self.excluded_directories:
            if value in normalized:
                return f'directory path matches excluded value "{value}"'
        return None

    def file_exclusion(self, filename) -> str | None:
        extension = self.extension(filename)
        for value in self.excluded_extensions:
            if extension.endswith(value):
                return f'extension "{extension}" matches excluded value "{value}"'
        return None

    def share_matches(self, share: str | None) -> bool:
        if not self.included_shares:
            return True
        return share is not None and share.lower() in self.included_shares

    def directory_matches(self, directory) -> bool:
        if not self.included_directories:
            return True
        normalized = self.normalize_directory(directory)
        return any(value in normalized for value in self.included_directories)

    def filename_matches(self, filename) -> bool:
        if not self.filename_filters:
            return True
        stem = Path(str(filename)).stem
        return any(expression.match(stem) for expression in self.filename_filters)

    def extension_matches(self, filename) -> bool:
        if not self.extensions:
            return True
        extension = self.extension(filename)
        return any(extension.endswith(value) for value in self.extensions)

    def evaluate_includes(
        self,
        *,
        share: str | None,
        directory,
        filename,
        date_match: bool = True,
        content_match=CONTENT_UNKNOWN,
    ) -> IncludeEvaluation:
        results = {}
        if self.included_shares and share is not None:
            results["share"] = self.share_matches(share)
        if self.included_directories:
            results["directory"] = self.directory_matches(directory)
        if self.filename_filters:
            results["filename"] = self.filename_matches(filename)
        if self.extensions:
            results["extension"] = self.extension_matches(filename)
        if self.date_active:
            results["date"] = bool(date_match)

        content_pending = self.content_active and content_match is CONTENT_UNKNOWN
        if self.content_active and not content_pending:
            results["content"] = bool(content_match)
        return IncludeEvaluation(results=results, content_pending=content_pending)

    def pre_content_candidate(self, **values) -> bool:
        evaluation = self.evaluate_includes(content_match=CONTENT_UNKNOWN, **values)
        if evaluation.content_pending:
            if self.or_logic:
                # Content can still make the file enter scope even when every
                # metadata category currently misses.
                return True
            return all(evaluation.results.values())
        return self._combine(evaluation.results)

    def final_include(self, *, content_match=False, **values) -> bool:
        evaluation = self.evaluate_includes(content_match=content_match, **values)
        return self._combine(evaluation.results)

    def _combine(self, results: dict[str, bool]) -> bool:
        if not results:
            return True
        return any(results.values()) if self.or_logic else all(results.values())

    def should_traverse_share(self, share: str) -> bool:
        if not self.included_shares or self.share_matches(share):
            return True
        if not self.or_logic:
            return False
        # Under OR, another active category can still select a file on an
        # unmatched share, so a share include cannot be used as a hard prune.
        return bool(
            self.included_directories
            or self.filename_filters
            or self.extensions
            or self.content_active
            or self.date_active
        )
