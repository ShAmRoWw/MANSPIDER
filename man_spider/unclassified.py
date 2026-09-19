"""Passive coverage-gap reporting derived from normal directory listings."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from man_spider.lib.localfs import atomic_local_text_output
from man_spider.path_safety import require_local_write_path
from man_spider.state import ScanState


UNCLASSIFIED_REPORT_SCHEMA_VERSION = 1


class UnclassifiedOutputError(RuntimeError):
    pass


def default_unclassified_report_path(state_path: str | Path) -> Path:
    return Path(state_path).expanduser().with_suffix(".unclassified-files.jsonl")


def _report_record(state: ScanState, row) -> dict:
    return {
        "schema_version": UNCLASSIFIED_REPORT_SCHEMA_VERSION,
        "run_id": state.run_id,
        "object_key": row["object_key"],
        "full_path": row["full_path"],
        "target": row["target"],
        "share": row["share"],
        "path": row["path"],
        "filename": row["filename"],
        "extension": row["extension"],
        "extensionless": not bool(row["extension"]),
        "extension_recognized": bool(row["extension_recognized"]),
        "size_bytes": row["size"],
        "mtime_epoch": row["mtime"],
        "reasons": json.loads(row["reasons_json"]),
        "matched_rule_ids": json.loads(row["matched_rule_ids_json"]),
        "content_read": None if row["content_read"] is None else bool(row["content_read"]),
        "content_status": row["content_status"],
        "processing_status": row["processing_status"],
        "processing_reason": row["processing_reason"],
        "first_seen_at": row["first_seen_at"],
        "last_seen_at": row["last_seen_at"],
    }


def write_unclassified_report(state: ScanState, destination: str | Path) -> tuple[Path, int]:
    """Atomically replace the JSONL view of durable coverage-gap observations."""

    try:
        destination = require_local_write_path(destination, purpose="unclassified-file report")
        if destination.resolve(strict=False) == state.path.resolve(strict=False):
            raise UnclassifiedOutputError("Unclassified-file report cannot overwrite the SQLite state file")
        count = 0
        with atomic_local_text_output(destination, purpose="unclassified-file report") as stream:
            for row in state.iter_unclassified_files():
                json.dump(
                    _report_record(state, row),
                    stream,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                stream.write("\n")
                count += 1
    except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise UnclassifiedOutputError(f"Unable to write unclassified-file report {destination}: {exc}") from exc
    return destination, count
