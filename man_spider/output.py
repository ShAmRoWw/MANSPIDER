import json
import sqlite3
from pathlib import Path

from man_spider.lib.localfs import atomic_local_text_output
from man_spider.path_safety import UnsafeWritePath, require_local_write_path
from man_spider.session_paths import session_path_conflict

from man_spider.state import ScanState, StateError


class JsonOutputError(StateError):
    """Raised when an explicitly requested report cannot be written safely."""


def finding_path(row) -> str:
    """Render the same readable location used by realtime human findings."""

    path = str(row["path"] or "")
    if not row["share"]:
        return path
    relative = path.replace("/", "\\").lstrip("\\")
    base = f"{row['target']}\\{row['share']}"
    return f"{base}\\{relative}" if relative else base


def manifest_path(row) -> str:
    """Render target/share/container rows without duplicating a share name."""

    if row["share"] and row["kind"] == "share":
        return f"{row['target']}\\{row['share']}"
    return finding_path(row) if row["share"] else str(row["path"] or row["target"] or "")


def build_json_report(state: ScanState) -> dict:
    run = state.run_row()
    configuration = json.loads(run["config_json"])
    findings = []
    for row in state.report_findings():
        findings.append(
            {
                "path": finding_path(row),
                "target": row["target"],
                "share": row["share"],
                "relative_path": row["path"],
                "rule": row["rule_id"],
                "representation": row["representation"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "category": row["category"],
                "tags": json.loads(row["tags_json"]),
                "rule_provenance": {
                    "source": row["rule_source"],
                    "schema_version": row["rule_schema_version"],
                    "pack": (
                        {
                            "id": row["rule_pack_id"],
                            "version": row["rule_pack_version"],
                        }
                        if row["rule_pack_id"] is not None
                        else None
                    ),
                },
                "value": row["value"],
                "context": row["context"],
                "match_start": row["match_start"],
                "match_end": row["match_end"],
                "object_status": row["object_status"],
                "object_reason": row["object_reason"],
                "analysis_status": row["analysis_status"],
                "analysis_reason": row["analysis_reason"],
                "analysis_read": None if row["analysis_read"] is None else bool(row["analysis_read"]),
                "changed": bool(row["changed"]),
                "size": row["size"],
                "mtime": row["mtime"],
            }
        )

    exclusions = [
        {
            "kind": row["kind"],
            "path": manifest_path(row),
            "target": row["target"],
            "share": row["share"],
            "relative_path": row["path"],
            "reason": row["reason"],
            "occurrences": row["occurrences"],
        }
        for row in state.connection.execute(
            """
            SELECT * FROM exclusions WHERE run_id=?
            ORDER BY kind, COALESCE(target, ''), COALESCE(share, ''), COALESCE(path, '')
            """,
            (state.run_id,),
        ).fetchall()
    ]
    errors = [
        {
            "kind": row["kind"],
            "path": manifest_path(row),
            "target": row["target"],
            "share": row["share"],
            "relative_path": row["path"],
            "reason": row["reason"],
            "attempts": row["attempts"],
        }
        for row in state.connection.execute(
            """
            SELECT * FROM objects WHERE run_id=? AND status='error'
            ORDER BY kind, COALESCE(target, ''), COALESCE(share, ''), COALESCE(path, '')
            """,
            (state.run_id,),
        ).fetchall()
    ]
    return {
        "scanner_version": run["scanner_version"],
        "run_status": run["status"],
        "error_reason": run["error_reason"],
        "created_at": run["created_at"],
        "updated_at": run["updated_at"],
        "completed_at": run["completed_at"],
        "configuration": configuration,
        "progress": state.progress_snapshot(),
        "findings": findings,
        "exclusions": exclusions,
        "errors": errors,
    }


def write_json_report(state: ScanState, destination: str | Path, *, overwrite: bool) -> Path:
    """Atomically write a complete UTF-8 report with non-restrictive local modes."""

    try:
        destination = require_local_write_path(destination, purpose="JSON report")
    except UnsafeWritePath as exc:
        raise JsonOutputError(str(exc)) from exc
    conflict = session_path_conflict(state.path, destination)
    if conflict is not None:
        raise JsonOutputError(f"JSON output cannot overwrite the reserved {conflict}: {destination}")
    if destination.exists() and not overwrite:
        raise JsonOutputError(f"JSON output already exists: {destination}")

    try:
        with atomic_local_text_output(destination, purpose="JSON report") as stream:
            json.dump(build_json_report(state), stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise JsonOutputError(f"Unable to write JSON report {destination}: {exc}") from exc
    return destination
