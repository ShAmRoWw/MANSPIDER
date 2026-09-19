"""Lossless, read-only access to inline and object-owned finding contexts.

Schema 9 keeps historical inline evidence and stores new shared contexts once
per object. Every resolved reference is checked for ownership: damaged states
must not silently turn missing evidence into an empty string.
"""

import re
import sqlite3


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
FINDING_COLUMNS = (
    "finding_id", "run_id", "object_id", "rule_id", "representation", "rule_source",
    "rule_schema_version", "rule_pack_id", "rule_pack_version", "severity", "confidence",
    "category", "tags_json", "match_start", "match_end", "value", "context", "created_at",
)


def _alias(value):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid internal SQL alias")
    return value


def _valid_context(run_id, object_id, inline_is_null, owner_run, owner_object, storage_type):
    if (
        inline_is_null != 1 or run_id != owner_run or object_id != owner_object
        or owner_run is None or owner_object is None or storage_type != "text"
    ):
        raise sqlite3.DatabaseError("Invalid normalized finding context reference")
    return 1


def configure_evidence_reader(connection):
    """Install a metadata-only guard; never pass full evidence through Python."""
    connection.create_function("manspider_context_valid", 6, _valid_context, deterministic=True)


def context_join(schema_version, alias="f", context_alias="fc"):
    alias, context_alias = _alias(alias), _alias(context_alias)
    if schema_version < 9:
        return ""
    return f" LEFT JOIN finding_contexts AS {context_alias} ON {context_alias}.context_id={alias}.context_id "


def context_sql(schema_version, alias="f", context_alias="fc"):
    alias, context_alias = _alias(alias), _alias(context_alias)
    if schema_version < 9:
        return f"{alias}.context"
    return (
        f"CASE WHEN {alias}.context_id IS NULL THEN {alias}.context "
        f"WHEN manspider_context_valid({alias}.run_id,{alias}.object_id,{alias}.context IS NULL,"
        f"{context_alias}.run_id,{context_alias}.object_id,typeof({context_alias}.context)) "
        f"THEN {context_alias}.context END"
    )


def finding_projection(schema_version=9, alias="f", context_alias="fc"):
    """The historical logical row shape, without exposing storage pointers."""
    alias = _alias(alias)
    return ",".join(
        f"{context_sql(schema_version, alias, context_alias)} AS context" if name == "context"
        else f"{alias}.{name}" for name in FINDING_COLUMNS
    )


def evidence_location(connection, finding_rowid, field, schema_version=None):
    """Resolve an authorized finding into allowlisted (table, field, rowid).

    Raises sqlite3.DatabaseError for missing or corrupt storage. Callers must
    authorize the finding first and resolve/read within the same read snapshot.
    Supports ordinary tuple rows as well as sqlite3.Row connections.
    """
    if type(finding_rowid) is not int or finding_rowid <= 0 or field not in {"value", "context"}:
        raise ValueError("Invalid evidence field or rowid")
    if schema_version is None:
        # Standalone evidence readers and historical schemas have no context
        # references (some minimal callers do not have a runs table either).
        columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}
        if "context_id" not in columns:
            return "findings", field, finding_rowid
        row = connection.execute(
            "SELECT r.schema_version FROM findings f JOIN runs r ON r.run_id=f.run_id WHERE f.rowid=?",
            (finding_rowid,),
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("Finding is no longer present")
        schema_version = row[0]
    if field == "value" or schema_version < 9:
        return "findings", field, finding_rowid
    row = connection.execute(
        "SELECT f.context_id,f.run_id,f.object_id,f.context IS NULL,fc.run_id,fc.object_id,typeof(fc.context) "
        "FROM findings f LEFT JOIN finding_contexts fc ON fc.context_id=f.context_id WHERE f.rowid=?",
        (finding_rowid,),
    ).fetchone()
    if row is None:
        raise sqlite3.DatabaseError("Finding is no longer present")
    if row[0] is None:
        return "findings", field, finding_rowid
    if type(row[0]) is not int or row[0] <= 0:
        raise sqlite3.DatabaseError("Invalid normalized finding context reference")
    _valid_context(*row[1:])
    return "finding_contexts", "context", row[0]
