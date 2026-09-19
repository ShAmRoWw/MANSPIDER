"""Compact human findings; stored evidence remains complete and unmodified."""

import builtins
import re
import sys
import traceback


CONTEXT_CHARACTERS = 60
# Escape terminal controls instead of letting scanned text create log entries,
# hide evidence, or issue terminal commands. Ordinary Unicode stays readable.
_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff]")
_ESCAPES = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
_LINE_BREAKS = re.compile(r"[\n\r\v\f\x85\u2028\u2029]")
_LINE_REPRESENTATIONS = {"text", "raw", "strings", "ocr", "structured"}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONFIDENCE_ORDER = {"high": 2, "medium": 1, "low": 0}


def _escape_control(match):
    character = match.group()
    if character in _ESCAPES:
        return _ESCAPES[character]
    number = ord(character)
    return f"\\x{number:02x}" if number <= 0xff else f"\\u{number:04x}"


def display_text(value) -> str:
    """Keep full values visible, including an explicit spelling of controls."""

    return _CONTROLS.sub(_escape_control, str(value))


def display_traceback(error=None) -> str:
    """Keep traceback structure multiline while escaping its untrusted fields.

    Formatting the whole traceback first loses the distinction between real
    frame separators and newlines supplied by exception text or a filename.
    Keep original exceptions/notes untouched and use public traceback APIs.
    """

    if error is None:
        error = sys.exc_info()[1]
    if error is None:
        return "NoneType: None\n"
    seen = set()
    group_type = getattr(builtins, "BaseExceptionGroup", ())

    def render(current):
        if id(current) in seen:
            return "[exception already displayed]\n"
        seen.add(id(current))
        parts = []
        if current.__cause__ is not None:
            parts.append(render(current.__cause__))
            parts.append("\nThe above exception was the direct cause of the following exception:\n\n")
        elif current.__context__ is not None and not current.__suppress_context__:
            parts.append(render(current.__context__))
            parts.append("\nDuring handling of the above exception, another exception occurred:\n\n")
        frames = traceback.extract_tb(current.__traceback__)
        if frames:
            parts.append("Traceback (most recent call last):\n")
        for frame in frames:
            parts.append(
                f'  File "{display_text(frame.filename)}", line {frame.lineno}, in {display_text(frame.name)}\n'
            )
            if frame.line:
                parts.append(f"    {display_text(frame.line)}\n")
        kind = type(current)
        exception_name = kind.__qualname__
        if kind.__module__ not in ("builtins", "__main__"):
            exception_name = f"{kind.__module__}.{exception_name}"
        parts.append(f"{display_text(exception_name)}: {display_text(current)}\n")
        for note in getattr(current, "__notes__", ()):
            parts.append(f"  note: {display_text(note)}\n")
        if isinstance(current, group_type):
            for index, child in enumerate(current.exceptions, 1):
                parts.append(f"\nException group item {index}:\n")
                parts.append(render(child))
        return "".join(parts)

    return render(error)


def _match_parts(finding, show_context):
    value = finding.value
    context = finding.context
    rendered_value = display_text(value) if value else "(empty match)"
    if not show_context or not context or finding.representation == "metadata":
        return "", rendered_value, ""

    # Regex findings carry the exact offset: repeated equal values on a long
    # line must each show their own surroundings. Inspector evidence may instead
    # provide a semantic description, so its fallback does not assume offsets.
    offset = getattr(finding, "context_offset", None)
    if not isinstance(offset, int) or offset < 0 or context[offset : offset + len(value)] != value:
        offset = context.find(value) if value else -1
    if offset >= 0:
        end = offset + len(value)
        left = max(0, offset - CONTEXT_CHARACTERS)
        right = min(len(context), end + CONTEXT_CHARACTERS)
        before = ("…" if left else "") + display_text(context[left:offset])
        after = display_text(context[end:right]) + ("…" if right < len(context) else "")
        return before, rendered_value, after

    explanation = display_text(context[: CONTEXT_CHARACTERS * 2])
    if len(context) > CONTEXT_CHARACTERS * 2:
        explanation += "…"
    return "", rendered_value, f" (context: {explanation})"


def _finding_prefix(location, finding):
    prefix = f'{display_text(location)}: rule="{display_text(finding.rule_id)}"; severity='
    severity = display_text(finding.severity)
    classification = f"; confidence={display_text(finding.confidence)}; match="
    return prefix + severity + classification, (len(prefix), len(prefix) + len(severity), "severity")


def finding_log_message(location, finding, *, show_context=True):
    """Return one plain line and exact spans for console-only highlighting."""

    prefix, severity_span = _finding_prefix(location, finding)
    before, value, after = _match_parts(finding, show_context)
    match_start = len(prefix) + len(before)
    message = prefix + before + value + after
    highlights = (
        severity_span,
        (match_start, match_start + len(value), "match"),
    )
    return message, highlights


def _line_group_key(finding):
    """Require actual regex coordinates, never inferred inspector positions."""

    if finding.representation not in _LINE_REPRESENTATIONS:
        return None
    if finding.severity not in _SEVERITY_ORDER or finding.confidence not in _CONFIDENCE_ORDER:
        return None
    start, end = finding.start, finding.end
    offset = getattr(finding, "context_offset", None)
    if any(type(value) is not int for value in (start, end, offset)):
        return None
    context, value = finding.context, finding.value
    if not isinstance(context, str) or not isinstance(value, str) or not value:
        return None
    if not 0 <= offset <= start or end - start != len(value) or offset + len(value) > len(context):
        return None
    if not context.startswith(value, offset):
        return None
    # A file's findings are supplied in one call. Representation offsets are
    # deliberately not compared with those of another extraction method.
    return finding.representation, start - offset, len(context)


def _merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _additional_rules(count):
    if count % 10 == 1 and count % 100 != 11:
        return "правило"
    if count % 10 in (2, 3, 4) and count % 100 not in (12, 13, 14):
        return "правила"
    return "правил"


def _group_message(location, group, leader, *, show_context):
    context = leader.context
    matches = _merge_ranges((item.context_offset, item.context_offset + len(item.value)) for item in group)
    if show_context:
        windows = _merge_ranges(
            (max(0, start - CONTEXT_CHARACTERS), min(len(context), end + CONTEXT_CHARACTERS))
            for start, end in matches
        )
    else:
        windows = matches

    prefix, severity_span = _finding_prefix(location, leader)
    pieces = [prefix]
    highlights = [severity_span]
    length = len(prefix)

    def append(text):
        nonlocal length
        pieces.append(text)
        length += len(text)

    match_index = 0
    for window_index, (left, right) in enumerate(windows):
        if window_index:
            append(" … ")
        elif show_context and left:
            append("…")
        cursor = left
        # Both interval lists are disjoint and sorted: no quadratic rescan for
        # long/minified lines containing many separate credentials.
        while match_index < len(matches) and matches[match_index][0] < right:
            start, end = matches[match_index]
            append(display_text(context[cursor:start]))
            highlight_start = length
            append(display_text(context[start:end]))
            highlights.append((highlight_start, length, "match"))
            cursor = end
            match_index += 1
        append(display_text(context[cursor:right]))
    if show_context and windows[-1][1] < len(context):
        append("…")

    others = sorted({item.rule_id for item in group} - {leader.rule_id})
    if others:
        names = ", ".join(display_text(name) for name in others)
        append(f" (ещё {len(others)} {_additional_rules(len(others))}: {names})")
    return "".join(pieces), tuple(highlights), leader.severity


def grouped_console_overrides(location, findings, *, show_context=True):
    """Build per-file console views without modifying any original finding.

    Indices not returned keep their normal message. A returned None suppresses
    only that record's console view; the leader carries the group's complete
    matched intervals and the unique names of other rules. All original log
    records still reach the file handler, SQLite and JSON unchanged.
    """

    if len(findings) < 2:
        return {}
    groups = {}
    for index, finding in enumerate(findings):
        key = _line_group_key(finding)
        if key is not None:
            groups.setdefault(key, []).append(index)

    overrides = {}
    for indices in groups.values():
        if len(indices) < 2:
            continue
        context = findings[indices[0]].context
        # Inspect one line for line breaks, then verify the shared context.
        # Conflicting or multiline evidence is never hidden by grouping.
        if _LINE_BREAKS.search(context) or any(findings[index].context != context for index in indices[1:]):
            continue
        leader_index = min(
            indices,
            key=lambda index: (
                -_SEVERITY_ORDER[findings[index].severity],
                -_CONFIDENCE_ORDER[findings[index].confidence],
                findings[index].rule_id,
                findings[index].start,
                findings[index].end,
                index,
            ),
        )
        view = _group_message(
            location, [findings[index] for index in indices], findings[leader_index], show_context=show_context
        )
        overrides.update((index, None) for index in indices)
        overrides[leader_index] = view
    return overrides
