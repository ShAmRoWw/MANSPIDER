"""Conservative negative-only guards derived from the actual compiled regex.

A guard may prove a match impossible; a successful guard never proves a match.
The original expression always supplies values, offsets and all occurrences.
Unsupported parser syntax/versions simply use the original regex. No rule IDs,
pack versions, source encodings or decoded values are special-cased here.
"""

import re
from dataclasses import dataclass

try:  # CPython 3.11+ moved the same parser into re; 3.10 retains sre_parse.
    from re import _parser as _regex_parser
except ImportError:  # pragma: no cover - exercised on Python 3.10
    try:
        import sre_parse as _regex_parser
    except ImportError:  # pragma: no cover - alternative interpreter fallback
        _regex_parser = None


_ASCII_TEXT = "".join(map(chr, range(128)))
_MAX_ALTERNATIVES = 8
_MAX_LITERAL_LENGTH = 128
_MAX_PATTERN_LENGTH = 65536
_MAX_NODES = 4096
_MAX_DEPTH = 48


@dataclass(frozen=True)
class RegexGuard:
    # At least one literal must occur anywhere in the complete representation.
    alternatives: tuple[str, ...] = ()
    requires_non_ascii: bool = False

    def impossible(self, content: str) -> bool:
        # re reads the underlying Unicode string, bypassing overridable methods
        # on str subclasses. Such callers retain the original regex path.
        if type(content) is not str:
            return False
        if self.requires_non_ascii and content.isascii():
            return True
        if self.alternatives:
            for literal in self.alternatives:
                if literal in content:
                    return False
            return True
        return False


def _best_clause(clauses):
    """Choose one necessary clause, bounding runtime work and retained memory."""

    useful = []
    for clause in clauses:
        if not clause:
            continue
        clause = tuple(dict.fromkeys(value[:_MAX_LITERAL_LENGTH] for value in clause))
        if len(clause) <= _MAX_ALTERNATIVES and min(map(len, clause)) >= 2:
            useful.append(clause)
    return max(useful, key=lambda clause: (min(map(len, clause)) / len(clause), -len(clause)), default=())


def _non_ascii_class(items, flags):
    # Ask the same regex implementation about case equivalences. In particular,
    # Unicode IGNORECASE lets non-ASCII İ/ı/ſ/K match ASCII: ord()>127 is not enough.
    fragments = []
    for operation, value in items:
        name = str(operation)
        if name == "LITERAL":
            if value < 128:
                return False
            fragments.append(re.escape(chr(value)))
        elif name == "RANGE":
            low, high = value
            if low < 128:
                return False
            fragments.append(f"{re.escape(chr(low))}-{re.escape(chr(high))}")
        else:  # Negated sets and categories deliberately have no such guard.
            return False
    if not fragments:
        return False
    expression = re.compile("[" + "".join(fragments) + "]", flags & (re.IGNORECASE | re.ASCII))
    return expression.search(_ASCII_TEXT) is None


def _facts(nodes, flags, budget, depth=0):
    if depth > _MAX_DEPTH:
        raise ValueError("regex guard depth budget")
    clauses = []
    non_ascii = False
    literal_run = []

    def flush_literal():
        if literal_run:
            clauses.append(("".join(literal_run),))
            literal_run.clear()

    for operation, value in nodes:
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError("regex guard node budget")
        name = str(operation)
        if name == "LITERAL":
            if not flags & re.IGNORECASE:
                literal_run.append(chr(value))
            non_ascii |= _non_ascii_class(((operation, value),), flags) if value >= 128 else False
            continue
        # The parser factors common branch prefixes: gh...|github... becomes
        # g + (h...|ithub...). Reattach an adjacent exact run when analyzing
        # each branch so a one-character fact does not hide useful gh/github.
        branch_prefix = tuple(("LITERAL", ord(char)) for char in literal_run) if name == "BRANCH" else ()
        flush_literal()
        clause, required = (), False
        if name == "SUBPATTERN":
            _group, added, removed, child = value
            child_flags = (flags | added) & ~removed
            if added & re.ASCII:
                child_flags &= ~re.UNICODE
            elif added & re.UNICODE:
                child_flags &= ~re.ASCII
            clause, required = _facts(child, child_flags, budget, depth + 1)
        elif name == "BRANCH":
            _unused, branches = value
            budget[0] -= len(branches)  # Empty alternatives also consume work.
            if budget[0] < 0:
                raise ValueError("regex guard branch budget")
            facts = [_facts((*branch_prefix, *branch), flags, budget, depth + 1) for branch in branches]
            if facts and all(item[0] for item in facts):
                clause = tuple(literal for item in facts for literal in item[0])
            required = bool(facts) and all(item[1] for item in facts)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            minimum, _maximum, child = value
            if minimum:
                clause, required = _facts(child, flags, budget, depth + 1)
        elif name == "ASSERT":
            _direction, child = value
            # Positive lookarounds also require their evidence somewhere in the
            # full input, even when it lies outside the returned match span.
            clause, required = _facts(child, flags, budget, depth + 1)
        elif name == "ATOMIC_GROUP":
            clause, required = _facts(value, flags, budget, depth + 1)
        elif name == "IN":
            required = _non_ascii_class(value, flags)
        elif name in ("AT", "ANY", "NOT_LITERAL", "CATEGORY", "ASSERT_NOT", "GROUPREF", "GROUPREF_EXISTS"):
            pass  # No proven necessary condition; never guess about references.
        else:
            raise ValueError(f"unsupported regex guard opcode: {name}")
        clauses.append(clause)
        non_ascii |= required
    flush_literal()
    return _best_clause(clauses), non_ascii


def build_regex_guard(expression: re.Pattern) -> RegexGuard | None:
    """Return safe necessary conditions, or opt out of this optional fast path."""

    if (
        _regex_parser is None
        or not isinstance(expression, re.Pattern)
        or not isinstance(expression.pattern, str)
        or len(expression.pattern) > _MAX_PATTERN_LENGTH
    ):
        return None
    try:
        parsed = _regex_parser.parse(expression.pattern, expression.flags)
        alternatives, non_ascii = _facts(parsed, parsed.state.flags, [_MAX_NODES])
        if alternatives or non_ascii:
            return RegexGuard(alternatives, non_ascii)
    except Exception:
        # Regex compilation/validation already happened upstream. Failure of an
        # optional internal-parser optimization must not reject a working rule.
        pass
    return None
