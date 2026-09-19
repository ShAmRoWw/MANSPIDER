"""DOCX namespace and package-layout compatibility, entirely in memory.

Kreuzberg 4.10.2 recognises lexical ``w:`` names rather than every equivalent
WordprocessingML namespace spelling.  Re-present those names to the existing
extractor, and relocate a relationship-declared nonstandard main part together
with its internal package links; never substitute a lossy XML-text/ZIP search.
The caller's bytes and every source file remain unchanged.  This is an analysis
copy, not a repaired document or a claim that its package signatures are valid.
"""

import io
import posixpath
import re
import stat
import zipfile
from copy import copy
from urllib.parse import quote, unquote, urlsplit
from xml.parsers import expat
from xml.sax.saxutils import escape, quoteattr


WORD_MIME_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-word.document.macroEnabled.12",
    }
)
_WORD_NAMESPACES = frozenset(
    {
        "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "http://purl.oclc.org/ooxml/wordprocessingml/main",
    }
)
_RELATIONSHIP_NAMESPACES = frozenset(
    {
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "http://purl.oclc.org/ooxml/officeDocument/relationships",
    }
)
_NAMESPACE_SEPARATOR = "\x1f"
_MAX_PARTS = 4096
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024
_MAX_XML_BYTES = 32 * 1024 * 1024
_MAX_XML_DEPTH = 512
_MAX_MANIFEST_RECORDS = 65536
_PACKAGE_RELATIONSHIPS = "http://schemas.openxmlformats.org/package/2006/relationships"
_CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
_MAIN_CONTENT_TYPES = frozenset({
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-word.document.macroEnabled.main+xml",
})
_CANONICAL_MAIN = "word/document.xml"
_WORD_PART_RELATIONSHIPS = frozenset(
    namespace + "/" + kind for namespace in _RELATIONSHIP_NAMESPACES
    for kind in ("header", "footer", "footnotes", "endnotes", "comments", "numbering",
                 "styles", "settings", "fontTable", "webSettings", "glossaryDocument")
)


def _read_xml_part(archive, part):
    if part.file_size > _MAX_XML_BYTES:
        raise ValueError(f"DOCX XML part exceeds {_MAX_XML_BYTES} byte analysis budget: {part.filename}")
    with archive.open(part) as source:
        data = source.read(_MAX_XML_BYTES + 1)
    if len(data) > _MAX_XML_BYTES:
        raise ValueError(f"DOCX XML part exceeds {_MAX_XML_BYTES} byte analysis budget: {part.filename}")
    return data


def _package_records(data, part_name, namespace, root, children):
    """Parse the small, flat OPC manifests without DTD/entity processing.

    Prefix spelling is immaterial. Unexpected nested/foreign markup is an
    explicit error, not something silently discarded while rewriting a package.
    """
    parser = expat.ParserCreate(namespace_separator=_NAMESPACE_SEPARATOR)
    records = []
    depth = 0

    def start(name, attributes):
        nonlocal depth
        depth += 1
        pieces = name.split(_NAMESPACE_SEPARATOR)
        if len(pieces) != 2 or pieces[0] != namespace:
            raise ValueError(f"DOCX invalid package manifest namespace: {part_name}")
        local = pieces[1]
        if depth == 1:
            if local != root or attributes:
                raise ValueError(f"DOCX invalid package manifest root: {part_name}")
        elif depth == 2 and local in children and all(_NAMESPACE_SEPARATOR not in name for name in attributes):
            if len(records) >= _MAX_MANIFEST_RECORDS:
                raise ValueError(f"DOCX package manifest exceeds {_MAX_MANIFEST_RECORDS} records: {part_name}")
            records.append((local, dict(attributes)))
        else:
            raise ValueError(f"DOCX invalid package manifest structure: {part_name}")

    def end(_name):
        nonlocal depth
        depth -= 1

    def content(value):
        if value.strip():
            raise ValueError(f"DOCX invalid package manifest text: {part_name}")

    def reject(*_args):
        raise ValueError(f"DTD and entity declarations are disabled during DOCX inspection: {part_name}")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = content
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError(f"invalid XML during DOCX package inspection ({part_name}): {exc}") from exc
    return records


def _render_records(namespace, root, records):
    output = [f'<{root} xmlns="{namespace}">']
    for name, attributes in records:
        whitespace = {"\r": "&#13;", "\n": "&#10;", "\t": "&#9;"}
        values = "".join(f" {key}={quoteattr(value, whitespace)}" for key, value in attributes.items())
        output.append(f"<{name}{values}/>")
    output.append(f"</{root}>")
    result = "".join(output).encode("utf-8")
    if len(result) > _MAX_XML_BYTES:
        raise ValueError("DOCX rewritten package manifest exceeds XML analysis budget")
    return result


def _relationship_owner(name):
    if name.casefold() == "_rels/.rels":
        return ""
    directory, filename = posixpath.split(name)
    if posixpath.basename(directory).casefold() == "_rels" and filename.casefold().endswith(".rels"):
        return posixpath.join(posixpath.dirname(directory), filename[:-5])
    return None


def _relationship_name(owner):
    if not owner:
        return "_rels/.rels"
    return posixpath.join(posixpath.dirname(owner), "_rels", posixpath.basename(owner) + ".rels")


def _resolve_target(owner, target, entries):
    """Resolve an internal OPC URI, never a filesystem path or network URL."""
    if not isinstance(target, str) or not target or "\\" in target or any(ord(char) < 32 for char in target):
        raise ValueError(f"DOCX unsafe internal relationship target: {target!r}")
    if re.search(r"%(?![0-9a-fA-F]{2})|%(?:2f|5c)", target, re.IGNORECASE):
        raise ValueError(f"DOCX ambiguous encoded relationship target: {target!r}")
    uri = urlsplit(target)
    if uri.scheme or uri.netloc or uri.query or target.startswith("//"):
        raise ValueError(f"DOCX non-package internal relationship target: {target!r}")
    path = unquote(uri.path, errors="strict")
    if "\\" in path or ":" in path or any(ord(char) < 32 for char in path):
        raise ValueError(f"DOCX unsafe decoded relationship target: {target!r}")
    components = [] if path.startswith("/") else posixpath.dirname(owner).split("/") if owner else []
    components = [component for component in components if component]
    if not path:
        path = posixpath.basename(owner)
    for component in path.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            if not components:
                raise ValueError(f"DOCX relationship escapes the package: {target!r}")
            components.pop()
        else:
            components.append(component)
    resolved = "/".join(components)
    if not resolved:
        raise ValueError(f"DOCX relationship does not identify a part: {target!r}")
    # URI escaping belongs to the relationship, not to a second URL lookup.
    part = entries.get(resolved.casefold())
    return (part.orig_filename if part else resolved), uri.fragment


def _relocate_main(archive, entries):
    """Build a rename map and rewritten manifests for a nonstandard Word main.

    Minimal historical fixtures without package manifests keep the canonical
    path. A nonstandard main is accepted only with a unique internal root
    relationship and an explicit Word main content type; arbitrary XML is not
    promoted into a document. All external relationships stay opaque.
    """
    root_part = entries.get("_rels/.rels")
    if root_part is None:
        return {}, {}, {_CANONICAL_MAIN}
    root_records = _package_records(
        _read_xml_part(archive, root_part), root_part.filename,
        _PACKAGE_RELATIONSHIPS, "Relationships", {"Relationship"},
    )
    main_links = [attributes for _, attributes in root_records
                  if attributes.get("Type") in {namespace + "/officeDocument" for namespace in _RELATIONSHIP_NAMESPACES}]
    if not main_links:
        return {}, {}, {_CANONICAL_MAIN}
    if len(main_links) != 1 or main_links[0].get("TargetMode", "Internal") != "Internal":
        raise ValueError("DOCX requires a unique internal officeDocument relationship")
    main, fragment = _resolve_target("", main_links[0].get("Target"), entries)
    if fragment or main.casefold() not in entries:
        raise ValueError("DOCX officeDocument relationship does not identify an existing main part")
    if main == _CANONICAL_MAIN:
        return {}, {}, {main}
    if _CANONICAL_MAIN.casefold() in entries and entries[_CANONICAL_MAIN.casefold()].orig_filename != main:
        raise ValueError("DOCX main relocation conflicts with an existing word/document.xml part")
    types_part = entries.get("[content_types].xml")
    if types_part is None:
        raise ValueError("DOCX nonstandard main part has no content type manifest")
    types = _package_records(_read_xml_part(archive, types_part), types_part.filename,
                             _CONTENT_TYPES, "Types", {"Default", "Override"})
    overrides = {}
    defaults = {}
    word_parts = {main}
    for kind, attributes in types:
        content_type = attributes.get("ContentType", "")
        if kind == "Override":
            name, suffix = _resolve_target("", attributes.get("PartName"), entries)
            if suffix or not attributes.get("PartName", "").startswith("/") or name.casefold() in overrides:
                raise ValueError("DOCX content type manifest has ambiguous part overrides")
            overrides[name.casefold()] = content_type
            if content_type.startswith("application/vnd.openxmlformats-officedocument.wordprocessingml."):
                word_parts.add(name)
        else:
            extension = attributes.get("Extension", "").casefold()
            if not extension or extension in defaults:
                raise ValueError("DOCX content type manifest has ambiguous extension defaults")
            defaults[extension] = content_type
    main_type = overrides.get(main.casefold(), defaults.get(main.rsplit(".", 1)[-1].casefold()))
    if main_type not in _MAIN_CONTENT_TYPES:
        raise ValueError("DOCX officeDocument target is not declared as a Word document main part")
    renames = {main: _CANONICAL_MAIN}
    main_rels = _relationship_name(main)
    destination = _relationship_name(_CANONICAL_MAIN)
    if destination.casefold() in entries and destination.casefold() != main_rels.casefold():
        raise ValueError("DOCX main relocation conflicts with an existing document relationships part")
    if main_rels.casefold() in entries:
        main_rels = entries[main_rels.casefold()].orig_filename
        renames[main_rels] = destination
    replacements = {}
    for part in entries.values():
        owner = _relationship_owner(part.orig_filename)
        if owner is None:
            continue
        if owner.casefold() in entries:
            owner = entries[owner.casefold()].orig_filename
        records = root_records if part is root_part else _package_records(
            _read_xml_part(archive, part), part.filename, _PACKAGE_RELATIONSHIPS, "Relationships", {"Relationship"},
        )
        changed = False
        new_owner = renames.get(owner, owner)
        ids = set()
        for _, attributes in records:
            identifier = attributes.get("Id")
            if not identifier or identifier in ids:
                raise ValueError(f"DOCX ambiguous relationship identifiers: {part.filename}")
            ids.add(identifier)
            mode = attributes.get("TargetMode", "Internal")
            if mode == "External":
                continue
            if mode != "Internal":
                raise ValueError(f"DOCX unsupported relationship TargetMode: {mode!r}")
            target, suffix = _resolve_target(owner, attributes.get("Target"), entries)
            if attributes.get("Type") in _WORD_PART_RELATIONSHIPS and target.casefold() in entries:
                word_parts.add(target)
            new_target = renames.get(target, target)
            if new_owner != owner or new_target != target:
                relative = posixpath.relpath(new_target, posixpath.dirname(new_owner) or ".")
                attributes["Target"] = quote(relative, safe="/!$&'()*+,-.;=@_~") + ("#" + suffix if suffix else "")
                changed = True
        if changed:
            replacements[part.orig_filename] = _render_records(_PACKAGE_RELATIONSHIPS, "Relationships", records)
    for kind, attributes in types:
        if kind == "Override":
            target, _ = _resolve_target("", attributes["PartName"], entries)
            if target in renames:
                attributes["PartName"] = "/" + quote(renames[target], safe="/!$&'()*+,-.;=@_~")
    # A Default can declare a main with a non-xml extension. Preserve that
    # declaration and override only the new canonical main, not every XML part.
    if main.casefold() not in overrides:
        types.append(("Override", {"PartName": "/" + _CANONICAL_MAIN, "ContentType": main_type}))
    replacements[types_part.orig_filename] = _render_records(_CONTENT_TYPES, "Types", types)
    return renames, replacements, word_parts


def _requires_rewrite(data, part_name, require_document=False):
    """Validate ordinary canonical parts without allocating a second XML copy."""
    parser = expat.ParserCreate(namespace_separator=_NAMESPACE_SEPARATOR)
    parser.namespace_prefixes = True
    parser.ordered_attributes = True
    changed = False
    depth = 0

    def inspect_namespace(prefix, uri):
        nonlocal changed
        canonical = "w" if uri in _WORD_NAMESPACES else "r" if uri in _RELATIONSHIP_NAMESPACES else None
        if prefix in {"w", "r"} and prefix != canonical:
            raise ValueError(f"DOCX canonical namespace prefix {prefix!r} has an incompatible binding: {part_name}")
        changed |= canonical is not None and prefix != canonical

    def start(name, _attributes):
        nonlocal depth
        depth += 1
        if depth == 1 and require_document:
            pieces = name.split(_NAMESPACE_SEPARATOR)
            if len(pieces) < 2 or pieces[0] not in _WORD_NAMESPACES or pieces[1] != "document":
                raise ValueError(f"invalid XML: DOCX main part is not a WordprocessingML document: {part_name}")
        if depth > _MAX_XML_DEPTH:
            raise ValueError(f"DOCX XML nesting exceeds {_MAX_XML_DEPTH} elements: {part_name}")

    def end(_name):
        nonlocal depth
        depth -= 1

    def reject_declaration(*_args):
        raise ValueError(f"DTD and entity declarations are disabled during DOCX inspection: {part_name}")

    # Every lexical alias (including a default or nested binding) must be
    # declared. Namespace events therefore prove the canonical fast path
    # without splitting every tag and attribute name or allocating output XML.
    parser.StartNamespaceDeclHandler = inspect_namespace
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError(f"invalid XML during DOCX namespace inspection ({part_name}): {exc}") from exc
    return changed


def _canonical_xml(data, part_name, require_document=False):
    """Preserve expanded XML names, text, attributes and namespace aliases.

    Existing aliases are retained, including aliases used only in QName-valued
    attributes such as mc:Ignorable/Requires.  A canonical prefix already bound to
    an incompatible namespace cannot be reassigned safely: reject that ambiguity
    explicitly instead of silently changing QName values or hiding some text.
    """
    if not _requires_rewrite(data, part_name, require_document=require_document):
        return data
    parser = expat.ParserCreate(namespace_separator=_NAMESPACE_SEPARATOR)
    parser.namespace_prefixes = True
    parser.ordered_attributes = True
    parser.buffer_text = True
    pending_namespaces = []
    frames = []
    output = []
    output_size = 0
    changed = False

    def append(value):
        nonlocal output_size
        output_size += len(value)
        if output_size > _MAX_PACKAGE_BYTES:
            raise ValueError(f"DOCX normalized XML exceeds analysis budget: {part_name}")
        output.append(value)

    def reject_declaration(*_args):
        raise ValueError(f"DTD and entity declarations are disabled during DOCX inspection: {part_name}")

    def name_for_output(name, required):
        nonlocal changed
        pieces = name.split(_NAMESPACE_SEPARATOR)
        if len(pieces) == 1:
            return name
        uri, local = pieces[:2]
        prefix = pieces[2] if len(pieces) == 3 else ""
        canonical = "w" if uri in _WORD_NAMESPACES else "r" if uri in _RELATIONSHIP_NAMESPACES else None
        if prefix in {"w", "r"} and prefix != canonical:
            raise ValueError(f"DOCX canonical namespace prefix {prefix!r} has an incompatible binding: {part_name}")
        if canonical is not None:
            previous = required.setdefault(canonical, uri)
            if previous != uri:
                raise ValueError(f"DOCX mixes incompatible namespaces for {canonical!r}: {part_name}")
            if prefix != canonical:
                changed = True
            return f"{canonical}:{local}"
        return f"{prefix}:{local}" if prefix else local

    def start(name, attributes):
        if len(frames) >= _MAX_XML_DEPTH:
            raise ValueError(f"DOCX XML nesting exceeds {_MAX_XML_DEPTH} elements: {part_name}")
        bindings = dict(frames[-1][1]) if frames else {"xml": "http://www.w3.org/XML/1998/namespace"}
        declarations = list(pending_namespaces)
        pending_namespaces.clear()
        for prefix, uri in declarations:
            bindings[prefix or ""] = uri or ""
        required = {}
        tag = name_for_output(name, required)
        rendered_attributes = [
            (name_for_output(attributes[index], required), attributes[index + 1])
            for index in range(0, len(attributes), 2)
        ]
        for prefix, uri in required.items():
            existing = bindings.get(prefix)
            if existing is not None and existing != uri:
                raise ValueError(f"DOCX cannot safely reuse namespace prefix {prefix!r}: {part_name}")
            if existing is None:
                declarations.append((prefix, uri))
                bindings[prefix] = uri
        append("<" + tag)
        for prefix, uri in declarations:
            attribute = "xmlns:" + prefix if prefix else "xmlns"
            append(f" {attribute}={quoteattr(uri or '')}")
        for attribute, value in rendered_attributes:
            # Preserve character-reference whitespace inside attribute values;
            # XML's ordinary whitespace normalization must not run a second time.
            quoted = quoteattr(value, {"\r": "&#13;", "\n": "&#10;", "\t": "&#9;"})
            append(f" {attribute}={quoted}")
        append(">")
        frames.append((tag, bindings))

    def end(_name):
        tag, _bindings = frames.pop()
        append(f"</{tag}>")

    parser.StartNamespaceDeclHandler = lambda prefix, uri: pending_namespaces.append((prefix, uri))
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = lambda value: append(escape(value, {"\r": "&#13;"}))
    parser.CommentHandler = lambda value: append(f"<!--{value}-->")
    parser.ProcessingInstructionHandler = lambda target, value: append(f"<?{target} {value}?>")
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError(f"invalid XML during DOCX namespace inspection ({part_name}): {exc}") from exc
    if not changed:
        return data
    result = ('<?xml version="1.0" encoding="UTF-8"?>' + "".join(output)).encode("utf-8")
    if len(result) > _MAX_PACKAGE_BYTES:
        raise ValueError(f"DOCX normalized XML exceeds analysis budget: {part_name}")
    return result


def normalize_wordprocessingml(data):
    """Return original bytes, or a bounded namespace/package analysis copy.

    Word XML parts are considered even when another part already yielded text;
    normalizing only an empty extraction would retain the partial-extraction bug.
    Limits fail explicitly; no part or finding is silently truncated.  Nothing is
    extracted onto disk, and XML entities are never resolved.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        parts = archive.infolist()
        if len(parts) > _MAX_PARTS:
            raise ValueError(f"DOCX package exceeds {_MAX_PARTS} parts; namespace analysis is incomplete")
        if sum(part.file_size for part in parts) > _MAX_PACKAGE_BYTES:
            raise ValueError(f"DOCX expanded package exceeds {_MAX_PACKAGE_BYTES} byte analysis budget")
        entries = {}
        for part in parts:
            name = part.orig_filename
            components = name.rstrip("/").split("/")
            if "\x00" in name or "\\" in name or any(component in {"", ".", ".."} for component in components):
                raise ValueError(f"DOCX package contains an unsafe part name: {name!r}")
            if any(":" in component for component in components):
                raise ValueError(f"DOCX package contains an unsafe part name: {name!r}")
            if name.casefold() in entries:
                raise ValueError(f"DOCX package contains duplicate/ambiguous parts: {name!r}")
            entries[name.casefold()] = part
            if part.flag_bits & 1:
                raise ValueError(f"DOCX package contains an encrypted part: {name!r}")
            if stat.S_IFMT(part.external_attr >> 16) == stat.S_IFLNK:
                raise ValueError(f"DOCX package contains a symbolic-link part: {name!r}")
        renames, replacements, word_parts = _relocate_main(archive, entries)
        main = next((name for name, destination in renames.items() if destination == _CANONICAL_MAIN), _CANONICAL_MAIN)
        for part in parts:
            name = part.orig_filename
            if name not in word_parts and not (name.casefold().startswith("word/") and name.casefold().endswith(".xml")):
                continue
            original = _read_xml_part(archive, part)
            normalized = _canonical_xml(original, name, require_document=name == main)
            if normalized is not original:
                replacements[name] = normalized
        if not replacements and not renames:
            return data
        normalized_size = sum(part.file_size for part in parts) + sum(
            len(replacements[part.orig_filename]) - part.file_size
            for part in parts
            if part.orig_filename in replacements
        )
        if normalized_size > _MAX_PACKAGE_BYTES:
            raise ValueError(f"DOCX normalized package exceeds {_MAX_PACKAGE_BYTES} byte analysis budget")
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w") as destination:
            destination.comment = archive.comment
            for part in parts:
                payload = replacements.get(part.orig_filename)
                if payload is None:
                    # A corrupt deflate stream can expand beyond the size
                    # advertised in the directory. Never request an unbounded
                    # read even for opaque parts which are only being copied.
                    with archive.open(part) as source:
                        payload = source.read(_MAX_PACKAGE_BYTES + 1)
                    if len(payload) > _MAX_PACKAGE_BYTES:
                        raise ValueError(
                            f"DOCX package part exceeds {_MAX_PACKAGE_BYTES} byte analysis budget: {part.filename}"
                        )
                output_part = copy(part)
                output_part.filename = renames.get(part.orig_filename, part.orig_filename)
                output_part.orig_filename = output_part.filename
                destination.writestr(output_part, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=1)
        return result.getvalue()
