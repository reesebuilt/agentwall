"""The rotation manifest: the ``linked`` layer.

The manifest answers a question the per-record chain cannot: was a whole
rotated file removed, reordered, or replaced? Checking it against itself is
only half the job. A manifest that vouches for a segment rewritten end to end,
with the segment's own chain rebuilt so it verifies, would pass a self-check
and prove nothing, so every entry is also checked against the bytes it names.
"""

from __future__ import annotations

import os

from . import codes
from .canon import sha256_hex
from .chain import RecordFile
from .codes import Problem
from .tokens import NUMBER, OBJECT, STRING, DuplicateKey, JsonError, Value, parse

_ENTRY_MEMBERS = (
    "path",
    "count",
    "firstIndex",
    "lastIndex",
    "finalHash",
    "previousSegmentHash",
    "sealedAt",
)


class Entry:
    """One sealed segment, as the manifest describes it."""

    __slots__ = (
        "line_no",
        "path",
        "resolved",
        "count",
        "first_index",
        "last_index",
        "final_hash",
        "previous_segment_hash",
        "entry_hash",
    )

    def __init__(self, line_no: int) -> None:
        self.line_no = line_no
        self.path = ""
        self.resolved = ""
        self.count = 0
        self.first_index = 0
        self.last_index = 0
        self.final_hash = ""
        self.previous_segment_hash: str | None = None
        self.entry_hash = ""


class Manifest:
    __slots__ = ("path", "present", "entries", "problems")

    def __init__(self, path: str) -> None:
        self.path = path
        self.present = False
        self.entries: list[Entry] = []
        self.problems: list[Problem] = []


def entry_hash_material(node: Value) -> str | None:
    """The literal bytes an entry's ``entryHash`` covers.

    The member order here is fixed by the format and has nothing to do with the
    order the members happen to occupy on the line, so each value is looked up
    by name and its source lexeme is placed where the format puts it.
    """
    parts = ['{"' + _ENTRY_MEMBERS[0] + '":']
    for i, name in enumerate(_ENTRY_MEMBERS):
        member = node.get(name)
        if member is None:
            return None
        if i:
            parts.append(',"' + name + '":')
        parts.append(member.lexeme)
    parts.append("}")
    return "".join(parts)


def read_manifest(path: str) -> Manifest:
    """Read the manifest and check it against itself."""
    out = Manifest(path)
    try:
        raw = open(path, "rb").read()
    except FileNotFoundError:
        return out
    except OSError as err:
        out.present = True
        out.problems.append(Problem(codes.MANIFEST_PARSE_ERROR, os.path.basename(path) + ": " + str(err)))
        return out
    out.present = True

    directory = os.path.dirname(os.path.abspath(path))
    previous: Entry | None = None

    for i, chunk in enumerate(raw.split(b"\n")):
        if not chunk.strip():
            continue
        line_no = i + 1
        where = os.path.basename(path) + " line " + str(line_no)
        try:
            node = parse(chunk.decode("utf-8"))
        except UnicodeDecodeError:
            out.problems.append(Problem(codes.MANIFEST_PARSE_ERROR, where + " is not UTF-8"))
            continue
        except DuplicateKey as err:
            out.problems.append(Problem(codes.DUP_KEY, where + " has two members named " + repr(err.key)))
            continue
        except JsonError as err:
            out.problems.append(Problem(codes.MANIFEST_PARSE_ERROR, where + ": " + err.message))
            continue

        entry = _entry(out, where, line_no, node, directory)
        if entry is None:
            continue

        if previous is None:
            if entry.previous_segment_hash is not None:
                out.problems.append(
                    Problem(codes.MANIFEST_LINK_BREAK, where + " opens the manifest with a non-null previousSegmentHash")
                )
        elif entry.previous_segment_hash != previous.final_hash:
            out.problems.append(
                Problem(
                    codes.MANIFEST_LINK_BREAK,
                    where
                    + " points back at "
                    + _short(entry.previous_segment_hash)
                    + " but the entry before it sealed "
                    + _short(previous.final_hash),
                )
            )

        out.entries.append(entry)
        previous = entry

    return out


def _short(digest: str | None) -> str:
    return "null" if digest is None else digest[:12]


def _entry(out: Manifest, where: str, line_no: int, node: Value, directory: str) -> Entry | None:
    if node.kind != OBJECT:
        out.problems.append(Problem(codes.MANIFEST_ENTRY_MALFORMED, where + " is not a JSON object"))
        return None

    material = entry_hash_material(node)
    recorded = node.get("entryHash")
    if material is None or recorded is None or recorded.kind != STRING:
        out.problems.append(Problem(codes.MANIFEST_ENTRY_MALFORMED, where + " is missing a member the format requires"))
        return None

    entry = Entry(line_no)
    path_node = node.get("path")
    count_node = node.get("count")
    first_node = node.get("firstIndex")
    last_node = node.get("lastIndex")
    final_node = node.get("finalHash")
    previous_node = node.get("previousSegmentHash")
    if (
        path_node.kind != STRING
        or count_node.kind != NUMBER
        or first_node.kind != NUMBER
        or last_node.kind != NUMBER
        or final_node.kind != STRING
        or not (previous_node.is_null or previous_node.kind == STRING)
    ):
        out.problems.append(Problem(codes.MANIFEST_ENTRY_MALFORMED, where + " has a member of the wrong type"))
        return None

    entry.path = path_node.text
    entry.count = int(count_node.lexeme)
    entry.first_index = int(first_node.lexeme)
    entry.last_index = int(last_node.lexeme)
    entry.final_hash = final_node.text
    entry.previous_segment_hash = None if previous_node.is_null else previous_node.text
    entry.entry_hash = recorded.text
    # A relative path resolves against the manifest's own directory. Resolving
    # it against the working directory would make the verdict a property of the
    # operator's shell rather than of the evidence.
    entry.resolved = entry.path if os.path.isabs(entry.path) else os.path.join(directory, entry.path)

    computed = sha256_hex(material)
    if computed != entry.entry_hash:
        out.problems.append(
            Problem(
                codes.MANIFEST_ENTRY_HASH,
                where + " hashes to " + computed[:12] + " and records " + entry.entry_hash[:12],
            )
        )
    return entry


def bind_segments(manifest: Manifest, segments: dict[str, RecordFile]) -> list[Problem]:
    """Check every entry against the file it names.

    Absence and contradiction are kept apart because they send an operator to
    different places: one is evidence that is not there, the other is evidence
    that disagrees.
    """
    problems: list[Problem] = []
    for entry in manifest.entries:
        where = "segment " + entry.path
        segment = segments.get(os.path.realpath(entry.resolved))
        if segment is None or not segment.present:
            problems.append(Problem(codes.SEGMENT_MISSING, where + " is named by the manifest but not on disk"))
            continue
        if not segment.records:
            # Truncating a sealed segment to nothing leaves the file in place,
            # so presence alone is not the test.
            problems.append(Problem(codes.SEGMENT_CONTENT_MISMATCH, where + " holds no readable record"))
            continue
        first = segment.records[0]
        last = segment.records[-1]
        if last.hash != entry.final_hash:
            problems.append(
                Problem(
                    codes.SEGMENT_CONTENT_MISMATCH,
                    where + " ends at " + last.hash[:12] + " and the manifest sealed " + entry.final_hash[:12],
                )
            )
        if len(segment.records) != entry.count:
            problems.append(
                Problem(
                    codes.SEGMENT_CONTENT_MISMATCH,
                    where + " holds " + str(len(segment.records)) + " records and the manifest counted " + str(entry.count),
                )
            )
        if first.index != entry.first_index or last.index != entry.last_index:
            problems.append(
                Problem(
                    codes.SEGMENT_CONTENT_MISMATCH,
                    where
                    + " spans indexes "
                    + str(first.index)
                    + ".."
                    + str(last.index)
                    + " and the manifest recorded "
                    + str(entry.first_index)
                    + ".."
                    + str(entry.last_index),
                )
            )
    return problems
