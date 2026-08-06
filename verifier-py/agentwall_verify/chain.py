"""Walking one record file: the ``chained`` layer.

Each record file is walked independently, in file order, from its first line.
A file need not start at index 0, because a chain that continues across a
rotation starts its next file where it left off.
"""

from __future__ import annotations

import os

from . import codes
from .canon import canonical_payload, has_control_bytes, hash_material, sha256_hex
from .codes import Problem
from .tokens import NUMBER, OBJECT, STRING, DuplicateKey, JsonError, TruncatedJson, Value, parse

GAP_ACTION = "audit:chain-gap"


class Record:
    """A record that is intact enough to take part in the chain.

    A record that is malformed never becomes one of these: the format says such
    a record counts toward nothing, so it must not be able to link, to fill a
    segment count, or to offer a committed live tail.
    """

    __slots__ = ("line_no", "index", "hash", "previous_hash", "is_gap_declaration")

    def __init__(self, line_no: int, index: int, digest: str, previous_hash: str | None) -> None:
        self.line_no = line_no
        self.index = index
        self.hash = digest
        self.previous_hash = previous_hash
        self.is_gap_declaration = False


class RecordFile:
    """The result of walking one record file."""

    __slots__ = ("path", "present", "records", "problems", "torn_tail")

    def __init__(self, path: str) -> None:
        self.path = path
        self.present = False
        self.records: list[Record] = []
        self.problems: list[Problem] = []
        self.torn_tail = False

    @property
    def count(self) -> int:
        return len(self.records)


def _where(path: str, line_no: int) -> str:
    return os.path.basename(path) + " line " + str(line_no)


def _integer_lexeme(value: Value) -> int | None:
    """A chainIndex is an integer, so a fraction or an exponent is not one."""
    if value.kind != NUMBER:
        return None
    lexeme = value.lexeme
    if "." in lexeme or "e" in lexeme or "E" in lexeme:
        return None
    return int(lexeme)


def read_record_file(path: str) -> RecordFile:
    """Walk one JSONL record file and report everything the format asks about."""
    out = RecordFile(path)
    try:
        raw = open(path, "rb").read()
    except FileNotFoundError:
        return out
    except OSError as err:
        out.present = True
        out.problems.append(Problem(codes.PARSE_ERROR, os.path.basename(path) + ": " + str(err)))
        return out
    out.present = True

    chunks = raw.split(b"\n")
    # The last chunk holding anything is the only one a torn tail can be: a
    # process killed mid-append leaves an unterminated line at end of file.
    last_content = -1
    for i, chunk in enumerate(chunks):
        if chunk.strip():
            last_content = i

    previous: Record | None = None
    seen_indexes: set[int] = set()

    for i, chunk in enumerate(chunks):
        if not chunk.strip():
            continue
        line_no = i + 1
        final = i == last_content
        try:
            line = chunk.decode("utf-8")
        except UnicodeDecodeError:
            # A multi-byte sequence cut in half at end of file is a torn tail
            # for the same reason an unterminated string is.
            if final:
                out.torn_tail = True
                out.problems.append(
                    Problem(codes.TORN_TAIL, _where(path, line_no) + " ends mid character", fatal=False)
                )
            else:
                out.problems.append(Problem(codes.PARSE_ERROR, _where(path, line_no) + " is not UTF-8"))
            continue

        try:
            record = parse(line)
        except DuplicateKey as err:
            out.problems.append(
                Problem(codes.DUP_KEY, _where(path, line_no) + " has two members named " + repr(err.key))
            )
            continue
        except TruncatedJson as err:
            if final:
                out.torn_tail = True
                out.problems.append(Problem(codes.TORN_TAIL, _where(path, line_no) + " is cut short", fatal=False))
            else:
                out.problems.append(Problem(codes.PARSE_ERROR, _where(path, line_no) + ": " + err.message))
            continue
        except JsonError as err:
            out.problems.append(Problem(codes.PARSE_ERROR, _where(path, line_no) + ": " + err.message))
            continue

        entry = _judge(out, path, line_no, record)
        if entry is None:
            continue

        if previous is None:
            if entry.index != 0 and entry.previous_hash is None:
                out.problems.append(
                    Problem(
                        codes.LINK_BREAK,
                        _where(path, line_no)
                        + " opens the file at index "
                        + str(entry.index)
                        + " with a null previousHash",
                    )
                )
        else:
            if entry.index != previous.index + 1:
                out.problems.append(
                    Problem(
                        codes.INDEX_GAP,
                        _where(path, line_no)
                        + " has index "
                        + str(entry.index)
                        + " after index "
                        + str(previous.index),
                    )
                )
            if entry.previous_hash != previous.hash:
                out.problems.append(
                    Problem(
                        codes.LINK_BREAK,
                        _where(path, line_no)
                        + " points at "
                        + _short(entry.previous_hash)
                        + " but the record before it hashes to "
                        + _short(previous.hash),
                    )
                )
        if entry.index in seen_indexes:
            # Many records with few distinct indexes is two writers sharing one
            # file, which reads nothing like a single edited record.
            out.problems.append(
                Problem(codes.INDEX_REUSE, _where(path, line_no) + " reuses index " + str(entry.index))
            )
        seen_indexes.add(entry.index)

        if entry.is_gap_declaration:
            dropped = _dropped_count(record)
            out.problems.append(
                Problem(
                    codes.CHAIN_GAP_DECLARED,
                    _where(path, line_no) + " declares " + dropped + " record(s) produced and not stored",
                    fatal=False,
                )
            )

        out.records.append(entry)
        previous = entry

    return out


def _short(digest: str | None) -> str:
    if digest is None:
        return "null"
    return digest[:12]


def _dropped_count(record: Value) -> str:
    metadata = record.get("metadata")
    if metadata is None or metadata.kind != OBJECT:
        return "an unstated number of"
    dropped = metadata.get("droppedRecords")
    if dropped is None or dropped.kind != STRING:
        return "an unstated number of"
    return dropped.text


def _judge(out: RecordFile, path: str, line_no: int, record: Value) -> Record | None:
    """Check one parsed record's integrity block and recompute its hash."""
    where = _where(path, line_no)
    if record.kind != OBJECT:
        out.problems.append(Problem(codes.PARSE_ERROR, where + " is not a JSON object"))
        return None

    integrity = record.get("integrity")
    if integrity is None:
        out.problems.append(Problem(codes.MISSING_INTEGRITY, where + " has no integrity member"))
        return None
    if integrity.kind != OBJECT:
        out.problems.append(Problem(codes.MALFORMED_INTEGRITY, where + " has a non-object integrity member"))
        return None

    index_node = integrity.get("chainIndex")
    index = None if index_node is None else _integer_lexeme(index_node)
    if index is None or index < 0:
        out.problems.append(Problem(codes.MALFORMED_INTEGRITY, where + " has no non-negative integer chainIndex"))
        return None

    hash_node = integrity.get("hash")
    if hash_node is None or hash_node.kind != STRING:
        out.problems.append(Problem(codes.MALFORMED_INTEGRITY, where + " has no string hash"))
        return None
    recorded = hash_node.text

    previous_node = integrity.get("previousHash")
    if previous_node is None:
        out.problems.append(Problem(codes.MALFORMED_INTEGRITY, where + " has no previousHash member"))
        return None
    if previous_node.is_null:
        previous_lexeme = "null"
        previous_hash = None
    elif previous_node.kind == STRING:
        previous_lexeme = previous_node.lexeme
        previous_hash = previous_node.text
    else:
        out.problems.append(Problem(codes.MALFORMED_INTEGRITY, where + " has a previousHash that is neither a string nor null"))
        return None

    algorithm = integrity.get("algorithm")
    if algorithm is None or algorithm.kind != STRING or algorithm.text != "sha256":
        # The hash material spells "sha256" literally, so a record naming any
        # other algorithm has no derivation this format defines.
        out.problems.append(Problem(codes.UNSUPPORTED_ALGORITHM, where + " does not declare algorithm sha256"))
        return None

    canon_node = integrity.get("canon")
    marked = canon_node is not None
    if marked and (canon_node.kind != STRING or canon_node.text != "cu1"):
        out.problems.append(Problem(codes.UNKNOWN_CANON, where + " names a canonical form this verifier does not define"))
        return None

    payload = canonical_payload(record)
    if has_control_bytes(payload):
        out.problems.append(Problem(codes.MALFORMED_INTEGRITY, where + " canonicalizes to text holding a control character"))
        return None
    computed = sha256_hex(hash_material(index_node.lexeme, previous_lexeme, payload))

    entry = Record(line_no, index, computed, previous_hash)
    if computed != recorded:
        if marked:
            out.problems.append(
                Problem(codes.HASH_MISMATCH, where + " hashes to " + _short(computed) + " and records " + _short(recorded))
            )
        else:
            # No canon marker means the record was hashed under an order this
            # format does not define. From the file alone, altered and legacy
            # are indistinguishable, so the report claims neither.
            out.problems.append(
                Problem(
                    codes.HASH_MISMATCH_OR_LEGACY,
                    where + " does not match under cu1 and carries no canon marker, so it was altered or predates cu1",
                )
            )
        # The recorded hash is what the next record points at, so linkage is
        # judged against the file's own claim rather than against a value the
        # file does not contain.
        entry.hash = recorded

    action = record.get("action")
    if action is not None and action.kind == STRING and action.text == GAP_ACTION:
        metadata = record.get("metadata")
        if metadata is not None and metadata.kind == OBJECT and metadata.has("droppedRecords"):
            entry.is_gap_declaration = True

    return entry
