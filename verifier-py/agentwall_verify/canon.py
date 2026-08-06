"""Canonical form cu1 and the record hash derived from it.

cu1 is defined over the JSON source tokens of a record's own line, so every
function here moves lexemes around and never reserializes a parsed value. The
one place a value is decoded is object key ordering, and even there the decoded
key only chooses the order while the original lexeme is what gets emitted.
"""

from __future__ import annotations

import hashlib

from .tokens import ARRAY, OBJECT, Value, sort_key


def canon(value: Value) -> str:
    """The cu1 byte string for one value, as text still to be UTF-8 encoded."""
    out: list[str] = []
    _canon(value, out)
    return "".join(out)


def _canon(value: Value, out: list[str]) -> None:
    kind = value.kind
    if kind == OBJECT:
        members = value.members or []
        out.append("{")
        first = True
        for member in sorted(members, key=lambda m: sort_key(m.key)):
            if not first:
                out.append(",")
            first = False
            out.append(value.src[member.key_start : member.key_end])
            out.append(":")
            _canon(member.value, out)
        out.append("}")
        return
    if kind == ARRAY:
        out.append("[")
        first = True
        for item in value.items or []:
            if not first:
                out.append(",")
            first = False
            _canon(item, out)
        out.append("]")
        return
    out.append(value.src[value.start : value.end])


def canonical_payload(record: Value) -> str:
    """cu1 of the record with its ``integrity`` member removed.

    Building a shallow copy of the member list rather than mutating the parsed
    record keeps the record reusable for the field lookups that follow.
    """
    stripped = Value(OBJECT, record.src, record.start, record.end)
    stripped.members = [m for m in (record.members or []) if m.key != "integrity"]
    return canon(stripped)


def embed(payload: str) -> str:
    """Encode a canonical payload as the JSON string member ``payload``.

    Exactly two substitutions, because a canonical payload is itself JSON text
    and JSON text carries no unescaped control character and no unpaired
    surrogate, so no other escape can arise.
    """
    return '"' + payload.replace("\\", "\\\\").replace('"', '\\"') + '"'


def hash_material(chain_index: str, previous_hash: str, payload: str) -> str:
    """The literal bytes the record hash is taken over.

    ``chain_index`` and ``previous_hash`` are source lexemes: the bare word
    ``null`` or a quoted hash for the latter, a base-ten integer for the former.
    """
    return (
        '{"chainIndex":'
        + chain_index
        + ',"previousHash":'
        + previous_hash
        + ',"algorithm":"sha256","payload":'
        + embed(payload)
        + "}"
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def record_hash(record: Value, chain_index: str, previous_hash: str) -> tuple[str, str]:
    """Recompute a record's hash. Returns the hash and the material it covered."""
    material = hash_material(chain_index, previous_hash, canonical_payload(record))
    return sha256_hex(material), material


def has_control_bytes(payload: str) -> bool:
    """Whether a canonical payload holds a character the format forbids there."""
    for ch in payload:
        if ch < " ":
            return True
    return False
